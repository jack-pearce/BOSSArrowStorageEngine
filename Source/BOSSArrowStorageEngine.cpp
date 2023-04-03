
#include "BOSSArrowStorageEngine.hpp"

#include <Algorithm.hpp>
#include <Expression.hpp>
#include <ExpressionUtilities.hpp>
#include <Utilities.hpp>

#include <arrow/array/array_base.h>
#include <arrow/array/builder_binary.h>
#include <arrow/array/builder_primitive.h>
#include <arrow/csv/api.h>
#include <arrow/io/api.h>
#include <arrow/ipc/reader.h>
#include <arrow/ipc/writer.h>
#include <arrow/memory_pool.h>
#include <arrow/visitor.h>
#include <arrow/visitor_inline.h>

#include <mutex>

// for the debug info
#include <chrono>
#include <iostream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  switch(fdwReason) {
  case DLL_PROCESS_ATTACH:
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
    break;
  case DLL_PROCESS_DETACH:
    // Make sure to call reset instead of letting destructors to be called.
    // It leaves the engine unique_ptr in a non-dangling state
    // in case the depending process still want to call reset() during its own destruction
    // (which does happen in a unpredictable order if it is itself a dll:
    // https://devblogs.microsoft.com/oldnewthing/20050523-05/?p=35573)
    reset();
    break;
  }
  return TRUE;
}
#endif

using boss::utilities::operator""_;
using boss::expressions::generic::isComplexExpression;
using namespace boss::algorithm;

namespace boss::engines::arrow_storage {

#ifdef NDEBUG
bool constexpr VERBOSE_LOADING = false;
#else
bool constexpr VERBOSE_LOADING = true;
#endif

namespace utilities {

/*
 * In the Expression API, we support only two cases at the moment:
 *   - moving the expressions (which will move the spans' data as well)
 *   - cloning the expressions (which will copy the spans' data)
 * However, when injecting the stored Columns into the query,
 * we want to copy the expression by without moving the spans' data:
 * this is the purpose of shallowCopy().
 *
 * We assume that spans' data will be used only during the storage engine's lifetime,
 * so the spans are still owned by the storage engine.
 */
static boss::ComplexExpression shallowCopy(boss::ComplexExpression const& e) {
  auto const& head = e.getHead();
  auto const& dynamics = e.getDynamicArguments();
  auto const& spans = e.getSpanArguments();
  boss::ExpressionArguments dynamicsCopy;
  std::transform(dynamics.begin(), dynamics.end(), std::back_inserter(dynamicsCopy),
                 [](auto const& arg) {
                   return std::visit(
                       boss::utilities::overload(
                           [&](boss::ComplexExpression const& expr) -> boss::Expression {
                             return shallowCopy(expr);
                           },
                           [](auto const& otherTypes) -> boss::Expression { return otherTypes; }),
                       arg);
                 });
  boss::expressions::ExpressionSpanArguments spansCopy;
  std::transform(spans.begin(), spans.end(), std::back_inserter(spansCopy), [](auto const& span) {
    return std::visit(
        [](auto const& typedSpan) -> boss::expressions::ExpressionSpanArgument {
          // just do a shallow copy of the span
          // the storage's span keeps the ownership
          // (since the storage will be alive until the query finishes)
          using SpanType = std::decay_t<decltype(typedSpan)>;
          using T = std::remove_const_t<typename SpanType::element_type>;
          if constexpr(std::is_same_v<T, bool>) {
            // TODO: this would still keep const spans for bools, need to fix later
            return SpanType(typedSpan.begin(), typedSpan.size(), []() {});
          } else {
            // force non-const value for now (otherwise expressions cannot be moved)
            auto* ptr = const_cast<T*>(typedSpan.begin()); // NOLINT
            return boss::Span<T>(ptr, typedSpan.size(), []() {});
          }
        },
        span);
  });
  return boss::ComplexExpression(head, {}, std::move(dynamicsCopy), std::move(spansCopy));
}

/*
 * This class allows to visit Arrow Arrays using generic lambdas.
 * It is used in conjunction with arrow::VisitArrayInline().
 */
template <typename Func> class ArrowArrayVisitor : public arrow::ArrayVisitor {
public:
  explicit ArrowArrayVisitor(Func&& func) : func(std::forward<Func>(func)) {}

  arrow::Status Visit(arrow::NullArray const& /*arrowArray*/) override {
    return arrow::Status::ExecutionError("unsupported arrow type");
  }

  template <typename ArrayType> arrow::Status Visit(ArrayType const& arrowArray) {
    func(arrowArray);
    return arrow::Status::OK();
  }

private:
  Func func;
};
} // namespace utilities

// Int32 -> Int64
std::shared_ptr<arrow::Int64Array> Engine::convertToInt64Array(int32_t const* srcData,
                                                               int64_t size) {
  auto intBuilder = arrow::Int64Builder();
  auto status = intBuilder.AppendEmptyValues(size);
  if(!status.ok()) {
    throw std::runtime_error(status.ToString());
  }
  for(int64_t i = 0; i < size; ++i) {
    intBuilder[i] = srcData[i];
  }
  auto int64arrayPtr = std::shared_ptr<arrow::Int64Array>();
  auto finishStatus = intBuilder.Finish(&int64arrayPtr);
  if(!finishStatus.ok()) {
    throw std::runtime_error(finishStatus.ToString());
  }
  return int64arrayPtr;
}

// Dictionary -> Int64 (+ store separately the strings)
std::shared_ptr<arrow::Int64Array>
Engine::convertToInt64Array(arrow::DictionaryArray const& dictionaryArray,
                            std::string const& dictionaryName) {
  auto const& dictionaryPtr = dictionaryArray.dictionary();
  // store the dictionary separately (as a single unified dictionary)
  auto& unifierPtr = dictionaries[dictionaryName];
  if(!unifierPtr) {
    auto createUnifierResult = arrow::DictionaryUnifier::Make(dictionaryPtr->type());
    if(!createUnifierResult.ok()) {
      throw std::runtime_error(createUnifierResult.status().ToString());
    }
    unifierPtr = std::move(*createUnifierResult);
  }
  std::shared_ptr<arrow::Buffer> transposeBuffer;
  auto unifyStatus = unifierPtr->Unify(*dictionaryPtr, &transposeBuffer);
  if(!unifyStatus.ok()) {
    throw std::runtime_error(unifyStatus.ToString());
  }
  // transpose indices (to unified dictionary) and convert to int64_t
  auto const& indices = *dictionaryArray.indices();
  auto const* srcArrayData = dynamic_cast<arrow::Int32Array const&>(indices).raw_values();
  auto transposeArray = arrow::Int32Array(dictionaryPtr->length(), transposeBuffer);
  auto intBuilder = arrow::Int64Builder();
  auto appendStatus = intBuilder.AppendEmptyValues(dictionaryArray.length());
  if(!appendStatus.ok()) {
    throw std::runtime_error(appendStatus.ToString());
  }
  auto const* transposeMap = transposeArray.raw_values();
  for(int64_t i = 0; i < intBuilder.length(); ++i) {
    intBuilder[i] = transposeMap[srcArrayData[i]];
  }
  auto int64arrayPtr = std::shared_ptr<arrow::Int64Array>();
  auto finishStatus = intBuilder.Finish(&int64arrayPtr);
  if(!finishStatus.ok()) {
    throw std::runtime_error(finishStatus.ToString());
  }
  return int64arrayPtr;
}

template <typename Columns>
void Engine::loadIntoColumns(Columns& columns, std::shared_ptr<arrow::RecordBatchReader>& reader,
                             unsigned long long maxRows) {
  static auto debugStart = std::chrono::high_resolution_clock::now();

  std::shared_ptr<arrow::RecordBatch> batch;
  int64_t totalRows = 0;
  while(maxRows > 0 && reader->ReadNext(&batch).ok() && batch) {
    auto numRows = batch->num_rows();
    if(numRows < maxRows) {
      maxRows -= numRows;
    } else {
      batch = batch->Slice(0, maxRows);
      numRows = maxRows;
      maxRows = 0;
    }

    // store the arrays as spans
    auto const& batchColumns = batch->columns();
    auto batchColumnIt = batchColumns.begin();
    std::transform(
        std::make_move_iterator(columns.begin()), std::make_move_iterator(columns.end()),
        columns.begin(), [&batchColumnIt, this](auto&& e) -> Expression {
          auto arrowArrayPtr = *batchColumnIt++;
          auto [head, statics, dynamics, spans] = std::move(get<ComplexExpression>(e)).decompose();
          auto const& columnName = get<Symbol>(dynamics[0]).getName();
          auto dynArgsIt = std::next(dynamics.begin());
          auto& columnData = *dynArgsIt;
          columnData = visit(
              [&arrowArrayPtr, &columnName, this](auto&& listExpr) -> Expression {
                if constexpr(isComplexExpression<decltype(listExpr)>) {
                  // prepare arrays (conversions to compatible types)
                  if(arrowArrayPtr->type_id() == arrow::Type::DATE32) {
                    arrowArrayPtr = convertToInt64Array(
                        dynamic_cast<arrow::Date32Array const&>(*arrowArrayPtr).raw_values(),
                        arrowArrayPtr->length());
                  } else if(arrowArrayPtr->type_id() == arrow::Type::DICTIONARY) {
                    arrowArrayPtr = convertToInt64Array(
                        dynamic_cast<arrow::DictionaryArray const&>(*arrowArrayPtr),
                        columnName); // store the dictionary's strings per column name
                  }
                  // convert to spans and store as complex expressions
                  auto visitor = utilities::ArrowArrayVisitor([&arrowArrayPtr,
                                                               &listExpr](auto const& columnArray) {
                    if constexpr(std::is_convertible_v<decltype(columnArray),
                                                       arrow::StringArray const&>) {
                      // convert to span of offsets + buffer as string argument
                      auto offsetsArrayPtr = convertToInt64Array(columnArray.raw_value_offsets(),
                                                                 columnArray.length() + 1);
                      auto [unused0, unused1, dynamics, unused2] = std::move(listExpr) // NOLINT
                                                                       .decompose();
                      if(dynamics.empty()) {
                        dynamics.emplace_back("List"_());
                        dynamics.emplace_back(std::string());
                      }
                      auto& encodedList = get<ComplexExpression>(dynamics[0]);
                      auto [head, unused3, unused4, spans] = std::move(encodedList) // NOLINT
                                                                 .decompose();
                      spans.emplace_back(boss::Span<int64_t const>(
                          offsetsArrayPtr->raw_values(), offsetsArrayPtr->length(),
                          [stored = offsetsArrayPtr]() {}));
                      encodedList = ComplexExpression{head, {}, {}, std::move(spans)};
                      auto& buffer = get<std::string>(dynamics[1]);
                      buffer += std::string(
                          static_cast<arrow::util::string_view>(*columnArray.value_data()));
                      listExpr =
                          ComplexExpression{"DictionaryEncodedList"_, {}, std::move(dynamics), {}};
                      return;
                    } else if constexpr(std::is_convertible_v<decltype(columnArray),
                                                              arrow::PrimitiveArray const&>) {
                      using ElementType = decltype(columnArray.Value(0)) const;
                      if constexpr(std::is_constructible_v<expressions::ExpressionSpanArgument,
                                                           boss::Span<ElementType>> &&
                                   std::is_constructible_v<boss::Span<ElementType>, ElementType*,
                                                           int, std::function<void(void)>>) {
                        // TODO: why listExpr is not always a r-value reference?
                        auto [head, statics, dynamics, spans] = std::move(listExpr) // NOLINT
                                                                    .decompose();
                        spans.emplace_back(boss::Span<ElementType>(columnArray.raw_values(),
                                                                   columnArray.length(),
                                                                   [stored = arrowArrayPtr]() {}));
                        listExpr = ComplexExpression{head, std::move(statics), std::move(dynamics),
                                                     std::move(spans)};
                        return;
                      }
                    }
                    throw std::runtime_error("unsupported arrow array type");
                  });
                  auto status = arrow::VisitArrayInline(*arrowArrayPtr, &visitor);
                  if(!status.ok()) {
                    throw std::runtime_error("failed to visit arrow array: " + status.ToString());
                  }
                  return std::move(listExpr); // NOLINT(bugprone-move-forwarding-reference)
                } else {
                  throw std::runtime_error("column must be a complex expression");
                }
              },
              std::move(columnData));
          return ComplexExpression{head, std::move(statics), std::move(dynamics), std::move(spans)};
        });

    if constexpr(VERBOSE_LOADING) {
      auto debugEnd = std::chrono::high_resolution_clock::now();
      std::chrono::duration<float> elapsed = debugEnd - debugStart;
      auto speed = static_cast<int>(static_cast<float>(numRows) / elapsed.count());
      debugStart = debugEnd;
      std::cerr << " [speed:" << speed << "/s] inserting " << numRows << " rows." << std::endl;
    }

    totalRows += numRows;
  }
}

void Engine::loadIntoMemoryMappedFile(
    std::shared_ptr<arrow::io::MemoryMappedFile>& memoryMappedFile,
    std::shared_ptr<arrow::RecordBatchReader>& csvReader) {
  static auto debugStart = std::chrono::high_resolution_clock::now();

  std::shared_ptr<arrow::ipc::RecordBatchWriter> writer;
  std::shared_ptr<arrow::RecordBatch> batch;
  while(csvReader->ReadNext(&batch).ok() && batch) {
    auto const& schema = batch->schema();
    if(!writer) {
      auto writerOptions = arrow::ipc::IpcWriteOptions::Defaults();
      auto maybeWriter = arrow::ipc::MakeStreamWriter(memoryMappedFile, schema, writerOptions);
      if(!maybeWriter.ok()) {
        throw std::runtime_error("failed to open memory-mapped stream writer\n" +
                                 maybeWriter.status().ToString());
      }
      writer = *maybeWriter;
    }

    const arrow::ipc::DictionaryFieldMapper mapper(*schema);
    auto dictionariesResult = arrow::ipc::CollectDictionaries(*batch, mapper);
    if(!dictionariesResult.ok()) {
      throw std::runtime_error("failed to collect dictionaries\n" +
                               dictionariesResult.status().ToString());
    }

    int64_t dictionarySize = 0;
    for(auto const& dictionary : *dictionariesResult) {
      auto const& dictionaryArray = dynamic_cast<arrow::StringArray const&>(*dictionary.second);
      auto dummyField = std::make_shared<arrow::Field>("dummy", dictionaryArray.type());
      auto fields = arrow::FieldVector{std::move(dummyField)};
      auto dummySchema = std::make_shared<arrow::Schema>(std::move(fields));
      auto dummybatchPtr = arrow::RecordBatch::Make(
          std::move(dummySchema), dictionaryArray.length(), arrow::ArrayVector{dictionary.second});
      int64_t thisDictionarySize = 0;
      auto getSizeStatus = arrow::ipc::GetRecordBatchSize(*dummybatchPtr, &thisDictionarySize);
      if(!getSizeStatus.ok()) {
        throw std::runtime_error("failed to get dictionary size\n" + getSizeStatus.ToString());
      }
      dictionarySize +=
          thisDictionarySize * 2; // temp fix: calculated dictionary size is not large enough
    }

    int64_t recordBatchSize = 0;
    auto getSizeStatus = arrow::ipc::GetRecordBatchSize(*batch, &recordBatchSize);
    if(!getSizeStatus.ok()) {
      throw std::runtime_error("failed to get record batch size\n" + getSizeStatus.ToString());
    }

    auto currentSize = *memoryMappedFile->GetSize();
    if(currentSize == 0) {
      // make space for schema
      currentSize = recordBatchSize;
    }

    auto resizeStatus = memoryMappedFile->Resize(currentSize + dictionarySize + recordBatchSize);
    if(!resizeStatus.ok()) {
      throw std::runtime_error(resizeStatus.ToString());
    }

    auto writeStatus = writer->WriteRecordBatch(*batch);
    if(!writeStatus.ok()) {
      throw std::runtime_error("failed to write\n" + writeStatus.ToString());
    }

    if constexpr(VERBOSE_LOADING) {
      auto numRows = batch->num_rows();
      auto debugEnd = std::chrono::high_resolution_clock::now();
      std::chrono::duration<float> elapsed = debugEnd - debugStart;
      auto speed = static_cast<int>(static_cast<float>(numRows) / elapsed.count());
      debugStart = debugEnd;
      std::cerr << " [speed:" << speed << "/s] caching " << numRows << " rows." << std::endl;
    }
  }

  if(writer) {
    auto closeStatus = writer->Close();
    if(!closeStatus.ok()) {
      throw std::runtime_error(closeStatus.ToString());
    }
  }

  auto seekStatus = memoryMappedFile->Seek(0);
  if(!seekStatus.ok()) {
    throw std::runtime_error(seekStatus.ToString());
  }
}

std::shared_ptr<arrow::RecordBatchReader>
Engine::loadFromCsvFile(std::string const& filepath,
                        std::vector<std::string> const& columnNames) const {
  if(filepath.rfind(".tbl") != std::string::npos) {
    return loadFromCsvFile(filepath, columnNames, '|', true, false);
  }
  if(filepath.rfind(".csv") != std::string::npos) {
    return loadFromCsvFile(filepath, columnNames, ',', false, true);
  }
  throw std::runtime_error("unsupported file format for " + filepath);
}

std::shared_ptr<arrow::RecordBatchReader>
Engine::loadFromCsvFile(std::string const& filepath, std::vector<std::string> const& columnNames,
                        char separator, bool eolHasSeparator, bool hasHeader) const {
  // load the original files
  auto const& io_context = arrow::io::default_io_context();
  auto maybeFileInput = arrow::io::ReadableFile::Open(filepath, io_context.pool());
  if(!maybeFileInput.ok()) {
    throw std::runtime_error("failed to find " + filepath + " \n" +
                             maybeFileInput.status().ToString());
  }
  auto cvsInput = *maybeFileInput;

  auto readOptions = arrow::csv::ReadOptions::Defaults();

  readOptions.block_size = properties.fileLoadingBlockSize;

  if(!hasHeader) {
    readOptions.column_names = columnNames;

    if(eolHasSeparator) {
      // need one more dummy column
      // to handle Arrow wrongly loading a value at the end of the line
      // (it will ignore during the loading...)
      readOptions.column_names.emplace_back();
    }
  }

  auto parseOptions = arrow::csv::ParseOptions::Defaults();
  parseOptions.delimiter = separator;

  auto convertOptions = arrow::csv::ConvertOptions::Defaults();
  convertOptions.include_columns = columnNames;
  convertOptions.include_missing_columns = true;
  convertOptions.auto_dict_encode = properties.useAutoDictionaryEncoding;

  auto maybeCvsReader = arrow::csv::StreamingReader::Make(io_context, cvsInput, readOptions,
                                                          parseOptions, convertOptions);
  if(!maybeCvsReader.ok()) {
    throw std::runtime_error("failed to open " + filepath + " \n" +
                             maybeCvsReader.status().ToString());
  }
  return *maybeCvsReader;
}

void Engine::load(Symbol const& tableSymbol, std::string const& filepath,
                  unsigned long long maxRows) {

  auto it = tables.find(tableSymbol.getName());
  if(it == tables.end()) {
    throw std::runtime_error("cannot find table " + tableSymbol.getName() + " to load data into.");
  }
  auto& table = it->second;
  auto columns = table.getArguments();
  auto columnNames = std::vector<std::string>();
  columnNames.reserve(columns.size());
  std::transform(columns.begin(), columns.end(), std::back_inserter(columnNames),
                 [](auto&& column) {
                   return get<Symbol>(get<ComplexExpression>(column).getArguments()[0]).getName();
                 });

  // check if the cached memory-mapped file exists
  std::shared_ptr<arrow::io::MemoryMappedFile> memoryMappedFile;
  if(properties.loadToMemoryMappedFiles) { // only if we want to use a memory-mapped file
    auto memoryMappedFilepath =
        filepath + "_" + std::to_string(properties.fileLoadingBlockSize) +
        (properties.useAutoDictionaryEncoding ? "_with_dict.cached" : ".cached");
    auto maybeMemoryMappedFile =
        arrow::io::MemoryMappedFile::Open(memoryMappedFilepath, arrow::io::FileMode::READWRITE);
    if(!maybeMemoryMappedFile.ok()) {
      throw std::runtime_error("failed to open " + memoryMappedFilepath + " \n" +
                               maybeMemoryMappedFile.status().ToString());
    }
    memoryMappedFile = *maybeMemoryMappedFile;
  }

  if(!memoryMappedFile || memoryMappedFile->GetSize() == 0) {
    // load from the csv file first
    auto csvReader = loadFromCsvFile(filepath, columnNames);
    // then write it to the memory-mapped file (so then we can open it)
    if(memoryMappedFile) {
      if constexpr(VERBOSE_LOADING) {
        std::cerr << "Caching: " << tableSymbol.getName() << std::endl;
      }
      loadIntoMemoryMappedFile(memoryMappedFile, csvReader);
    } else { // not using a memory mapped file
      // just load the file directly
      if constexpr(VERBOSE_LOADING) {
        std::cerr << "Loading from file: " << tableSymbol.getName() << std::endl;
      }
      loadIntoColumns(columns, csvReader, maxRows);
      return; // early return: we don't use memory-mapped files
    }
  }
  // load the memory-mapped file
  auto maybeReader = arrow::ipc::RecordBatchStreamReader::Open(memoryMappedFile);
  if(!maybeReader.ok()) {
    throw std::runtime_error("failed to open memory-mapped stream reader\n" +
                             maybeReader.status().ToString());
  }
  if constexpr(VERBOSE_LOADING) {
    std::cerr << "Loading from cache: " << tableSymbol.getName() << std::endl;
  }
  std::shared_ptr<arrow::RecordBatchReader> memoryMappedFileReader = *maybeReader;
  loadIntoColumns(columns, memoryMappedFileReader, maxRows);
}

boss::Expression Engine::evaluate(boss::Expression&& expr) { // NOLINT
  try {
    return visit(
        boss::utilities::overload(
            [this](ComplexExpression&& e) -> boss::Expression {
              boss::ExpressionArguments args = e.getArguments();
              if(e.getHead() == "CreateTable"_) {
                ExpressionArguments columns;
                columns.reserve(args.size() - 1);
                auto it = std::make_move_iterator(args.begin());
                auto tableSymbol = get<Symbol>(std::move(*it));
                std::transform(++it, std::make_move_iterator(args.end()),
                               std::back_inserter(columns), [](auto&& arg) {
                                 return "Column"_(get<Symbol>(std::forward<decltype(arg)>(arg)),
                                                  "List"_());
                               });
                tables.emplace(std::make_pair(std::move(tableSymbol).getName(),
                                              ComplexExpression("Table"_, std::move(columns))));
                return true;
              }
              if(e.getHead() == "DropTable"_) {
                auto const& table = get<Symbol>(args[0]);
                auto it = tables.find(table.getName());
                if(it != tables.end()) {
                  tables.erase(it);
                }
                return true;
              }
              if(e.getHead() == "Load"_) {
                auto const& table = get<Symbol>(args[0]);
                auto const& filepath = get<std::string>(args[1]);
                load(table, filepath);
                return true;
              }
              if(e.getHead() == "Set"_) {
                auto const& propertyName = get<Symbol>(args[0]);
                if(propertyName == "LoadToMemoryMappedFiles"_) {
                  properties.loadToMemoryMappedFiles = get<bool>(args[1]);
                  return true;
                }
                if(propertyName == "UseAutoDictionaryEncoding"_) {
                  properties.useAutoDictionaryEncoding = get<bool>(args[1]);
                  return true;
                }
                if(propertyName == "FileLoadingBlockSize"_) {
                  auto blockSize = get<int64_t>(args[1]);
                  if(blockSize <= 0 || blockSize > std::numeric_limits<int32_t>::max()) {
                    throw std::runtime_error("block size must be positive and within int32 range");
                  }
                  properties.fileLoadingBlockSize = blockSize;
                  return true;
                }
                return false;
              }
              if(e.getHead() == "Equal"_ || e.getHead() == "StringContainsQ"_) {
                if(std::holds_alternative<Symbol>(args[0]) &&
                   std::holds_alternative<std::string>(args[1])) {
                  auto const& column = get<Symbol>(args[0]);
                  auto const& unifierPtr = dictionaries[column.getName()];
                  if(unifierPtr) {
                    auto const& str = get<std::string>(args[1]);
                    auto dummyDicBuilder = arrow::StringBuilder();
                    auto appendStatus = dummyDicBuilder.Append(str);
                    if(!appendStatus.ok()) {
                      throw std::runtime_error(appendStatus.ToString());
                    }
                    std::shared_ptr<arrow::StringArray> dummyDictionaryPtr;
                    auto finishStatus = dummyDicBuilder.Finish(&dummyDictionaryPtr);
                    if(!finishStatus.ok()) {
                      throw std::runtime_error(finishStatus.ToString());
                    }
                    std::shared_ptr<arrow::Buffer> indices;
                    auto unifyStatus = unifierPtr->Unify(*dummyDictionaryPtr, &indices);
                    if(!unifyStatus.ok()) {
                      throw std::runtime_error(unifyStatus.ToString());
                    }
                    int64_t index = *reinterpret_cast<int32_t const*>(indices->data());
                    return "Equal"_(column, index);
                  }
                  return boss::ComplexExpression(e.getHead(), {}, std::move(args), {});
                }
              }
              visitTransform(args, [this](auto&& arg) -> boss::Expression {
                if constexpr(isComplexExpression<decltype(arg)> &&
                             std::is_lvalue_reference_v<decltype(arg)>) {
                  return evaluate(arg.clone());
                } else {
                  return evaluate(std::forward<decltype(arg)>(arg));
                }
              });
              return boss::ComplexExpression(e.getHead(), {}, std::move(args), {});
            },
            [this](Symbol&& symbol) -> boss::Expression {
              auto it = tables.find(symbol.getName());
              if(it == tables.end()) {
                return std::move(symbol);
              }
              return utilities::shallowCopy(it->second);
            },
            [](auto&& arg) -> boss::Expression { return std::forward<decltype(arg)>(arg); }),
        std::move(expr));
  } catch(std::exception const& e) {
    boss::ExpressionArguments args;
    args.reserve(2);
    args.emplace_back(expr.clone());
    args.emplace_back(std::string{e.what()});
    return boss::ComplexExpression{"ErrorWhenEvaluatingExpression"_, std::move(args)};
  }
}

} // namespace boss::engines::arrow_storage

static auto& enginePtr(bool initialise = true) {
  static auto engine = std::unique_ptr<boss::engines::arrow_storage::Engine>();
  if(!engine && initialise) {
    engine.reset(new boss::engines::arrow_storage::Engine());
  }
  return engine;
}

extern "C" BOSSExpression* evaluate(BOSSExpression* e) {
  static std::mutex m;
  std::lock_guard lock(m);
  auto* r = new BOSSExpression{enginePtr()->evaluate(std::move(e->delegate))};
  return r;
};

extern "C" void reset() { enginePtr(false).reset(nullptr); }
