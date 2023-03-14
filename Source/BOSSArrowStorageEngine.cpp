
#include "BOSSArrowStorageEngine.hpp"

#include <Algorithm.hpp>
#include <Expression.hpp>
#include <ExpressionUtilities.hpp>
#include <Utilities.hpp>

#include <arrow/array/array_base.h>
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

boss::Expression Engine::evaluate(boss::Expression&& expr) { // NOLINT
  try {
    return visit(
        [this](auto&& e) -> boss::Expression {
          if constexpr(isComplexExpression<decltype(e)>) {
            boss::ExpressionArguments args = e.getArguments();
            if(e.getHead() == "CreateTable"_) {
              ExpressionArguments columns;
              columns.reserve(args.size() - 1);
              auto it = std::make_move_iterator(args.begin());
              auto tableSymbol = get<Symbol>(std::move(*it));
              std::transform(++it, std::make_move_iterator(args.end()), std::back_inserter(columns),
                             [](auto&& arg) {
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
            visitTransform(args, [this](auto&& arg) -> boss::Expression {
              if constexpr(isComplexExpression<decltype(arg)> &&
                           std::is_lvalue_reference_v<decltype(arg)>) {
                return evaluate(arg.clone());
              } else {
                return evaluate(std::forward<decltype(arg)>(arg));
              }
            });
            return boss::ComplexExpression(e.getHead(), {}, std::move(args), {});
          } else if constexpr(std::is_same_v<std::decay_t<decltype(e)>, Symbol>) {
            auto it = tables.find(e.getName());
            if(it == tables.end()) {
              return std::forward<decltype(e)>(e);
            }
            return shallowCopy(it->second);
          } else {
            return std::forward<decltype(e)>(e);
          }
        },
        expr);
  } catch(std::exception const& e) {
    boss::ExpressionArguments args;
    args.reserve(2);
    args.emplace_back(expr.clone());
    args.emplace_back(std::string{e.what()});
    return boss::ComplexExpression{"ErrorWhenEvaluatingExpression"_, std::move(args)};
  }
}

bool Engine::load(Symbol const& tableSymbol, std::string const& filepath) {
  if(filepath.rfind(".tbl") != std::string::npos) {
    return load(tableSymbol, filepath, '|', true, false);
  }
  if(filepath.rfind(".csv") != std::string::npos) {
    return load(tableSymbol, filepath, '|', true, false);
  }
  throw std::runtime_error("unsupported file format for " + filepath);
}

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

bool Engine::load(Symbol const& tableSymbol, std::string const& filepath, char separator,
                  bool eolHasSeparator, bool hasHeader, unsigned long long maxRows) {

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

  // loading code which will be from a normal cvs file reader or from a memory-mapped file reader
  auto loadFromReader = [&](auto& reader) {
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

      auto const& batchColumns = batch->columns();
      auto batchColumnIt = batchColumns.begin();
      std::transform(
          std::make_move_iterator(columns.begin()), std::make_move_iterator(columns.end()),
          columns.begin(), [&batchColumnIt](auto&& e) -> Expression {
            auto arrowArrayPtr = *batchColumnIt++;
            auto [head, statics, dynamics, spans] =
                std::move(get<ComplexExpression>(e)).decompose();
            auto dynArgsIt = std::next(dynamics.begin());
            auto& columnData = *dynArgsIt;
            columnData = visit(
                [&arrowArrayPtr](auto&& listExpr) -> Expression {
                  if constexpr(isComplexExpression<decltype(listExpr)>) {
                    if(arrowArrayPtr->type_id() == arrow::Type::DATE32) {
                      // convert to int64_t
                      auto intBuilder = arrow::Int64Builder();
                      auto status = intBuilder.AppendEmptyValues(arrowArrayPtr->length());
                      if(!status.ok()) {
                        throw std::runtime_error(status.ToString());
                      }
                      auto const* srcArrayData =
                          std::dynamic_pointer_cast<arrow::Date32Array>(arrowArrayPtr)
                              ->raw_values();
                      for(int64_t i = 0; i < arrowArrayPtr->length(); ++i) {
                        intBuilder[i] = srcArrayData[i];
                      }
                      auto int64arrayPtr = std::shared_ptr<arrow::Int64Array>();
                      auto finishStatus = intBuilder.Finish(&int64arrayPtr);
                      if(!finishStatus.ok()) {
                        throw std::runtime_error(finishStatus.ToString());
                      }
                      arrowArrayPtr = int64arrayPtr;
                    }
                    auto visitor = ArrowArrayVisitor([&arrowArrayPtr,
                                                      &listExpr](auto const& columnArray) {
                      if constexpr(std::is_convertible_v<decltype(columnArray),
                                                         arrow::StringArray const&>) {
                        // TODO: properly implement string arrays
                        // for now make it an integer column with arbitrary values
                        auto [head, statics, dynamics, spans] = std::move(listExpr) // NOLINT
                                                                    .decompose();
                        spans.emplace_back(
                            boss::Span<int64_t>(std::vector<int64_t>(columnArray.length())));
                        listExpr = ComplexExpression{head, std::move(statics), std::move(dynamics),
                                                     std::move(spans)};
                        return;
                      } else if constexpr(std::is_convertible_v<decltype(columnArray),
                                                                arrow::PrimitiveArray const&>) {
                        using ElementType = const decltype(columnArray.Value(0));
                        if constexpr(std::is_constructible_v<expressions::ExpressionSpanArgument,
                                                             boss::Span<ElementType>> &&
                                     std::is_constructible_v<boss::Span<ElementType>, ElementType*,
                                                             int, std::function<void(void)>>) {
                          // TODO: why listExpr is not always a r-value reference?
                          auto [head, statics, dynamics, spans] = std::move(listExpr) // NOLINT
                                                                      .decompose();
                          spans.emplace_back(boss::Span<ElementType>(
                              columnArray.raw_values(), columnArray.length(),
                              [stored = arrowArrayPtr]() {}));
                          listExpr = ComplexExpression{head, std::move(statics),
                                                       std::move(dynamics), std::move(spans)};
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
            return ComplexExpression{head, std::move(statics), std::move(dynamics),
                                     std::move(spans)};
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
  };

  auto const& io_context = arrow::io::default_io_context();

  // try to load cached memory-mapped file
  std::shared_ptr<arrow::io::MemoryMappedFile> memoryMappedFile;
  if(memoryMapped) {
    auto memoryMappedFilepath = filepath + ".cached";
    auto maybeMemoryMappedFile =
        arrow::io::MemoryMappedFile::Open(memoryMappedFilepath, arrow::io::FileMode::READWRITE);
    if(!maybeMemoryMappedFile.ok()) {
      throw std::runtime_error("failed to open " + memoryMappedFilepath + " \n" +
                               maybeMemoryMappedFile.status().ToString());
    }
    memoryMappedFile = *maybeMemoryMappedFile;
  }

  if(!memoryMappedFile || memoryMappedFile->GetSize() == 0) {
    // load the original files
    auto maybeFileInput = arrow::io::ReadableFile::Open(filepath, io_context.pool());
    if(!maybeFileInput.ok()) {
      throw std::runtime_error("failed to find " + filepath + " \n" +
                               maybeFileInput.status().ToString());
    }
    auto cvsInput = *maybeFileInput;

    auto readOptions = arrow::csv::ReadOptions::Defaults();

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

    auto maybeCvsReader = arrow::csv::StreamingReader::Make(io_context, cvsInput, readOptions,
                                                            parseOptions, convertOptions);
    if(!maybeCvsReader.ok()) {
      throw std::runtime_error("failed to open " + filepath + " \n" +
                               maybeCvsReader.status().ToString());
    }
    auto cvsReader = *maybeCvsReader;

    if(!memoryMappedFile) {
      // not using a memory mapped file, just load the file directly
      if constexpr(VERBOSE_LOADING) {
        std::cerr << "Loading from file: " << tableSymbol.getName() << std::endl;
      }
      loadFromReader(cvsReader);
      return true;
    }

    // otherwise write the memory-mapped file (so then we can open it)

    if constexpr(VERBOSE_LOADING) {
      std::cerr << "Caching: " << tableSymbol.getName() << std::endl;
    }
    static auto debugStart = std::chrono::high_resolution_clock::now();

    std::shared_ptr<arrow::ipc::RecordBatchWriter> writer;
    std::shared_ptr<arrow::RecordBatch> batch;
    while(cvsReader->ReadNext(&batch).ok() && batch) {
      if(!writer) {
        auto const& schema = batch->schema();

        auto maybeWriter = arrow::ipc::MakeStreamWriter(memoryMappedFile, schema);
        if(!maybeWriter.ok()) {
          throw std::runtime_error("failed to open memory-mapped stream writer\n" +
                                   maybeWriter.status().ToString());
        }

        writer = *maybeWriter;
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

      auto resizeStatus = memoryMappedFile->Resize(currentSize + recordBatchSize);
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

  // load the memory-mapped file

  auto maybeReader = arrow::ipc::RecordBatchStreamReader::Open(memoryMappedFile);
  if(!maybeReader.ok()) {
    throw std::runtime_error("failed to open memory-mapped stream reader\n" +
                             maybeReader.status().ToString());
  }

  if constexpr(VERBOSE_LOADING) {
    std::cerr << "Loading from cache: " << tableSymbol.getName() << std::endl;
  }
  loadFromReader(*maybeReader);

  return true;
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
