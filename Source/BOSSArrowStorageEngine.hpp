#pragma once

#include <BOSS.hpp>
#include <Expression.hpp>

#include <arrow/array/array_dict.h>

#include <unordered_map>

#ifdef _WIN32
extern "C" {
__declspec(dllexport) BOSSExpression* evaluate(BOSSExpression* e);
__declspec(dllexport) void reset();
}
#endif // _WIN32

namespace boss::engines::arrow_storage {

class Engine {
public:
  Engine(Engine&) = delete;
  Engine& operator=(Engine&) = delete;
  Engine(Engine&&) = default;
  Engine& operator=(Engine&&) = delete;
  Engine() = default;
  ~Engine() = default;

  boss::Expression evaluate(boss::Expression&& expr);

private:
  struct {
    bool loadToMemoryMappedFiles = true;
    bool useAutoDictionaryEncoding = true;
    int32_t fileLoadingBlockSize = 1U << 30U; // 1GB // NOLINT
  } properties;

  std::unordered_map<Symbol, boss::ComplexExpression> tables;
  std::unordered_map<Symbol, std::vector<Symbol>> primaryKeys;
  std::unordered_map<Symbol, std::vector<std::pair<Symbol, Symbol>>> foreignKeys;
  std::unordered_map<Symbol, std::unique_ptr<arrow::DictionaryUnifier>> dictionaries;

  void rebuildIndexes(Symbol const& updatedTableSymbol);

  void load(Symbol const& tableSymbol, std::string const& filepath,
            unsigned long long maxRows = -1);

  std::shared_ptr<arrow::RecordBatchReader>
  loadFromCsvFile(std::string const& filepath, std::vector<std::string> const& columnNames) const;
  std::shared_ptr<arrow::RecordBatchReader>
  loadFromCsvFile(std::string const& filepath, std::vector<std::string> const& columnNames,
                  char separator, bool eolHasSeparator, bool hasHeader) const;

  static void
  loadIntoMemoryMappedFile(std::shared_ptr<arrow::io::MemoryMappedFile>& memoryMappedFile,
                           std::shared_ptr<arrow::RecordBatchReader>& csvReader);

  template <typename Columns>
  void loadIntoColumns(Columns& columns, std::shared_ptr<arrow::RecordBatchReader>& reader,
                       unsigned long long maxRows);

  static std::shared_ptr<arrow::Int64Array> convertToInt64Array(int32_t const* srcData,
                                                                int64_t size);
  std::shared_ptr<arrow::Int64Array>
  convertToInt64Array(arrow::DictionaryArray const& dictionaryArray, Symbol const& dictionaryName);
};

} // namespace boss::engines::arrow_storage
