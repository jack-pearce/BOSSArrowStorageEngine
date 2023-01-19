#pragma once

#include <BOSS.hpp>
#include <Expression.hpp>

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
  bool memoryMapped = true;
  std::unordered_map<std::string, boss::ComplexExpression> tables;

  bool load(Symbol const& tableSymbol, std::string const& filepath);
  bool load(Symbol const& tableSymbol, std::string const& filepath, char separator,
            bool eolHasSeparator, bool hasHeader, unsigned long long maxRows = -1);
};

} // namespace boss::engines::arrow_storage
