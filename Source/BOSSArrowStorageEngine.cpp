#include "BOSSArrowStorageEngine.hpp"

#include <mutex>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
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

namespace boss::engines::arrow_storage {

boss::Expression Engine::evaluate(boss::Expression const& expr) { // NOLINT
  try {
    // do the evaluation
    return expr.clone();
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
  auto* r = new BOSSExpression{enginePtr()->evaluate(e->delegate.clone())};
  return r;
};

extern "C" void reset() { enginePtr(false).reset(nullptr); }
