#ifndef OXFUZZ_CLANG_PROTOCOL_H
#define OXFUZZ_CLANG_PROTOCOL_H
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Index/USRGeneration.h"
#include "llvm/Support/JSON.h"
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
namespace J = llvm::json;
struct Exploration {
  unsigned maxNodes, maxBlockVisits, maxInlineDepth;
  size_t maxRecords, maxCfgBlocks, cfgBlocks = 0, omitted = 0;
  bool exhausted = false;
  J::Object limits;
  J::Array targets, cfgs, calls, branches;
  std::set<std::string> roots;
};
struct Output {
  std::map<std::string, J::Object> functions;
  J::Array calls, units;
  size_t maxFunctions, maxCalls;
  std::string unit;
  std::optional<Exploration> exploration;
};
inline J::Value projectLocation(const clang::SourceManager &sm, clang::SourceLocation source) {
  auto loc = sm.getExpansionLoc(source);
  if (loc.isInvalid()) return nullptr;
  std::string file = sm.getFilename(loc).str();
  const std::string prefix = "/work/source/";
  if (file.rfind(prefix, 0) != 0) return nullptr;
  return J::Object{{"file", file.substr(prefix.size())},
    {"line", sm.getSpellingLineNumber(loc)}, {"column", sm.getSpellingColumnNumber(loc)}};
}
inline std::string functionId(const clang::FunctionDecl *decl, const std::string &unit) {
  llvm::SmallString<256> usr;
  if (clang::index::generateUSRForDecl(decl->getCanonicalDecl(), usr))
    throw std::runtime_error("declaration has no stable USR");
  return unit + ":" + usr.str().str();
}
#endif
