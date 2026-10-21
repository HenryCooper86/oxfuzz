#include "exploration.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/CFG.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/AnalysisConsumer.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/Tooling/Tooling.h"
#include <algorithm>
using namespace clang;
using namespace clang::ento;
using namespace clang::tooling;

REGISTER_MAP_WITH_PROGRAMSTATE(OxfuzzInputs, const ParmVarDecl *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(OxfuzzProducers, SymbolRef, const CallExpr *)

namespace {
unsigned limit(const J::Object &object, llvm::StringRef name, unsigned maximum) {
  auto value = object.getInteger(name);
  if (!value || *value < 1 || *value > maximum) throw std::runtime_error("invalid exploration limit");
  return static_cast<unsigned>(*value);
}
bool selected(FunctionDecl *decl, ASTContext &context, const Exploration &analysis) {
  auto location = projectLocation(context.getSourceManager(), decl->getBeginLoc());
  auto *loc = location.getAsObject();
  if (!loc) return false;
  for (const auto &value : analysis.targets) {
    auto *target = value.getAsObject();
    if (!target) throw std::runtime_error("invalid target selector");
    auto symbol = target->getString("symbol");
    if (!symbol || (decl->getNameAsString() != *symbol && decl->getQualifiedNameAsString() != *symbol)
        || target->getString("file") != loc->getString("file")) continue;
    auto line = loc->getInteger("line"), column = loc->getInteger("column");
    auto startLine = target->getInteger("line"), startColumn = target->getInteger("column");
    auto endLine = target->getInteger("end_line"), endColumn = target->getInteger("end_column");
    if (!startLine || !startColumn || !endLine || !endColumn)
      throw std::runtime_error("invalid target coordinates");
    if (std::make_pair(*line, *column) >= std::make_pair(*startLine, *startColumn) &&
        std::make_pair(*line, *column) < std::make_pair(*endLine, *endColumn)) return true;
  }
  return false;
}
class ParameterUses : public RecursiveASTVisitor<ParameterUses> {
  const FunctionDecl *function;
public:
  std::set<unsigned> used;
  explicit ParameterUses(const FunctionDecl *function) : function(function) {}
  bool VisitDeclRefExpr(DeclRefExpr *expression) {
    for (unsigned i = 0; i < function->getNumParams(); ++i)
      if (expression->getDecl() == function->getParamDecl(i)) used.insert(i);
    return true;
  }
};
J::Value condition(const Stmt *statement, const FunctionDecl *function, ASTContext &context) {
  if (!statement) return nullptr;
  auto location = projectLocation(context.getSourceManager(), statement->getBeginLoc());
  if (location.getAsNull()) return nullptr;
  ParameterUses uses(function);
  uses.TraverseStmt(const_cast<Stmt *>(statement));
  J::Array parameters;
  for (auto index : uses.used) parameters.push_back(index);
  auto text = Lexer::getSourceText(CharSourceRange::getTokenRange(statement->getSourceRange()),
                                  context.getSourceManager(), context.getLangOpts());
  J::Value encodedText = nullptr;
  if (!text.empty() && text.size() <= 4096) encodedText = text.str();
  return J::Object{{"location", std::move(location)}, {"text", std::move(encodedText)},
                   {"parameters", std::move(parameters)}};
}
std::string integer(const llvm::APSInt &value) {
  llvm::SmallString<128> result;
  value.toString(result, 10);
  return result.str().str();
}
const FunctionDecl *rootFunction(CheckerContext &context) {
  const LocationContext *location = context.getLocationContext();
  while (location->getParent()) location = location->getParent();
  return dyn_cast<FunctionDecl>(location->getDecl());
}
J::Array constraints(const FunctionDecl *root, CheckerContext &context) {
  J::Array records;
  const auto &state = context.getState();
  for (unsigned i = 0; i < root->getNumParams(); ++i) {
    auto *parameter = root->getParamDecl(i);
    auto *original = state->get<OxfuzzInputs>(parameter);
    J::Value minimum = nullptr, maximum = nullptr, nonnull = nullptr;
    if (original && !original->isUnknownOrUndef()) {
      if (parameter->getType()->isIntegerType()) {
        if (auto symbol = original->getAsSymbol()) {
          if (auto value = context.getConstraintManager().getSymMinVal(state, symbol)) minimum = integer(*value);
          if (auto value = context.getConstraintManager().getSymMaxVal(state, symbol)) maximum = integer(*value);
        }
      } else if (parameter->getType()->isPointerType()) {
        if (auto defined = original->getAs<DefinedOrUnknownSVal>()) {
          auto yes = state->assume(*defined, true), no = state->assume(*defined, false);
          if (yes && !no) nonnull = true;
          if (!yes && no) nonnull = false;
        }
      }
    }
    records.push_back(J::Object{{"parameter", i}, {"min", std::move(minimum)},
      {"max", std::move(maximum)}, {"nonnull", std::move(nonnull)}});
  }
  return records;
}
thread_local Output *activeOutput = nullptr;
bool reserve(Exploration &analysis) {
  if (analysis.calls.size() + analysis.branches.size() < analysis.maxRecords) return true;
  ++analysis.omitted; analysis.exhausted = true; return false;
}
class InputFlowChecker : public Checker<check::BeginFunction, check::PreCall,
                                        check::PostCall, check::BranchCondition, check::EndAnalysis> {
  const FunctionDecl *selectedRoot(CheckerContext &context) const {
    auto *root = rootFunction(context);
    if (!root || !activeOutput || !activeOutput->exploration->roots.count(functionId(root, activeOutput->unit))) return nullptr;
    return root;
  }
public:
  void checkBeginFunction(CheckerContext &context) const {
    if (!context.inTopFrame()) return;
    auto *root = selectedRoot(context);
    if (!root) return;
    auto state = context.getState();
    for (unsigned i = 0; i < root->getNumParams(); ++i) {
      auto *parameter = root->getParamDecl(i);
      auto *region = context.getSValBuilder().getRegionManager().getVarRegion(parameter, context.getLocationContext());
      auto value = state->getSVal(region);
      state = state->set<OxfuzzInputs>(parameter, value);
      state = taint::addTaint(state, value, i + 1);
    }
    context.addTransition(state);
  }
  void checkPreCall(const CallEvent &call, CheckerContext &context) const {
    auto *root = selectedRoot(context);
    auto *origin = dyn_cast_or_null<CallExpr>(call.getOriginExpr());
    auto *caller = dyn_cast<FunctionDecl>(context.getLocationContext()->getDecl());
    if (!root || !origin || !caller) return;
    auto location = projectLocation(context.getSourceManager(), origin->getExprLoc());
    if (location.getAsNull() || !reserve(*activeOutput->exploration)) return;
    auto state = context.getState();
    J::Array arguments;
    for (unsigned i = 0; i < call.getNumArgs(); ++i) {
      auto value = call.getArgSVal(i);
      J::Array sources;
      for (unsigned p = 0; p < root->getNumParams(); ++p)
        if (taint::isTainted(state, value, p + 1)) sources.push_back(p);
      J::Value scalar = nullptr, producer = nullptr;
      if (auto concrete = value.getAs<nonloc::ConcreteInt>()) scalar = integer(concrete->getValue());
      if (auto symbol = value.getAsSymbol()) {
        if (auto *previous = state->get<OxfuzzProducers>(symbol)) {
          if (auto *decl = (*previous)->getDirectCallee())
            producer = J::Object{{"function", functionId(decl, activeOutput->unit)},
              {"location", projectLocation(context.getSourceManager(), (*previous)->getExprLoc())}};
        }
      }
      arguments.push_back(J::Object{{"argument", i}, {"parameters", std::move(sources)},
        {"constant", std::move(scalar)}, {"producer", std::move(producer)}});
    }
    J::Value callee = nullptr;
    if (auto *decl = dyn_cast_or_null<FunctionDecl>(call.getDecl())) callee = functionId(decl, activeOutput->unit);
    J::Array path;
    std::vector<std::string> frames;
    for (const LocationContext *frame = context.getLocationContext(); frame; frame = frame->getParent())
      if (auto *decl = dyn_cast<FunctionDecl>(frame->getDecl())) frames.push_back(functionId(decl, activeOutput->unit));
    for (auto it = frames.rbegin(); it != frames.rend(); ++it) path.push_back(*it);
    if (auto value = callee.getAsString()) path.push_back(value->str());
    activeOutput->exploration->calls.push_back(J::Object{{"root", functionId(root, activeOutput->unit)},
      {"caller", functionId(caller, activeOutput->unit)}, {"callee", std::move(callee)},
      {"location", std::move(location)}, {"arguments", std::move(arguments)},
      {"constraints", constraints(root, context)}, {"path", std::move(path)}});
  }
  void checkPostCall(const CallEvent &call, CheckerContext &context) const {
    if (!selectedRoot(context)) return;
    auto *origin = dyn_cast_or_null<CallExpr>(call.getOriginExpr());
    auto symbol = call.getReturnValue().getAsSymbol();
    if (origin && origin->getDirectCallee() && symbol)
      context.addTransition(context.getState()->set<OxfuzzProducers>(symbol, origin));
  }
  void checkBranchCondition(const Stmt *statement, CheckerContext &context) const {
    auto *root = selectedRoot(context);
    auto *caller = dyn_cast<FunctionDecl>(context.getLocationContext()->getDecl());
    if (!root || !caller) return;
    auto description = condition(statement, caller, context.getASTContext());
    auto value = context.getSVal(statement).getAs<DefinedOrUnknownSVal>();
    if (description.getAsNull() || !value || !reserve(*activeOutput->exploration)) return;
    activeOutput->exploration->branches.push_back(J::Object{
      {"root", functionId(root, activeOutput->unit)}, {"caller", functionId(caller, activeOutput->unit)},
      {"condition", std::move(description)}, {"constraints", constraints(root, context)},
      {"true_state", bool(context.getState()->assume(*value, true))},
      {"false_state", bool(context.getState()->assume(*value, false))}});
  }
  void checkEndAnalysis(ExplodedGraph &, BugReporter &, ExprEngine &engine) const {
    if (engine.getCoreEngine().hasWorkRemaining()) activeOutput->exploration->exhausted = true;
  }
};
class ExplorationAction : public ASTFrontendAction {
  Output &output;
public:
  explicit ExplorationAction(Output &output) : output(output) {}
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &compiler, llvm::StringRef) override {
    auto &options = compiler.getAnalyzerOpts();
    auto &limits = *output.exploration;
    options.CheckersAndPackages = {{"core", true}, {"oxfuzz.InputFlow", true}};
    options.MaxNodesPerTopLevelFunction = limits.maxNodes;
    options.maxBlockVisitOnPath = limits.maxBlockVisits;
    options.InlineMaxStackDepth = limits.maxInlineDepth;
    options.AnalyzeAll = true;
    options.InliningMode = All;
    options.AnalysisDiagOpt = PD_NONE;
    options.NoRetryExhausted = true;
    auto consumer = CreateAnalysisConsumer(compiler);
    consumer->AddCheckerRegistrationFn([](CheckerRegistry &registry) {
      registry.addChecker<InputFlowChecker>("oxfuzz.InputFlow", "Retain input-flow and path evidence", "");
    });
    return consumer;
  }
};
class ExplorationFactory : public FrontendActionFactory {
  Output &output;
public:
  explicit ExplorationFactory(Output &output) : output(output) {}
  std::unique_ptr<FrontendAction> create() override { return std::make_unique<ExplorationAction>(output); }
};
} // namespace

void configureExploration(const J::Object &request, Output &output) {
  auto *limits = request.getObject("exploration");
  auto *targets = request.getArray("targets");
  if (!limits || !targets || targets->empty() || targets->size() > 64)
    throw std::runtime_error("invalid exploration request");
  Exploration analysis;
  analysis.maxNodes = limit(*limits, "max_nodes", 1000000);
  analysis.maxBlockVisits = limit(*limits, "max_block_visits", 64);
  analysis.maxRecords = limit(*limits, "max_records", 10000);
  analysis.maxCfgBlocks = limit(*limits, "max_cfg_blocks", 100000);
  analysis.maxInlineDepth = limit(*limits, "max_inline_depth", 16);
  analysis.limits = *limits;
  analysis.targets = *targets;
  output.exploration = std::move(analysis);
}
void collectCFG(FunctionDecl *decl, ASTContext &context, Output &output) {
  if (!output.exploration || !decl->isThisDeclarationADefinition() ||
      !selected(decl, context, *output.exploration)) return;
  auto &analysis = *output.exploration;
  auto id = functionId(decl, output.unit);
  if (!analysis.roots.insert(id).second) return;
  auto cfg = CFG::buildCFG(decl, decl->getBody(), &context, CFG::BuildOptions());
  J::Array blocks;
  std::string status = "unavailable";
  if (cfg) {
    status = "complete";
    if (analysis.cfgBlocks + cfg->size() > analysis.maxCfgBlocks) {
      status = "truncated"; analysis.exhausted = true;
    } else {
      analysis.cfgBlocks += cfg->size();
      for (const auto *block : *cfg) {
        J::Array successors;
        for (auto successor : block->succs()) {
          if (const auto *next = successor.getReachableBlock()) successors.push_back(next->getBlockID());
          else successors.push_back(nullptr);
        }
        blocks.push_back(J::Object{{"id", block->getBlockID()}, {"successors", std::move(successors)},
          {"condition", condition(block->getTerminatorCondition(), decl, context)}});
      }
    }
  }
  analysis.cfgs.push_back(J::Object{{"function", id}, {"status", status}, {"blocks", std::move(blocks)}});
}
void runExploration(const CompilationDatabase &database, const std::string &source, Output &output) {
  if (!output.exploration) return;
  bool any = std::any_of(output.exploration->roots.begin(), output.exploration->roots.end(),
                         [&](const auto &id) { return id.rfind(output.unit + ":", 0) == 0; });
  if (!any) return;
  activeOutput = &output;
  ClangTool tool(database, {source});
  ExplorationFactory factory(output);
  int result = tool.run(&factory);
  activeOutput = nullptr;
  if (result != 0) throw std::runtime_error("symbolic analysis failed");
}
J::Object explorationJSON(Exploration &analysis) {
  J::Array roots;
  for (const auto &root : analysis.roots) roots.push_back(root);
  return J::Object{{"engine", "clang-static-analyzer-range-v1"}, {"limits", std::move(analysis.limits)},
    {"roots", std::move(roots)}, {"cfgs", std::move(analysis.cfgs)}, {"calls", std::move(analysis.calls)},
    {"branches", std::move(analysis.branches)}, {"exhausted", analysis.exhausted}, {"omitted_records", analysis.omitted}};
}
