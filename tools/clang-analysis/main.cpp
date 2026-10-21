// Compiler-resolved declarations and call sites; target code is never executed.
#include "exploration.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Index/USRGeneration.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>

using namespace clang;
using namespace clang::tooling;
namespace J = llvm::json;

static std::string required(const J::Object &o, llvm::StringRef key) {
  auto value = o.getString(key);
  if (!value) throw std::runtime_error("missing string field");
  return value->str();
}

class Visitor : public RecursiveASTVisitor<Visitor> {
  ASTContext &context;
  Output &output;
  FunctionDecl *current = nullptr;

  J::Value location(SourceLocation source) {
    return projectLocation(context.getSourceManager(), source);
  }

public:
  Visitor(ASTContext &context, Output &output) : context(context), output(output) {}
  bool shouldVisitTemplateInstantiations() const { return true; }

  bool TraverseLambdaExpr(LambdaExpr *expression, DataRecursionQueue * = nullptr) {
    for (auto *capture : expression->capture_inits())
      if (!TraverseStmt(capture)) return false;
    std::vector<FunctionDecl *> operators{expression->getCallOperator()};
    if (auto *templated = expression->getCallOperator()->getDescribedFunctionTemplate())
      for (auto *specialization : templated->specializations()) operators.push_back(specialization);
    for (auto *function : operators) {
      auto *previous = current;
      current = function;
      add(function);
      collectCFG(function, context, output);
      bool result = TraverseStmt(function->getBody());
      current = previous;
      if (!result) return false;
    }
    return true;
  }

  std::string add(FunctionDecl *decl) {
    auto *canonical = decl->getCanonicalDecl();
    llvm::SmallString<256> usr;
    if (index::generateUSRForDecl(canonical, usr))
      throw std::runtime_error("declaration has no stable USR");
    std::string id = output.unit + ":" + usr.str().str();
    auto *definition = decl->getDefinition();
    auto *record = definition ? definition : decl;
    auto loc = location(record->getBeginLoc());
    J::Array declarations;
    for (auto *redecl : record->redecls()) {
      auto declaration = location(redecl->getBeginLoc());
      if (!declaration.getAsNull()) declarations.push_back(std::move(declaration));
      if (declarations.size() > 1024) throw std::runtime_error("declaration limit exceeded");
    }
    bool hasBody = definition && !loc.getAsNull();
    J::Array parameters;
    for (auto *p : record->parameters())
      parameters.push_back(J::Object{{"name", p->getNameAsString()},
                                     {"type_name", p->getType().getCanonicalType().getAsString()}});
    auto *method = dyn_cast<CXXMethodDecl>(record);
    std::string access = "none";
    if (method) {
      switch (method->getAccess()) {
        case AS_public: access = "public"; break;
        case AS_protected: access = "protected"; break;
        case AS_private: access = "private"; break;
        case AS_none: break;
      }
    }
    output.functions.insert_or_assign(id, J::Object{
      {"id", id}, {"unit", output.unit}, {"usr", usr.str().str()},
      {"name", record->getQualifiedNameAsString()}, {"location", std::move(loc)},
      {"declarations", std::move(declarations)},
      {"result_type", record->getReturnType().getCanonicalType().getAsString()},
      {"parameters", std::move(parameters)}, {"variadic", record->isVariadic()},
      {"linkage", record->isExternallyVisible() ? "external" : "internal"},
      {"access", access}, {"method_kind", !method ? "function" : method->isStatic() ? "static" : "instance"}, {"definition", hasBody}});
    if (output.functions.size() > output.maxFunctions)
      throw std::runtime_error("function limit exceeded");
    return id;
  }

  bool TraverseDecl(Decl *decl) {
    auto *function = dyn_cast_or_null<FunctionDecl>(decl);
    if (!function) return RecursiveASTVisitor<Visitor>::TraverseDecl(decl);
    if (context.getSourceManager().isInSystemHeader(function->getLocation())) return true;
    auto *previous = current;
    current = function;
    add(function);
    collectCFG(function, context, output);
    bool result = RecursiveASTVisitor<Visitor>::TraverseDecl(decl);
    current = previous;
    return result;
  }

  bool VisitCallExpr(CallExpr *call) {
    if (!current) return true;
    auto loc = location(call->getExprLoc());
    if (loc.getAsNull()) return true;
    J::Value callee = nullptr;
    std::string dispatch = "indirect";
    if (auto *decl = call->getDirectCallee()) {
      callee = add(decl);
      auto *method = dyn_cast<CXXMethodDecl>(decl);
      dispatch = method && method->isVirtual() ? "virtual" : "direct";
    }
    output.calls.push_back(J::Object{{"caller", add(current)},
      {"callee", std::move(callee)}, {"dispatch", dispatch}, {"location", std::move(loc)}});
    if (output.calls.size() > output.maxCalls) throw std::runtime_error("call limit exceeded");
    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *expression) {
    if (auto *function = dyn_cast<FunctionDecl>(expression->getDecl())) add(function);
    return true;
  }
};

class Consumer : public ASTConsumer {
  Output &output;
public:
  explicit Consumer(Output &output) : output(output) {}
  void HandleTranslationUnit(ASTContext &context) override {
    Visitor visitor(context, output);
    visitor.TraverseDecl(context.getTranslationUnitDecl());
  }
};

class Action : public ASTFrontendAction {
  Output &output;
public:
  explicit Action(Output &output) : output(output) {}
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &, llvm::StringRef) override {
    return std::make_unique<Consumer>(output);
  }
};
class Factory : public FrontendActionFactory {
  Output &output;
public:
  explicit Factory(Output &output) : output(output) {}
  std::unique_ptr<FrontendAction> create() override { return std::make_unique<Action>(output); }
};

int main(int argc, char **argv) {
  try {
    if (argc != 1) throw std::runtime_error("helper accepts no arguments");
    auto input = llvm::MemoryBuffer::getFile("/work/input/request.json");
    if (!input) throw std::runtime_error("request unavailable");
    auto parsed = J::parse((*input)->getBuffer());
    if (!parsed) { llvm::consumeError(parsed.takeError()); throw std::runtime_error("invalid request JSON"); }
    auto *request = parsed->getAsObject();
    if (!request || (request->getInteger("schema_version") != 1 && request->getInteger("schema_version") != 2)) throw std::runtime_error("unsupported schema");
    auto functions = request->getInteger("max_functions"), calls = request->getInteger("max_calls"), bytes = request->getInteger("max_output_bytes");
    auto *units = request->getArray("units");
    if (!functions || *functions < 1 || !calls || *calls < 1 || !bytes || *bytes < 1 || !units || units->empty()) throw std::runtime_error("invalid limits or units");
    Output output;
    if (request->getInteger("schema_version") == 2) configureExploration(*request, output);
    output.maxFunctions = *functions; output.maxCalls = *calls;
    for (const auto &unitValue : *units) {
      auto *unit = unitValue.getAsObject();
      if (!unit) throw std::runtime_error("invalid unit");
      output.unit = required(*unit, "id");
      auto file = required(*unit, "file"), directory = required(*unit, "directory");
      auto *arguments = unit->getArray("arguments");
      if (!arguments) throw std::runtime_error("missing arguments");
      std::vector<std::string> args;
      for (const auto &value : *arguments) {
        auto arg = value.getAsString(); if (!arg) throw std::runtime_error("invalid argument");
        args.push_back(arg->str());
      }
      output.units.push_back(J::Object{{"id", output.unit}, {"file", file}, {"scope", required(*unit, "scope")}});
      args.push_back("-resource-dir=/usr/lib/llvm-18/lib/clang/18");
      FixedCompilationDatabase database(directory, args);
      ClangTool tool(database, {"/work/source/" + file});
      Factory factory(output);
      if (tool.run(&factory) != 0) throw std::runtime_error("translation unit parse failed");
      runExploration(database, "/work/source/" + file, output);
    }
    auto executable = llvm::MemoryBuffer::getFile(argv[0]);
    if (!executable) throw std::runtime_error("helper identity unavailable");
    auto hash = llvm::SHA256::hash(llvm::arrayRefFromStringRef((*executable)->getBuffer()));
    J::Array records;
    for (auto &entry : output.functions) records.push_back(std::move(entry.second));
    J::Object result{{"schema_version", *request->getInteger("schema_version")}, {"clang_version", getClangFullVersion()},
      {"helper_sha256", llvm::toHex(hash, true)}, {"units", std::move(output.units)},
      {"functions", std::move(records)}, {"calls", std::move(output.calls)}};
    if (output.exploration) result["exploration"] = explorationJSON(*output.exploration);
    std::string encoded; llvm::raw_string_ostream stream(encoded); stream << J::Value(std::move(result)); stream.flush();
    if (encoded.size() > static_cast<size_t>(*bytes)) throw std::runtime_error("output limit exceeded");
    std::ofstream outputFile("/work/output/index.json", std::ios::binary | std::ios::trunc);
    outputFile << encoded;
    if (!outputFile) throw std::runtime_error("result write failed");
    return 0;
  } catch (const std::exception &error) {
    llvm::errs() << "Clang analysis failed: " << error.what() << "\n";
    return 1;
  }
}
