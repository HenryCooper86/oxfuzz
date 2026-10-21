#ifndef OXFUZZ_CLANG_EXPLORATION_H
#define OXFUZZ_CLANG_EXPLORATION_H
#include "protocol.h"
#include "clang/AST/ASTContext.h"
#include "clang/Tooling/CompilationDatabase.h"
void configureExploration(const J::Object &request, Output &output);
void collectCFG(clang::FunctionDecl *decl, clang::ASTContext &context, Output &output);
void runExploration(const clang::tooling::CompilationDatabase &database,
                    const std::string &source, Output &output);
J::Object explorationJSON(Exploration &exploration);
#endif
