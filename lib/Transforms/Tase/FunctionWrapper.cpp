#include <algorithm>
#include <fstream>
#include <string>

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "tase"

// We tag functions with either 'instrumented','scaffold' or 'modeled' tags so that
// the X86 assembly emission will appropriately batch instructions in said
// functions.

// We don't have an enclave or ecalls/ocalls.  Therefore, I name things a bit
// differently to make things clear.  There are functions that can be executed
// natively.  These functions must also be processed for transactional batching.
// We call these functions 'instrumented'.
//
// There are functions that are specially written glue-code/context-switch/
// scaffolding functions.  These functions are either hand-written assembly or
// support functions that are already aware of symbolic variables and handle
// them appropriately.  They do not need to run in a transaction.  These are
// called 'scaffold' functions.
//
// Modeled functions are functions which the KLEE interpretation environment
// understands. These functions will never run inside a transaction and
// its implementation here only exists to support running the function during
// concrete execution.
//
// Currently, we are not worrying about system/libc functions here.  Those are
// compiled and exported separately as part of klee-uclibc.  We will need to link
// any target binary with a custom uclibc that has been sufficiently instrumented
// that any system call will bail out and jump into the interpreter when needed.
//
// No manual cache-line TSGX-style alignment of arguments is made.

// Declared in X86AsmPrinter.cpp
extern std::string TaseInstrumentedFile;
extern std::string TaseModeledFile;

namespace {
  struct FunctionWrapperPass : public FunctionPass {
    static char ID;
    std::vector<std::string> TaseInstrumentedFunctions;
    std::vector<std::string> TaseModeledFunctions;

    FunctionWrapperPass() : FunctionPass(ID), TaseInstrumentedFunctions(), TaseModeledFunctions() {}

    virtual bool doInitialization(Module& M) {
      if (TaseModeledFile.empty()) {
        errs() << "No list of modeled functions provided.  All functions will be marked for instrumentation.\n";
        return false;
      }
      std::ifstream is(TaseModeledFile, std::ios::in);
      if (!is.is_open()) {
        errs() << "Unable to open TASE modeled functions file.\n";
        return false;
      }
      std::string line;
      while (std::getline(is, line)) {
        TaseModeledFunctions.push_back(line);
      }
      std::sort(TaseModeledFunctions.begin(), TaseModeledFunctions.end());
      return false;
    }

    // When the pass is complete, emit the name of every function eligible
    // for Tase instrumentation to the provided output file.
    virtual bool doFinalization(Module& M) {
      if (TaseInstrumentedFile.empty()) {
        errs() << "No list of modeled functions provided.  A list of marked functions will not be generated.\n";
        return false;
      }
      std::error_code ec;
      raw_fd_ostream out(TaseInstrumentedFile, ec, sys::fs::F_Text);
      if (ec) {
        errs() << "Unable to open TASE instrumented function output file.\n";
        return false;
      }

      std::sort(TaseInstrumentedFunctions.begin(), TaseInstrumentedFunctions.end());
      for (auto const& name: TaseInstrumentedFunctions) {
        out << name << "\n";
      }
      return false;
    }

    virtual bool runOnFunction(Function& F) {
      LLVMContext& ctx = F.getContext();
      DEBUG(dbgs() << "Function: " << F.getName() << " ... ");
      char* function_type;

      // TODO: Extract tags into a header to share it with the codegen stage.
      // That would mean tase.fun.info, scaffold and instrumented would all
      // be defines in a header once we figure out where they go.
      std::string function_name = F.getName().str();
      bool is_modeled = std::binary_search(TaseModeledFunctions.begin(), TaseModeledFunctions.end(), function_name);
      if (is_modeled) {
        DEBUG(dbgs() << "function modeled in interpreter\n");
        function_type = "modeled";
      } else if (F.empty() || function_name == "springboard") {
        // All TASE binaries will have a method named springboard that should never be instrumented.
        DEBUG(dbgs() << "scaffold function or trivial\n");
        function_type = "scaffold";
      }
      else {
        DEBUG(dbgs() << "target function\n");
        function_type = "instrumented";
        TaseInstrumentedFunctions.push_back(function_name);
      }
      MDNode *node = MDNode::get(ctx, MDString::get(ctx, function_type));
      F.setMetadata("tase.fun.info", node);
      // No really we modified some functions...  in a trivial way.
      // But let's obey the API.
      return true;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.setPreservesAll();
    }
  };
}

char FunctionWrapperPass::ID = 0;
static RegisterPass<FunctionWrapperPass> X("function-wrapper", "Tag functions for TASE TSX instrumentation");
