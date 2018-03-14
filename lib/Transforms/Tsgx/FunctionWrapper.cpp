#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/Debug.h"
using namespace llvm;

#define DEBUG_TYPE "tsgx"

// We tag functions with either 'instrumented' or 'scaffold' tags so that
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
// Currently, we are not worrying about system/libc functions here.  Those are
// compiled and exported separately as part of klee-uclibc.  We will need to link
// any target binary with a custom uclibc that has been sufficiently instrumented
// that any system call will bail out and jump into the interpreter when needed.
//
// No manual cache-line TSGX alignment of arguments is made.

namespace {
  struct FunctionWrapperPass : public FunctionPass {
    static char ID;
    FunctionWrapperPass() : FunctionPass(ID) {}

    virtual bool runOnFunction(Function& F) {
      LLVMContext& ctx = F.getContext();
      DEBUG(dbgs() << "Function: " << F.getName() << " ... ");
      char* function_type;

      // Hard-coded here for skipping tsgx_init function.
      // TODO: Hardcode or establish a convention to detect scaffold functions.
      // TODO: Extract tags into a header to share it with the codegen stage.
      // That would mean sgxtsx.fun.info, scaffold and instrumented would all
      // be defines in a header once we figure out where they go.
      if (F.empty() || F.getName().str() == "tsgx_init") {
        DEBUG(dbgs() << "scaffold function or trivial\n");
        function_type = "scaffold";
      }
      else {
        DEBUG(dbgs() << "target function\n");
        function_type = "instrumented";
      }
      MDNode *node = MDNode::get(ctx, MDString::get(ctx, function_type));
      F.setMetadata("sgxtsx.fun.info", node);
      // No really we modified some functions...  in a trivial way.
      // But let's obey the API.
      return true;
    }
  };
}

char FunctionWrapperPass::ID = 0;
static RegisterPass<FunctionWrapperPass> X("function-wrapper", "TSX function tagging");
