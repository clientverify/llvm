// Common utility functions for all TASE passes.

#include "X86TASE.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/MemoryBuffer.h"
#include <algorithm>
#include <cassert>

using namespace llvm;

std::string TaseModeledFunctionsFile;
static cl::opt<std::string, true> TaseModeledFunctionsFlag(
    "x86-tase-modeled-functions",
    cl::desc("File holding names of modeled functions that are to be interpreted."),
    cl::value_desc("filename"),
    cl::location(TaseModeledFunctionsFile),
    cl::ValueRequired);

namespace llvm {

const std::vector<std::string> &getTASEModeledFunctions() {
  static std::vector<std::string> TaseModeledFunctions;

  if (!TaseModeledFunctions.empty()) {
    return TaseModeledFunctions;
  }

  if (TaseModeledFunctionsFile.empty()) {
    report_fatal_error("TASE: Must provide path to a file listing modeled functions.");
    return TaseModeledFunctions;
  }

  std::unique_ptr<MemoryBuffer> MB =
    std::move(MemoryBuffer::getFile(TaseModeledFunctionsFile).get());

  for(line_iterator I = line_iterator(*MB); !I.is_at_eof(); I++) {
    TaseModeledFunctions.push_back(I->str());
  }

  std::sort(TaseModeledFunctions.begin(), TaseModeledFunctions.end());
  TaseModeledFunctions.erase(
      std::unique(TaseModeledFunctions.begin(), TaseModeledFunctions.end()),
      TaseModeledFunctions.end());

  if (TaseModeledFunctions.empty()) {
    report_fatal_error("TASE: No modeled functions found in function file.");
  }
  return TaseModeledFunctions;
}

}
