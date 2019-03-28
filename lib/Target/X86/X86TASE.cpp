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

std::string TASEModeledFunctionsFile;
static cl::opt<std::string, true> TASEModeledFunctionsFlag(
    "x86-tase-modeled-functions",
    cl::desc("File holding names of modeled functions that are to be interpreted."),
    cl::value_desc("filename"),
    cl::location(TASEModeledFunctionsFile),
    cl::ValueRequired);

TASEInstMode TASEInstrumentationMode;
static cl::opt<TASEInstMode, true> TASEInstrumentationModeFlag(
    "x86-tase-instrumentation-mode",
    cl::desc("Choose the tain tracking instrumentation kind."),
    cl::values(
      clEnumValN(TIM_NONE, "none", "No TASE taint tracking"),
      clEnumValN(TIM_GPR, "gpr", "GPR based TASE taint tracking"),
      clEnumValN(TIM_SIMD, "simd", "SIMD based TASE taint tracking")),
    cl::location(TASEInstrumentationMode),
    cl::init(TIM_GPR));

namespace llvm {

bool TASEAnalysis::uncachedModeledFunctions(true);
bool TASEAnalysis::uncachedMemInstrs(true);
std::vector<std::string> TASEAnalysis::ModeledFunctions = {};
TASEAnalysis::meminstrs_t TASEAnalysis::MemInstrs(MEM_INSTRS);

void TASEAnalysis::initModeledFunctions() {
  assert(uncachedModeledFunctions);

  if (TASEModeledFunctionsFile.empty()) {
    uncachedModeledFunctions = false;
    return;
  }

  std::unique_ptr<MemoryBuffer> MB =
    std::move(MemoryBuffer::getFile(TASEModeledFunctionsFile).get());

  for(line_iterator I = line_iterator(*MB); !I.is_at_eof(); I++) {
    ModeledFunctions.push_back(I->str());
  }

  std::sort(ModeledFunctions.begin(), ModeledFunctions.end());
  ModeledFunctions.erase(
      std::unique(ModeledFunctions.begin(), ModeledFunctions.end()),
      ModeledFunctions.end());

  if (ModeledFunctions.empty()) {
    report_fatal_error("TASE: No modeled functions found in function file.");
  }
  uncachedModeledFunctions = false;
}

void TASEAnalysis::initMemInstrs() {
  assert(uncachedMemInstrs);
  std::sort(MemInstrs.begin(), MemInstrs.end());
  uncachedMemInstrs = false;
}

TASEInstMode TASEAnalysis::getInstrumentationMode() {
  return TASEInstrumentationMode;
}


TASEAnalysis::TASEAnalysis() {
  ResetAccOffsets();
  ResetDataOffsets();
}

bool TASEAnalysis::isModeledFunction(StringRef name) {
  if (uncachedModeledFunctions) {
    initModeledFunctions();
  }
  return std::binary_search(ModeledFunctions.begin(), ModeledFunctions.end(), name);
}

bool TASEAnalysis::isMemInstr(unsigned int opcode) {
  if (uncachedMemInstrs) {
    initMemInstrs();
  }
  return std::binary_search(MemInstrs.begin(), MemInstrs.end(), opcode);
}

size_t TASEAnalysis::getMemFootprint(unsigned int opcode) {
  switch (opcode) {
    default:
      return 0;
    case X86::FARCALL64:
      errs() << "TASE: FARCALL64?";
      return 0;
    case X86::RETQ:
    case X86::CALLpcrel16:
    case X86::CALL64pcrel32:
    case X86::CALL64r:
    case X86::POP64r:
    case X86::PUSH64i8:
    case X86::PUSH64i32:
    case X86::PUSH64r:
    case X86::POPF64:
    case X86::PUSHF64:
      return 8;
    case X86::MOV8mi:
    case X86::MOV8mr:
    case X86::MOV8mr_NOREX:
    case X86::MOV8rm:
    case X86::MOV8rm_NOREX:
    case X86::MOVZX16rm8:
    case X86::MOVZX32rm8:
    case X86::MOVZX32rm8_NOREX:
    case X86::MOVZX64rm8:
    case X86::MOVSX16rm8:
    case X86::MOVSX32rm8:
    case X86::MOVSX32rm8_NOREX:
    case X86::MOVSX64rm8:
      return 1;
    case X86::MOV16mi:
    case X86::MOV16mr:
    case X86::MOV16rm:
    case X86::MOVZX32rm16:
    case X86::MOVZX64rm16:
    case X86::MOVSX32rm16:
    case X86::MOVSX64rm16:
      return 2;
    case X86::MOV32mi:
    case X86::MOV32mr:
    case X86::MOV32rm:
    case X86::MOVSX64rm32:
      return 4;
    case X86::MOV64mi32:
    case X86::MOV64mr:
    case X86::MOV64rm:
      return 8;
  }
  llvm_unreachable("TASE: How is this even possible?");
}


/* -- GPR ------------------------------------------------------------------- */
int TASEAnalysis::AllocateAccOffset(size_t bytes) {
  assert(bytes && " TASE: Cannot instrument instruction with unknown operand bytes.");
  assert(bytes <= REG_SIZE && "TASE: Cannot currently handle SIMD values or larger.");
  assert(bytes > 1 && "TASE: Cannot do single byte taint checks.");

  for (int i = 0; i < static_cast<int>(NUM_ACCUMULATORS); i++) {
    if (AccumulatorBytes[i] + bytes <= REG_SIZE) {
      AccumulatorBytes[i] += bytes;
      return i;
    }
  }
  /* Only got here if we weren't able to find a slot.  TO THE SPRINGBOARD!!!*/
  return -1;
}

void TASEAnalysis::ResetAccOffsets() {
  std::fill(AccumulatorBytes, AccumulatorBytes + NUM_ACCUMULATORS, 0);
}

uint8_t TASEAnalysis::getAccUsage(unsigned int idx) const {
  assert(idx < NUM_ACCUMULATORS);
  return AccumulatorBytes[idx];
}

/* -- SIMD ------------------------------------------------------------------ */
int TASEAnalysis::AllocateDataOffset(size_t bytes) {
  assert(bytes && " TASE: Cannot instrument instruction with unknown operand bytes.");
  assert(bytes <= REG_SIZE && "TASE: Cannot currently handle SIMD values or larger.");
  assert(bytes > 1 && "TASE: Cannot do single byte taint checks.");

  // We want a word offset.
  // Examples:
  // If we are storing a 4 byte int...
  //    bytes = 4
  // => stride = 2
  // => mask = (1 << 2) - 1 = 3 = 0b11.
  // The above makes sense because the mask (0b11) indicates 2 words (2x2 byte values).
  // => offset in [0, 2, 4, 6]
  // => offset/stride in [0, 1, 2, 3]
  uint8_t stride = bytes / POISON_SIZE;
  uint8_t mask = (1 << stride) - 1;
  uint8_t offset = 0;
  // The < 8  here is sizeof(xmm)/2.
  for (; offset < XMMREG_SIZE / POISON_SIZE; offset += stride) {
    if ((DataUsageMask & (mask << offset)) == 0) {
      break;
    }
  }

  // Compare and reload.
  if (offset >= XMMREG_SIZE / POISON_SIZE) {
    return -1;
  } else {
    // Mark the new words as being used.
    DataUsageMask |= mask << offset;
    return offset * POISON_SIZE;
  }
}

void TASEAnalysis::ResetDataOffsets() {
  DataUsageMask = 0;
}

}  // namespace llvm
