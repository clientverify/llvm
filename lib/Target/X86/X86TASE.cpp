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
    cl::init(TIM_SIMD));

namespace llvm {

bool TASEAnalysis::uncachedModeledFunctions(true);
bool TASEAnalysis::uncachedInstrs(true);
std::vector<std::string> TASEAnalysis::ModeledFunctions = {};
TASEAnalysis::meminstrs_t TASEAnalysis::MemInstrs(MEM_INSTRS);
TASEAnalysis::safeinstrs_t TASEAnalysis::SafeInstrs(SAFE_INSTRS);
TASEAnalysis::xmmdestinstrs_t TASEAnalysis::XmmDestInstrs(XMM_DEST_INSTRS);

void TASEAnalysis::initModeledFunctions() {
  assert(uncachedModeledFunctions);

  if (TASEModeledFunctionsFile.empty()) {
    uncachedModeledFunctions = false;
    return;
  }

  std::unique_ptr<MemoryBuffer> MB =
    std::move(MemoryBuffer::getFile(TASEModeledFunctionsFile).get());

  for(line_iterator I = line_iterator(*MB); !I.is_at_eof(); I++) {
    std::string name = I->str();
    name.erase(0, name.find_first_not_of("\t\n\v\f\r "));
    name.erase(name.find_last_not_of("\t\n\v\f\r ") + 1);
    if (name.find("(")) {
      name.erase(0, name.find_last_of("(") + 1);
      assert(name.find(")") && "TASE: Modeled function file malformed - cannot find ) matching (");
      name.erase(name.find_first_of(")"));
    }
    ModeledFunctions.push_back(name);
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

void TASEAnalysis::initInstrs() {
  assert(uncachedInstrs);
  std::sort(MemInstrs.begin(), MemInstrs.end());
  std::sort(SafeInstrs.begin(), SafeInstrs.end());
  std::sort(XmmDestInstrs.begin(), XmmDestInstrs.end());
  uncachedInstrs = false;
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
  if (uncachedInstrs) {
    initInstrs();
  }
  return std::binary_search(MemInstrs.begin(), MemInstrs.end(), opcode);
}

bool TASEAnalysis::isSafeInstr(unsigned int opcode) {
  if (uncachedInstrs) {
    initInstrs();
  }
  return std::binary_search(SafeInstrs.begin(), SafeInstrs.end(), opcode);
}

bool TASEAnalysis::isXmmDestInstr(unsigned opcode) {
  if (uncachedInstrs) {
    initInstrs();
  }
  return std::binary_search(XmmDestInstrs.begin(), XmmDestInstrs.end(), opcode);
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
    case X86::CALL64r_NT:
    case X86::POP64r:
    case X86::PUSH64i8:
    case X86::PUSH64i32:
    case X86::PUSH64r:
    case X86::POPF64:
    case X86::PUSHF64:
      return 8;
    case X86::MOV8mi: case X86::MOV8mr: case X86::MOV8mr_NOREX: case X86::MOV8rm: case X86::MOV8rm_NOREX:
    case X86::MOVZX16rm8: case X86::MOVZX32rm8: case X86::MOVZX32rm8_NOREX: case X86::MOVZX64rm8:
    case X86::MOVSX16rm8: case X86::MOVSX32rm8: case X86::MOVSX32rm8_NOREX: case X86::MOVSX64rm8:
    case X86::PEXTRBmr: case X86::VPEXTRBmr:
    case X86::PINSRBrm: case X86::VPINSRBrm:
      return 1;
    case X86::MOV16mi: case X86::MOV16mr: case X86::MOV16rm:
    case X86::MOVZX32rm16: case X86::MOVZX64rm16:
    case X86::MOVSX32rm16: case X86::MOVSX64rm16:
    case X86::PEXTRWmr: case X86::VPEXTRWmr:
    case X86::PINSRWrm: case X86::VPINSRWrm:
      return 2;
    case X86::MOV32mi: case X86::MOV32mr: case X86::MOV32rm:
    case X86::MOVSX64rm32:
    case X86::MOVSSmr: case X86::MOVSSrm:
    case X86::VMOVSSmr: case X86::VMOVSSrm:
    case X86::MOVPDI2DImr: case X86::MOVSS2DImr: case X86::MOVDI2PDIrm: case X86::MOVDI2SSrm:
    case X86::VMOVPDI2DImr: case X86::VMOVSS2DImr: case X86::VMOVDI2PDIrm: case X86::VMOVDI2SSrm:
    case X86::PEXTRDmr: case X86::VPEXTRDmr:
    case X86::PINSRDrm: case X86::VPINSRDrm:
    case X86::INSERTPSrm: case X86::VINSERTPSrm:
      return 4;
    case X86::MOV64mi32: case X86::MOV64mr: case X86::MOV64rm:
    case X86::MOVLPSmr: case X86::MOVHPSmr: case X86::MOVLPSrm: case X86::MOVHPSrm:
    case X86::VMOVLPSmr: case X86::VMOVHPSmr: case X86::VMOVLPSrm: case X86::VMOVHPSrm:
    case X86::MOVSDmr: case X86::MOVSDrm:
    case X86::VMOVSDmr: case X86::VMOVSDrm:
    case X86::MOVLPDmr: case X86::MOVHPDmr: case X86::MOVLPDrm: case X86::MOVHPDrm:
    case X86::VMOVLPDmr: case X86::VMOVHPDmr: case X86::VMOVLPDrm: case X86::VMOVHPDrm:
    case X86::MOVPQIto64mr: case X86::MOVSDto64mr: case X86::MOVPQI2QImr:
    case X86::MOV64toPQIrm: case X86::MOV64toSDrm: case X86::MOVQI2PQIrm:
    case X86::VMOVPQIto64mr: case X86::VMOVSDto64mr: case X86::VMOVPQI2QImr:
    case X86::VMOV64toPQIrm: case X86::VMOV64toSDrm: case X86::VMOVQI2PQIrm:
    case X86::PEXTRQmr: case X86::VPEXTRQmr:
    case X86::PINSRQrm: case X86::VPINSRQrm:
      return 8;
    case X86::MOVUPSmr: case X86::MOVUPDmr: case X86::MOVDQUmr:
    case X86::MOVAPSmr: case X86::MOVAPDmr: case X86::MOVDQAmr:
    case X86::VMOVUPSmr: case X86::VMOVUPDmr: case X86::VMOVDQUmr:
    case X86::VMOVAPSmr: case X86::VMOVAPDmr: case X86::VMOVDQAmr:
    case X86::MOVUPSrm: case X86::MOVUPDrm: case X86::MOVDQUrm:
    case X86::MOVAPSrm: case X86::MOVAPDrm: case X86::MOVDQArm:
    case X86::VMOVUPSrm: case X86::VMOVUPDrm: case X86::VMOVDQUrm:
    case X86::VMOVAPSrm: case X86::VMOVAPDrm: case X86::VMOVDQArm:
    case X86::PMOVSXBWrm: case X86::PMOVSXBDrm: case X86::PMOVSXBQrm:
    case X86::PMOVSXWDrm: case X86::PMOVSXWQrm: case X86::PMOVSXDQrm:
    case X86::PMOVZXBWrm: case X86::PMOVZXBDrm: case X86::PMOVZXBQrm:
    case X86::PMOVZXWDrm: case X86::PMOVZXWQrm: case X86::PMOVZXDQrm:
      return 16;
    case X86::VMOVUPSYmr: case X86::VMOVUPDYmr: case X86::VMOVDQUYmr:
    case X86::VMOVAPSYmr: case X86::VMOVAPDYmr: case X86::VMOVDQAYmr:
    case X86::VMOVUPSYrm: case X86::VMOVUPDYrm: case X86::VMOVDQUYrm:
    case X86::VMOVAPSYrm: case X86::VMOVAPDYrm: case X86::VMOVDQAYrm:
      return 32;
  }
  llvm_unreachable("TASE: How is this even possible?");
}

bool TASEAnalysis::isSpecialInlineAsm(const MachineInstr &MI) const {
  if (!MI.isInlineAsm()) return false;

  unsigned NumDefs = 0;
  for (; MI.getOperand(NumDefs).isReg() && MI.getOperand(NumDefs).isDef(); ++NumDefs) {}
  std::string AsmStr = std::string(MI.getOperand(NumDefs).getSymbolName());
  if (AsmStr.empty()) {
    errs() << "TASE: ASSEMBLY - Ignoring empty inline asm/barrier " << AsmStr << "\n";
    return true;
  } else if (AsmStr.find("mov %fs:0,$0") == 0) {
    errs() << "TASE: ASSEMBLY - Special exception for __pthread_self: " << AsmStr << "\n";
    return true;
  } else if (AsmStr.find("syscall") == 0) {
    errs() << "TASE: ASSEMBLY - Allowing syscalls: " << AsmStr << "\n";
    return true;
  } else if (AsmStr.find("mov $1,%rsp ; jmp *$0") == 0) {
    errs() << "TASE: ASSEMBLY - Special exception for CRTJMP: " << AsmStr << "\n";
    return true;
  } else {
    return false;
  }
}


/* -- GPR ------------------------------------------------------------------- */
int TASEAnalysis::AllocateAccOffset(size_t bytes) {
  assert(bytes && " TASE: Cannot instrument instruction with unknown operand bytes.");
  assert(bytes <= GREG_SIZE && "TASE: Cannot currently handle SIMD values or larger.");
  assert(bytes > 1 && "TASE: Cannot do single byte taint checks.");

  for (int i = 0; i < static_cast<int>(NUM_ACCUMULATORS); i++) {
    if (AccumulatorBytes[i] + bytes <= GREG_SIZE) {
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
  assert(bytes > 1 && "TASE: Cannot do single byte taint checks.");
  assert(bytes <= XMMREG_SIZE);

  // We want a word offset.
  // Examples:
  // If we are storing a 4 byte int...
  //    bytes = 4
  // => stride = 2
  // => mask = (1 << 2) - 1 = 3 = 0b11.
  // The above makes sense because the mask (0b11) indicates 2 words (2x2 byte values).
  // => offset in [0, 2, 4, 6]
  // => offset/stride in [0, 1, 2, 3]
  unsigned int stride = bytes / POISON_SIZE;
  unsigned int mask = (1 << stride) - 1;
  unsigned int offset = 0;
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
    if (bytes >= XMMREG_SIZE) {
      assert(offset == 0 && "TASE instrumentation must poison instrument SIMD operands directly.");
    }
    // Mark the new words as being used.
    DataUsageMask |= mask << offset;
    return offset * POISON_SIZE;
  }
}

void TASEAnalysis::ResetDataOffsets() {
  DataUsageMask = 0;
}

}  // namespace llvm
