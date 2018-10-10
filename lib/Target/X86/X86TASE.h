#ifndef LLVM_LIB_TARGET_X86_X86TASE_H
#define LLVM_LIB_TARGET_X86_X86TASE_H

// DANGER WILL ROBINSON! C IN C++!
#include "tase/tase_interp.h"

#include "X86.h"
#include "X86InstrInfo.h"

enum TASEInstMode {
  TIM_NONE, TIM_GPR, TIM_SIMD
};

namespace llvm {

// Utility functionality.
static constexpr size_t cLog2(size_t n) {
  //assert(n);
  return ((n < 2) ? 0 : 1 + cLog2(n/2));
}

template <typename... Ts>
constexpr auto array_of(Ts&&... vals) -> std::array<unsigned int, sizeof...(Ts)> {
  return {{ vals... }};
}

static constexpr size_t NUM_ACCUMULATORS = 2;
static constexpr unsigned int TASE_REG_TMP = X86::R14;
static constexpr unsigned int TASE_REG_RET = X86::R15;
static constexpr unsigned int TASE_REG_ACC[] = {X86::R12, X86::R13};

static constexpr unsigned int TASE_REG_REFERENCE = X86::XMM13;
static constexpr unsigned int TASE_REG_ACCUMULATOR = X86::XMM14;
static constexpr unsigned int TASE_REG_DATA = X86::XMM15;

// Ordered by size.
static constexpr unsigned int TASE_LOADrr[] = {
  X86::MOV8rr, X86::MOV16rr, X86::MOV32rr, X86::MOV64rr
};
static constexpr unsigned int TASE_LOADrm[] = {
  X86::MOV8rm, X86::MOV16rm, X86::MOV32rm, X86::MOV64rm
};

static constexpr unsigned int TASE_PINSRrr[] = {
  X86::PINSRBrr, X86::PINSRWrr, X86::PINSRDrr, X86::PINSRQrr
};
static constexpr unsigned int TASE_PINSRrm[] = {
  X86::PINSRBrm, X86::PINSRWrm, X86::PINSRDrm, X86::PINSRQrm
};


// We can actually autogenerate this but I have these here to double check my understanding
// of tblgen. To productionize this, see include/llvm/MC/MCInstrDesc.h.  You can add another
// entry to enum Flag since isAllowedMemInstr is already part of Instruction in
// include/llvm/Target/Target.td, it can be packed into the Flags field in the output of
// tblgen and write an "isAllowedMemInstr" predicate in MCInstrDesc.h to mask and read
// the value.
//
// Only 64-bit values are considered here.
// In C++17, we could have directly sorted this array...  no such luck here.
constexpr auto MEM_INSTRS = array_of(
  X86::RETQ, X86::CALLpcrel16, X86::CALL64pcrel32, X86::CALL64r, X86::FARCALL64,
  X86::POP64r, X86::PUSH64r, X86::PUSH64i8, X86::PUSH64i32,
  X86::PUSHF64, X86::POPF64,
  // Must allow loads and stores of GPRs and immediates.
  X86::MOV8rm, X86::MOV16rm, X86::MOV32rm, X86::MOV64rm, X86::MOV8rm_NOREX,
  X86::MOV8mr, X86::MOV16mr, X86::MOV32mr, X86::MOV64mr, X86::MOV8mr_NOREX,
  X86::MOV8mi, X86::MOV16mi, X86::MOV32mi, X86::MOV64mi32,
  // LLVM passes insist on some form of implicit sign-extension
  // instruction available in order to rematerialize spilled values
  // efficiently.
  X86::MOVZX16rm8, X86::MOVZX32rm8, X86::MOVZX32rm8_NOREX, X86::MOVZX32rm16,
  X86::MOVZX64rm8, X86::MOVZX64rm16,
  X86::MOVSX16rm8, X86::MOVSX32rm8, X86::MOVSX32rm8_NOREX, X86::MOVSX32rm16,
  X86::MOVSX64rm8, X86::MOVSX64rm16, X86::MOVSX64rm32,

  // We allow some forms of SIMD register loads in order to support floating
  // point arguments. Opportunisitic optimization attempts are welcome.

  // Loads 32-bit values into SIMD registers.
  // BEWARE: LPS/HPS move 2 single-precision 32-bit values (so moved 64-bit values).
  X86::MOVSSmr, X86::MOVLPSmr, X86::MOVHPSmr,
  X86::VMOVSSmr, X86::VMOVLPSmr, X86::VMOVHPSmr,
  X86::MOVSSrm, X86::MOVLPSrm, X86::MOVHPSrm,
  X86::VMOVSSrm, X86::VMOVLPSrm, X86::VMOVHPSrm,
  X86::MOVDI2PDIrm, X86::MOVDI2SSrm, X86::MOVPDI2DImr, X86::MOVSS2DImr,
  X86::VMOVDI2PDIrm, X86::VMOVDI2SSrm, X86::VMOVPDI2DImr, X86::VMOVSS2DImr,
  // Loads 64-bit values into SIMD registers.
  X86::MOVSDmr, X86::MOVLPDmr, X86::MOVHPDmr,
  X86::VMOVSDmr, X86::VMOVLPDmr, X86::VMOVHPDmr,
  X86::MOVSDrm, X86::MOVLPDrm, X86::MOVHPDrm,
  X86::VMOVSDrm, X86::VMOVLPDrm, X86::VMOVHPDrm,
  X86::MOV64toPQIrm, X86::MOVPQIto64mr, X86::MOV64toSDrm, X86::MOVSDto64mr, X86::MOVQI2PQIrm, X86::MOVPQI2QImr,
  X86::VMOV64toPQIrm, X86::VMOVPQIto64mr, X86::VMOV64toSDrm, X86::VMOVSDto64mr, X86::VMOVQI2PQIrm, X86::VMOVPQI2QImr,
  // These instructions all perform the same thing with roughly the same
  // execution performance on Skylake - perform a 128-bit load or store.
  X86::MOVUPSmr, X86::MOVUPDmr, X86::MOVDQUmr,
  X86::MOVAPSmr, X86::MOVAPDmr, X86::MOVDQAmr,
  X86::VMOVUPSmr, X86::VMOVUPDmr, X86::VMOVDQUmr,
  X86::VMOVAPSmr, X86::VMOVAPDmr, X86::VMOVDQAmr,
  X86::MOVUPSrm, X86::MOVUPDrm, X86::MOVDQUrm,
  X86::MOVAPSrm, X86::MOVAPDrm, X86::MOVDQArm,
  X86::VMOVUPSrm, X86::VMOVUPDrm, X86::VMOVDQUrm,
  X86::VMOVAPSrm, X86::VMOVAPDrm, X86::VMOVDQArm,
  // These load 256-bits into YMM registers.
  X86::VMOVUPSYmr, X86::VMOVUPDYmr, X86::VMOVDQUYmr,
  X86::VMOVAPSYmr, X86::VMOVAPDYmr, X86::VMOVDQAYmr,
  X86::VMOVUPSYrm, X86::VMOVUPDYrm, X86::VMOVDQUYrm,
  X86::VMOVAPSYrm, X86::VMOVAPDYrm, X86::VMOVDQAYrm,

  // Partial updates:
  X86::PEXTRBmr, X86::PEXTRWmr, X86::PEXTRDmr, X86::PEXTRQmr,
  X86::VPEXTRBmr, X86::VPEXTRWmr, X86::VPEXTRDmr, X86::VPEXTRQmr,
  X86::PINSRBrm, X86::PINSRWrm, X86::PINSRDrm, X86::PINSRQrm,
  X86::VPINSRBrm, X86::VPINSRWrm, X86::VPINSRDrm, X86::VPINSRQrm
  );

constexpr auto SAFE_INSTRS = array_of(
  X86::TAILJMPd, X86::TAILJMPr, X86::TAILJMPd_CC,
  X86::TAILJMPd64, X86::TAILJMPr64, X86::TAILJMPr64_REX, X86::TAILJMPd64_CC
  );

class TASEAnalysis {
public:
  TASEAnalysis();

  bool isModeledFunction(StringRef name);
  bool isMemInstr(unsigned int opcode);
  bool isSafeInstr(unsigned int opcode);
  size_t getMemFootprint(unsigned int opcode);

  // These functions only make sense in GPR instrumentation mode.
  // Returns an index between 0 and NUM_ACCUMULATORS or -1 if we're out of
  // room in all accumulators.
  int AllocateAccOffset(size_t bytes);
  void ResetAccOffsets();
  uint8_t getAccUsage(unsigned int offset) const;

  // These functions only make sense in SIMD instrumentation mode.
  // Returns a byte offset between 0 and XMMREG_SIZE for the LSB index of a
  // slice of the requested size aligned to the requested size or -1 if we're
  // out of room.
  int AllocateDataOffset(size_t bytes);
  void ResetDataOffsets();

  static TASEInstMode getInstrumentationMode();

private:
  // Use C++11 trickery to extract the size of the array above at compile time.
  using meminstrs_t = std::array<unsigned int, MEM_INSTRS.size()>;
  using safeinstrs_t = std::array<unsigned int, SAFE_INSTRS.size()>;

  uint8_t AccumulatorBytes[NUM_ACCUMULATORS];
  unsigned int DataUsageMask;

  static void initModeledFunctions();
  static void initMemInstrs();
  static void initSafeInstrs();
  static bool uncachedModeledFunctions;
  static bool uncachedMemInstrs;
  static bool uncachedSafeInstrs;
  static std::vector<std::string> ModeledFunctions;
  static meminstrs_t MemInstrs;
  static safeinstrs_t SafeInstrs;
};

}

#endif
