// Add TASE taint discovery instrumentation after every load or store
// instruction.


#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86TASE.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include <algorithm>
#include <cassert>

using namespace llvm;

#define PASS_KEY "x86-tase-capture-taint"
#define PASS_DESC "X86 TASE taint tracking instrumentation."
#define DEBUG_TYPE PASS_KEY


// STATISTIC(NumCondBranchesTraced, "Number of conditional branches traced");

namespace llvm {

void initializeX86TASECaptureTaintPassPass(PassRegistry &);
}

namespace {

class X86TASECaptureTaintPass : public MachineFunctionPass {
public:
  X86TASECaptureTaintPass() : MachineFunctionPass(ID),
    CurrentMI(nullptr),
    NextMII(nullptr),
    InsertBefore(true) {
    initializeX86TASECaptureTaintPassPass(
        *PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override {
    return PASS_DESC;
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

  MachineFunctionProperties getRequiredProperties() const override {
    return MachineFunctionProperties().set(
        MachineFunctionProperties::Property::NoVRegs);
  }

  /// Pass identification, replacement for typeid.
  static char ID;

private:
  const X86Subtarget *Subtarget;
//   MachineRegisterInfo *MRI;
  const X86InstrInfo *TII;
//   const TargetRegisterInfo *TRI;
  MachineInstr *CurrentMI;
  MachineBasicBlock::instr_iterator NextMII;
  bool InsertBefore;

  TASEAnalysis Analysis;
  void InstrumentInstruction(MachineInstr &MI);
  MachineInstrBuilder InsertInstr(unsigned int opcode, unsigned int destReg);
  void PoisonCheckReg(size_t size);
  void PoisonCheckStack(int64_t stackOffset);
  void PoisonCheckMem(size_t size);
  void PoisonCheckRegInternal(size_t size, unsigned int reg, unsigned int acc_idx);
  void RotateAccumulator(size_t size, unsigned int acc_idx);
  unsigned int AllocateOffset(size_t size);
};

} // end anonymous namespace


char X86TASECaptureTaintPass::ID = 0;

bool X86TASECaptureTaintPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");

  if (Analysis.isModeledFunction(MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Function is modeled in the interpreter.\n");
    return false;
  }

  if (Analysis.getInstrumentationMode() == TIM_NONE) {
    LLVM_DEBUG(dbgs() << "TASE: Skipping instrumentation by requst.\n");
    return false;
  }

  Subtarget = &MF.getSubtarget<X86Subtarget>();
//   MRI = &MF.getRegInfo();
  TII = Subtarget->getInstrInfo();
//   TRI = Subtarget->getRegisterInfo();

  bool modified = false;
  for (MachineBasicBlock &MBB : MF) {
    LLVM_DEBUG(dbgs() << "TASE: Analyzing taint for block " << MBB);
    // Every cartridge entry sequence is going to flush the accumulators.
    Analysis.ResetAccOffsets();
    Analysis.ResetDataOffsets();
    // In using this range, we use the super special property that a machine
    // instruction list obeys the iterator characteristics of list<
    // undocumented property that instr_iterator is not invalidated when
    // one inserts into the list.
    for (MachineInstr &MI : MBB.instrs()) {
      LLVM_DEBUG(dbgs() << "TASE: Analyzing taint for " << MI);
      assert(!(MI.mayLoad() && MI.mayStore()) && "TASE: Somehow we have a CISC instruction! ");
      // Only our RISC-like loads should have this set.
      if (!MI.mayLoad() && !MI.mayStore()) {
        // Non-memory instructions need no instrumentation.
        continue;
      }
      assert(Analysis.isMemInstr(MI.getOpcode()) && "TASE: Encountered an instruction we haven't handled.");
      InstrumentInstruction(MI);
      modified = true;
    }
  }
  return modified;
}

// Appends a poison check to load instructions and prepends a poison check to
// a store instructions. Expects to see only known instructions.
//
void X86TASECaptureTaintPass::InstrumentInstruction(MachineInstr &MI) {
  CurrentMI = &MI;
  NextMII = std::next(MachineBasicBlock::instr_iterator(MI));
  size_t size = Analysis.getMemFootprint(MI.getOpcode());
  switch (MI.getOpcode()) {
    default:
      MI.dump();
      llvm_unreachable("TASE: Unknown instructions.");
      break;
    case X86::FARCALL64:
      errs() << "TASE: FARCALL64?";
      MI.dump();
      //llvm_unreachable("TASE: Who's jumping across segmented code?");
      break;
    case X86::POP64r:
      // Fast path
      PoisonCheckReg(size);
      break;
    case X86::RETQ:
      // We should not have a symbolic return address but we treat this as a
      // standard pop of the stack just in case.
    case X86::POPF64:
      PoisonCheckStack(0);
      break;
    case X86::CALLpcrel16:
    case X86::CALLpcrel32:
    case X86::CALL64r:
      // Fixed addresses cannot be symbolic. Indirect calls are detected as
      // symbolic when their base address is loaded and calculated.
      // A stack push is performed during a call and since we don't sweep old
      // taint from the stacm values from the stack when returning from
      // previous functions,, we check to see if we are pushing into a
      // "symbolic" stack cell.
    case X86::PUSH64i8:
    case X86::PUSH64i32:
    case X86::PUSH64r:
    case X86::PUSHF64:
      // Values are zero-extended during the push - so check the entire stack
      // slot for poison before the write.
      PoisonCheckStack(-size);
      break;
    case X86::MOV8mi: case X86::MOV8mr: case X86::MOV8mr_NOREX: case X86::MOV8rm: case X86::MOV8rm_NOREX:
    case X86::MOVZX16rm8: case X86::MOVZX32rm8: case X86::MOVZX32rm8_NOREX: case X86::MOVZX64rm8:
    case X86::MOVSX16rm8: case X86::MOVSX32rm8: case X86::MOVSX32rm8_NOREX: case X86::MOVSX64rm8:
    case X86::PINSRBrm: case X86::VPINSRBrm:
      // For 8 bit memory accesses, we want access to the address so that we can
      // appropriately align it for our 2 byte poison check.
    case X86::MOV16mi: case X86::MOV16mr:
    case X86::MOV32mi: case X86::MOV32mr:
    case X86::MOV64mi32: case X86::MOV64mr:
    case X86::MOVSSmr: case X86::MOVLPSmr: case X86::MOVHPSmr:
    case X86::VMOVSSmr: case X86::VMOVLPSmr: case X86::VMOVHPSmr:
    case X86::MOVPDI2DImr: case X86::MOVSS2DImr:
    case X86::VMOVPDI2DImr: case X86::VMOVSS2DImr:
    case X86::MOVSDmr: case X86::MOVLPDmr: case X86::MOVHPDmr:
    case X86::VMOVSDmr: case X86::VMOVLPDmr: case X86::VMOVHPDmr:
    case X86::MOVPQIto64mr: case X86::MOVSDto64mr: case X86::MOVPQI2QImr:
    case X86::VMOVPQIto64mr: case X86::VMOVSDto64mr: case X86::VMOVPQI2QImr:
    case X86::MOVUPSmr: case X86::MOVUPDmr: case X86::MOVDQUmr:
    case X86::MOVAPSmr: case X86::MOVAPDmr: case X86::MOVDQAmr:
    case X86::VMOVUPSmr: case X86::VMOVUPDmr: case X86::VMOVDQUmr:
    case X86::VMOVAPSmr: case X86::VMOVAPDmr: case X86::VMOVDQAmr:
    case X86::PEXTRBmr: case X86::PEXTRWmr: case X86::PEXTRDmr: case X86::PEXTRQmr:
    case X86::VPEXTRBmr: case X86::VPEXTRWmr: case X86::VPEXTRDmr: case X86::VPEXTRQmr:
      PoisonCheckMem(size);
      break;
    case X86::MOV16rm: case X86::MOV32rm: case X86::MOV64rm:
    case X86::MOVZX32rm16: case X86::MOVZX64rm16:
    case X86::MOVSX32rm16: case X86::MOVSX64rm16: case X86::MOVSX64rm32:
    case X86::MOVSSrm: case X86::MOVLPSrm: case X86::MOVHPSrm:
    case X86::VMOVSSrm: case X86::VMOVLPSrm: case X86::VMOVHPSrm:
    case X86::MOVDI2PDIrm: case X86::MOVDI2SSrm:
    case X86::VMOVDI2PDIrm: case X86::VMOVDI2SSrm:
    case X86::MOVSDrm: case X86::MOVLPDrm: case X86::MOVHPDrm:
    case X86::VMOVSDrm: case X86::VMOVLPDrm: case X86::VMOVHPDrm:
    case X86::MOV64toPQIrm: case X86::MOV64toSDrm: case X86::MOVQI2PQIrm:
    case X86::VMOV64toPQIrm: case X86::VMOV64toSDrm: case X86::VMOVQI2PQIrm:
    case X86::MOVUPSrm: case X86::MOVUPDrm: case X86::MOVDQUrm:
    case X86::MOVAPSrm: case X86::MOVAPDrm: case X86::MOVDQArm:
    case X86::VMOVUPSrm: case X86::VMOVUPDrm: case X86::VMOVDQUrm:
    case X86::VMOVAPSrm: case X86::VMOVAPDrm: case X86::VMOVDQArm:
    case X86::PINSRWrm: case X86::PINSRDrm: case X86::PINSRQrm:
    case X86::VPINSRWrm: case X86::VPINSRDrm: case X86::VPINSRQrm:
      PoisonCheckReg(size);
      break;
    //case X86::VMOVUPSYmr: case X86::VMOVUPDYmr: case X86::VMOVDQUYmr:
    //case X86::VMOVAPSYmr: case X86::VMOVAPDYmr: case X86::VMOVDQAYmr:
    //case X86::VMOVUPSYrm: case X86::VMOVUPDYrm: case X86::VMOVDQUYrm:
    //case X86::VMOVAPSYrm: case X86::VMOVAPDYrm: case X86::VMOVDQAYrm:
  }
  CurrentMI = nullptr;
}

MachineInstrBuilder X86TASECaptureTaintPass::InsertInstr(unsigned int opcode, unsigned int destReg) {
  assert(CurrentMI && "TASE: Must only be called in the context of of instrumenting an instruction.");
  return BuildMI(*CurrentMI->getParent(),
      InsertBefore ? MachineBasicBlock::instr_iterator(CurrentMI) : NextMII,
      CurrentMI->getDebugLoc(), TII->get(opcode), destReg);
}

void X86TASECaptureTaintPass::PoisonCheckStack(int64_t stackOffset) {
  InsertBefore = true;
  const size_t stackAlignment = 8;
  assert(stackOffset % stackAlignment == 0 && "TASE: Unaligned offset into the stack - must be multiple of 8");
  unsigned int acc_idx = AllocateOffset(stackAlignment);

  if (Analysis.getInstrumentationMode() == TIM_GPR) {
    InsertInstr(TASE_LOADrm[cLog2(stackAlignment)], TASE_REG_ACC[acc_idx])
      .addReg(X86::RSP)         // base
      .addImm(1)                // scale
      .addReg(X86::NoRegister)  // index
      .addImm(stackOffset)      // offset
      .addReg(X86::NoRegister)  // segment
      .cloneMemRefs(*CurrentMI);
    // No rotation needed - it's an 8 byte read.
  } else {
    assert(Analysis.getInstrumentationMode() == TIM_SIMD);
    //TODO: If AVX is enabled, switch to VPINSR or something else.
    InsertInstr(TASE_PINSRrm[cLog2(stackAlignment)], TASE_REG_DATA)
      .addReg(TASE_REG_DATA)
      .addReg(X86::RSP)         // base
      .addImm(1)                // scale
      .addReg(X86::NoRegister)  // index
      .addImm(stackOffset)      // offset
      .addReg(X86::NoRegister)  // segment
      .addImm(acc_idx / stackAlignment)
      .cloneMemRefs(*CurrentMI);
  }
}

void X86TASECaptureTaintPass::PoisonCheckMem(size_t size) {
  InsertBefore = true;
  int addrOffset = X86II::getMemoryOperandNo(CurrentMI->getDesc().TSFlags);
  // addrOffset is -1 if we failed to find the operand.
  assert(addrOffset >= 0 && "TASE: Unable to determine instruction memory operand!");
  addrOffset += X86II::getOperandBias(CurrentMI->getDesc());
  unsigned int acc_idx = AllocateOffset(size == 1 ? 2 : size);

  // Stash our poison - use the given memory operands as our source.
  // We may get the mem_operands incorrect.  I believe we need to clear the
  // MachineMemOperand::MOStore flag and set the MOLoad flag but we're late
  // in the compilation process and mem_operands is mostly a hint anyway.
  // It is always legal to have instructions with no mem_operands - the
  // rest of the compiler should just deal with it extremely conservatively
  // in terms of alignment and volatility.
  if (size >= 16) {
    assert(Analysis.getInstrumentationMode() == TIM_SIMD && "TASE: GPR poisnoning not implemented for SIMD registers.");
    assert(size == 16 && "TASE: Unimplemented. Handle YMM/ZMM SIMD instructions properly.");
    // We are going to be silly and not check mem_operands.getAlignment here.
    // Agner Fog says MOVUPS/MOVDQU run at the same speed as MOVAPS/MOVDQA on
    // post Nahalem architectures. My assumption is that this carries over to VCMPEQW.
    // So we just assume reasonably aligned access and let the memory fabric/L1 cache
    // controller do its magic.
    // TODO: Check if our alignment is at least 2. The compiler would have to
    // be stark-raving mad to emit a vex-prefixed SIMD load on a buffer
    // misaligned by one byte but one never knows...
    //MachineInstrBuilder MIB = InsertInstr(X86::VPCMPEQWrm, TASE_REG_DATA)
    //  .addReg(TASE_REG_REFERENCE);
    //for (int i = 0; i < X86::AddrNumOperands; i++) {
    //  MIB.addAndUse(CurrentMI->getOperand(addrOffset + i));
    //}
    //MIB.cloneMemRefs(*CurrentMI);
    //InsertInstr(X86::PORrr, TASE_REG_ACCUMULATOR)
    //  .addReg(TASE_REG_ACCUMULATOR);
    //  .addReg(TASE_REG_DATA);
    Analysis.ResetDataOffsets();
  } else if (size == 1) {
    // Precalculate the address, align it to a two byte boundary and then
    // read two bytes to ensure a proper taint check.
    size = 2;
    MachineInstrBuilder MIB = InsertInstr(X86::LEA64r, TASE_REG_TMP);
    for (int i = 0; i < X86::AddrNumOperands; i++) {
      MIB.addAndUse(CurrentMI->getOperand(addrOffset + i));
    }
    // Use TASE_REG_RET as a temporary register to hold offsets/indices.
    // TODO: If we can establish that EFLAGS is dead, we can use a shorter SHR.
    InsertInstr(X86::MOV32ri, getX86SubSuperRegister(TASE_REG_RET, 4 * 8))
      .addImm(1);
    InsertInstr(X86::SHRX64rr, TASE_REG_TMP)
      .addReg(TASE_REG_TMP)
      .addReg(TASE_REG_RET);
    if (Analysis.getInstrumentationMode() == TIM_GPR) {
      InsertInstr(TASE_LOADrm[cLog2(size)], getX86SubSuperRegister(TASE_REG_ACC[acc_idx], size * 8))
        .addReg(TASE_REG_TMP)     // base
        .addImm(1)                // scale
        .addReg(TASE_REG_TMP)     // index
        .addImm(0)                // offset
        .addReg(X86::NoRegister); // segment
        //.cloneMemRefs(*CurrentMI);
      RotateAccumulator(size, acc_idx);
    } else {
      assert(Analysis.getInstrumentationMode() == TIM_SIMD);
      InsertInstr(TASE_PINSRrm[cLog2(size)], TASE_REG_DATA)
        .addReg(TASE_REG_DATA)
        .addReg(TASE_REG_TMP)     // base
        .addImm(1)                // scale
        .addReg(TASE_REG_TMP)     // index
        .addImm(0)                // offset
        .addReg(X86::NoRegister)  // segment
        .addImm(acc_idx / size);
        //.cloneMemRefs(*CurrentMI);
    }
  } else if (Analysis.getInstrumentationMode() == TIM_GPR) {
    if (size == 4 && Analysis.getAccUsage(acc_idx) > 4) { 
      // Cannot use a direct 32-bit load as that will zero out the top bits
      // of the 64-bit accumulator.  Instead, load into temporary register
      // and then move it into accumulator 2 bytes at a time.
      MachineInstrBuilder MIB = InsertInstr(X86::MOV32rm, getX86SubSuperRegister(TASE_REG_TMP, size * 8));
      for (int i = 0; i < X86::AddrNumOperands; i++) {
        MIB.addAndUse(CurrentMI->getOperand(addrOffset + i));
      }
      //MIB.cloneMemRefs(*CurrentMI);
      PoisonCheckRegInternal(size, TASE_REG_TMP, acc_idx);
    } else {
    // size is 2 or 8
      MachineInstrBuilder MIB =
        InsertInstr(TASE_LOADrm[cLog2(size)], getX86SubSuperRegister(TASE_REG_ACC[acc_idx], size * 8));
      for (int i = 0; i < X86::AddrNumOperands; i++) {
        MIB.addAndUse(CurrentMI->getOperand(addrOffset + i));
      }
      //MIB.cloneMemRefs(*CurrentMI);
      RotateAccumulator(size, acc_idx);
    }
  } else {
    assert(Analysis.getInstrumentationMode() == TIM_SIMD);
    MachineInstrBuilder MIB =
      InsertInstr(TASE_PINSRrm[cLog2(size)], TASE_REG_DATA)
      .addReg(TASE_REG_DATA);
    for (int i = 0; i < X86::AddrNumOperands; i++) {
      MIB.addAndUse(CurrentMI->getOperand(addrOffset + i));
    }
    MIB.addImm(acc_idx / size);
    //MIB.cloneMemRefs(*CurrentMI);
  }
}

// Optimized fast-path case where we can simply check the value from a destination register.
// Clobbers the bottom byte of the temporary register.
void X86TASECaptureTaintPass::PoisonCheckReg(size_t size) {
  InsertBefore = false;
  unsigned int acc_idx = AllocateOffset(size);
  PoisonCheckRegInternal(size, CurrentMI->getOperand(0).getReg(), acc_idx);
}

void X86TASECaptureTaintPass::PoisonCheckRegInternal(size_t size, unsigned int reg, unsigned int acc_idx) {
  assert(reg != X86::NoRegister);
  if (size >= 16) {
    assert(Analysis.getInstrumentationMode() == TIM_SIMD && "TASE: GPR poisnoning not implemented for SIMD registers.");
    assert(size == 16 && "TASE: Handle AVX instructions");
    //InsertInstr(X86::VPCMPEQWrr, TASE_REG_DATA)
    //  .addReg(reg)
    //  .addReg(TASE_REG_REFERENCE);
    //InsertInstr(X86::PORrr, TASE_REG_ACCUMULATOR)
    //  .addReg(TASE_REG_ACCUMULATOR);
    //  .addReg(TASE_REG_DATA);
    Analysis.ResetDataOffsets();
  } else {
    reg = getX86SubSuperRegister(reg, size * 8);
    if (Analysis.getInstrumentationMode() == TIM_GPR) {
      if (size == 4 && Analysis.getAccUsage(acc_idx) >= 4) {
        // Cannot use a direct 32-bit move as that will zero out the top bits
        // of the 64-bit accumulator.  Instead, move 2 bytes at a time.
        // Note that PoisonCheckReg will clobber the bottom byte of the (unused)
        // return register.
        PoisonCheckRegInternal(2, reg, acc_idx);
        unsigned int tmp_reg = getX86SubSuperRegister(TASE_REG_TMP, size * 8);
        // Bottom byte of temporary should already have "16" loaded into it.
        InsertInstr(X86::SHRX32rr, tmp_reg)
          .addReg(reg)
          .addReg(getX86SubSuperRegister(TASE_REG_RET, size * 8));
        PoisonCheckRegInternal(2, tmp_reg, acc_idx);
      } else {
        // Exploit the fact that a zero extension is exactly what we need if size == 4.-
        InsertInstr(TASE_LOADrr[cLog2(size)], getX86SubSuperRegister(TASE_REG_ACC[acc_idx], size * 8))
          .addReg(reg);
        RotateAccumulator(size, acc_idx);
      }
    } else {
      assert(Analysis.getInstrumentationMode() == TIM_SIMD);
      InsertInstr(TASE_PINSRrr[cLog2(size)], TASE_REG_DATA)
        .addReg(TASE_REG_DATA)
        .addReg(reg)
        .addImm(acc_idx / size);
    }
  }
}

void X86TASECaptureTaintPass::RotateAccumulator(size_t size, unsigned int acc_idx) {
  assert(Analysis.getInstrumentationMode() == TIM_GPR);
  if (size < 8) {
    InsertInstr(X86::MOV32ri, getX86SubSuperRegister(TASE_REG_RET, 4 * 8))
      .addImm(size * 8);
    InsertInstr(X86::SHLX64rr, TASE_REG_ACC[acc_idx])
      .addReg(TASE_REG_ACC[acc_idx])
      .addReg(TASE_REG_RET);
  }
}

unsigned int X86TASECaptureTaintPass::AllocateOffset(size_t size) {
  int offset = -1;
  if (Analysis.getInstrumentationMode() == TIM_SIMD) {
    offset = Analysis.AllocateDataOffset(size);
    if (offset < 0) {
      InsertInstr(X86::PCMPEQWrr, TASE_REG_DATA)
        .addReg(TASE_REG_DATA)
        .addReg(TASE_REG_REFERENCE);
      InsertInstr(X86::PORrr, TASE_REG_ACCUMULATOR)
        .addReg(TASE_REG_ACCUMULATOR)
        .addReg(TASE_REG_DATA);
      Analysis.ResetDataOffsets();
      offset = Analysis.AllocateDataOffset(size);
    }
  } else {
    offset = Analysis.AllocateAccOffset(size);
  }
  assert(offset >= 0 && "TASE: Unable to acquire a register for poison instrumentation.");
  return offset;
}

INITIALIZE_PASS(X86TASECaptureTaintPass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASECaptureTaint() {
  return new X86TASECaptureTaintPass();
}
