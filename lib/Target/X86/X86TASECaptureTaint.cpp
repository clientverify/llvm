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
    NextMII(nullptr) {
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

  TASEAnalysis Analysis;
  void InstrumentInstruction(MachineInstr &MI);
  MachineInstrBuilder InsertInstr(unsigned int opcode, unsigned int destReg, bool append = false);
  void PoisonCheckReg(size_t size);
  void PoisonCheckStack(int64_t stackOffset);
  void PoisonCheckMem(size_t size);
};

} // end anonymous namespace


char X86TASECaptureTaintPass::ID = 0;

bool X86TASECaptureTaintPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");

  if (Analysis.isModeledFunction(MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Function is modeled in the interpreter\n.");
    return false;
  }

  Subtarget = &MF.getSubtarget<X86Subtarget>();
//   MRI = &MF.getRegInfo();
  TII = Subtarget->getInstrInfo();
//   TRI = Subtarget->getRegisterInfo();

  bool modified = false;
  for (MachineBasicBlock &MBB : MF) {
    // Every cartridge entry sequence is going to flush the accumulators.
    Analysis.ResetAccOffsets();
    // In using this range, we use the super special property that a machine
    // instruction list obeys the iterator characteristics of list<
    // undocumented property that instr_iterator is not invalidated when
    // one inserts into the list.
    for (MachineInstr &MI : MBB.instrs()) {
      assert(!(MI.mayLoad() && MI.mayStore()) && "TASE: Somehow we have a CISC instruction!");
      // Only our RISC-like loads should have this set.
      if (!MI.mayLoad() && !MI.mayStore()) {
        // Non-memory instructions need no instrumentation.
        continue;
      }
      assert(Analysis.isMemInstr(MI.getOpcode()) &&
          "TASE: Encountered an instruction we haven't handled.");
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
      // For 8 bit memory accesses, we want access to the address so that we can
      // appropriately align it for our 2 byte poison check.
    case X86::MOV16mi:
    case X86::MOV16mr:
    case X86::MOV32mi:
    case X86::MOV32mr:
    case X86::MOV64mi32:
    case X86::MOV64mr:
      PoisonCheckMem(size);
      break;
    case X86::MOV16rm:
    case X86::MOVZX32rm16:
    case X86::MOVZX64rm16:
    case X86::MOVSX32rm16:
    case X86::MOVSX64rm16:
    case X86::MOV32rm:
    case X86::MOVSX64rm32:
    case X86::MOV64rm:
      PoisonCheckReg(size);
      break;
  }
  CurrentMI = nullptr;
}

MachineInstrBuilder X86TASECaptureTaintPass::InsertInstr(unsigned int opcode, unsigned int destReg, bool append) {
  assert(CurrentMI && "TASE: Must only be called in the context of of instrumenting an instruction.");
  return BuildMI(*CurrentMI->getParent(),
      append ? NextMII : MachineBasicBlock::instr_iterator(CurrentMI),
      CurrentMI->getDebugLoc(), TII->get(opcode), destReg);
}

void X86TASECaptureTaintPass::PoisonCheckStack(int64_t stackOffset) {
  const size_t stackAlignment = 8;
  assert(stackOffset % stackAlignment == 0 && "TASE: Unaligned offset into the stack - must be multiple of 8");

  int acc_idx = Analysis.AllocateAccOffset(stackAlignment);
  assert(acc_idx >= 0);
  InsertInstr(TASE_LOADrm[cLog2(stackAlignment)], TASE_REG_ACC[acc_idx])
    .addReg(TASE_REG_ACC[acc_idx])
    .addReg(X86::RSP)         // base
    .addImm(0)                // scale
    .addReg(X86::NoRegister)  // index
    .addImm(stackOffset)      // offset
    .addReg(X86::NoRegister)  // segment
    .cloneMemRefs(*CurrentMI);
  // No rotation needed - it's an 8 byte read.
}

void X86TASECaptureTaintPass::PoisonCheckMem(size_t size) {
  int addrOffset = X86II::getMemoryOperandNo(CurrentMI->getDesc().TSFlags);
  // addrOffset is -1 if we failed to find the operand.
  assert(addrOffset >= 0 && "TASE: Unable to determine instruction memory operand!");
  addrOffset += X86II::getOperandBias(CurrentMI->getDesc());
  size_t real_size = size == 1 ? 2 : size;
  int acc_idx = Analysis.AllocateAccOffset(real_size);
  assert(acc_idx >= 0);
  unsigned int acc_reg = getX86SubSuperRegister(TASE_REG_ACC[acc_idx], real_size * 8);
  unsigned int tmp_reg = getX86SubSuperRegister(TASE_REG_TMP, real_size * 8);

  // Stash our poison - use the given memory operands as our source.
  // We may get the mem_operands incorrect.  I believe we need to clear the
  // MachineMemOperand::MOStore flag and set the MOLoad flag but we're late
  // in the compilation process and mem_operands is mostly a hint anyway.
  // It is always legal to have instructions with no mem_operands - the
  // rest of the compiler should just deal with it extremely conservatively
  // in terms of alignment and volatility.
  if (size == 16) {
    // TODO: Handle 16-byte SIMD case.
    /*
    UsageMask = 0;
    MachineInstrBuilder MIB = InsertInstr(X86::VPCMPEQDrm, TASE_REG_DATA);
    MIB.addReg(TASE_REG_REFERENCE);
    for (int i = 0; i < X86::AddrNumOperands; i++) {
      MIB.add(CurrentMI->getOperand(addrOffset + i));
    }
    MIB.cloneMemRefs(*CurrentMI);
    InsertInstr(X86::VPORrr, TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_DATA); */
  } else if (size == 1) {
    // Precalculate the address, align it to a two byte boundary and then
    // read two bytes to ensure a proper taint check.
    MachineInstrBuilder MIB = InsertInstr(X86::LEA64r, TASE_REG_TMP);
    for (int i = 0; i < X86::AddrNumOperands; i++) {
      MIB.add(CurrentMI->getOperand(addrOffset + i));
    }
    InsertInstr(X86::SHR64ri, TASE_REG_TMP)
      .addReg(TASE_REG_TMP)
      .addImm(1);
    InsertInstr(TASE_LOADrm[cLog2(2)], acc_reg)
      .addReg(acc_reg)
      .addReg(TASE_REG_TMP)     // base
      .addImm(1)                // scale
      .addReg(TASE_REG_TMP)     // index
      .addImm(0)                // offset
      .addReg(X86::NoRegister)  // segment
      .cloneMemRefs(*CurrentMI);
  } else if (size == 4) {
    // Cannot use a direct 32-bit XOR as that will zero out the top bits
    // of the 64-bit accumulator.  Instead, load it into a temporary and then
    // xor it into the accumulator.
    acc_reg = TASE_REG_ACC[acc_idx];
    MachineInstrBuilder MIB = InsertInstr(X86::MOV32rm, tmp_reg);
    for (int i = 0; i < X86::AddrNumOperands; i++) {
      MIB.add(CurrentMI->getOperand(addrOffset + i));
    }
    MIB.cloneMemRefs(*CurrentMI);
    InsertInstr(TASE_LOADrr[cLog2(8)], acc_reg)
      .addReg(acc_reg)
      .addReg(TASE_REG_TMP);
  } else {
    // size is 2 or 8
    MachineInstrBuilder MIB = InsertInstr(TASE_LOADrm[cLog2(real_size)], acc_reg)
      .addReg(acc_reg);
    for (int i = 0; i < X86::AddrNumOperands; i++) {
      MIB.add(CurrentMI->getOperand(addrOffset + i));
    }
    MIB.cloneMemRefs(*CurrentMI);
  }

  // Rotate the current accumulator to put more reference poison bytes at the
  // bottom.
  if (size < 8) {
    InsertInstr(X86::ROR64ri, TASE_REG_ACC[acc_idx])
      .addReg(TASE_REG_ACC[acc_idx])
      .addImm(real_size * 8);
  }
}

// Optimized fast-path case where we can simply check the value from a destination register.
void X86TASECaptureTaintPass::PoisonCheckReg(size_t size) {
  assert(size > 1 && "TASE: Cannot do a register-optimized poison check on byte value.");
  int acc_idx = Analysis.AllocateAccOffset(size);
  assert(acc_idx >= 0);
  unsigned int acc_reg = getX86SubSuperRegister(TASE_REG_ACC[acc_idx], size * 8);

  if (size == 16) {
    // TODO: Handle 16-byte SIMD case.
    /*
    UsageMask = 0;
    InsertInstr(X86::VPCMPEQDrr, TASE_REG_DATA, true)
      .add(CurrentMI->getOperand(0))
      .addReg(TASE_REG_REFERENCE);
    InsertInstr(X86::VPORrr, TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_DATA);
    */
  } else if (size == 4 && CurrentMI->getOpcode() != X86::MOV32rm) {
    unsigned int tmp_reg = getX86SubSuperRegister(TASE_REG_TMP, size * 8);
    acc_reg = TASE_REG_ACC[acc_idx];
    InsertInstr(X86::MOV32rr, tmp_reg, true)
      .addReg(getX86SubSuperRegister(CurrentMI->getOperand(0).getReg(), size * 8));
    InsertInstr(TASE_LOADrr[cLog2(8)], acc_reg, true)
      .addReg(acc_reg)
      .addReg(TASE_REG_TMP);
  } else {
    size_t real_size = size;
    if (size == 4) {
      // Exploit the fact that a zero extension is exactly what we need -
      // hence we can directly use the 8 byte version of the register instead
      // of 4.
      assert(CurrentMI->getOpcode() == X86::MOV32rm);
      real_size = 8;
      acc_reg = TASE_REG_ACC[acc_idx];
    }
    InsertInstr(TASE_LOADrr[cLog2(real_size)], acc_reg, true)
      .addReg(acc_reg)
      .addReg(getX86SubSuperRegister(CurrentMI->getOperand(0).getReg(), real_size * 8));
  }
  if (size < 8) {
    InsertInstr(X86::ROR64ri, TASE_REG_ACC[acc_idx], true)
      .addReg(TASE_REG_ACC[acc_idx])
      .addImm(size * 8);
  }
}

INITIALIZE_PASS(X86TASECaptureTaintPass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASECaptureTaint() {
  return new X86TASECaptureTaintPass();
}
