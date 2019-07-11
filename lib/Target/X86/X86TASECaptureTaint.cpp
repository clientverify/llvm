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
  void PoisonCheckReg(size_t size, unsigned int align = 0);
  void PoisonCheckStack(int64_t stackOffset);
  void PoisonCheckMem(size_t size);
  void PoisonCheckRegInternal(size_t size, unsigned int reg, unsigned int acc_idx);
  unsigned int AllocateOffset(size_t size);
  unsigned int getAddrReg(unsigned Op);
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

  assert(Analysis.getInstrumentationMode() == TIM_SIMD);

  Subtarget = &MF.getSubtarget<X86Subtarget>();
//   MRI = &MF.getRegInfo();
  TII = Subtarget->getInstrInfo();
//   TRI = Subtarget->getRegisterInfo();

  bool modified = false;
  for (MachineBasicBlock &MBB : MF) {
    LLVM_DEBUG(dbgs() << "TASE: Analyzing taint for block " << MBB);
    // Every cartridge entry sequence is going to flush the accumulators.
    Analysis.ResetDataOffsets();
    // In using this range, we use the super special property that a machine
    // instruction list obeys the iterator characteristics of list<
    // undocumented property that instr_iterator is not invalidated when
    // one inserts into the list.
    for (MachineInstr &MI : MBB.instrs()) {
      LLVM_DEBUG(dbgs() << "TASE: Analyzing taint for " << MI);
      if (Analysis.isSpecialInlineAsm(MI)) {
        continue;
      }
      if (MI.mayLoad() && MI.mayStore()) {
        errs() << "TASE: Somehow we have a CISC instruction! " << MI;
        llvm_unreachable("TASE: Please handle this instruction.");
      }
      // Only our RISC-like loads should have this set.
      if (!MI.mayLoad() && !MI.mayStore() && !MI.isCall() && !MI.isReturn() && !MI.hasUnmodeledSideEffects()) {
        // Non-memory instructions need no instrumentation.
        continue;
      }
      if (Analysis.isSafeInstr(MI.getOpcode())) {
        continue;
      }
      if (MI.hasUnmodeledSideEffects() && !Analysis.isMemInstr(MI.getOpcode())) {
        errs() << "TASE: An instruction with potentially unwanted side-effects is emitted. " << MI;
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
      PoisonCheckReg(size, 8);
      break;
    case X86::RETQ:
      // We should not have a symbolic return address but we treat this as a
      // standard pop of the stack just in case.
    case X86::POPF64:
      PoisonCheckStack(0);
      break;
    case X86::CALLpcrel16:
    case X86::CALL64pcrel32:
    case X86::CALL64r:
    case X86::CALL64r_NT:
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
    case X86::INSERTPSrm: case X86::VINSERTPSrm:
    case X86::PMOVSXBWrm: case X86::PMOVSXBDrm: case X86::PMOVSXBQrm:
    case X86::PMOVSXWDrm: case X86::PMOVSXWQrm: case X86::PMOVSXDQrm:
    case X86::PMOVZXBWrm: case X86::PMOVZXBDrm: case X86::PMOVZXBQrm:
    case X86::PMOVZXWDrm: case X86::PMOVZXWQrm: case X86::PMOVZXDQrm:
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

void X86TASECaptureTaintPass::PoisonCheckMem(size_t size) {
  InsertBefore = true;
  int addrOffset = X86II::getMemoryOperandNo(CurrentMI->getDesc().TSFlags);
  // addrOffset is -1 if we failed to find the operand.
  assert(addrOffset >= 0 && "TASE: Unable to determine instruction memory operand!");
  addrOffset += X86II::getOperandBias(CurrentMI->getDesc());

  SmallVector<MachineOperand,X86::AddrNumOperands> MOs;

  // Stash our poison - use the given memory operands as our source.
  // We may get the mem_operands incorrect.  I believe we need to clear the
  // MachineMemOperand::MOStore flag and set the MOLoad flag but we're late
  // in the compilation process and mem_operands is mostly a hint anyway.
  // It is always legal to have instructions with no mem_operands - the
  // rest of the compiler should just deal with it extremely conservatively
  // in terms of alignment and volatility.
  //
  // We can optimize the aligned case a bit but usually, we just assume an
  // unaligned memory operand and re-align it to a 2-byte boundary.
  if (size >= 16) {
    assert(size == 16 && "TASE: Unimplemented. Handle YMM/ZMM SIMD instructions properly.");
    // TODO: Assert that the compiler only emits aligned XMM reads.
    MOs.append(CurrentMI->operands_begin() + addrOffset, CurrentMI->operands_begin() + addrOffset + X86::AddrNumOperands);
  } else if (CurrentMI->hasOneMemOperand() && (*CurrentMI->memoperands_begin())->getAlignment() >= 2) {
    // We actually have operand alignment information and it is 2 byte aligned.
    // Hence we don't need to force-align the memory operand.
    LLVM_DEBUG(dbgs() << "TASE: Skipping poison alignment for instruction: " << *CurrentMI);
    // We can still have a byte value that's 2 byte aligned.
    if (size == 1) size = 2;
    MOs.append(CurrentMI->operands_begin() + addrOffset, CurrentMI->operands_begin() + addrOffset + X86::AddrNumOperands);
  } else {
    // Precalculate the address, align it to a two byte boundary and then
    // read double the size just to be safe.
    size *= 2;
    // If this address operand is just a register, we can skip the lea. But don't do this if
    // EFLAGS is dead and we want to not emit shrx.
    unsigned int AddrReg = getAddrReg(addrOffset);
    bool eflags_dead = TII->isSafeToClobberEFLAGS(*CurrentMI->getParent(), MachineBasicBlock::iterator(CurrentMI));
    if (AddrReg == X86::NoRegister || eflags_dead) {
      AddrReg = TASE_REG_TMP;
      MachineInstrBuilder MIB = InsertInstr(X86::LEA64r, TASE_REG_TMP);
      for (int i = 0; i < X86::AddrNumOperands; i++) {
        MIB.addAndUse(CurrentMI->getOperand(addrOffset + i));
      }
    }
    if (eflags_dead) {
      assert(AddrReg == TASE_REG_TMP);
      InsertInstr(X86::SHR64r1, TASE_REG_TMP)
        .addReg(TASE_REG_TMP);
    } else {
      // Use TASE_REG_RET as a temporary register to hold offsets/indices.
      InsertInstr(X86::MOV32ri, getX86SubSuperRegister(TASE_REG_RET, 4 * 8))
        .addImm(1);
      InsertInstr(X86::SHRX64rr, TASE_REG_TMP)
        .addReg(AddrReg)
        .addReg(TASE_REG_RET);
    }

    MOs.push_back(MachineOperand::CreateReg(TASE_REG_TMP, false));     // base
    MOs.push_back(MachineOperand::CreateImm(1));                       // scale
    MOs.push_back(MachineOperand::CreateReg(TASE_REG_TMP, false));     // index
    MOs.push_back(MachineOperand::CreateImm(0));                       // offset
    MOs.push_back(MachineOperand::CreateReg(X86::NoRegister, false));  // segment
  }

  unsigned int acc_idx = AllocateOffset(size);
  unsigned int op;
  if (size == 16) {
    assert(acc_idx == 0);
    // Agner Fog says MOVUPS/MOVDQU run at the same speed as MOVAPS/MOVDQA on
    // post Nahalem architectures. My assumption is that this carries over to VCMPEQW.
    // So we just assume reasonably aligned access and let the memory fabric/L1 cache
    // controller do its magic.
    op = X86::VPCMPEQWrm;
    MOs.insert(MOs.begin(), MachineOperand::CreateReg(TASE_REG_REFERENCE, false));
  // Can we use a short instruction while zeroing the register?
  } else if (acc_idx == 0 && size == 4) {
    op = X86::MOVSSrm;
  } else if (acc_idx == 0 && size == 8) {
    op = X86::MOVSDrm;
  } else if (acc_idx == 8 && size == 8) {
    op = X86::MOVHPSrm;
    MOs.insert(MOs.begin(), MachineOperand::CreateReg(TASE_REG_DATA, false));
  } else {
    op = TASE_PINSRrm[cLog2(size)];
    MOs.insert(MOs.begin(), MachineOperand::CreateReg(TASE_REG_DATA, false));
    MOs.push_back(MachineOperand::CreateImm(acc_idx / size));
  }
  MachineInstrBuilder MIB = InsertInstr(op, TASE_REG_DATA);
  for (unsigned int i = 0; i < MOs.size(); i++) {
    MIB.addAndUse(MOs[i]);
  }
  //MIB.cloneMemRefs(*CurrentMI);
  if (size == 16) {
    InsertInstr(X86::PORrr, TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_DATA);
    Analysis.ResetDataOffsets();
  }
}

// Optimized fast-path case where we can simply check the value from a destination register.
// Clobbers the bottom byte of the temporary register.
void X86TASECaptureTaintPass::PoisonCheckReg(size_t size, unsigned int align) {

  // TODO: Handle all stack accesses which we know are aligned.
  // Check if stack loads come with memoperand info.

  if (align == 0 && CurrentMI->hasOneMemOperand()) {
    align = (*CurrentMI->memoperands_begin())->getAlignment();
  }

  if (align >= 2) {
   InsertBefore = false;
   // Partial register transfers from XMM are slow - just check the entire thing at once.
   if (Analysis.isXmmDestInstr(CurrentMI->getOpcode())) size = 16;
   unsigned int acc_idx = AllocateOffset(size);
   PoisonCheckRegInternal(size, CurrentMI->getOperand(0).getReg(), acc_idx);
  } else {
    PoisonCheckMem(size);
  }
}

void X86TASECaptureTaintPass::PoisonCheckRegInternal(size_t size, unsigned int reg, unsigned int acc_idx) {
  assert(reg != X86::NoRegister);
  if (size >= 16) {
    assert(size == 16 && "TASE: Handle AVX instructions");
    InsertInstr(X86::VPCMPEQWrr, TASE_REG_DATA)
      .addReg(TASE_REG_REFERENCE)
      .addReg(reg);
    InsertInstr(X86::PORrr, TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_DATA);
    Analysis.ResetDataOffsets();
  } else {
    reg = getX86SubSuperRegister(reg, size * 8);
    // Can we use a short instruction while zeroing the register?
    if (acc_idx == 0 && size == 4) {
      InsertInstr(X86::MOVDI2PDIrr, TASE_REG_DATA).addReg(reg);
    } else if (acc_idx == 0 && size == 8) {
      // TODO: What's the canonical instruction LLVM uses?
      InsertInstr(X86::MOV64toPQIrr, TASE_REG_DATA).addReg(reg);
    } else {
      InsertInstr(TASE_PINSRrr[cLog2(size)], TASE_REG_DATA)
        .addReg(TASE_REG_DATA)
        .addReg(reg)
        .addImm(acc_idx / size);
    }
  }
}

unsigned int X86TASECaptureTaintPass::getAddrReg(unsigned Op) {
  auto Disp = CurrentMI->getOperand(Op + X86::AddrDisp);
  unsigned int AddrBase = CurrentMI->getOperand(Op + X86::AddrBaseReg).getReg();
  if (Disp.isImm() && Disp.getImm() == 0 &&
      CurrentMI->getOperand(Op + X86::AddrIndexReg).getReg() == X86::NoRegister &&
      CurrentMI->getOperand(Op + X86::AddrScaleAmt).getImm() == 1) {
    // Special case - check if we are reading address 0. Doesn't matter how we instrument this.
    if (AddrBase != X86::NoRegister) {
      return AddrBase;
    } else {
      LLVM_DEBUG(dbgs() << "TASE: Founds a zero address at instruction: " << *CurrentMI);
    }
  }
  return X86::NoRegister;
}

unsigned int X86TASECaptureTaintPass::AllocateOffset(size_t size) {
  int offset = Analysis.AllocateDataOffset(size);
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
  assert(offset >= 0 && "TASE: Unable to acquire a register for poison instrumentation.");
  return offset;
}

INITIALIZE_PASS(X86TASECaptureTaintPass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASECaptureTaint() {
  return new X86TASECaptureTaintPass();
}
