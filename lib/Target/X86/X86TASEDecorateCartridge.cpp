// Split up LLVM machine basic blocks at call sites in order to create
// TASE compatible cartridges.  Each TASE cartridge now automatically
// gets a MBB start label and address.
//
// We heavily lean on the code in Mips\MipsBranchExpansion.cpp to model
// our splitting gymnastics.

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
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include <algorithm>
#include <cassert>

using namespace llvm;

#define PASS_KEY "x86-tase-decorate-cartridge"
#define PASS_DESC "X86 MBB to TASE Cartridge conversion pass."
#define DEBUG_TYPE PASS_KEY

bool TASEParanoidControlFlow;
static cl::opt<bool, true> TASEParanoidControlFlowFlag(
    "x86-tase-paranoid-control-flow",
    cl::desc("Isolate indirect control flow transfers - rets and calls."),
    cl::location(TASEParanoidControlFlow),
    cl::init(true));

namespace llvm {

void initializeX86TASEDecorateCartridgePassPass(PassRegistry &);
}

namespace {

class X86TASEDecorateCartridgePass : public MachineFunctionPass {
public:
  X86TASEDecorateCartridgePass() : MachineFunctionPass(ID) {
    initializeX86TASEDecorateCartridgePassPass(
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
  const X86InstrInfo *TII;
  const X86RegisterInfo *TRI;
  TASEAnalysis Analysis;

  bool SplitAtCalls(MachineBasicBlock &MBB);
  bool SplitAtSpills(MachineBasicBlock &MBB);
  bool SplitBeforeIndirectFlow(MachineBasicBlock &MBB);
  MachineBasicBlock *SplitBefore(MachineBasicBlock *MBB, MachineBasicBlock::iterator MII);
  bool isLive(MachineBasicBlock *MBB, unsigned Reg);
};

} // end anonymous namespace


char X86TASEDecorateCartridgePass::ID = 0;

bool X86TASEDecorateCartridgePass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");

  if (Analysis.isModeledFunction(MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Function is modeled in the interpreter\n.");
    return false;
  }

  Subtarget = &MF.getSubtarget<X86Subtarget>();
  TII = Subtarget->getInstrInfo();
  TRI = Subtarget->getRegisterInfo();

  bool modified = false;

  if (Analysis.getInstrumentationMode() != TIM_NONE) {
    // Do reverse analysis to break blocks at call boundaries.
    for (MachineBasicBlock &MBB : MF) {
      modified |= SplitAtCalls(MBB);
    }

    if (Analysis.getInstrumentationMode() == TIM_GPR) {
      // Do forward analysis to break blocks when taint accumulator registers
      // need spilling.
      for (MachineBasicBlock &MBB : MF) {
        modified |= SplitAtSpills(MBB);
      }
    }

    if (TASEParanoidControlFlow) {
      for (MachineBasicBlock &MBB : MF) {
        modified |= SplitBeforeIndirectFlow(MBB);
      }
    }

    // Make the blocks monotonic again.
    MF.RenumberBlocks();
  }
  return modified;
}

bool X86TASEDecorateCartridgePass::SplitBeforeIndirectFlow(MachineBasicBlock &MBB) {
  bool hasSplit = false;
  bool hasInstr = false;

  MachineBasicBlock *pMBB = &MBB;

  for (auto MII = pMBB->instr_begin(); MII != pMBB->instr_end(); MII++) {
    if (MII->isDebugInstr()) {
      continue;
    }
    switch (MII->getOpcode()) {
    case X86::CALL64r:
    case X86::CALL64r_NT:
    case X86::RETQ:
    case X86::TAILJMPr64:
    case X86::TAILJMPr64_REX:
    case X86::JMP64r:
    case X86::JMP64r_NT:
      if (hasInstr) {
        pMBB = SplitBefore(pMBB, MachineBasicBlock::iterator(MII));
        MII = pMBB->instr_begin();
        hasSplit = true;
      }
    default:
      hasInstr = true;
    }
  }
  return hasSplit;
}


bool X86TASEDecorateCartridgePass::SplitAtCalls(MachineBasicBlock &MBB) {
  bool hasSplit = false;;
  bool hasInstr = false;

  // Do not cache MBB.rend - allow for reallocation.
  for (auto rMII = MBB.instr_rbegin(); rMII != MBB.instr_rend(); ++rMII) {
    if (rMII->isDebugInstr()) {
      // Doesn't count as an actual instruction - these are usually tagged
      // onto a block and they are sensitive to control flow but since we
      // don't change control flow in a real sense, we just let them "stick"
      // to the closest real instruction.
      continue;
    } else if (rMII->isCall()) {
      // We need to break this basic block up - create a new one underneath
      // it but only if it contains any instructions.
      if (hasInstr) {
        // Copy instructions after the call into newMBB and remove them from
        // MBB.
        auto MII = MachineBasicBlock::iterator(*rMII);
        assert(MII->isCall() && "TASE: Bizarre iterator behavior.");
        MII++;
        SplitBefore(&MBB, MII);
        hasSplit = true;
      } else {
        // Doesn't matter if we're in a termination sequence (I don't know
        // if a call instruction acting as a fallthrough counts as a
        // terminator).  There is no code below us in this BB. Just let
        // things be.
      }
      // A call is a real instruction...  so we have seen one.
      hasInstr = true;
    } else {
      // We don't currently know how to recalculate all the successors of a
      // basic block once it has entered its termination sequence.  We only
      // know how to split basic blocks before termination - i.e. the new
      // block inherits all of the current block's sucessors and the current
      // block just has the new block as a successor.
      // So if we see a non-call terminator after we have split an MBB... we
      // flip the table and just split.
      assert(!(rMII->isTerminator() && hasSplit) && "TASE: Encountered a call after a terminator instruction.");
      // Just another instruction..
      hasInstr = true;
    }
  }

  // Unoptimized code sometimes has empty blocks.
  // Just throw a NOP in there.
  if (!hasInstr) {
    LLVM_DEBUG(dbgs() << "TASE: Encountered an empty block.  Adding a NOOP to legalize it.");
    BuildMI(&MBB, DebugLoc(), TII->get(X86::NOOP));
    hasSplit = true;
  }
  return hasSplit;
}

bool X86TASEDecorateCartridgePass::SplitAtSpills(MachineBasicBlock &MBB) {
  bool hasSplit = false;
  MachineBasicBlock *CurrMBB = &MBB;

  Analysis.ResetAccOffsets();
  auto MII = CurrMBB->instr_begin();

  while(MII != CurrMBB->instr_end()) {
    unsigned int opcode = MII->getOpcode();
    if (Analysis.isMemInstr(opcode)) {
      size_t size = Analysis.getMemFootprint(opcode);
      assert(size > 0);
      size = (size == 1) ? 2 : size;
      int idx = Analysis.AllocateAccOffset(size);
      if (idx < 0) {
        // This instruction made the taint tracker run out of accumulator
        // registers. Copy it and everything after it into a new block.
        // TODO: Does this orphan debug instructions?  Explore if we have
        // bundles or implicitly attached debug instructions that need to be
        // copied over.
        CurrMBB = SplitBefore(CurrMBB, MachineBasicBlock::iterator(*MII));
        Analysis.ResetAccOffsets();
        MII = CurrMBB->instr_begin();
        hasSplit = true;
        // Rereun the accumulator analysis on the instruction in the new block.
        continue;
      }
    }
    ++MII;
  }

  return hasSplit;
}

MachineBasicBlock *X86TASEDecorateCartridgePass::SplitBefore(
    MachineBasicBlock *MBB, MachineBasicBlock::iterator MII) {
  // Make a new MBB that's parented to the same LLVM IR BB that our
  // current BB (possibly partially) implements.  Remember that BB -> MBB
  // is a one to many relation.
  MachineFunction *MF = MBB->getParent();
  MachineBasicBlock *newMBB = MF->CreateMachineBasicBlock(MBB->getBasicBlock());
  // No phi nodes at this point - so no need to update them.
  // Is there predecessor information?  Maybe that get's auto updated?
  // *fingers crossed*
  newMBB->transferSuccessors(MBB);
  MBB->addSuccessor(newMBB);
  // Insert the new MBB after us in the machine function MBB chain.
  // This will preserve locality and help renumber basic blocks correctly.
  MF->insert(std::next(MachineFunction::iterator(MBB)), newMBB);
  // Move all instructions starting at MII (including MII) until the end of
  // this MBB into the new MBB.
  newMBB->splice(newMBB->end(), MBB, MII, MBB->end());

  // TODO: There is probably a better function to compute this but we simply
  // manually walk through all the callee saved registers to check what's still
  // live after a call.
  // See X86CallLowering.cpp and the CallingConv infrastruction and its *Handlers.
  LLVM_DEBUG(dbgs() << "TASE: Computing liveness for " << *newMBB);
  for (const MCPhysReg *CSR = MF->getRegInfo().getCalleeSavedRegs();
       unsigned Reg = *CSR; ++CSR) {
    if (isLive(newMBB, Reg)) {
      LLVM_DEBUG(dbgs() << "  -> TASE: Register " << printReg(Reg) << " is live.\n");
      newMBB->addLiveIn(Reg);
    } else {
      LLVM_DEBUG(dbgs() << "  -> TASE: Register " << printReg(Reg) << " is dead.\n");
    }
  }
  // rax, rdx, xmm0 and xmm1 are caller saved but hold live return values if present.
  for (unsigned Reg : {X86::RAX, X86::RDX, X86::XMM0, X86::XMM1}) {
    if (isLive(newMBB, Reg)) {
      newMBB->addLiveIn(Reg);
    }
  }

  return newMBB;
}

bool X86TASEDecorateCartridgePass::isLive(MachineBasicBlock *MBB, unsigned Reg) {
  // We use fragments and fixes from commit 556673f9, 23c93c1752 and 7a455510
  // to accurately forward scan to detect the liveness of callee saved registers.
  MachineBasicBlock::const_iterator I = MBB->begin();
  for (; I != MBB->end(); ++I) {
    if (I->isDebugInstr()) continue;

    MachineOperandIteratorBase::PhysRegInfo Info = ConstMIOperands(*I).analyzePhysReg(Reg, TRI);
    // Register is live when we read it here.
    if (Info.Read) {
      return true;
    }
    // Register is dead if we can fully overwrite or clobber it here.
    else if (Info.FullyDefined || Info.Clobbered) {
      return false;
    }
  }
  // If we reached the end, it is safe to clobber Reg at the end of a block of
  // no successor has it live in.
  assert(I == MBB->end());
  for (MachineBasicBlock *S : MBB->successors()) {
    for (const MachineBasicBlock::RegisterMaskPair &LI : S->liveins()) {
      if (TRI->regsOverlap(LI.PhysReg, Reg))
        return true;
    }
  }
  return false;
}

INITIALIZE_PASS(X86TASEDecorateCartridgePass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASEDecorateCartridge() {
  return new X86TASEDecorateCartridgePass();
}
