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
    cl::init(false));

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
  bool SplitAfterNonTerminatorFlow(MachineBasicBlock &MBB);
  bool SplitBeforeIndirectFlow(MachineBasicBlock &MBB);
  MachineInstrBuilder InsertInstr(unsigned int, unsigned int, MachineInstr*);
  bool InsertCheckBeforeIndirectFlow(MachineBasicBlock &MBB); 
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

    //Insert instruction before indirect control flow
    //to test for taint
    if (TASEParanoidControlFlow) {
      for (MachineBasicBlock &MBB : MF) {
	modified |= InsertCheckBeforeIndirectFlow(MBB);
      }
    }
    
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

    //Difficult to split up paired jump statements at end of BB
    
    for (MachineBasicBlock &MBB : MF) {
      modified |= SplitAfterNonTerminatorFlow(MBB);
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

//This function adds an extra safety check for our poisoning scheme before any of our
//other passes run.  The idea is that it will help us ensure that any instructions that
//encounter poison data will eventually directly jump to the springboard before encountering
//indirect control flow that potentially computes an destination address using variables
//marred by the poison taint tag.

//Since we only emit a subset of x86, this extra check only needs to be inserted for
//rets.  If we add extra call or jump variants in the future that support "doubly indirect"
//addressing (ie jumps to the address pointed to by the instruction's register arg) we'll
//need to add an extra check on those args here, and a jump to the springboard later.
bool X86TASEDecorateCartridgePass::InsertCheckBeforeIndirectFlow(MachineBasicBlock &MBB) {

  MachineBasicBlock *pMBB = &MBB;
  bool modified = false;
  
  for (auto MII = pMBB->instr_begin(); MII != pMBB->instr_end(); MII++) {
    if (MII->isDebugInstr()) {
      continue;
    }
    switch (MII->getOpcode()) {
    case X86::CALL64r:
    case X86::CALL64r_NT:
      //Don't need insert an extra pre-check for indirect calls, but we do need to
      //go to the springboard before executing them.  The taint will be checked because
      //addr had to loaded via a preceeding instruction into the register.

      //If we decide to support doubly-indirect calls (i.e. calls that jump to the
      //addr located at the addr store in the register) we'll need to insert an extra check.
      break;
    case X86::RETQ:
      //Example of added code: 
      // mov    (%rsp),%r14
      //Because we're adding this early in our pass structure, the captureTaint pass
      //will instrument 
      InsertInstr(X86::MOV64rm, TASE_REG_TMP, &(*MII))
	.addReg(X86::RSP)         // base
	.addImm(1)                // scale
	.addReg(X86::NoRegister)  // index
	.addImm(0)      // offset
	.addReg(X86::NoRegister);  // segment
      
      modified = true;
      break;
    case X86::TAILJMPr64:
    case X86::TAILJMPr64_REX:
    case X86::JMP64r:
    case X86::JMP64r_NT:
      //As long as these instructions aren't doubly-indirect, we shouldn't need an
      //extra instrumentation instruction.  If we jump to the springboard before
      //executing the jmp, we'll catch poison that was recorded earlier when the
      //jump address was moved into the register.
      break;
    }
  }
  
  return modified;
  

}


//Split up paired control flow instructions into seperate cartridges
//ex.
/*
767f0c:       4c 8d 3d 07 00 00 00    lea    0x7(%rip),%r15        # 767f1a <rsa_pss_param_print+0x1aa>
767f13:       ff 24 25 58 ef 6a 01    jmpq   *0x16aef58
767f1a:       85 c0                   test   %eax,%eax
767f1c:       0f 8f c7 00 00 00       jg     767fe9 <rsa_pss_param_print+0x279>
767f22:       eb 3b                   jmp    767f5f <rsa_pss_param_print+0x1ef>
*/								  

bool X86TASEDecorateCartridgePass::SplitAfterNonTerminatorFlow(MachineBasicBlock &MBB) {
  bool hasSplit = false;
  int numTerms = 0;
  MachineBasicBlock *pMBB = &MBB; 
  for (auto MII = pMBB->instr_begin(); MII != pMBB->instr_end(); MII++) {
    if (MII->isTerminator())
      numTerms++;
  }

  if (numTerms >= 2) {
    printf("\n\n\n\n\n IMPORTANT:  MULTIPLE TERMINATORS (%d) \n\n\n\n\n", numTerms);
  }
  
  return hasSplit;
  /*
  MachineBasicBlock *pMBB = &MBB;

  auto rMII = MBB.instr_rbegin();
  rMII++;
  if (rMII != MBB.instr_rend()) {
    if (rMII->isBranch()) {
      
      SplitBefore(pMBB, MachineBasicBlock::iterator(rMII));
      hasSplit= true;
    }
  }
  return hasSplit;
  */
  /*
  
  for (auto MII = pMBB->instr_begin(); MII != pMBB->instr_end(); MII++) {
    //Skip debug instrs and the first instr in the MBB
    if (MII->isDebugInstr() && MII == pMBB->instr_begin()) {
      continue;
    }


    if (MII->isBranch() && prevMI->isBranch() ) {
      pMBB = SplitBefore(pMBB , MachineBasicBlock::iterator(MII));
      MII = pMBB->instr_begin();
      hasSplit = true;
    }
    prevMI++;
  }
  
  return hasSplit;
  */
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
      // Because MII will be incremented and therefore, we will always have
      // an instruction.
      LLVM_FALLTHROUGH;
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

  // Just iterate *all* registers to see what's live and what isn't.
  // See X86CallLowering.cpp and the CallingConv infrastruction and its *Handlers.
  // Not sure how to get all the top-level registers - we do our best for now.
  LLVM_DEBUG(dbgs() << "TASE: Computing liveness for " << *newMBB);
  for (unsigned Reg : X86::GR64_NOSPRegClass) {
    if (isLive(newMBB, Reg)) {
      newMBB->addLiveIn(Reg);
    }
  }
  for (unsigned Reg : X86::VR128RegClass) {
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

MachineInstrBuilder X86TASEDecorateCartridgePass::InsertInstr(unsigned int opcode, unsigned int destReg, MachineInstr * MI) {
  return BuildMI(*MI->getParent(),
		 MachineBasicBlock::instr_iterator(MI),
		 MI->getDebugLoc(), TII->get(opcode), destReg);
}


INITIALIZE_PASS(X86TASEDecorateCartridgePass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASEDecorateCartridge() {
  return new X86TASEDecorateCartridgePass();
}
