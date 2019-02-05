// Split up LLVM machine basic blocks at call sites in order to create
// TASE compatible cartridges.  Each TASE cartridge now automatically
// gets a MBB start label and address.
//
// We heavily lean on the code in Mips\MipsBranchExpansion.cpp to model
// our splitting gymnastics.
//
// TODO: Investigate if marking call the CALL variants in X86InstrControl.td
// as isTerminator=1 is sufficient to force the scheduler to do this break-up
// pass automatically.

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

#define PASS_KEY "x86-tase-decorate-cartridge"
#define PASS_DESC "X86 MBB to TASE Cartridge conversion pass."
#define DEBUG_TYPE PASS_KEY


namespace llvm {

void initializeX86TASEDecorateCartridgePassPass(PassRegistry &);
}

namespace {

class X86TASEDecorateCartridgePass : public MachineFunctionPass {
public:
  X86TASEDecorateCartridgePass() : MachineFunctionPass(ID),
    ModeledFunctions(getTASEModeledFunctions()) {
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
  const std::vector<std::string> &ModeledFunctions;

  bool SplitToCartridges(MachineBasicBlock &MBB);

};

} // end anonymous namespace


char X86TASEDecorateCartridgePass::ID = 0;

bool X86TASEDecorateCartridgePass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");

  if (std::binary_search(ModeledFunctions.begin(), ModeledFunctions.end(), MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Function is modeled in the interpreter\n.");
    return false;
  }

  Subtarget = &MF.getSubtarget<X86Subtarget>();
  TII = Subtarget->getInstrInfo();

  bool modified = false;
  for (MachineBasicBlock &MBB : MF) {
    modified |= SplitToCartridges(MBB);
  }
  // Make the blocks monotonic again.
  MF.RenumberBlocks();
  return modified;
}

bool X86TASEDecorateCartridgePass::SplitToCartridges(MachineBasicBlock &MBB) {
  bool hasSplit = false;;
  bool hasInstr = false;

  auto rEnd = MBB.rend();
  for (auto rMI = MBB.rbegin(); rMI != rEnd; ++rMI) {
    if (rMI->isDebugInstr()) {
      // Doesn't count as an actual instruction - these are usually tagged
      // onto a block and they are sensitive to control flow but since we
      // don't change control flow in a real sense, we just let them "stick"
      // to the closest real instruction.
      continue;
    } else if (rMI->isCall()) {
      // We need to break this basic block up - create a new one underneath
      // it but only if it contains any instructions.
      if (hasInstr) {
        // Make a new MBB that's parented to the same LLVM IR BB that our
        // current BB (possibly partially) implements.  Remember that BB -> MBB
        // is a one to many relation.
        MachineFunction *MF = MBB.getParent();
        MachineBasicBlock *newMBB = MF->CreateMachineBasicBlock(MBB.getBasicBlock());
        // No phi nodes at this point - so no need to update them.
        // Is there predecessor information?  Maybe that get's auto updated?
        // *fingers crossed*
        newMBB->transferSuccessors(&MBB);
        MBB.addSuccessor(newMBB);
        // Insert the new MBB after us in the machine function MBB chain.
        // This will preserve locality and help renumber basic blocks correctly.
        MF->insert(std::next(MachineFunction::iterator(MBB)), newMBB);
        // Copy instructions after the call into newMBB and remove them from
        // MBB.
        newMBB->splice(newMBB->end(), &MBB, rMI.getReverse(), MBB.end());
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
      assert(!(rMI->isTerminator() && hasSplit) && "TASE: Encountered a call after a terminator instruction.");
      // Just another instruction..
      hasInstr = true;
    }
  }

  assert(hasInstr && "TASE: Encountered an empty block!");
  return hasSplit;
}

INITIALIZE_PASS(X86TASEDecorateCartridgePass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASEDecorateCartridge() {
  return new X86TASEDecorateCartridgePass();
}
