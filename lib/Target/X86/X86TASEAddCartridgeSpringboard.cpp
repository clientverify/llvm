// Add TASE springboard prolog to each cartridge.
// Modeled functions get a special "always eject" header for the first cartridge
// with no other processing being performed.
// Regular instrumented functions have each of their cartridges instrumented.


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
#include "llvm/MC/MCContext.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include <algorithm>
#include <cassert>

using namespace llvm;

#define PASS_KEY "x86-tase-add-cartridge-springboard"
#define PASS_DESC "X86 TASE cartridge prolog addition pass."
#define DEBUG_TYPE PASS_KEY


namespace llvm {

void initializeX86TASEAddCartridgeSpringboardPassPass(PassRegistry &);
}

namespace {

class X86TASEAddCartridgeSpringboardPass : public MachineFunctionPass {
public:
  X86TASEAddCartridgeSpringboardPass() : MachineFunctionPass(ID),
    ModeledFunctions(getTASEModeledFunctions()) {
    initializeX86TASEAddCartridgeSpringboardPassPass(
        *PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override {
    return PASS_DESC;
  }

  // bool doInitialization(Module &M) override;

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

  const std::vector<std::string> &ModeledFunctions;

  MCCartridgeRecord *emitSpringboard(MachineFunction &MF, MachineBasicBlock::instr_iterator MBBIFirstInstr, MachineBasicBlock::instr_iterator MBBILastInstr);
};

} // end anonymous namespace


char X86TASEAddCartridgeSpringboardPass::ID = 0;


MCCartridgeRecord *X86TASEAddCartridgeSpringboardPass::emitSpringboard(MachineFunction &MF, MachineBasicBlock::instr_iterator MBBIFirstInstr, MachineBasicBlock::instr_iterator MBBILastInstr) {
  // We emit four labels per cartridge - the header, the cartridge descriptor, body and end.
  // The cartridge body contains all instruction starting from and including FirstInstr and ending at and including LastInstr.
  // This guarantees that every cartridge has at least one instruction in its body.
  // Remember that for modeled functions, this implies that the native implementation must be non-empty and have at least one instruction.
  MCCartridgeRecord *cartridge = MF.getContext().createCartridgeRecord();
  MBBIFirstInstr->setPreInstrSymbol(MF, cartridge->Body);
  MBBILastInstr->setPostInstrSymbol(MF, cartridge->End);

  // Load the cartridge record for this block but don't overwrite the status flags.
  BuildMI(*(MBBIFirstInstr->getParent()), MBBIFirstInstr, MBBIFirstInstr->getDebugLoc(), TII->get(X86::VPBLENDWrmi), TASE_REG_CARTRIDGE)
    .addReg(TASE_REG_CARTRIDGE)
    .addSym(cartridge->Record)
    .addImm((1 << (SB_FLAG_MODE_IDX / 2)) - 1)
    ->setPreInstrSymbol(MF, cartridge->Header);

  return cartridge;
}


bool X86TASEAddCartridgeSpringboardPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");
  Subtarget = &MF.getSubtarget<X86Subtarget>();
  TII = Subtarget->getInstrInfo();

  if (std::binary_search(ModeledFunctions.begin(), ModeledFunctions.end(), MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Adding prolog to modeled function\n.");

    MachineBasicBlock &MBB = MF.front();
    MachineBasicBlock::instr_iterator MBBI = MBB.instr_begin();
    emitSpringboard(MF, MBBI, MBBI);
    // Request ejection in the header by merging the flag bits.
    BuildMI(MBB, MBBI, MBBI->getDebugLoc(), TII->get(X86::VPANDrm), TASE_REG_CARTRIDGE)
      .addReg(TASE_REG_CARTRIDGE)
      .addExternalSymbol("modeled_function_mask");
  } else {
    for (MachineBasicBlock &MBB : MF) {
      MachineBasicBlock::instr_iterator MBBIStart = MBB.instr_begin();
      for (MachineInstr &MI : MBB) {
        // We consider call boundaries to be cartridge terminating instructions.
        // If we encounter one, close the current cartridge and reopen.
        if (MI.isCall()) {
          MachineBasicBlock::instr_iterator MBBIEnd(MI);
          emitSpringboard(MF, MBBIStart, MBBIEnd);
          MBBIStart = std::next(MBBIEnd);
        }
      }
      if (MBBIStart != MBB.instr_end()) {
        emitSpringboard(MF, MBBIStart, MachineBasicBlock::instr_iterator(MBB.back()));
      }
    }
  }

  return true;
}

INITIALIZE_PASS(X86TASEAddCartridgeSpringboardPass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASEAddCartridgeSpringboard() {
  return new X86TASEAddCartridgeSpringboardPass();
}
