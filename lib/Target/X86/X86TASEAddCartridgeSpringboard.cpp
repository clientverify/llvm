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
#include "llvm/MC/MCCartridgeRecord.h"
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
  const X86InstrInfo *TII;

  const std::vector<std::string> &ModeledFunctions;

  MCCartridgeRecord *EmitSpringboard(MachineInstr &firstMI);
};

} // end anonymous namespace


char X86TASEAddCartridgeSpringboardPass::ID = 0;


MCCartridgeRecord *X86TASEAddCartridgeSpringboardPass::EmitSpringboard(MachineInstr &firstMI) {
  // We run after cartridge splitting - this guarantees that each machine block
  // has at least one instruction.  It also guarantees that every basic block
  // is a cartridge.  So just add the BB to our record along with a label
  // attached to the first instruction in the block.
  MachineBasicBlock *MBB = firstMI.getParent();
  MachineFunction *MF = MBB->getParent();
  MCCartridgeRecord *cartridge = MF->getContext().createCartridgeRecord(MBB->getSymbol());

  // TODO: Only emit the rax save-restore sequence if rax is live-in.
  // Also....  who the heck comes up with these names?  VMOV64toPQIrr is just VMOVQ.
  // TODO: If there are unused registers as determined by liveness analysis, move
  // rax to that instead.  GPR renaming is much faster than loading into XMM regs.
  //BuildMI(*MBB, firstMI, firstMI.getDebugLoc(), TII->get(X86::VMOV64toPQIrr), TASE_REG_CONTEXT)
  //  .addReg(X86::RAX);
  BuildMI(*MBB, firstMI, firstMI.getDebugLoc(), TII->get(X86::VPINSRQrr), TASE_REG_CONTEXT)
    .addReg(TASE_REG_CONTEXT)
    .addReg(X86::RAX)
    .addImm(0);
  // Load the body address into rax.
  BuildMI(*MBB, firstMI, firstMI.getDebugLoc(), TII->get(X86::LEA64r), X86::RAX)
    .addReg(X86::RIP)           // base
    .addImm(0)                  // scale
    .addReg(X86::NoRegister)    // index
    .addSym(cartridge->Body())  // offset
    .addReg(X86::NoRegister);   // segment
  BuildMI(*MBB, firstMI, firstMI.getDebugLoc(), TII->get(X86::JMP_1))
    .addExternalSymbol("sb_reopen"); // JMP_1 encodes relative to RIP.

  // If we add an rax recovery instruction, it becomes part of the cartridge body.
  MachineInstr *cartridgeBodyPDMI = &firstMI;
  cartridgeBodyPDMI =
    BuildMI(*MBB, cartridgeBodyPDMI, cartridgeBodyPDMI->getDebugLoc(), TII->get(X86::VPEXTRQrr))
    .addReg(X86::RAX)
    .addReg(TASE_REG_CONTEXT)
    .addImm(0);

  // DEBUG: Assert that we are in an RTM transaction to check springboard behavior.
  MachineInstr *cartridgeBodyMI =
    BuildMI(*MBB, cartridgeBodyPDMI, cartridgeBodyPDMI->getDebugLoc(), TII->get(X86::XTEST));
  BuildMI(*MBB, cartridgeBodyPDMI, cartridgeBodyPDMI->getDebugLoc(), TII->get(X86::JE_1))
    .addSym(cartridge->BodyPostDebug());
  BuildMI(*MBB, cartridgeBodyPDMI, cartridgeBodyPDMI->getDebugLoc(), TII->get(X86::MOV64rm))
    .addReg(X86::RAX)
    .addReg(X86::NoRegister)  // base
    .addImm(0)                // scale
    .addReg(X86::NoRegister)  // index
    .addImm(0)                // offset
    .addReg(X86::NoRegister); // segment

  cartridgeBodyMI->setPreInstrSymbol(*MF, cartridge->Body());
  cartridgeBodyPDMI->setPreInstrSymbol(*MF, cartridge->BodyPostDebug());

  MBB->back().setPostInstrSymbol(*MF, cartridge->End());
  return cartridge;
}


bool X86TASEAddCartridgeSpringboardPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");
  Subtarget = &MF.getSubtarget<X86Subtarget>();
  TII = Subtarget->getInstrInfo();

  if (std::binary_search(ModeledFunctions.begin(), ModeledFunctions.end(), MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Adding prolog to modeled function\n.");
    // Request ejection in the header by merging that flag bit.
    MachineInstr &firstMI = MF.front().front();
    BuildMI(MF.front(), firstMI, firstMI.getDebugLoc(), TII->get(X86::XOR64rr), X86::RAX)
      .addReg(X86::RAX)
      .addReg(X86::RAX);
    BuildMI(MF.front(), firstMI, firstMI.getDebugLoc(), TII->get(X86::VPINSRBrr), TASE_REG_STATUS)
      .addReg(TASE_REG_STATUS)
      .addReg(X86::EAX)
      .addImm(SB_FLAG_TRAN_OUT);
    auto cartridge = EmitSpringboard(firstMI);
    MF.front().front().setPreInstrSymbol(MF, cartridge->Cartridge());
  } else {
    for (MachineBasicBlock &MBB : MF) {
      auto cartridge = EmitSpringboard(MBB.front());
      MBB.front().setPreInstrSymbol(MF, cartridge->Cartridge());
    }
  }

  return true;
}

INITIALIZE_PASS(X86TASEAddCartridgeSpringboardPass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASEAddCartridgeSpringboard() {
  return new X86TASEAddCartridgeSpringboardPass();
}
