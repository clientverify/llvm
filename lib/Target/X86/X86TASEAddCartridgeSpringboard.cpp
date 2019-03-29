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
    FirstMI(nullptr) {
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
  MachineInstr *FirstMI;

  TASEAnalysis Analysis;

  MCCartridgeRecord *EmitSpringboard();
  MachineInstrBuilder InsertInstr(
      unsigned int opcode, unsigned int destReg = X86::NoRegister, MachineInstr *MI = nullptr);
};

} // end anonymous namespace


char X86TASEAddCartridgeSpringboardPass::ID = 0;

MachineInstrBuilder X86TASEAddCartridgeSpringboardPass::InsertInstr(
    unsigned int opcode, unsigned int destReg, MachineInstr *MI) {
  if (MI == nullptr) {
    MI = FirstMI;
  }
  assert(MI && "TASE: Unable to determine the instruction insertion location.");
  if (destReg == X86::NoRegister) {
    return BuildMI(*MI->getParent(), MI, MI->getDebugLoc(), TII->get(opcode));
  } else {
    return BuildMI(*MI->getParent(), MI, MI->getDebugLoc(), TII->get(opcode), destReg);
  }
}

MCCartridgeRecord *X86TASEAddCartridgeSpringboardPass::EmitSpringboard() {
  // We run after cartridge splitting - this guarantees that each machine block
  // has at least one instruction.  It also guarantees that every basic block
  // is a cartridge.  So just add the BB to our record along with a label
  // attached to the first instruction in the block.
  MachineBasicBlock *MBB = FirstMI->getParent();
  MachineFunction *MF = MBB->getParent();
  MCCartridgeRecord *cartridge = MF->getContext().createCartridgeRecord(MBB->getSymbol());

  // Load the body address into GPR_RET.
  InsertInstr(X86::LEA64r, TASE_REG_RET)
    .addReg(X86::RIP)           // base - attempt to use the locality of cartridgeBody.
    .addImm(0)                  // scale
    .addReg(X86::NoRegister)    // index
    .addSym(cartridge->Body())  // offset
    .addReg(X86::NoRegister);   // segment
  // Indirectly jump to the springboard.
  InsertInstr(X86::JMP64m)
    .addReg(X86::RIP)           // base - TODO: double check the encoded lengths here.
    //.addReg(X86::NoRegister)  // base
    .addImm(0)                  // scale
    .addReg(X86::NoRegister)    // index
    .addExternalSymbol("tase_springboard") // offset
    .addReg(X86::NoRegister);   // segment

  //MachineInstr *cartridgeBodyPDMI = &firstMI;
  // DEBUG: Assert that we are in an RTM transaction to check springboard behavior.
  //MachineInstr *cartridgeBodyMI =
  //  BuildMI(*MBB, cartridgeBodyPDMI, cartridgeBodyPDMI->getDebugLoc(), TII->get(X86::XTEST));
  //BuildMI(*MBB, cartridgeBodyPDMI, cartridgeBodyPDMI->getDebugLoc(), TII->get(X86::JE_1))
  //  .addSym(cartridge->BodyPostDebug());
  //BuildMI(*MBB, cartridgeBodyPDMI, cartridgeBodyPDMI->getDebugLoc(), TII->get(X86::MOV64rm))
  //  .addReg(X86::RAX)
  //  .addReg(X86::NoRegister)  // base
  //  .addImm(0)                // scale
  //  .addReg(X86::NoRegister)  // index
  //  .addImm(0)                // offset
  //  .addReg(X86::NoRegister); // segment

  FirstMI->setPreInstrSymbol(*MF, cartridge->Body());
  //cartridgeBodyPDMI->setPreInstrSymbol(*MF, cartridge->BodyPostDebug());

  MBB->front().setPreInstrSymbol(*MF, cartridge->Cartridge());
  MBB->back().setPostInstrSymbol(*MF, cartridge->End());
  return cartridge;
}


bool X86TASEAddCartridgeSpringboardPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");
  if (Analysis.getInstrumentationMode() == TIM_NONE) {
    return false;
  }

  Subtarget = &MF.getSubtarget<X86Subtarget>();
  TII = Subtarget->getInstrInfo();

  if (Analysis.isModeledFunction(MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Adding prolog to modeled function\n.");
    // To make our debug scenarios work well, we jump to sb_modeled (a helper)
    // only if springboard is not disabled.  We assume TASE_REG_RET is already
    // valid and pointing to the cartridge body.
    //
    // Note: testing for sb_reopen should be conceptually considered as equal
    // to an xtest.
    FirstMI = &MF.front().front();
    // Exploit the fact that we are using a small code model and implicit
    // zero extension to shorten our instructions.
    InsertInstr(X86::CMP32mi)
      //.addReg(X86::NoRegister)    // base
      .addReg(X86::RIP)           // base
      .addImm(0)                  // scale
      .addReg(X86::NoRegister)    // index
      .addExternalSymbol("tase_springboard") // offset
      .addReg(X86::NoRegister)    // segment
      .addExternalSymbol("sb_disabled");
    InsertInstr(X86::JNE_1)
      .addExternalSymbol("sb_modeled");
    FirstMI = &MF.front().front();
    EmitSpringboard();
  } else {
    for (MachineBasicBlock &MBB : MF) {
      FirstMI = &MBB.front();
      EmitSpringboard();
    }
  }
  FirstMI = nullptr;

  return true;
}

INITIALIZE_PASS(X86TASEAddCartridgeSpringboardPass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASEAddCartridgeSpringboard() {
  return new X86TASEAddCartridgeSpringboardPass();
}
