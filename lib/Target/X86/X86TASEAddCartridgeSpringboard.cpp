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
  X86TASEAddCartridgeSpringboardPass() : MachineFunctionPass(ID) {
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
  const X86InstrInfo *TII;
  TASEAnalysis Analysis;

  void EmitSpringboard(TASECartridgeInfo &cInfo);
  MachineInstrBuilder InsertInstr(
      MachineInstr *MI, unsigned int opcode, unsigned int destReg = X86::NoRegister);
};

} // end anonymous namespace


char X86TASEAddCartridgeSpringboardPass::ID = 0;

MachineInstrBuilder X86TASEAddCartridgeSpringboardPass::InsertInstr(
    MachineInstr *MI, unsigned int opcode, unsigned int destReg) {
  if (destReg == X86::NoRegister) {
    return BuildMI(*MI->getParent(), MI, MI->getDebugLoc(), TII->get(opcode));
  } else {
    return BuildMI(*MI->getParent(), MI, MI->getDebugLoc(), TII->get(opcode), destReg);
  }
}

void X86TASEAddCartridgeSpringboardPass::EmitSpringboard(TASECartridgeInfo &cInfo) {
  // Use our precalculated cartridge boundaries to label the first instruction in each of them.
  // This will be run after all the decoration and cartridge discovery/coagulation code has already run.
  MCCartridgeRecord *cartridge = cInfo.Record;
  MachineBasicBlock *startMBB = cInfo.Blocks.front();
  MachineFunction &MF = *startMBB->getParent();
  MachineInstr *startMI = &startMBB->front();

  // Cartridge prologue.
  // Load the body address into GPR_RET.
  InsertInstr(startMI, X86::LEA64r, TASE_REG_RET)
    .addReg(X86::RIP)           // base - attempt to use the locality of cartridgeBody.
    .addImm(1)                  // scale
    .addReg(X86::NoRegister)    // index
    .addSym(cartridge->Body())  // offset
    .addReg(X86::NoRegister);   // segment
  if (cInfo.Record->Modeled) {
    // Direct jump to the provided label in an rip relative manner.
    InsertInstr(startMI, X86::TASE_JMP)
      .addExternalSymbol("sb_modeled");
  } else {
    // Indirectly jump to the springboard - this jumps to the 64-bit address stored at this label.
    InsertInstr(startMI, X86::TASE_JMP64m)
      .addReg(X86::NoRegister)                 // base
      .addImm(1)                               // scale
      .addReg(X86::NoRegister)                 // index
      .addExternalSymbol("tase_springboard")   // offset
      .addReg(X86::NoRegister);                // segment
  }

  startMI->setPreInstrSymbol(MF, cartridge->Body());

  // Tag the first instruction of our first block in our congealed cartridge.
  // startMBB->front is now distinct from startMI because we have shoved
  // instructions in front of it.
  startMBB->front().setPreInstrSymbol(MF, cartridge->Cartridge());
  // Tag past the last instruction of our last block in our congealed cartridge.
  cInfo.Blocks.back()->back().setPostInstrSymbol(MF, cartridge->End());
}


bool X86TASEAddCartridgeSpringboardPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");
  if (Analysis.getInstrumentationMode() == TIM_NONE) {
    return false;
  }
  TII = MF.getSubtarget<X86Subtarget>().getInstrInfo();
  auto cInfos = MF.getCartridgeInfos();

  if (Analysis.isModeledFunction(MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Adding prolog to modeled function\n.");
    assert(cInfos.size() == 1 && cInfos.front().Record->Modeled &&
        "TASE: Modeled function not marked as such.");
    assert(cInfos.front().Blocks.size() == 1 &&
        cInfos.front().Blocks.front() == &MF.front() &&
        "TASE: Nonsensical cartridge information for a modeled function.");
  }

  for (TASECartridgeInfo &cInfo : cInfos) {
    EmitSpringboard(cInfo);
  }

  return true;
}

INITIALIZE_PASS(X86TASEAddCartridgeSpringboardPass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASEAddCartridgeSpringboard() {
  return new X86TASEAddCartridgeSpringboardPass();
}
