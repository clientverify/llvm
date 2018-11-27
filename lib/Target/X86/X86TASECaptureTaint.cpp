// Add TASE taint discovery instrumentation after every load or store
// instruction.


#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
// #include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
// #include "llvm/CodeGen/MachineRegisterInfo.h"
// #include "llvm/CodeGen/MachineSSAUpdater.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
// #include "llvm/CodeGen/TargetRegisterInfo.h"
// #include "llvm/CodeGen/TargetSchedule.h"
// #include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
// #include <iterator>
// #include <utility>

using namespace llvm;

#define PASS_KEY "x86-tase-capture-taint"
#define PASS_DESC "X86 TASE taint tracking instrumentation."
#define DEBUG_TYPE PASS_KEY


// STATISTIC(NumCondBranchesTraced, "Number of conditional branches traced");

std::string TaseModeledFunctionsFile;
static cl::opt<std::string, true> TaseModeledFunctionsFlag(
    "x86-tase-modeled-functions",
    cl::desc("File holding names of modeled functions that are to be interpreted."),
    cl::value_desc("filename"),
    cl::location(TaseModeledFunctionsFile),
    cl::ValueRequired);

namespace {

class X86TASECaptureTaintPass : public MachineFunctionPass {
public:
  X86TASECaptureTaintPass() : MachineFunctionPass(ID),
    TaseModeledFunctions(), UsageMask(0) {
    // Doing an old fasion loop just to make sure we don't trip up
    // the constexpr evaluator.
    for (int i = 0; i < sizeof(TASE_INSTRS)/sizeof(TASE_INTRS[0]); i++) {
      SortedMemInstrs[i] = TASE_INSTRS[i];
    }
    std::sort(std::begin(SortedMemInstrs), std::end(SortedMemInstrs));

    initializeX86TASECaptureTaintPassPass(
        *PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override {
    return PASS_DESC;
  }

  bool doInitialization(Module &M) override;

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

  // If we had C++17, there's constexpr way to sort TASE_INSTRS but for now, we
  // sort it anytime the pass is created.
  unsigned int SortedMemInstrs[sizeof(TASE_INSTRS)/sizeof(TASE_INSTRS[0])];
  std::vector<std::string> TaseModeledFunctions;
  // Every bit represents whether the corresponding word in XMM_DATA has been
  // used.
  uint8_t   UsageMask;

  void InstrumentInstruction(MachineInstr &MI);
  void PoisonCheckReg(MachineBasicBlock::instr_iterator MBBI,
      const MachineOperand &MO, size_t size);
  void PoisonCheckImm(MachineBasicBlock::instr_iterator MBBI,
      const MachineOperand &MO, size_t size);
  size_t getPoisonOperandSize(const MachineInstr &MI) const;
};

} // end anonymous namespace


char X86TASECaptureTaintPass::ID = 0;


bool X86TASECaptureTaintPass::doInitialization(Module &M) override {
  if (TaseModeledFunctionsFile.empty()) {
    report_fatal_error("TASE: Must provide path to a file listing modeled functions.");
    return false;
  }

  std::unique_ptr<MemoryBuffer> MB =
    std::move(MemoryBuffer::getFile(TaseModeledFunctionsFile).get());

  for(line_iterator I = line_iterator(*MB); !I.is_at_eof(); I++) {
    TaseModeledFunctions.push_back(I->str());
  }

  std::sort(TaseModeledFunctions.begin(), TaseModeledFunctions.end());
  TaseModeledFunctions.erase(
      std::unique(TaseModeledFunctions.begin(), TaseModeledFunctions.end()),
      TaseModeledFunctions.end());

  if (TaseModeledFunctions.empty()) {
    report_fatal_error("TASE: No modeled functions found in function file.");
  }
  return false;
}

bool X86TASECaptureTaintPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");

  if (std::binary_search(TaseModeledFunctions.begin(), TaseModeledFunctions.end(), MF->getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Function is modeled in the interpreter\n.");
    return false;
  }

  Subtarget = &MF.getSubtarget<X86Subtarget>();
//   MRI = &MF.getRegInfo();
  TII = Subtarget->getInstrInfo();
//   TRI = Subtarget->getRegisterInfo();

  for (MachineBasicBlock &MBB : MF) {
    // Every cartridge entry sequence is going to flush the data register.
    UsageMask = 0;
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
      assert(std::binary_search(std::begin(SortedMemInstrs), std::end(SortedMemInstrs),
            MI.getOpcode()) && "TASE: Encountered an instruction we haven't handled.");
      InstrumentInstruction(MI);
      // Calls begin a new cartridge.
      if (MI.isCall()) {
        UsageMask = 0;
      }
    }
  }
}

// Appends a poison check to load instructions and prepends a poison check to
// a store instructions. Expects to see only known instructions.
//
void X86TASECaptureTaintPass::InstrumentInstruction(MachineInstr &MI) {
  MachineBasicBlock::instr_iterator curMBBI(MI);
  MachineBasicBlock::instr_iterator nextMBBI(std::next(cur_MBBI));

  size_t size = getPoisonOperandSize(MI);

  // We don't need to bother with operand bias because we know these
  // instructions are moves and don't have tied operands.
  switch (MI.getOpcode()) {
    default:
      llvm_unreachable("TASE: Unknown instructions.");
    case X86::FARCALL64:
      MI.dump();
      llvm_unreachable("TASE: Who's jumping across segmented code?");
    case X86::RETQ:
      // We are never going to have a symbolic return address - we are either
      // returning to a known target, or somone earlier wrote a symbolic value
      // to the stack explicitly (in a buffer overflow attack kind of way)
      // in which case, we would have detected the poison at that point.
    case X86::CALLpcrel16:
    case X86::CALLpcrel32:
      // Fixed addresses cannot be symbolic.
      // A stack push is performed but if this was somehow symbolic, the call
      // would fail/abort.
      break;
    case X86::LEAVE64:
      PoisonCheckRegister(nextMBBI, MachineOperand::createReg(X86::RBP), size);
      break;
    case X86::PUSH64i8:
    case X86::PUSH64i32:
    case X86::PUSH16i8:
    case X86::PUSHi16:
      PoisonCheckImm(curMBBI, MI.getOperand(0), size);
      break;
    case X86::MOV8mi:
    case X86::MOV16mi:
    case X86::MOV32mi:
    case X86::MOV64mi:
      PoisonCheckImm(curMBBI, MI.getOperand(X86::AddrNumOperands), size);
    case X86::POP16r:
    case X86::POP64r:
    case X86::MOV8rm:
    case X86::MOV16rm:
    case X86::MOV32rm:
    case X86::MOV64rm:
    case X86::MOV8rm_NOREX:
      PoisonCheckRegister(nextMBBI, MI.getOperand(0), size);
      break;
    case X86::MOV8mr:
    case X86::MOV16mr:
    case X86::MOV32mr:
    case X86::MOV64mr:
    case X86::MOV8mr_NOREX:
      PoisonCheckRegister(curMBBI, MI.getOperand(X86::AddrNumOperands), size);
      break;
    case X86::PUSHF64:
      // Well that can't possibly be poison.
    case X86::POPF64:
      MI.dump();
      // We will need to beg the compiler for a free register or special case
      // this to make an aligned read of an entire xmm register.
      llvm_unreachable("TASE: Flag poison not considered yet.")
  }
}

bool X86TASECaptureTaintPass::PoisonCheckImm(
    MachineBasicBlock::instr_iterator MBBI, const MachineOperand &MO, size_t size) {
  assert(MO.isImm() && (MI.dump(); "TASE: Immediate expected."));
  assert(size && "TASE: Unknown operand size - why does it have an immediate?");
  assert(size <= sizeof(uint64_t) && "TASE: Cannot handle SIMD registers and values > 64-bits.");

  // Note that this will leave 1 byte values with 0xFF as the significant mask.
  // That's ok! One byte immediates can *never* match the poison.
  uint64_t significant = (1 << (8 * size)) - 1;
  // Should have 1 bits in places where the immediate disagrees with the reference.
  if (folded_diff)
    return false;

  // Just abort the entire thing! But wait! We might be a system function
  // running with instrumentation disabled? Huh...  well, just sabotage ourselves.
  BuildMI(*(MBBI->getParent()), MBBI, MBBI->getDebugLoc(), TII->get(X86::VPCMPEQDrr),
      TASE_REG_ACCMULATOR)
    .addReg(TASE_REG_ACCUMULATOR)
    .addReg(TASE_REG_ACCUMULATOR);
  UsageMask = 0;
  return true;
}

void X86TASECaptureTaintPass::PoisonCheckReg(
    MachineBasicBlock::instr_iterator MBBI, const MachineOperand &MO, size_t size) {
  assert(MO.isReg() && (MI.dump(); "TASE: Register expected."));
  assert(size && "TASE: Unknown register size - cannot check for poison.");
  assert(size > 1 && "TASE: Ooops...  why are we checking 1 byte values?");
  assert(size <= sizeof(uint64_t) && "TASE: Cannot handle SIMD registers and values > 64-bits.");

  // We want a word offset.
  // Examples:
  // If we are storing a 4 byte int...
  //    size = 4
  // => stride = 2
  // => mask = (1 << 2) - 1 = 3 = 0b11.
  // The above makes sense because the mask (0b11) indicates 2 words (2x2 byte values).
  // => offset in [0, 2, 4, 6]
  // => offset/stride in [0, 1, 2, 3]
  uint8_t stride = size / 2;
  uint8_t mask = (1 << stride) - 1;
  // The < 8  here is sizeof(xmm)/8/2.
  for (int offset = 0; offset < 8; offset += stride) {
    if (UsageMask & (mask << offset) == 0) {
      break;
    }
  }

  // Compare and reload.
  if (offset == 8) {
    // Compare in 2 byte chunks always.
    BuildMI(*(MBBI->getParent()), MBBI, MBBI->getDebugLoc(), TII->get(X86::VPCMPEQDrr),
        TASE_REG_DATA)
      .addReg(TASE_REG_DATA)
      .addReg(TASE_REG_REFERENCE);
    BuildMI(*(MBBI->getParent()), MBBI, MBBI->getDebugLoc(), TII->get(X86::VPORrr),
        TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_DATA);
    UsageMask = 0;
    offset = 0;
  }

  // Stash our poison.
  unsigned int reg = MO.getReg();
  BuildMI(*(MBBI->getParent()), MBBI, MBBI->getDebugLoc(), TII->get(VPINSR[Log2(size)]),
      TASE_REG_DATA)
    .addReg(TASE_REG_DATA)
    .addReg(reg)
    .addImm(offset/stride);
  UsageMask |= mask << offset;
}

size_t X86TASECaptureTaintPass::getPoisonOperandSize(const MachineInstr &MI) const {
  switch(MI.getOpCode()) {
    case X86::FARCALL64:
    case X86::RETQ:
    case X86::CALLpcrel16:
    case X86::CALLpcrel32:
    case X86::PUSHF64:
    case X86::POPF64:
      return 0;
    case X86::LEAVE64:
    case X86::MOV64mi:
    case X86::POP64r:
    case X86::MOV64rm:
    case X86::MOV64mr:
      return 8;
    case X86::PUSH64i32:
    case X86::MOV32mi:
    case X86::MOV32rm:
    case X86::MOV32mr:
      return 4;
    case X86::PUSHi16:
    case X86::POP16r:
    case X86::MOV16mi:
    case X86::MOV16rm:
    case X86::MOV16mr:
      return 2;
    case X86::PUSH64i8:
    case X86::PUSH16i8:
    case X86::MOV8mi:
    case X86::MOV8rm:
    case X86::MOV8rm_NOREX:
    case X86::MOV8mr:
    case X86::MOV8mr_NOREX:
      return 1;
    default:
      return 0;
  }
}

INITIALIZE_PASS(X86TASECaptureTaintPass, DEBUG_TYPE,
                      "X86 TASE basic block decorator", false, false)
INITIALIZE_PASS_END(X86TASECaptureTaintPass, DEBUG_TYPE,
                    "X86 TASE basic block decorator", false, false)

FunctionPass *llvm::createX86TASECaptureTaintPass() {
  return new X86TASECaptureTaintPass();
}
