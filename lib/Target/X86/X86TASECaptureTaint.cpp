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

template <typename... Ts>
constexpr auto array_of(Ts&&... vals) -> std::array<unsigned int, sizeof...(Ts)> {
  return {{ vals... }};
}

// TASE constants!
// We can actually autogenerate this but I have these here to double check my understanding
// of tblgen. To productionize this, see include/llvm/MC/MCInstrDesc.h.  You can add another
// entry to enum Flag since isAllowedMemInstr is already part of Instruction in
// include/llvm/Target/Target.td, it can be packed into the Flags field in the output of
// tblgen and write an "isAllowedMemInstr" predicate in MCInstrDesc.h to mask and read
// the value.
//
// Only 64-bit values are considered here.
// In C++17, we could have directly sorted this array...  no such luck here.
constexpr auto MEM_INSTRS = array_of(
  X86::RETQ, X86::CALLpcrel16, X86::CALL64pcrel32, X86::CALL64r, X86::FARCALL64,
  X86::POP64r, X86::PUSH64r, X86::PUSH64i8, X86::PUSH64i32,
  X86::PUSHF64, X86::POPF64,
  X86::MOV8rm, X86::MOV16rm, X86::MOV32rm, X86::MOV64rm, X86::MOV8rm_NOREX,
  X86::MOV8mr, X86::MOV16mr, X86::MOV32mr, X86::MOV64mr, X86::MOV8mr_NOREX,
  X86::MOV8mi, X86::MOV16mi, X86::MOV32mi, X86::MOV64mi32,
  X86::MOVZX16rm8, X86::MOVZX32rm8, X86::MOVZX32rm8_NOREX, X86::MOVZX32rm16,
  X86::MOVZX64rm8, X86::MOVZX64rm16,
  X86::MOVSX16rm8, X86::MOVSX32rm8, X86::MOVSX32rm8_NOREX, X86::MOVSX32rm16,
  X86::MOVSX64rm8, X86::MOVSX64rm16, X86::MOVSX64rm32
  );

// Use C++11 trickery to extract the size of the array above at compile time.
using meminstrs_t = std::array<unsigned int, MEM_INSTRS.size()>;

const meminstrs_t &getSortedMemInstrs() {
  static meminstrs_t instrs = MEM_INSTRS;
  static bool first = true;
  if (first) {
    std::sort(instrs.begin(), instrs.end());
  }
  return instrs;
}


class X86TASECaptureTaintPass : public MachineFunctionPass {
public:
  X86TASECaptureTaintPass() : MachineFunctionPass(ID),
    CurrentMI(nullptr),
    ModeledFunctions(getTASEModeledFunctions()),
    SortedMemInstrs(getSortedMemInstrs()),
    UsageMask(0) {
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

  const std::vector<std::string> &ModeledFunctions;
  // A list of every TASE instruction that can potentially read or write
  // tainted values to or from memory.
  const meminstrs_t &SortedMemInstrs;
  // Every bit represents whether the corresponding word in XMM_DATA has been
  // used.
  uint8_t UsageMask;

  void InstrumentInstruction(MachineInstr &MI);
  MachineInstrBuilder InsertInstr(unsigned int opcode, unsigned int destReg);
  uint8_t AllocateOffset(size_t size);
  void PoisonCheckReg(size_t size);
  void PoisonCheckStack(int64_t stackOffset);
  void PoisonCheckMem(size_t size);
};

} // end anonymous namespace


char X86TASECaptureTaintPass::ID = 0;

bool X86TASECaptureTaintPass::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << " **********\n");

  if (std::binary_search(ModeledFunctions.begin(), ModeledFunctions.end(), MF.getName())) {
    LLVM_DEBUG(dbgs() << "TASE: Function is modeled in the interpreter\n.");
    return false;
  }

  Subtarget = &MF.getSubtarget<X86Subtarget>();
//   MRI = &MF.getRegInfo();
  TII = Subtarget->getInstrInfo();
//   TRI = Subtarget->getRegisterInfo();

  bool modified = false;
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
      assert(std::binary_search(SortedMemInstrs.begin(), SortedMemInstrs.end(),
            MI.getOpcode()) && "TASE: Encountered an instruction we haven't handled.");
      InstrumentInstruction(MI);
      modified = true;
      // Calls begin a new cartridge.
      // TODO: When cartridge identification is performed, use the pseudoinstruction
      // for that to identify cartridge boundaries.
      if (MI.isCall()) {
        UsageMask = 0;
      }
    }
  }
  return modified;
}

// Appends a poison check to load instructions and prepends a poison check to
// a store instructions. Expects to see only known instructions.
//
void X86TASECaptureTaintPass::InstrumentInstruction(MachineInstr &MI) {
  CurrentMI = &MI;
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
      PoisonCheckReg(8);
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
      // A stack push is performed and since we don't sweep old poison
      // indicators and (now-stale) marked symbolic values from the stack when
      // returning, we check to see if we are pushing into a "symbolic" stack
      // cell.
    case X86::PUSH64i8:
    case X86::PUSH64i32:
    case X86::PUSH64r:
    case X86::PUSHF64:
      // Values are zero-extended during the push - so check the entire stack
      // slot for poison before the write.
      PoisonCheckStack(-8);
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
      PoisonCheckMem(1);
      break;
    case X86::MOV16mi:
    case X86::MOV16mr:
      PoisonCheckMem(2);
      break;
    case X86::MOV16rm:
    case X86::MOVZX32rm16:
    case X86::MOVZX64rm16:
    case X86::MOVSX32rm16:
    case X86::MOVSX64rm16:
      PoisonCheckReg(2);
      break;
    case X86::MOV32mi:
    case X86::MOV32mr:
      PoisonCheckMem(4);
      break;
    case X86::MOV32rm:
    case X86::MOVSX64rm32:
      PoisonCheckReg(4);
      break;
    case X86::MOV64mi32:
    case X86::MOV64mr:
      PoisonCheckMem(8);
      break;
    case X86::MOV64rm:
      PoisonCheckReg(8);
      break;
  }
  CurrentMI = nullptr;
}

MachineInstrBuilder X86TASECaptureTaintPass::InsertInstr(unsigned int opcode, unsigned int destReg) {
  assert(CurrentMI && "TASE: Must only be called in the context of of instrumenting an instruction.");
  return BuildMI(*CurrentMI->getParent(), CurrentMI, CurrentMI->getDebugLoc(),
      TII->get(opcode), destReg);
}

uint8_t X86TASECaptureTaintPass::AllocateOffset(size_t size) {
  assert(size && "TASE: Unknown operand size - cannot check for poison.");
  assert(size <= 16 && "TASE: Cannot handle values > 128-bits.");

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
  uint8_t offset = 0;
  // The < 8  here is sizeof(xmm)/2.
  for (; offset < XMMREG_SIZE / 2; offset += stride) {
    if ((UsageMask & (mask << offset)) == 0) {
      break;
    }
  }

  // Compare and reload.
  if (offset == 8) {
    // Compare in 2 byte chunks always.
    InsertInstr(X86::VPCMPEQDrr, TASE_REG_DATA)
      .addReg(TASE_REG_DATA)
      .addReg(TASE_REG_REFERENCE);
    InsertInstr(X86::VPORrr, TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_DATA);
    UsageMask = 0;
    offset = 0;
  }

  // Mark the new words as being used.
  UsageMask |= mask << offset;
  return offset;
}

void X86TASECaptureTaintPass::PoisonCheckStack(int64_t stackOffset) {
  const size_t stackAlignment = 8;
  assert(stackOffset % stackAlignment == 0 && "TASE: Unaligned offset into the stack - must be multiple of 8");

  uint8_t offset = AllocateOffset(stackAlignment);
  InsertInstr(VPINSRrm[Log2(stackAlignment)], TASE_REG_DATA)
    .addReg(TASE_REG_DATA)
    .addReg(X86::RSP)         // base
    .addImm(1)                // scale
    .addReg(X86::NoRegister)  // index
    .addImm(stackOffset)           // offset
    .addReg(X86::NoRegister)  // segment
    .addImm(2 * offset / stackAlignment);
  // TODO: Check if we need MIB.cloneMemRefs or MIB.addMemRefs.
}

void X86TASECaptureTaintPass::PoisonCheckMem(size_t size) {
  // assert(size > 1 && "TASE: Ooops...  why are we checking 1 byte values?");
  if (size == 1) {
    // We can't handle byte values right now.
    return;
  }
  uint8_t offset = AllocateOffset(size);

  int addrOffset = X86II::getMemoryOperandNo(CurrentMI->getDesc().TSFlags);
  assert(addrOffset && "TASE: Unable to determine instruction memory operand!");
  addrOffset += X86II::getOperandBias(CurrentMI->getDesc());

  // Stash our poison - use the given memory operands as our source.
  if (size == 16) {
    // We are guaranteed to have cleared the data register.  Directly compare into it.
    UsageMask = 0;
    MachineInstrBuilder MIB = InsertInstr(X86::VPCMPEQDrm, TASE_REG_DATA);
    MIB.addReg(TASE_REG_REFERENCE);
    for (int i = 0; i < X86::AddrNumOperands; i++) {
      MIB.add(CurrentMI->getOperand(addrOffset + i));
    }
    InsertInstr(X86::VPORrr, TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_DATA);
  } else {
    MachineInstrBuilder MIB = InsertInstr(VPINSRrm[Log2(size)], TASE_REG_DATA);
    MIB.addReg(TASE_REG_DATA);
    for (int i = 0; i < X86::AddrNumOperands; i++) {
      MIB.add(CurrentMI->getOperand(addrOffset + i));
    }
    MIB.addImm(2 * offset / size);
    // TODO: Check if we need MIB.cloneMemRefs or MIB.addMemRefs.
  }
}

// Optimized fast-path case where we can simply check the value from a destination register.
void X86TASECaptureTaintPass::PoisonCheckReg(size_t size) {
  assert(size > 1 && "TASE: Cannot do a register-optimized poison check on byte value.");
  uint8_t offset = AllocateOffset(size);

  if (size == 16) {
    UsageMask = 0;
    InsertInstr(X86::VPCMPEQDrr, TASE_REG_DATA)
      .add(CurrentMI->getOperand(0))
      .addReg(TASE_REG_REFERENCE);
    InsertInstr(X86::VPORrr, TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_ACCUMULATOR)
      .addReg(TASE_REG_DATA);
  } else {
    InsertInstr(VPINSRrr[Log2(size)], TASE_REG_DATA)
      .addReg(TASE_REG_DATA)
      .addReg(getX86SubSuperRegister(CurrentMI->getOperand(0).getReg(), size * 8))
      .addImm(2 * offset / size);
  }
}

INITIALIZE_PASS(X86TASECaptureTaintPass, PASS_KEY, PASS_DESC, false, false)

FunctionPass *llvm::createX86TASECaptureTaint() {
  return new X86TASECaptureTaintPass();
}
