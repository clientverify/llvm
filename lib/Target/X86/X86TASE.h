#ifndef LLVM_LIB_TARGET_X86_X86_H
#define LLVM_LIB_TARGET_X86_X86_H
#endif

// DANGER WILL ROBINSON! C IN C++!
#include "tase/tase_interp.h"

namespace llvm {

// TASE constants!
// We can actually autogenerate this but I have these here to double check my understanding
// of tblgen. To productionize this, see include/llvm/MC/MCInstrDesc.h.  You can add another
// entry to enum Flag since isAllowedMemInstr is already part of Instruction in
// include/llvm/Target/Target.td, it can be packed into the Flags field in the output of
// tblgen and write an "isAllowedMemInstr" predicate in MCInstrDesc.h to mask and read
// the value.
//
// Only 64-bit values are considered here.
static constexpr unsigned int TASE_INSTRS[] = {
  X86::RETQ, X86::CALLpcrel16, X86::CALL64pcrel32, X86::CALL64r, X86::FARCALL64,
  // The 16 bit versions are only here for completeness. It's still possible to
  // encode sign-extending 16-bit pushes because you can still push fs/gs because
  // fuck us all that's why.
  X86::LEAVE64, X86::POP16r, X86::POP64r, X86::PUSH16r, X86::PUSH64r,
  X86::PUSH64i8, X86::PUSH64i32, X86::PUSH16i8, X86::PUSHi16,
  X86::PUSHF64, X86::POPF64,
  X86::MOV8rm, X86::MOV16rm, X86::MOV32rm, X86::MOV64rm, X86::MOV8rm_NOREX,
  X86::MOV8mr, X86::MOV16mr, X86::MOV32mr, X86::MOV64mr, X86::MOV8mr_NOREX,
  X86::MOV8mi, X86::MOV16mi, X86::MOV32mi, X86::MOV64mi32
};

/* Ordered by size. */
static constexpr unsigned int VPINSR[] = {
  X86::VPINSRBrr, X86::VPINSRWrr, X86::VPINSRDrr, X86::VPINSRQrr
};

static constexpr size_t Log2(size_t n) {
  //assert(n);
  return ((n < 2) ? 0 : 1 + Log2(n/2));
}

#define LLVM_XMM_EXPANDED(x, n) x ## n
#define LLVM_XMM(n)  LLVM_XMM_EXPANDED(X86::XMM, n)

static constexpr unsigned int TASE_REG_REFERENCE = LLVM_XMM(REG_REFERENCE);
static constexpr unsigned int TASE_REG_ACCUMULATOR = LLVM_XMM(REG_ACCUMULATOR);
static constexpr unsigned int TASE_REG_DATA = LLVM_XMM(REG_DATA);
static constexpr unsigned int TASE_REG_CARTRIDGE = LLVM_XMM(REG_CARTRIDGE);

}
