#ifndef LLVM_LIB_TARGET_X86_X86TASE_H
#define LLVM_LIB_TARGET_X86_X86TASE_H

// DANGER WILL ROBINSON! C IN C++!
#include "tase/tase_interp.h"

#include "X86.h"
#include "X86InstrInfo.h"

namespace llvm {

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

extern const std::vector<std::string> &getTASEModeledFunctions();
}

#endif
