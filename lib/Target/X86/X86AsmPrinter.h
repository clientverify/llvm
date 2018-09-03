//===-- X86AsmPrinter.h - X86 implementation of AsmPrinter ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_X86_X86ASMPRINTER_H
#define LLVM_LIB_TARGET_X86_X86ASMPRINTER_H

#include "X86Subtarget.h"
#include "X86CacheAnalysis.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/FaultMaps.h"
#include "llvm/CodeGen/StackMaps.h"
#include "llvm/Target/TargetMachine.h"

// Implemented in X86MCInstLower.cpp
namespace {
  class X86MCInstLower;
}

// Command line flags.
extern std::string TaseInstrumentedFile;
extern std::string TaseModeledFile;

namespace llvm {
class MCStreamer;
class MCSymbol;

class LLVM_LIBRARY_VISIBILITY X86AsmPrinter : public AsmPrinter {
  const X86Subtarget *Subtarget;
  StackMaps SM;
  FaultMaps FM;

  // T-SGX Cache analysis module
  X86CacheAnalysis CA;

  // This utility class tracks the length of a stackmap instruction's 'shadow'.
  // It is used by the X86AsmPrinter to ensure that the stackmap shadow
  // invariants (i.e. no other stackmaps, patchpoints, or control flow within
  // the shadow) are met, while outputting a minimal number of NOPs for padding.
  //
  // To minimise the number of NOPs used, the shadow tracker counts the number
  // of instruction bytes output since the last stackmap. Only if there are too
  // few instruction bytes to cover the shadow are NOPs used for padding.
  class StackMapShadowTracker {
  public:
    StackMapShadowTracker(TargetMachine &TM);
    ~StackMapShadowTracker();
    void startFunction(MachineFunction &MF);
    void count(MCInst &Inst, const MCSubtargetInfo &STI);

    // Called to signal the start of a shadow of RequiredSize bytes.
    void reset(unsigned RequiredSize) {
      RequiredShadowSize = RequiredSize;
      CurrentShadowSize = 0;
      InShadow = true;
    }

    // Called before every stackmap/patchpoint, and at the end of basic blocks,
    // to emit any necessary padding-NOPs.
    void emitShadowPadding(MCStreamer &OutStreamer, const MCSubtargetInfo &STI);
  private:
    TargetMachine &TM;
    const MachineFunction *MF;
    std::unique_ptr<MCCodeEmitter> CodeEmitter;
    bool InShadow;

    // RequiredShadowSize holds the length of the shadow specified in the most
    // recently encountered STACKMAP instruction.
    // CurrentShadowSize counts the number of bytes encoded since the most
    // recently encountered STACKMAP, stopping when that number is greater than
    // or equal to RequiredShadowSize.
    unsigned RequiredShadowSize, CurrentShadowSize;
  };

  StackMapShadowTracker SMShadowTracker;

  // All instructions emitted by the X86AsmPrinter should use this helper
  // method.
  //
  // This helper function invokes the SMShadowTracker on each instruction before
  // outputting it to the OutStream. This allows the shadow tracker to minimise
  // the number of NOPs used for stackmap padding.
  void EmitAndCountInstruction(MCInst &Inst);

  void InsertStackMapShadows(MachineFunction &MF);
  void LowerSTACKMAP(const MachineInstr &MI);
  void LowerPATCHPOINT(const MachineInstr &MI, X86MCInstLower &MCIL);
  void LowerSTATEPOINT(const MachineInstr &MI, X86MCInstLower &MCIL);
  void LowerFAULTING_LOAD_OP(const MachineInstr &MI, X86MCInstLower &MCIL);

  void LowerTlsAddr(X86MCInstLower &MCInstLowering, const MachineInstr &MI);

 public:
   explicit X86AsmPrinter(TargetMachine &TM,
                          std::unique_ptr<MCStreamer> Streamer)
       : AsmPrinter(TM, std::move(Streamer)), SM(*this), FM(*this),
         CA(), SMShadowTracker(TM), TaseInstrumentedFunctions(), TaseModeledFunctions() {
           // Clear poison checking indices before the first block.
           std::fill(std::begin(SimdIndex), std::end(SimdIndex), 0);
         }

  const char *getPassName() const override {
    return "X86 Assembly / Object Emitter";
  }

  const X86Subtarget &getSubtarget() const { return *Subtarget; }

  void EmitStartOfAsmFile(Module &M) override;

  void EmitEndOfAsmFile(Module &M) override;

  void EmitInstruction(const MachineInstr *MI) override;

  void EmitBasicBlockStart(const MachineBasicBlock &MBB) override;

  void EmitBasicBlockEnd(const MachineBasicBlock &MBB) override {
    // Reset Poison checking indices for the next block.
    // TODO: Change this to an assert. We should have already accumulated all
    // the poison we encountered by this point.
    std::fill(std::begin(SimdIndex), std::end(SimdIndex), 0);
    SMShadowTracker.emitShadowPadding(*OutStreamer, getSubtargetInfo());
  }

  bool PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                       unsigned AsmVariant, const char *ExtraCode,
                       raw_ostream &OS) override;
  bool PrintAsmMemoryOperand(const MachineInstr *MI, unsigned OpNo,
                             unsigned AsmVariant, const char *ExtraCode,
                             raw_ostream &OS) override;

  /// \brief Return the symbol for the specified constant pool entry.
  MCSymbol *GetCPISymbol(unsigned CPID) const override;

  bool doInitialization(Module &M) override {
    SMShadowTracker.reset(0);
    SM.reset();
    loadTaseFunctions(TaseInstrumentedFile, TaseInstrumentedFunctions, "Cannot instrument CALL instructions without a list of instrumented functions");
    loadTaseFunctions(TaseModeledFile, TaseModeledFunctions, "Cannot instrument CALL instructions without a list of modeled functions");
    if (TaseModeledFunctions.size() > 128) {
      report_fatal_error("Cannot handle more than 128 modeled functions");
    }
    return AsmPrinter::doInitialization(M);
  }

  bool runOnMachineFunction(MachineFunction &F) override;

private:
  MCSymbol* EmitTsxSpringboard(const Twine& suffix, unsigned int opcode, const Twine& springName);
  MCSymbol* EmitTsxSpringboardJmp(const Twine& suffix, const Twine& springName, bool saveAndRestoreRax = false);
  // Springboard for loop/branch analysis
  MCSymbol* EmitTsxSpringLoop(const MachineBasicBlock* targetBasicBlock, const MachineInstr *MI, bool saveRax);
  // Springboard before and after call instructions.
  MCSymbol* getMBBLabel(const MachineBasicBlock* targetBasicBlock);
  void EmitSaveRax();
  void EmitRestoreRax();
  void loadTaseFunctions(const std::string& path, std::vector<std::string>& store, const std::string& error_msg);
  void EmitInstructionCore(const MachineInstr *MI, X86MCInstLower &MCInstLowering);
  // Returns whether core instruction processing should be run.
  bool EmitInstrumentedInstruction(const MachineInstr *MI, X86MCInstLower &MCIL);
  void EmitPoisonAccumulate(unsigned int offset);
  void EmitPoisonInstrumentation(const MachineInstr *MI, X86MCInstLower &MCIL, bool before);
  void EmitPoisonCheck(const MachineInstr *MI, X86MCInstLower &MCIL, bool isFastPath);

  unsigned int getPhysRegSize(unsigned int reg) const;
  bool usesRax(unsigned int reg) const {
    return getX86SubSuperRegisterOrZero(reg, MVT::i64) == X86::RAX;
  }

  unsigned int getOffsetForSize(unsigned int size) const {
    switch (size) {
      // Due to the size of our poison value, we need to read/write 2-bytes
      // any time we test a single byte value.
      case 1: return 1;
      case 2: return 1;
      case 4: return 2;
      case 8: return 3;
      default:
        llvm_unreachable("Cannot handler non-standard register sizes");
    }
  }

  unsigned int SpringboardCounter;
  // Convention - index i corresponds to poison storage for operand size 2^i.
  unsigned int SimdIndex[4];
  std::vector<std::string> TaseInstrumentedFunctions;
  std::vector<std::string> TaseModeledFunctions;
};

} // end namespace llvm

#endif
