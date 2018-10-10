//===- MCCartridgeRecord.h - Machine Code Cartridge -------------*- C++ -*-===//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCCARTRIDGERECORD_H
#define LLVM_MC_MCCARTRIDGERECORD_H

namespace llvm {
  class MCContext;
  class MCSymbol;


  class MCCartridgeRecord {
  public:
    MCCartridgeRecord() = delete;
    MCCartridgeRecord(MCSymbol *bb, MCContext *ctx):
      BB(bb), Ctx(ctx) {}
    ~MCCartridgeRecord() {}

    MCSymbol *Cartridge();
    MCSymbol *Body();
    MCSymbol *End();
    MCSymbol *BodyPostDebug();

  private:
    MCSymbol *BB;
    MCContext *Ctx;
  };
}

#endif // LLVM_MC_MCCARTRIDGERECORD_H
