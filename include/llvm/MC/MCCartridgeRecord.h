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
    MCCartridgeRecord(MCSymbol *bb, std::string mf, MCContext *ctx):
      Modeled(false), BB(bb), MF(mf), Ctx(ctx) {}
    ~MCCartridgeRecord() {}

    MCSymbol *Cartridge();
    MCSymbol *Body();
    MCSymbol *End();
    MCSymbol *BodyPostDebug();
    MCSymbol *ModeledRecord();

    bool     Modeled;
    bool     flags_live = true;

  private:
    MCSymbol *BB;
    std::string MF;
    MCContext *Ctx;
  };
}

#endif // LLVM_MC_MCCARTRIDGERECORD_H
