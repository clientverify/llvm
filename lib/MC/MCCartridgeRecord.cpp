//===- lib/MC/MCCartridgeRecord.cpp - Machine Code Cartridge --------------===//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCCartridgeRecord.h"
#include "llvm/MC/MCSymbol.h"

using namespace llvm;

MCSymbol *MCCartridgeRecord::Cartridge() {
  return Ctx->getOrCreateSymbol(BB->getName() + "_CartridgeHead");
}

MCSymbol *MCCartridgeRecord::Body() {
  return Ctx->getOrCreateSymbol(BB->getName() + "_CartridgeBody");
}

MCSymbol *MCCartridgeRecord::End() {
  return Ctx->getOrCreateSymbol(BB->getName() + "_CartridgeEnd");
}

MCSymbol *MCCartridgeRecord::BodyPostDebug() {
  return Ctx->getOrCreateSymbol(BB->getName() + "_CartridgeBodyPostDebug");
}
