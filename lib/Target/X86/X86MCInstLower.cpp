//===-- X86MCInstLower.cpp - Convert X86 MachineInstr to an MCInst --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains code to lower X86 MachineInstrs to their corresponding
// MCInst records.
//
//===----------------------------------------------------------------------===//

#include <iostream>
#include <fstream>

#include "X86AsmPrinter.h"
#include "X86RegisterInfo.h"
#include "InstPrinter/X86ATTInstPrinter.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "Utils/X86ShuffleDecode.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineConstantPool.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineModuleInfoImpls.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/StackMaps.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Mangler.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixup.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstBuilder.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/TargetRegistry.h"
using namespace llvm;

namespace {

/// X86MCInstLower - This class is used to lower an MachineInstr into an MCInst.
class X86MCInstLower {
  MCContext &Ctx;
  const MachineFunction &MF;
  const TargetMachine &TM;
  const MCAsmInfo &MAI;
  X86AsmPrinter &AsmPrinter;
public:
  X86MCInstLower(const MachineFunction &MF, X86AsmPrinter &asmprinter);

  Optional<MCOperand> LowerMachineOperand(const MachineInstr *MI,
                                          const MachineOperand &MO) const;
  void Lower(const MachineInstr *MI, MCInst &OutMI) const;

  MCSymbol *GetSymbolFromOperand(const MachineOperand &MO) const;
  MCOperand LowerSymbolOperand(const MachineOperand &MO, MCSymbol *Sym) const;

private:
  MachineModuleInfoMachO &getMachOMMI() const;
  Mangler *getMang() const {
    return AsmPrinter.Mang;
  }
};

} // end anonymous namespace

// Emit a minimal sequence of nops spanning NumBytes bytes.
static void EmitNops(MCStreamer &OS, unsigned NumBytes, bool Is64Bit,
                     const MCSubtargetInfo &STI);

namespace llvm {
   X86AsmPrinter::StackMapShadowTracker::StackMapShadowTracker(TargetMachine &TM)
     : TM(TM), InShadow(false), RequiredShadowSize(0), CurrentShadowSize(0) {}

  X86AsmPrinter::StackMapShadowTracker::~StackMapShadowTracker() {}

  void
  X86AsmPrinter::StackMapShadowTracker::startFunction(MachineFunction &F) {
    MF = &F;
    CodeEmitter.reset(TM.getTarget().createMCCodeEmitter(
        *MF->getSubtarget().getInstrInfo(),
        *MF->getSubtarget().getRegisterInfo(), MF->getContext()));
  }

  void X86AsmPrinter::StackMapShadowTracker::count(MCInst &Inst,
                                                   const MCSubtargetInfo &STI) {
    if (InShadow) {
      SmallString<256> Code;
      SmallVector<MCFixup, 4> Fixups;
      raw_svector_ostream VecOS(Code);
      CodeEmitter->encodeInstruction(Inst, VecOS, Fixups, STI);
      VecOS.flush();
      CurrentShadowSize += Code.size();
      if (CurrentShadowSize >= RequiredShadowSize)
        InShadow = false; // The shadow is big enough. Stop counting.
    }
  }

  void X86AsmPrinter::StackMapShadowTracker::emitShadowPadding(
    MCStreamer &OutStreamer, const MCSubtargetInfo &STI) {
    if (InShadow && CurrentShadowSize < RequiredShadowSize) {
      InShadow = false;
      EmitNops(OutStreamer, RequiredShadowSize - CurrentShadowSize,
               MF->getSubtarget<X86Subtarget>().is64Bit(), STI);
    }
  }

  void X86AsmPrinter::EmitAndCountInstruction(MCInst &Inst) {

    //printf("\n %s \n", "Emitting a MCInst");
    //Inst.dump();

    OutStreamer->EmitInstruction(Inst, getSubtargetInfo());
    SMShadowTracker.count(Inst, getSubtargetInfo());
  }
} // end llvm namespace

X86MCInstLower::X86MCInstLower(const MachineFunction &mf,
                               X86AsmPrinter &asmprinter)
    : Ctx(mf.getContext()), MF(mf), TM(mf.getTarget()), MAI(*TM.getMCAsmInfo()),
      AsmPrinter(asmprinter) {}

MachineModuleInfoMachO &X86MCInstLower::getMachOMMI() const {
  return MF.getMMI().getObjFileInfo<MachineModuleInfoMachO>();
}


/// GetSymbolFromOperand - Lower an MO_GlobalAddress or MO_ExternalSymbol
/// operand to an MCSymbol.
MCSymbol *X86MCInstLower::
GetSymbolFromOperand(const MachineOperand &MO) const {
  const DataLayout *DL = TM.getDataLayout();
  if(!(MO.isGlobal() || MO.isSymbol() || MO.isMBB())) {
    MO.getParent()->dump();
    assert(false && "Isn't a symbol reference");
  }

  MCSymbol *Sym = nullptr;
  SmallString<128> Name;
  StringRef Suffix;

  switch (MO.getTargetFlags()) {
  case X86II::MO_DLLIMPORT:
    // Handle dllimport linkage.
    Name += "__imp_";
    break;
  case X86II::MO_DARWIN_STUB:
    Suffix = "$stub";
    break;
  case X86II::MO_DARWIN_NONLAZY:
  case X86II::MO_DARWIN_NONLAZY_PIC_BASE:
  case X86II::MO_DARWIN_HIDDEN_NONLAZY_PIC_BASE:
    Suffix = "$non_lazy_ptr";
    break;
  }

  if (!Suffix.empty())
    Name += DL->getPrivateGlobalPrefix();

  unsigned PrefixLen = Name.size();

  if (MO.isGlobal()) {
    const GlobalValue *GV = MO.getGlobal();
    AsmPrinter.getNameWithPrefix(Name, GV);
  } else if (MO.isSymbol()) {
    Mangler::getNameWithPrefix(Name, MO.getSymbolName(), *DL);
  } else if (MO.isMBB()) {
    assert(Suffix.empty());
    Sym = MO.getMBB()->getSymbol();
  }
  unsigned OrigLen = Name.size() - PrefixLen;

  Name += Suffix;
  if (!Sym)
    Sym = Ctx.getOrCreateSymbol(Name);

  StringRef OrigName = StringRef(Name).substr(PrefixLen, OrigLen);

  // If the target flags on the operand changes the name of the symbol, do that
  // before we return the symbol.
  switch (MO.getTargetFlags()) {
  default: break;
  case X86II::MO_DARWIN_NONLAZY:
  case X86II::MO_DARWIN_NONLAZY_PIC_BASE: {
    MachineModuleInfoImpl::StubValueTy &StubSym =
      getMachOMMI().getGVStubEntry(Sym);
    if (!StubSym.getPointer()) {
      assert(MO.isGlobal() && "Extern symbol not handled yet");
      StubSym =
        MachineModuleInfoImpl::
        StubValueTy(AsmPrinter.getSymbol(MO.getGlobal()),
                    !MO.getGlobal()->hasInternalLinkage());
    }
    break;
  }
  case X86II::MO_DARWIN_HIDDEN_NONLAZY_PIC_BASE: {
    MachineModuleInfoImpl::StubValueTy &StubSym =
      getMachOMMI().getHiddenGVStubEntry(Sym);
    if (!StubSym.getPointer()) {
      assert(MO.isGlobal() && "Extern symbol not handled yet");
      StubSym =
        MachineModuleInfoImpl::
        StubValueTy(AsmPrinter.getSymbol(MO.getGlobal()),
                    !MO.getGlobal()->hasInternalLinkage());
    }
    break;
  }
  case X86II::MO_DARWIN_STUB: {
    MachineModuleInfoImpl::StubValueTy &StubSym =
      getMachOMMI().getFnStubEntry(Sym);
    if (StubSym.getPointer())
      return Sym;

    if (MO.isGlobal()) {
      StubSym =
        MachineModuleInfoImpl::
        StubValueTy(AsmPrinter.getSymbol(MO.getGlobal()),
                    !MO.getGlobal()->hasInternalLinkage());
    } else {
      StubSym =
        MachineModuleInfoImpl::
        StubValueTy(Ctx.getOrCreateSymbol(OrigName), false);
    }
    break;
  }
  }

  return Sym;
}

MCOperand X86MCInstLower::LowerSymbolOperand(const MachineOperand &MO,
                                             MCSymbol *Sym) const {
  // FIXME: We would like an efficient form for this, so we don't have to do a
  // lot of extra uniquing.
  const MCExpr *Expr = nullptr;
  MCSymbolRefExpr::VariantKind RefKind = MCSymbolRefExpr::VK_None;

  switch (MO.getTargetFlags()) {
  default: llvm_unreachable("Unknown target flag on GV operand");
  case X86II::MO_NO_FLAG:    // No flag.
  // These affect the name of the symbol, not any suffix.
  case X86II::MO_DARWIN_NONLAZY:
  case X86II::MO_DLLIMPORT:
  case X86II::MO_DARWIN_STUB:
    break;

  case X86II::MO_TLVP:      RefKind = MCSymbolRefExpr::VK_TLVP; break;
  case X86II::MO_TLVP_PIC_BASE:
    Expr = MCSymbolRefExpr::create(Sym, MCSymbolRefExpr::VK_TLVP, Ctx);
    // Subtract the pic base.
    Expr = MCBinaryExpr::createSub(Expr,
                                  MCSymbolRefExpr::create(MF.getPICBaseSymbol(),
                                                           Ctx),
                                   Ctx);
    break;
  case X86II::MO_SECREL:    RefKind = MCSymbolRefExpr::VK_SECREL; break;
  case X86II::MO_TLSGD:     RefKind = MCSymbolRefExpr::VK_TLSGD; break;
  case X86II::MO_TLSLD:     RefKind = MCSymbolRefExpr::VK_TLSLD; break;
  case X86II::MO_TLSLDM:    RefKind = MCSymbolRefExpr::VK_TLSLDM; break;
  case X86II::MO_GOTTPOFF:  RefKind = MCSymbolRefExpr::VK_GOTTPOFF; break;
  case X86II::MO_INDNTPOFF: RefKind = MCSymbolRefExpr::VK_INDNTPOFF; break;
  case X86II::MO_TPOFF:     RefKind = MCSymbolRefExpr::VK_TPOFF; break;
  case X86II::MO_DTPOFF:    RefKind = MCSymbolRefExpr::VK_DTPOFF; break;
  case X86II::MO_NTPOFF:    RefKind = MCSymbolRefExpr::VK_NTPOFF; break;
  case X86II::MO_GOTNTPOFF: RefKind = MCSymbolRefExpr::VK_GOTNTPOFF; break;
  case X86II::MO_GOTPCREL:  RefKind = MCSymbolRefExpr::VK_GOTPCREL; break;
  case X86II::MO_GOT:       RefKind = MCSymbolRefExpr::VK_GOT; break;
  case X86II::MO_GOTOFF:    RefKind = MCSymbolRefExpr::VK_GOTOFF; break;
  case X86II::MO_PLT:       RefKind = MCSymbolRefExpr::VK_PLT; break;
  case X86II::MO_PIC_BASE_OFFSET:
  case X86II::MO_DARWIN_NONLAZY_PIC_BASE:
  case X86II::MO_DARWIN_HIDDEN_NONLAZY_PIC_BASE:
    Expr = MCSymbolRefExpr::create(Sym, Ctx);
    // Subtract the pic base.
    Expr = MCBinaryExpr::createSub(Expr,
                            MCSymbolRefExpr::create(MF.getPICBaseSymbol(), Ctx),
                                   Ctx);
    if (MO.isJTI()) {
      assert(MAI.doesSetDirectiveSuppressesReloc());
      // If .set directive is supported, use it to reduce the number of
      // relocations the assembler will generate for differences between
      // local labels. This is only safe when the symbols are in the same
      // section so we are restricting it to jumptable references.
      MCSymbol *Label = Ctx.createTempSymbol();
      AsmPrinter.OutStreamer->EmitAssignment(Label, Expr);
      Expr = MCSymbolRefExpr::create(Label, Ctx);
    }
    break;
  }

  if (!Expr)
    Expr = MCSymbolRefExpr::create(Sym, RefKind, Ctx);

  if (!MO.isJTI() && !MO.isMBB() && MO.getOffset())
    Expr = MCBinaryExpr::createAdd(Expr,
                                   MCConstantExpr::create(MO.getOffset(), Ctx),
                                   Ctx);
  return MCOperand::createExpr(Expr);
}


/// \brief Simplify FOO $imm, %{al,ax,eax,rax} to FOO $imm, for instruction with
/// a short fixed-register form.
static void SimplifyShortImmForm(MCInst &Inst, unsigned Opcode) {
  unsigned ImmOp = Inst.getNumOperands() - 1;
  assert(Inst.getOperand(0).isReg() &&
         (Inst.getOperand(ImmOp).isImm() || Inst.getOperand(ImmOp).isExpr()) &&
         ((Inst.getNumOperands() == 3 && Inst.getOperand(1).isReg() &&
           Inst.getOperand(0).getReg() == Inst.getOperand(1).getReg()) ||
          Inst.getNumOperands() == 2) && "Unexpected instruction!");

  // Check whether the destination register can be fixed.
  unsigned Reg = Inst.getOperand(0).getReg();
  if (Reg != X86::AL && Reg != X86::AX && Reg != X86::EAX && Reg != X86::RAX)
    return;

  // If so, rewrite the instruction.
  MCOperand Saved = Inst.getOperand(ImmOp);
  Inst = MCInst();
  Inst.setOpcode(Opcode);
  Inst.addOperand(Saved);
}

/// \brief If a movsx instruction has a shorter encoding for the used register
/// simplify the instruction to use it instead.
static void SimplifyMOVSX(MCInst &Inst) {
  unsigned NewOpcode = 0;
  unsigned Op0 = Inst.getOperand(0).getReg(), Op1 = Inst.getOperand(1).getReg();
  switch (Inst.getOpcode()) {
  default:
    llvm_unreachable("Unexpected instruction!");
  case X86::MOVSX16rr8:  // movsbw %al, %ax   --> cbtw
    if (Op0 == X86::AX && Op1 == X86::AL)
      NewOpcode = X86::CBW;
    break;
  case X86::MOVSX32rr16: // movswl %ax, %eax  --> cwtl
    if (Op0 == X86::EAX && Op1 == X86::AX)
      NewOpcode = X86::CWDE;
    break;
  case X86::MOVSX64rr32: // movslq %eax, %rax --> cltq
    if (Op0 == X86::RAX && Op1 == X86::EAX)
      NewOpcode = X86::CDQE;
    break;
  }

  if (NewOpcode != 0) {
    Inst = MCInst();
    Inst.setOpcode(NewOpcode);
  }
}

/// \brief Simplify things like MOV32rm to MOV32o32a.
static void SimplifyShortMoveForm(X86AsmPrinter &Printer, MCInst &Inst,
                                  unsigned Opcode) {
  // Don't make these simplifications in 64-bit mode; other assemblers don't
  // perform them because they make the code larger.
  if (Printer.getSubtarget().is64Bit())
    return;

  bool IsStore = Inst.getOperand(0).isReg() && Inst.getOperand(1).isReg();
  unsigned AddrBase = IsStore;
  unsigned RegOp = IsStore ? 0 : 5;
  unsigned AddrOp = AddrBase + 3;
  assert(Inst.getNumOperands() == 6 && Inst.getOperand(RegOp).isReg() &&
         Inst.getOperand(AddrBase + X86::AddrBaseReg).isReg() &&
         Inst.getOperand(AddrBase + X86::AddrScaleAmt).isImm() &&
         Inst.getOperand(AddrBase + X86::AddrIndexReg).isReg() &&
         Inst.getOperand(AddrBase + X86::AddrSegmentReg).isReg() &&
         (Inst.getOperand(AddrOp).isExpr() ||
          Inst.getOperand(AddrOp).isImm()) &&
         "Unexpected instruction!");

  // Check whether the destination register can be fixed.
  unsigned Reg = Inst.getOperand(RegOp).getReg();
  if (Reg != X86::AL && Reg != X86::AX && Reg != X86::EAX && Reg != X86::RAX)
    return;

  // Check whether this is an absolute address.
  // FIXME: We know TLVP symbol refs aren't, but there should be a better way
  // to do this here.
  bool Absolute = true;
  if (Inst.getOperand(AddrOp).isExpr()) {
    const MCExpr *MCE = Inst.getOperand(AddrOp).getExpr();
    if (const MCSymbolRefExpr *SRE = dyn_cast<MCSymbolRefExpr>(MCE))
      if (SRE->getKind() == MCSymbolRefExpr::VK_TLVP)
        Absolute = false;
  }

  if (Absolute &&
      (Inst.getOperand(AddrBase + X86::AddrBaseReg).getReg() != 0 ||
       Inst.getOperand(AddrBase + X86::AddrScaleAmt).getImm() != 1 ||
       Inst.getOperand(AddrBase + X86::AddrIndexReg).getReg() != 0))
    return;

  // If so, rewrite the instruction.
  MCOperand Saved = Inst.getOperand(AddrOp);
  MCOperand Seg = Inst.getOperand(AddrBase + X86::AddrSegmentReg);
  Inst = MCInst();
  Inst.setOpcode(Opcode);
  Inst.addOperand(Saved);
  Inst.addOperand(Seg);
}

static unsigned getRetOpcode(const X86Subtarget &Subtarget) {
  return Subtarget.is64Bit() ? X86::RETQ : X86::RETL;
}

Optional<MCOperand>
X86MCInstLower::LowerMachineOperand(const MachineInstr *MI,
                                    const MachineOperand &MO) const {
  switch (MO.getType()) {
  default:
    MI->dump();
    llvm_unreachable("unknown operand type");
  case MachineOperand::MO_Register:
    // Ignore all implicit register operands.
    if (MO.isImplicit())
      return None;
    return MCOperand::createReg(MO.getReg());
  case MachineOperand::MO_Immediate:
    return MCOperand::createImm(MO.getImm());
  case MachineOperand::MO_MachineBasicBlock:
  case MachineOperand::MO_GlobalAddress:
  case MachineOperand::MO_ExternalSymbol:
    return LowerSymbolOperand(MO, GetSymbolFromOperand(MO));
  case MachineOperand::MO_MCSymbol:
    return LowerSymbolOperand(MO, MO.getMCSymbol());
  case MachineOperand::MO_JumpTableIndex:
    return LowerSymbolOperand(MO, AsmPrinter.GetJTISymbol(MO.getIndex()));
  case MachineOperand::MO_ConstantPoolIndex:
    return LowerSymbolOperand(MO, AsmPrinter.GetCPISymbol(MO.getIndex()));
  case MachineOperand::MO_BlockAddress:
    return LowerSymbolOperand(
        MO, AsmPrinter.GetBlockAddressSymbol(MO.getBlockAddress()));
  case MachineOperand::MO_RegisterMask:
    // Ignore call clobbers.
    return None;
  }
}

void X86MCInstLower::Lower(const MachineInstr *MI, MCInst &OutMI) const {
  OutMI.setOpcode(MI->getOpcode());

  for (const MachineOperand &MO : MI->operands())
    if (auto MaybeMCOp = LowerMachineOperand(MI, MO))
      OutMI.addOperand(MaybeMCOp.getValue());

  // Handle a few special cases to eliminate operand modifiers.
ReSimplify:
  switch (OutMI.getOpcode()) {
  case X86::LEA64_32r:
  case X86::LEA64r:
  case X86::LEA16r:
  case X86::LEA32r:
    // LEA should have a segment register, but it must be empty.
    assert(OutMI.getNumOperands() == 1+X86::AddrNumOperands &&
           "Unexpected # of LEA operands");
    assert(OutMI.getOperand(1+X86::AddrSegmentReg).getReg() == 0 &&
           "LEA has segment specified!");
    break;

  case X86::MOV32ri64:
    OutMI.setOpcode(X86::MOV32ri);
    break;

  // Commute operands to get a smaller encoding by using VEX.R instead of VEX.B
  // if one of the registers is extended, but other isn't.
  case X86::VMOVAPDrr:
  case X86::VMOVAPDYrr:
  case X86::VMOVAPSrr:
  case X86::VMOVAPSYrr:
  case X86::VMOVDQArr:
  case X86::VMOVDQAYrr:
  case X86::VMOVDQUrr:
  case X86::VMOVDQUYrr:
  case X86::VMOVUPDrr:
  case X86::VMOVUPDYrr:
  case X86::VMOVUPSrr:
  case X86::VMOVUPSYrr: {
    if (!X86II::isX86_64ExtendedReg(OutMI.getOperand(0).getReg()) &&
        X86II::isX86_64ExtendedReg(OutMI.getOperand(1).getReg())) {
      unsigned NewOpc;
      switch (OutMI.getOpcode()) {
      default: llvm_unreachable("Invalid opcode");
      case X86::VMOVAPDrr:  NewOpc = X86::VMOVAPDrr_REV;  break;
      case X86::VMOVAPDYrr: NewOpc = X86::VMOVAPDYrr_REV; break;
      case X86::VMOVAPSrr:  NewOpc = X86::VMOVAPSrr_REV;  break;
      case X86::VMOVAPSYrr: NewOpc = X86::VMOVAPSYrr_REV; break;
      case X86::VMOVDQArr:  NewOpc = X86::VMOVDQArr_REV;  break;
      case X86::VMOVDQAYrr: NewOpc = X86::VMOVDQAYrr_REV; break;
      case X86::VMOVDQUrr:  NewOpc = X86::VMOVDQUrr_REV;  break;
      case X86::VMOVDQUYrr: NewOpc = X86::VMOVDQUYrr_REV; break;
      case X86::VMOVUPDrr:  NewOpc = X86::VMOVUPDrr_REV;  break;
      case X86::VMOVUPDYrr: NewOpc = X86::VMOVUPDYrr_REV; break;
      case X86::VMOVUPSrr:  NewOpc = X86::VMOVUPSrr_REV;  break;
      case X86::VMOVUPSYrr: NewOpc = X86::VMOVUPSYrr_REV; break;
      }
      OutMI.setOpcode(NewOpc);
    }
    break;
  }
  case X86::VMOVSDrr:
  case X86::VMOVSSrr: {
    if (!X86II::isX86_64ExtendedReg(OutMI.getOperand(0).getReg()) &&
        X86II::isX86_64ExtendedReg(OutMI.getOperand(2).getReg())) {
      unsigned NewOpc;
      switch (OutMI.getOpcode()) {
      default: llvm_unreachable("Invalid opcode");
      case X86::VMOVSDrr:   NewOpc = X86::VMOVSDrr_REV;   break;
      case X86::VMOVSSrr:   NewOpc = X86::VMOVSSrr_REV;   break;
      }
      OutMI.setOpcode(NewOpc);
    }
    break;
  }

  // TAILJMPr64, CALL64r, CALL64pcrel32 - These instructions have register
  // inputs modeled as normal uses instead of implicit uses.  As such, truncate
  // off all but the first operand (the callee).  FIXME: Change isel.
  case X86::TAILJMPr64:
  case X86::TAILJMPr64_REX:
  case X86::CALL64r:
  case X86::CALL64pcrel32: {
    unsigned Opcode = OutMI.getOpcode();
    MCOperand Saved = OutMI.getOperand(0);
    OutMI = MCInst();
    OutMI.setOpcode(Opcode);
    OutMI.addOperand(Saved);
    break;
  }

  case X86::EH_RETURN:
  case X86::EH_RETURN64: {
    OutMI = MCInst();
    OutMI.setOpcode(getRetOpcode(AsmPrinter.getSubtarget()));
    break;
  }

  // TAILJMPd, TAILJMPd64 - Lower to the correct jump instructions.
  case X86::TAILJMPr:
  case X86::TAILJMPd:
  case X86::TAILJMPd64: {
    unsigned Opcode;
    switch (OutMI.getOpcode()) {
    default: llvm_unreachable("Invalid opcode");
    case X86::TAILJMPr: Opcode = X86::JMP32r; break;
    case X86::TAILJMPd:
    case X86::TAILJMPd64: Opcode = X86::JMP_1; break;
    }

    MCOperand Saved = OutMI.getOperand(0);
    OutMI = MCInst();
    OutMI.setOpcode(Opcode);
    OutMI.addOperand(Saved);
    break;
  }

  case X86::DEC16r:
  case X86::DEC32r:
  case X86::INC16r:
  case X86::INC32r:
    // If we aren't in 64-bit mode we can use the 1-byte inc/dec instructions.
    if (!AsmPrinter.getSubtarget().is64Bit()) {
      unsigned Opcode;
      switch (OutMI.getOpcode()) {
      default: llvm_unreachable("Invalid opcode");
      case X86::DEC16r: Opcode = X86::DEC16r_alt; break;
      case X86::DEC32r: Opcode = X86::DEC32r_alt; break;
      case X86::INC16r: Opcode = X86::INC16r_alt; break;
      case X86::INC32r: Opcode = X86::INC32r_alt; break;
      }
      OutMI.setOpcode(Opcode);
    }
    break;

  // These are pseudo-ops for OR to help with the OR->ADD transformation.  We do
  // this with an ugly goto in case the resultant OR uses EAX and needs the
  // short form.
  case X86::ADD16rr_DB:   OutMI.setOpcode(X86::OR16rr); goto ReSimplify;
  case X86::ADD32rr_DB:   OutMI.setOpcode(X86::OR32rr); goto ReSimplify;
  case X86::ADD64rr_DB:   OutMI.setOpcode(X86::OR64rr); goto ReSimplify;
  case X86::ADD16ri_DB:   OutMI.setOpcode(X86::OR16ri); goto ReSimplify;
  case X86::ADD32ri_DB:   OutMI.setOpcode(X86::OR32ri); goto ReSimplify;
  case X86::ADD64ri32_DB: OutMI.setOpcode(X86::OR64ri32); goto ReSimplify;
  case X86::ADD16ri8_DB:  OutMI.setOpcode(X86::OR16ri8); goto ReSimplify;
  case X86::ADD32ri8_DB:  OutMI.setOpcode(X86::OR32ri8); goto ReSimplify;
  case X86::ADD64ri8_DB:  OutMI.setOpcode(X86::OR64ri8); goto ReSimplify;

  // Atomic load and store require a separate pseudo-inst because Acquire
  // implies mayStore and Release implies mayLoad; fix these to regular MOV
  // instructions here
  case X86::ACQUIRE_MOV8rm:    OutMI.setOpcode(X86::MOV8rm); goto ReSimplify;
  case X86::ACQUIRE_MOV16rm:   OutMI.setOpcode(X86::MOV16rm); goto ReSimplify;
  case X86::ACQUIRE_MOV32rm:   OutMI.setOpcode(X86::MOV32rm); goto ReSimplify;
  case X86::ACQUIRE_MOV64rm:   OutMI.setOpcode(X86::MOV64rm); goto ReSimplify;
  case X86::RELEASE_MOV8mr:    OutMI.setOpcode(X86::MOV8mr); goto ReSimplify;
  case X86::RELEASE_MOV16mr:   OutMI.setOpcode(X86::MOV16mr); goto ReSimplify;
  case X86::RELEASE_MOV32mr:   OutMI.setOpcode(X86::MOV32mr); goto ReSimplify;
  case X86::RELEASE_MOV64mr:   OutMI.setOpcode(X86::MOV64mr); goto ReSimplify;
  case X86::RELEASE_MOV8mi:    OutMI.setOpcode(X86::MOV8mi); goto ReSimplify;
  case X86::RELEASE_MOV16mi:   OutMI.setOpcode(X86::MOV16mi); goto ReSimplify;
  case X86::RELEASE_MOV32mi:   OutMI.setOpcode(X86::MOV32mi); goto ReSimplify;
  case X86::RELEASE_MOV64mi32: OutMI.setOpcode(X86::MOV64mi32); goto ReSimplify;
  case X86::RELEASE_ADD8mi:    OutMI.setOpcode(X86::ADD8mi); goto ReSimplify;
  case X86::RELEASE_ADD32mi:   OutMI.setOpcode(X86::ADD32mi); goto ReSimplify;
  case X86::RELEASE_ADD64mi32: OutMI.setOpcode(X86::ADD64mi32); goto ReSimplify;
  case X86::RELEASE_AND8mi:    OutMI.setOpcode(X86::AND8mi); goto ReSimplify;
  case X86::RELEASE_AND32mi:   OutMI.setOpcode(X86::AND32mi); goto ReSimplify;
  case X86::RELEASE_AND64mi32: OutMI.setOpcode(X86::AND64mi32); goto ReSimplify;
  case X86::RELEASE_OR8mi:     OutMI.setOpcode(X86::OR8mi); goto ReSimplify;
  case X86::RELEASE_OR32mi:    OutMI.setOpcode(X86::OR32mi); goto ReSimplify;
  case X86::RELEASE_OR64mi32:  OutMI.setOpcode(X86::OR64mi32); goto ReSimplify;
  case X86::RELEASE_XOR8mi:    OutMI.setOpcode(X86::XOR8mi); goto ReSimplify;
  case X86::RELEASE_XOR32mi:   OutMI.setOpcode(X86::XOR32mi); goto ReSimplify;
  case X86::RELEASE_XOR64mi32: OutMI.setOpcode(X86::XOR64mi32); goto ReSimplify;
  case X86::RELEASE_INC8m:     OutMI.setOpcode(X86::INC8m); goto ReSimplify;
  case X86::RELEASE_INC16m:    OutMI.setOpcode(X86::INC16m); goto ReSimplify;
  case X86::RELEASE_INC32m:    OutMI.setOpcode(X86::INC32m); goto ReSimplify;
  case X86::RELEASE_INC64m:    OutMI.setOpcode(X86::INC64m); goto ReSimplify;
  case X86::RELEASE_DEC8m:     OutMI.setOpcode(X86::DEC8m); goto ReSimplify;
  case X86::RELEASE_DEC16m:    OutMI.setOpcode(X86::DEC16m); goto ReSimplify;
  case X86::RELEASE_DEC32m:    OutMI.setOpcode(X86::DEC32m); goto ReSimplify;
  case X86::RELEASE_DEC64m:    OutMI.setOpcode(X86::DEC64m); goto ReSimplify;

  // We don't currently select the correct instruction form for instructions
  // which have a short %eax, etc. form. Handle this by custom lowering, for
  // now.
  //
  // Note, we are currently not handling the following instructions:
  // MOV64ao8, MOV64o8a
  // XCHG16ar, XCHG32ar, XCHG64ar
  case X86::MOV8mr_NOREX:
  case X86::MOV8mr:     SimplifyShortMoveForm(AsmPrinter, OutMI, X86::MOV8o32a); break;
  case X86::MOV8rm_NOREX:
  case X86::MOV8rm:     SimplifyShortMoveForm(AsmPrinter, OutMI, X86::MOV8ao32); break;
  case X86::MOV16mr:    SimplifyShortMoveForm(AsmPrinter, OutMI, X86::MOV16o32a); break;
  case X86::MOV16rm:    SimplifyShortMoveForm(AsmPrinter, OutMI, X86::MOV16ao32); break;
  case X86::MOV32mr:    SimplifyShortMoveForm(AsmPrinter, OutMI, X86::MOV32o32a); break;
  case X86::MOV32rm:    SimplifyShortMoveForm(AsmPrinter, OutMI, X86::MOV32ao32); break;

  case X86::ADC8ri:     SimplifyShortImmForm(OutMI, X86::ADC8i8);    break;
  case X86::ADC16ri:    SimplifyShortImmForm(OutMI, X86::ADC16i16);  break;
  case X86::ADC32ri:    SimplifyShortImmForm(OutMI, X86::ADC32i32);  break;
  case X86::ADC64ri32:  SimplifyShortImmForm(OutMI, X86::ADC64i32);  break;
  case X86::ADD8ri:     SimplifyShortImmForm(OutMI, X86::ADD8i8);    break;
  case X86::ADD16ri:    SimplifyShortImmForm(OutMI, X86::ADD16i16);  break;
  case X86::ADD32ri:    SimplifyShortImmForm(OutMI, X86::ADD32i32);  break;
  case X86::ADD64ri32:  SimplifyShortImmForm(OutMI, X86::ADD64i32);  break;
  case X86::AND8ri:     SimplifyShortImmForm(OutMI, X86::AND8i8);    break;
  case X86::AND16ri:    SimplifyShortImmForm(OutMI, X86::AND16i16);  break;
  case X86::AND32ri:    SimplifyShortImmForm(OutMI, X86::AND32i32);  break;
  case X86::AND64ri32:  SimplifyShortImmForm(OutMI, X86::AND64i32);  break;
  case X86::CMP8ri:     SimplifyShortImmForm(OutMI, X86::CMP8i8);    break;
  case X86::CMP16ri:    SimplifyShortImmForm(OutMI, X86::CMP16i16);  break;
  case X86::CMP32ri:    SimplifyShortImmForm(OutMI, X86::CMP32i32);  break;
  case X86::CMP64ri32:  SimplifyShortImmForm(OutMI, X86::CMP64i32);  break;
  case X86::OR8ri:      SimplifyShortImmForm(OutMI, X86::OR8i8);     break;
  case X86::OR16ri:     SimplifyShortImmForm(OutMI, X86::OR16i16);   break;
  case X86::OR32ri:     SimplifyShortImmForm(OutMI, X86::OR32i32);   break;
  case X86::OR64ri32:   SimplifyShortImmForm(OutMI, X86::OR64i32);   break;
  case X86::SBB8ri:     SimplifyShortImmForm(OutMI, X86::SBB8i8);    break;
  case X86::SBB16ri:    SimplifyShortImmForm(OutMI, X86::SBB16i16);  break;
  case X86::SBB32ri:    SimplifyShortImmForm(OutMI, X86::SBB32i32);  break;
  case X86::SBB64ri32:  SimplifyShortImmForm(OutMI, X86::SBB64i32);  break;
  case X86::SUB8ri:     SimplifyShortImmForm(OutMI, X86::SUB8i8);    break;
  case X86::SUB16ri:    SimplifyShortImmForm(OutMI, X86::SUB16i16);  break;
  case X86::SUB32ri:    SimplifyShortImmForm(OutMI, X86::SUB32i32);  break;
  case X86::SUB64ri32:  SimplifyShortImmForm(OutMI, X86::SUB64i32);  break;
  case X86::TEST8ri:    SimplifyShortImmForm(OutMI, X86::TEST8i8);   break;
  case X86::TEST16ri:   SimplifyShortImmForm(OutMI, X86::TEST16i16); break;
  case X86::TEST32ri:   SimplifyShortImmForm(OutMI, X86::TEST32i32); break;
  case X86::TEST64ri32: SimplifyShortImmForm(OutMI, X86::TEST64i32); break;
  case X86::XOR8ri:     SimplifyShortImmForm(OutMI, X86::XOR8i8);    break;
  case X86::XOR16ri:    SimplifyShortImmForm(OutMI, X86::XOR16i16);  break;
  case X86::XOR32ri:    SimplifyShortImmForm(OutMI, X86::XOR32i32);  break;
  case X86::XOR64ri32:  SimplifyShortImmForm(OutMI, X86::XOR64i32);  break;

  // Try to shrink some forms of movsx.
  case X86::MOVSX16rr8:
  case X86::MOVSX32rr16:
  case X86::MOVSX64rr32:
    SimplifyMOVSX(OutMI);
    break;
  }
}

void X86AsmPrinter::LowerTlsAddr(X86MCInstLower &MCInstLowering,
                                 const MachineInstr &MI) {

  bool is64Bits = MI.getOpcode() == X86::TLS_addr64 ||
                  MI.getOpcode() == X86::TLS_base_addr64;

  bool needsPadding = MI.getOpcode() == X86::TLS_addr64;

  MCContext &context = OutStreamer->getContext();

  if (needsPadding)
    EmitAndCountInstruction(MCInstBuilder(X86::DATA16_PREFIX));

  MCSymbolRefExpr::VariantKind SRVK;
  switch (MI.getOpcode()) {
    case X86::TLS_addr32:
    case X86::TLS_addr64:
      SRVK = MCSymbolRefExpr::VK_TLSGD;
      break;
    case X86::TLS_base_addr32:
      SRVK = MCSymbolRefExpr::VK_TLSLDM;
      break;
    case X86::TLS_base_addr64:
      SRVK = MCSymbolRefExpr::VK_TLSLD;
      break;
    default:
      llvm_unreachable("unexpected opcode");
  }

  MCSymbol *sym = MCInstLowering.GetSymbolFromOperand(MI.getOperand(3));
  const MCSymbolRefExpr *symRef = MCSymbolRefExpr::create(sym, SRVK, context);

  MCInst LEA;
  if (is64Bits) {
    LEA.setOpcode(X86::LEA64r);
    LEA.addOperand(MCOperand::createReg(X86::RDI)); // dest
    LEA.addOperand(MCOperand::createReg(X86::RIP)); // base
    LEA.addOperand(MCOperand::createImm(1));        // scale
    LEA.addOperand(MCOperand::createReg(0));        // index
    LEA.addOperand(MCOperand::createExpr(symRef));  // disp
    LEA.addOperand(MCOperand::createReg(0));        // seg
  } else if (SRVK == MCSymbolRefExpr::VK_TLSLDM) {
    LEA.setOpcode(X86::LEA32r);
    LEA.addOperand(MCOperand::createReg(X86::EAX)); // dest
    LEA.addOperand(MCOperand::createReg(X86::EBX)); // base
    LEA.addOperand(MCOperand::createImm(1));        // scale
    LEA.addOperand(MCOperand::createReg(0));        // index
    LEA.addOperand(MCOperand::createExpr(symRef));  // disp
    LEA.addOperand(MCOperand::createReg(0));        // seg
  } else {
    LEA.setOpcode(X86::LEA32r);
    LEA.addOperand(MCOperand::createReg(X86::EAX)); // dest
    LEA.addOperand(MCOperand::createReg(0));        // base
    LEA.addOperand(MCOperand::createImm(1));        // scale
    LEA.addOperand(MCOperand::createReg(X86::EBX)); // index
    LEA.addOperand(MCOperand::createExpr(symRef));  // disp
    LEA.addOperand(MCOperand::createReg(0));        // seg
  }
  EmitAndCountInstruction(LEA);

  if (needsPadding) {
    EmitAndCountInstruction(MCInstBuilder(X86::DATA16_PREFIX));
    EmitAndCountInstruction(MCInstBuilder(X86::DATA16_PREFIX));
    EmitAndCountInstruction(MCInstBuilder(X86::REX64_PREFIX));
  }

  StringRef name = is64Bits ? "__tls_get_addr" : "___tls_get_addr";
  MCSymbol *tlsGetAddr = context.getOrCreateSymbol(name);
  const MCSymbolRefExpr *tlsRef =
    MCSymbolRefExpr::create(tlsGetAddr,
                            MCSymbolRefExpr::VK_PLT,
                            context);

  EmitAndCountInstruction(MCInstBuilder(is64Bits ? X86::CALL64pcrel32
                                                 : X86::CALLpcrel32)
                            .addExpr(tlsRef));
}

/// \brief Emit the optimal amount of multi-byte nops on X86.
static void EmitNops(MCStreamer &OS, unsigned NumBytes, bool Is64Bit, const MCSubtargetInfo &STI) {
  // This works only for 64bit. For 32bit we have to do additional checking if
  // the CPU supports multi-byte nops.
  assert(Is64Bit && "EmitNops only supports X86-64");
  while (NumBytes) {
    unsigned Opc, BaseReg, ScaleVal, IndexReg, Displacement, SegmentReg;
    Opc = IndexReg = Displacement = SegmentReg = 0;
    BaseReg = X86::RAX; ScaleVal = 1;
    switch (NumBytes) {
    case  0: llvm_unreachable("Zero nops?"); break;
    case  1: NumBytes -=  1; Opc = X86::NOOP; break;
    case  2: NumBytes -=  2; Opc = X86::XCHG16ar; break;
    case  3: NumBytes -=  3; Opc = X86::NOOPL; break;
    case  4: NumBytes -=  4; Opc = X86::NOOPL; Displacement = 8; break;
    case  5: NumBytes -=  5; Opc = X86::NOOPL; Displacement = 8;
             IndexReg = X86::RAX; break;
    case  6: NumBytes -=  6; Opc = X86::NOOPW; Displacement = 8;
             IndexReg = X86::RAX; break;
    case  7: NumBytes -=  7; Opc = X86::NOOPL; Displacement = 512; break;
    case  8: NumBytes -=  8; Opc = X86::NOOPL; Displacement = 512;
             IndexReg = X86::RAX; break;
    case  9: NumBytes -=  9; Opc = X86::NOOPW; Displacement = 512;
             IndexReg = X86::RAX; break;
    default: NumBytes -= 10; Opc = X86::NOOPW; Displacement = 512;
             IndexReg = X86::RAX; SegmentReg = X86::CS; break;
    }

    unsigned NumPrefixes = std::min(NumBytes, 5U);
    NumBytes -= NumPrefixes;
    for (unsigned i = 0; i != NumPrefixes; ++i)
      OS.EmitBytes("\x66");

    switch (Opc) {
    default: llvm_unreachable("Unexpected opcode"); break;
    case X86::NOOP:
      OS.EmitInstruction(MCInstBuilder(Opc), STI);
      break;
    case X86::XCHG16ar:
      OS.EmitInstruction(MCInstBuilder(Opc).addReg(X86::AX), STI);
      break;
    case X86::NOOPL:
    case X86::NOOPW:
      OS.EmitInstruction(MCInstBuilder(Opc).addReg(BaseReg)
                         .addImm(ScaleVal).addReg(IndexReg)
                         .addImm(Displacement).addReg(SegmentReg), STI);
      break;
    }
  } // while (NumBytes)
}

void X86AsmPrinter::LowerSTATEPOINT(const MachineInstr &MI,
                                    X86MCInstLower &MCIL) {
  assert(Subtarget->is64Bit() && "Statepoint currently only supports X86-64");

  StatepointOpers SOpers(&MI);
  if (unsigned PatchBytes = SOpers.getNumPatchBytes()) {
    EmitNops(*OutStreamer, PatchBytes, Subtarget->is64Bit(),
             getSubtargetInfo());
  } else {
    // Lower call target and choose correct opcode
    const MachineOperand &CallTarget = SOpers.getCallTarget();
    MCOperand CallTargetMCOp;
    unsigned CallOpcode;
    switch (CallTarget.getType()) {
    case MachineOperand::MO_GlobalAddress:
    case MachineOperand::MO_ExternalSymbol:
      CallTargetMCOp = MCIL.LowerSymbolOperand(
          CallTarget, MCIL.GetSymbolFromOperand(CallTarget));
      CallOpcode = X86::CALL64pcrel32;
      // Currently, we only support relative addressing with statepoints.
      // Otherwise, we'll need a scratch register to hold the target
      // address.  You'll fail asserts during load & relocation if this
      // symbol is to far away. (TODO: support non-relative addressing)
      break;
    case MachineOperand::MO_Immediate:
      CallTargetMCOp = MCOperand::createImm(CallTarget.getImm());
      CallOpcode = X86::CALL64pcrel32;
      // Currently, we only support relative addressing with statepoints.
      // Otherwise, we'll need a scratch register to hold the target
      // immediate.  You'll fail asserts during load & relocation if this
      // address is to far away. (TODO: support non-relative addressing)
      break;
    case MachineOperand::MO_Register:
      CallTargetMCOp = MCOperand::createReg(CallTarget.getReg());
      CallOpcode = X86::CALL64r;
      break;
    default:
      llvm_unreachable("Unsupported operand type in statepoint call target");
      break;
    }

    // Emit call
    MCInst CallInst;
    CallInst.setOpcode(CallOpcode);
    CallInst.addOperand(CallTargetMCOp);
    OutStreamer->EmitInstruction(CallInst, getSubtargetInfo());
  }

  // Record our statepoint node in the same section used by STACKMAP
  // and PATCHPOINT
  SM.recordStatepoint(MI);
}

void X86AsmPrinter::LowerFAULTING_LOAD_OP(const MachineInstr &MI,
                                       X86MCInstLower &MCIL) {
  // FAULTING_LOAD_OP <def>, <handler label>, <load opcode>, <load operands>

  unsigned LoadDefRegister = MI.getOperand(0).getReg();
  MCSymbol *HandlerLabel = MI.getOperand(1).getMCSymbol();
  unsigned LoadOpcode = MI.getOperand(2).getImm();
  unsigned LoadOperandsBeginIdx = 3;

  FM.recordFaultingOp(FaultMaps::FaultingLoad, HandlerLabel);

  MCInst LoadMI;
  LoadMI.setOpcode(LoadOpcode);
  LoadMI.addOperand(MCOperand::createReg(LoadDefRegister));
  for (auto I = MI.operands_begin() + LoadOperandsBeginIdx,
            E = MI.operands_end();
       I != E; ++I)
    if (auto MaybeOperand = MCIL.LowerMachineOperand(&MI, *I))
      LoadMI.addOperand(MaybeOperand.getValue());

  OutStreamer->EmitInstruction(LoadMI, getSubtargetInfo());
}

// Lower a stackmap of the form:
// <id>, <shadowBytes>, ...
void X86AsmPrinter::LowerSTACKMAP(const MachineInstr &MI) {
  SMShadowTracker.emitShadowPadding(*OutStreamer, getSubtargetInfo());
  SM.recordStackMap(MI);
  unsigned NumShadowBytes = MI.getOperand(1).getImm();
  SMShadowTracker.reset(NumShadowBytes);
}

// Lower a patchpoint of the form:
// [<def>], <id>, <numBytes>, <target>, <numArgs>, <cc>, ...
void X86AsmPrinter::LowerPATCHPOINT(const MachineInstr &MI,
                                    X86MCInstLower &MCIL) {
  assert(Subtarget->is64Bit() && "Patchpoint currently only supports X86-64");

  SMShadowTracker.emitShadowPadding(*OutStreamer, getSubtargetInfo());

  SM.recordPatchPoint(MI);

  PatchPointOpers opers(&MI);
  unsigned ScratchIdx = opers.getNextScratchIdx();
  unsigned EncodedBytes = 0;
  const MachineOperand &CalleeMO =
    opers.getMetaOper(PatchPointOpers::TargetPos);

  // Check for null target. If target is non-null (i.e. is non-zero or is
  // symbolic) then emit a call.
  if (!(CalleeMO.isImm() && !CalleeMO.getImm())) {
    MCOperand CalleeMCOp;
    switch (CalleeMO.getType()) {
    default:
      /// FIXME: Add a verifier check for bad callee types.
      llvm_unreachable("Unrecognized callee operand type.");
    case MachineOperand::MO_Immediate:
      if (CalleeMO.getImm())
        CalleeMCOp = MCOperand::createImm(CalleeMO.getImm());
      break;
    case MachineOperand::MO_ExternalSymbol:
    case MachineOperand::MO_GlobalAddress:
      CalleeMCOp =
        MCIL.LowerSymbolOperand(CalleeMO,
                                MCIL.GetSymbolFromOperand(CalleeMO));
      break;
    }

    // Emit MOV to materialize the target address and the CALL to target.
    // This is encoded with 12-13 bytes, depending on which register is used.
    unsigned ScratchReg = MI.getOperand(ScratchIdx).getReg();
    if (X86II::isX86_64ExtendedReg(ScratchReg))
      EncodedBytes = 13;
    else
      EncodedBytes = 12;

    EmitAndCountInstruction(
        MCInstBuilder(X86::MOV64ri).addReg(ScratchReg).addOperand(CalleeMCOp));
    EmitAndCountInstruction(MCInstBuilder(X86::CALL64r).addReg(ScratchReg));
  }

  // Emit padding.
  unsigned NumBytes = opers.getMetaOper(PatchPointOpers::NBytesPos).getImm();
  assert(NumBytes >= EncodedBytes &&
         "Patchpoint can't request size less than the length of a call.");

  EmitNops(*OutStreamer, NumBytes - EncodedBytes, Subtarget->is64Bit(),
           getSubtargetInfo());
}

// Returns instruction preceding MBBI in MachineFunction.
// If MBBI is the first instruction of the first basic block, returns null.
static MachineBasicBlock::const_iterator
PrevCrossBBInst(MachineBasicBlock::const_iterator MBBI) {
  const MachineBasicBlock *MBB = MBBI->getParent();
  while (MBBI == MBB->begin()) {
    if (MBB == MBB->getParent()->begin())
      return nullptr;
    MBB = MBB->getPrevNode();
    MBBI = MBB->end();
  }
  return --MBBI;
}

static const Constant *getConstantFromPool(const MachineInstr &MI,
                                           const MachineOperand &Op) {
  if (!Op.isCPI())
    return nullptr;

  ArrayRef<MachineConstantPoolEntry> Constants =
      MI.getParent()->getParent()->getConstantPool()->getConstants();
  const MachineConstantPoolEntry &ConstantEntry =
      Constants[Op.getIndex()];

  // Bail if this is a machine constant pool entry, we won't be able to dig out
  // anything useful.
  if (ConstantEntry.isMachineConstantPoolEntry())
    return nullptr;

  auto *C = dyn_cast<Constant>(ConstantEntry.Val.ConstVal);
  assert((!C || ConstantEntry.getType() == C->getType()) &&
         "Expected a constant of the same type!");
  return C;
}

static std::string getShuffleComment(const MachineOperand &DstOp,
                                     const MachineOperand &SrcOp,
                                     ArrayRef<int> Mask) {
  std::string Comment;

  // Compute the name for a register. This is really goofy because we have
  // multiple instruction printers that could (in theory) use different
  // names. Fortunately most people use the ATT style (outside of Windows)
  // and they actually agree on register naming here. Ultimately, this is
  // a comment, and so its OK if it isn't perfect.
  auto GetRegisterName = [](unsigned RegNum) -> StringRef {
    return X86ATTInstPrinter::getRegisterName(RegNum);
  };

  StringRef DstName = DstOp.isReg() ? GetRegisterName(DstOp.getReg()) : "mem";
  StringRef SrcName = SrcOp.isReg() ? GetRegisterName(SrcOp.getReg()) : "mem";

  raw_string_ostream CS(Comment);
  CS << DstName << " = ";
  bool NeedComma = false;
  bool InSrc = false;
  for (int M : Mask) {
    // Wrap up any prior entry...
    if (M == SM_SentinelZero && InSrc) {
      InSrc = false;
      CS << "]";
    }
    if (NeedComma)
      CS << ",";
    else
      NeedComma = true;

    // Print this shuffle...
    if (M == SM_SentinelZero) {
      CS << "zero";
    } else {
      if (!InSrc) {
        InSrc = true;
        CS << SrcName << "[";
      }
      if (M == SM_SentinelUndef)
        CS << "u";
      else
        CS << M;
    }
  }
  if (InSrc)
    CS << "]";
  CS.flush();

  return Comment;
}

void X86AsmPrinter::EmitInstruction(const MachineInstr *MI) {
  X86MCInstLower MCInstLowering(*MF, *this);
  const Function *F = MF->getFunction();
  if (F->hasMetadata()) {
    MDNode *node = F->getMetadata("tase.fun.info");
    if ((cast<MDString>(node->getOperand(0))->getString() == "instrumented")) {
      // Only instrument functions that are tagged to be instrumented.
      EmitPoisonInstrumentation(MI, MCInstLowering, true);
      // TODO: THIS IS INCORRECT IN GENERAL!
      // You cannot do fast-path poison checking for an instruction after
      // you have already emitted instructions to close/restart our TSX transaction.
      // The only reason this currently works is because our instruction batching
      // logic is too naive to split long basic blocks and happens to mostly
      // split on branch instructions/instructions that don't read from memory.
      // THIS ASSUMPTION IS NOT ACCURATE!  The end or beginning of a basic block
      // may very well be a memory-accessing instruction.
      // A fix for this would involve restructuring transaction batching so
      // that instead of directly emitting the instruction, it instead delegates
      // that responsibility to a function that pre- and post-poison instruments
      // said instruction.  Labels will need to be carefully handled here.
      if (EmitInstrumentedInstruction(MI, MCInstLowering)) {
        EmitInstructionCore(MI, MCInstLowering);
      }
      EmitPoisonInstrumentation(MI, MCInstLowering, false);
    }
  } else {
    EmitInstructionCore(MI, MCInstLowering);
  }
}

//===----------------------------------------------------------------------===//
// Transaction Batching and Springboarding.
//===----------------------------------------------------------------------===//
#define DEBUG_TYPE "tase"

// Clean this up at some point once we figure out how the loop splitting works.
bool insert_jmp = false;
bool bb_save_rax = false;

void X86AsmPrinter::EmitSaveRax() {
  EmitAndCountInstruction(MCInstBuilder(X86::MOV64rr)
    .addReg(X86::R14)
    .addReg(X86::RAX));
}

void X86AsmPrinter::EmitRestoreRax() {
  EmitAndCountInstruction(MCInstBuilder(X86::MOV64rr)
    .addReg(X86::RAX)
    .addReg(X86::R14));
}

MCSymbol* X86AsmPrinter::EmitTsxSpringboard(const Twine& suffix, unsigned int opcode, const Twine& springName) {
  MCSymbol *resume = OutContext.getOrCreateSymbol(Twine(MF->getName()) + "." + suffix);
  EmitAndCountInstruction(MCInstBuilder(X86::LEA64r)
    .addReg(X86::R15)
    .addReg(X86::RIP)               // base
    .addImm(0)                      // scale
    .addReg(X86::NoRegister)        // index
    .addExpr(MCSymbolRefExpr::create(resume, OutContext))     // disp
    .addReg(X86::NoRegister));      // seg

  // Either close the previous transaction or jump to the middle of the springboard and
  // only open a new one.
  MCSymbol *spring = OutContext.getOrCreateSymbol(springName);

  EmitAndCountInstruction(MCInstBuilder(opcode)
    .addExpr(MCSymbolRefExpr::create(spring, OutContext)));

  return resume;
}

MCSymbol* X86AsmPrinter::EmitTsxSpringLoop(const MachineBasicBlock* targetBasicBlock, const MachineInstr *MI, bool saveRax) {
  if (saveRax) {
    EmitSaveRax();
  }

  unsigned opcode = (MI == nullptr) ? unsigned(X86::JMP_1) : MI->getOpcode();
  return EmitTsxSpringboard(Twine(targetBasicBlock->getNumber()), opcode, "sb_reopen");
}

MCSymbol* X86AsmPrinter::EmitTsxSpringboardJmp(const Twine& suffix, const Twine& springName, bool saveAndRestoreRax) {
  if (saveAndRestoreRax) {
    EmitSaveRax();
  }

  MCSymbol* resume = EmitTsxSpringboard(suffix + "." + Twine(++SpringboardCounter), X86::JMP_1, springName);
  OutStreamer->EmitLabel(resume);

  if (saveAndRestoreRax) {
    EmitRestoreRax();
  }
  return resume;
}

MCSymbol* X86AsmPrinter::getMBBLabel(const MachineBasicBlock* targetBasicBlock) {
  return OutContext.getOrCreateSymbol(Twine(MF->getName()) + "." + Twine(targetBasicBlock->getNumber()));
}

void X86AsmPrinter::EmitBasicBlockStart(const MachineBasicBlock &MBB) {
  AsmPrinter::EmitBasicBlockStart(MBB);

  if (MBB.getNumber() != 0) {
    // If last basic block ends with an conditional jmp or without branch, insert additional
    // jmp to the springboard.
    if (insert_jmp) {
      DEBUG(dbgs() << "Last basic block ends with conditional branch or no branch\n");
      EmitTsxSpringLoop(&MBB, nullptr, bb_save_rax);
      bb_save_rax = false;
    }
    insert_jmp = false;
    // Always insert label in the beginning of the basic block.
    OutStreamer->EmitLabel(getMBBLabel(&MBB));
  }

  // If the current basic block using RAX as soruce, insert restore rax instruction.
  if (CA.isRAXSrc(MBB.getNumber())) {
    EmitRestoreRax();
  }
}

// TODO: Do we ever actually terminate a transaction if its cache way usage exceeds the batching limit?
// It doesn't look like we ever break up non-control flow instructions in the middle of a basic block.
bool X86AsmPrinter::EmitInstrumentedInstruction(const MachineInstr *MI, X86MCInstLower &MCIL) {
  const MachineBasicBlock *MBB = MI->getParent();
  MachineLoopInfo *MLI = AsmPrinter::LI;

  if (MI == MBB->begin()) {
    DEBUG(dbgs() << "EmitInstruction::found first instr in " << MBB->getName() << ":" << MF->getName() << "\n");
  }

  // Basic block level split
  // Split with optimization.
  // Split by loop strategy:
  // 1. Beginning of the loop: If the branch target is a loop header.
  // 2. End of the loop: If the branch target is right after the loop ends.

  bool is_loop_header = false;
  const MachineLoop *loop = MLI->getLoopFor(MBB);
  if (loop) {
    MachineBasicBlock *header = loop->getHeader();
    if (header == MBB) {
      is_loop_header = true;
    }
  }

  // Loop split stragegy 1.
  if (MI->isBranch()) {
    DEBUG(dbgs() << "Found branch in " << MBB->getName() << "\n");
    if (MI->getOperand(0).isMBB()) {
      const MachineBasicBlock *target_mbb = MI->getOperand(0).getMBB();
      DEBUG(dbgs() << "The branch target is basicblock: " << target_mbb->getName() << "\n");
      int way_usage = CA.getJointBBCacheWayUsage(MBB->getNumber(), target_mbb->getNumber());

      const MachineLoop *target_loop = MLI->getLoopFor(target_mbb);
      if (target_loop) {
        MachineBasicBlock *target_header = target_loop->getHeader();
        if ((way_usage > 7) ||
            ((target_header == target_mbb) && (target_loop != loop))) {
          DEBUG(dbgs() << "the target is loop header\n");
          EmitTsxSpringLoop(target_mbb, MI, CA.isRAXDst(MBB->getNumber()));
          return false;
        }
      }
    }
  } // end of loop split strategy 1

  // Loop split strategy 2.
  // First, check if the current basicblock is a loop header as
  // a loop always ends in a loop header.

  // Then, check the branch target.
  // If the branch target is in the same loop, it means that the target is the loop body.
  // We do nothing for this case.
  // If the branch target is in the different loop or is not in the loop, it means that
  // the target is only executed after the loop ends. We do split in this case.
  if (is_loop_header) {
    if (MI->isBranch()) {
      DEBUG(dbgs() << "Found branch in loop header " << MBB->getName() << "\n");
      if (MI->getOperand(0).isMBB()) {
        const MachineBasicBlock *target_mbb = MI->getOperand(0).getMBB();
        DEBUG(dbgs() << "The branch target is basicblock: " << target_mbb->getName() << "\n");
        int way_usage = CA.getJointBBCacheWayUsage(MBB->getNumber(), target_mbb->getNumber());

        // If the jump target is not inside a loop or in different loop means that
        // it is the end of current loop.
        const MachineLoop *target_loop  = MLI->getLoopFor(target_mbb);
        if ((way_usage > 7) || !target_loop || (target_loop != loop)) {
          DEBUG(dbgs() << "The branch is at the end of the loop " << MBB->getName() << "\n");
          // If current basic block use rax as destination save the rax at the end.
          EmitTsxSpringLoop(target_mbb, MI, CA.isRAXDst(MBB->getNumber()));
          return false;
        }

        DEBUG(dbgs()<< "special case on " << MF->getName() << ":" << MBB->getNumber() <<"\n");
        MachineBasicBlock::const_iterator MBBI(MI);
        if (++MBBI == MBB->end()) {
          insert_jmp = true;
          // If current basic block use rax as destination save the rax at the end.
          if (CA.isRAXDst(MBB->getNumber())) {
            DEBUG(dbgs() << "[EmitInstruction] RAX used as dst on BB: " << MBB->getNumber() << "\n");
            bb_save_rax = true;
          }
        }
      }
    }
  } // end of is loop hedaer

  // For the remaining branch, make sure the target is own-defined label.
  if (MI->isBranch()) {
    DEBUG(dbgs() << "Found branch in " << MBB->getName() << "\n");
    if (MI->getOperand(0).isMBB()) {
      const MachineBasicBlock *target_mbb = MI->getOperand(0).getMBB();
      DEBUG(dbgs() << "The branch target is basicblock: " << target_mbb->getName() << "\n");

      // If current basic block use rax as destination, we save the rax at the end.
      if (CA.isRAXDst(MBB->getNumber())) {
        EmitSaveRax();
      }
      EmitAndCountInstruction(MCInstBuilder(MI->getOpcode())
        .addExpr(MCSymbolRefExpr::create(getMBBLabel(target_mbb), OutContext)));
      return false;
    }
  }
  // Basic block level split end


  // Instructions are always split as follows:
  //   lea call_label.begin, %r15
  //   jmp springboard
  // call_label.begin:
  //   call fun
  // call_label.end:
  //   lea call_label.end, %r15
  //   jmp springboard
  //
  // Care is made to preserve rax across a split.
  if (MI->isCall()) {
    int way_usage = CA.getBBCacheWayUsage(MBB->getNumber());
    bool call_opt = way_usage <= 4;
    bool is_instrumented = false;
    bool save_rax_before = false;
    int modeled_index = -1; // Not modeled.
    MCSymbol *callee_sym = nullptr;

    // Check if it is a indirect call.
    const MachineOperand &MO0 = MI->getOperand(0);
    if (MO0.isReg()) {
      int index = X86::NoRegister;
      if (MI->getNumOperands() > 4 && MI->getOperand(1).isImm() &&
          MI->getOperand(2).isReg() && MI->getOperand(3).isImm()) {
        index = MI->getOperand(2).getReg();
      }

      save_rax_before = usesRax(MO0.getReg()) || usesRax(index);
      // Local indirect jumps are always TSX instrumented.
      is_instrumented = true;
      DEBUG(dbgs() << "Call to indirect target based on: " << MO0.getReg() << "\n");
    } else {
      if (MO0.isMCSymbol()) {
        // is_instrumented remains false - these are compiler intrinsics
        // and until we figure out how to correctly handle them, we assume they
        // run outside transactions on concrete values.
        DEBUG(dbgs() << "Call to instrinsic");
        callee_sym = MO0.getMCSymbol();
      } else {
        DEBUG(dbgs() << "Call to function");
        callee_sym = MCIL.GetSymbolFromOperand(MO0);
      }
      std::string callee_name = callee_sym->getName().str();
      DEBUG(dbgs() << ": " << callee_name << "\n");

      is_instrumented = std::binary_search(TaseInstrumentedFunctions.begin(), TaseInstrumentedFunctions.end(), callee_name);
      if (std::binary_search(TaseModeledFunctions.begin(), TaseModeledFunctions.end(), callee_name)) {
        modeled_index = std::lower_bound(TaseModeledFunctions.begin(), TaseModeledFunctions.end(), callee_name) - TaseModeledFunctions.begin();
      }
    }

    if (is_instrumented) {
      DEBUG(dbgs() << "Known instrumented call target\n");
      if (!call_opt) {
        EmitTsxSpringboardJmp("call.begin", "sb_reopen", save_rax_before);
      } else {
        DEBUG(dbgs() << "Optimizing away transaction\n");
      }
    } else {
      DEBUG(dbgs() << "Scaffolding/external call target\n");
      // rax does not need to be saved.  A scaffold call will always return in rax - so rax should be dead.
      // Close previous transaction.
      EmitTsxSpringboardJmp("scaffold.begin", "sb_exittran_wrapped");
    }

    // There was a reason for getting the modeled function index - it was to optimize dispatch of modeled
    // functions.  For now, we just use the RIP of the function to identify the call.  We can return
    // to this when we need to optimize instruction -> IR lookup.
    if (modeled_index >= 0) {
      DEBUG(dbgs() << "Known modeled function\n");

      // Just load the function symbol location in RAX and call our dispatch function
      // with r15 pointed to the actual call instruction.  The interpreter can
      // figure out what the emulated function is being called through RAX.
      EmitAndCountInstruction(MCInstBuilder(X86::LEA64r)
        .addReg(X86::RAX)
        .addReg(X86::RIP)               // base
        .addImm(0)                      // scale
        .addReg(X86::NoRegister)        // index
        .addExpr(MCSymbolRefExpr::create(callee_sym, OutContext))     // disp
        .addReg(X86::NoRegister));      // seg

      EmitAndCountInstruction(MCInstBuilder(X86::LEA64r)
        .addReg(X86::R15)
        .addReg(X86::RIP)               // base
        .addImm(0)                      // scale
        .addReg(X86::NoRegister)        // index
        .addImm(0)                      // disp
        .addReg(X86::NoRegister));      // seg

      MCSymbol *modeled_sym = OutContext.getOrCreateSymbol("sb_enter_modeled");
      EmitAndCountInstruction(MCInstBuilder(X86::CALL64pcrel32)
          .addExpr(MCSymbolRefExpr::create(modeled_sym, OutContext)));
    } else {
      // Ignore shadow map tracking - oh well :(
      MCInst CallInst;
      MCIL.Lower(MI, CallInst);
      EmitAndCountInstruction(CallInst);
    }

    // Check whether we need to save & restore rax after a call instruction.
    MachineBasicBlock::const_iterator MBBI(MI);
    bool save_rax_after = CA.isRAXSrcAfterCall(MBB->getNumber(), std::distance(MBB->begin(), MBBI));
    if (is_instrumented) {
      if (!call_opt) {
        EmitTsxSpringboardJmp("call.end", "sb_reopen", save_rax_after);
      }
    } else {
      // Open/Enter a transaction.
      EmitTsxSpringboardJmp("scaffold.end", "sb_entertran", save_rax_after);
    }

    return false;
  } // end of call-level split

  return true;
}


//===----------------------------------------------------------------------===//
// Poison Checking.
//===----------------------------------------------------------------------===//

/*
  Big picture here is that we add "safe" (doesn't change flags or the output of a program)
  instrumentation whenever an X86_64 instruction directly or indirectly accesses a value from
  memory.

  We perform SIMD-based poison checking by storing the value read from or written to memory in
  a SIMD register, and check it later before the current transaction is committed to
  make sure it isn't poison.

  We assume that registers r14 and r15 are reserved and unavailable to the binary we're instrumenting,
  as done in t-sgx.  We also assume that the SIMD registers are unavailable to the target program,
  since we use them for poison checking.  We're also assuming that alignment is enforced, e.g. that
  quad word values are stored on 8 byte boundaries, longs are stored on 4 byte boundaries, etc;
  we'll need to thing about how to deal with this on packed structs where alignment may be off.
  We further assume that any logical allocation of memory (say an array of bytes or the payload
  of a packet or whatever) is performed at a 2 byte boundary at least.  The reason this is
  required is that right now, we assume a two-byte poison value is used.  This 2 byte value
  is stored repeatedly in XMM7.  We assume that any time a byte value in memory is accessed,
  we can poison the other byte at the nearest 2 byte boundary as well.  The interpreter will
  internally keep track of which of these bytes are actually symbolic and which ones are
  concrete but are being poisoned due to this alignment restriction.

  To avoid issues with checking the alignment of values that are read, we have separate SIMD
  registers for each of the 3 possible data sizes in x86_64.  The result of the poison checks
  are OR'd with XMM1, which serves as an indicator variable that contains at least one "1" value
  if any poison is encountered in a transaction.

  Byte and word (2-byte) values that are read are stored in XMM4.
  Long/double word (4 byte) values are stored in XMM5.
  Quad word (8 byte) values are stored in XMM6.

  The transaction verification code in our springboard assembly file will ensure that these
  registers are zeroed at the end of any transaction.  We do not need to clear the registers
  during a transaction because the presense of poison anywhere in a transaction automatically
  invalidates the entire transaction.

  There are two cases for instrumentation -- the fast case, and the slow case.
  Fast cases are used when we need to instrument an instruction that loads or stores a value
  from/to memory without altering it for the purposes of poison checking.  We have hence
  bypass the need to re-read said value from memory, either before it has been read
  or after it has been written,
  e.g. MOVQ (%r11), %r12 in AT&T syntax.
  In that case, we can just move from r12 into a SIMD register for checking later.

  However, if an instruction doesn't explicitly load a "clean copy" of the memory it operates on,
  e.g. ADDQ $5, (%RAX)
  we need to pay for a load from the address in %RAX to a SIMD register for poison checking
  before the memory value is operated on.  This is the slow case.

  Finally, note that we record the number of values loaded into SIMD registers in SIMD_index_X  based on the size X
  of the value read from memory.  When we've filled up a 128-bit SIMD register, we need to check it for poison before
  we load it with more values.  We do this by checking the values against the poison SIMD register XMM7, and bitwise
  OR-ing the result into XMM1.
*/

// TODO: check that this is OK with bundles!

static const unsigned int MOVrr[] = {X86::MOV8rr, X86::MOV16rr, X86::MOV32rr, X86::MOV64rr};
static const unsigned int MOVrm[] = {X86::MOV8rm, X86::MOV16rm, X86::MOV32rm, X86::MOV64rm};
static const unsigned int PINSR[] = {X86::PINSRBrr, X86::PINSRWrri, X86::PINSRDrr, X86::PINSRQrr};
static const unsigned int R15_SIZED[] = {X86::R15B, X86::R15W, X86::R15D, X86::R15};
// We will never use POISON_STORE[0].  It's just here to make the math easier.
static const unsigned int POISON_STORE[] = {X86::XMM3, X86::XMM4, X86::XMM5, X86::XMM6};
static const unsigned int POISON_REFERENCE = X86::XMM7;
static const unsigned int POISON_ACCUMULATOR = X86::XMM1;
static const unsigned int FAST_OPS[] = {
  // Loads
  X86::MOV64rm, X86::MOV32rm, X86::MOV16rm,
  // X86::MOV8rm,
  X86::POP16r, X86::POP32r, X86::POP64r,
  // X86::MOVZX16rm8, X86::MOVZX32rm8,
  X86::MOVZX32rm16,
  // Stores
  X86::PUSH16r, X86::PUSH32r, X86::PUSH64r
  };


void X86AsmPrinter::EmitPoisonAccumulate(unsigned int offset) {
  if (SimdIndex[offset] == 0) {
    // Compare in 2 byte chunks always!  When reading byte values, we read surrounding
    // byte as well.
    EmitAndCountInstruction(MCInstBuilder(X86::PCMPEQWrr)
      .addReg(POISON_STORE[offset])
      .addReg(POISON_STORE[offset])
      .addReg(POISON_REFERENCE));
    EmitAndCountInstruction(MCInstBuilder(X86::PORrr)
      .addReg(POISON_ACCUMULATOR)
      .addReg(POISON_ACCUMULATOR)
      .addReg(POISON_STORE[offset]));
  }
}

void X86AsmPrinter::EmitPoisonCheck(const MachineInstr *MI, X86MCInstLower &MCIL, bool isFastPath) {
  assert((MI->mayLoad() || MI->mayStore()) &&
        "Non memory instruction cannot be instrumented for poison accumulation");

  unsigned int regSize = 0;
  unsigned int offset = 0;

  if (!MI->memoperands_empty()) {
    regSize = (*MI->memoperands_begin())->getSize();
    if (regSize > 8) {
      errs() << "TASE: Found large size register (possibly SSE) \n";
      return;
    }
    offset = getOffsetForSize(regSize);
    
    if (!regSize) {
      errs() << "TASE: Instruction has zero-size memory operand:  " << *MI;
      errs() << "  -> operand is:  " << *(*MI->memoperands_begin());
    }
  } else {
    errs() << "TASE: Instruction has no memory operands:  " << *MI;
  }

  if (!isFastPath && !regSize) {
    // Weird... we have an operation that might read but we can't recognize it.
    errs() << "TASE: Unrecognized operation that reads from memory:  " << *MI;
    // Disabling the panic here because we don't handle implicit memory operands from idiv32 yet.
    // llvm_unreachable("Unrecognized operation that reads from memory");
    return;
  }

  if (isFastPath) {
    // In case the read involved sign extension or one of the "h" registers,
    // just move the value into r15 temporarily.  Then we can only use
    // the size of memory that was read from/written to to compute the taint size.
    unsigned newReg = MI->getOperand(0).getReg();
    unsigned newSize = getPhysRegSize(newReg);

    //ABH & Kartik added 10/19 for implicit loads of mov32rm into eax.
    if (!newSize) {
      switch (MI->getOpcode()) {
      case (X86::MOV32rm):
	newSize =4;
	newReg = X86::EAX;
	break;
      default:
	newSize = 0;
      } 
    }

    unsigned newOffset = getOffsetForSize(newSize);
    
    
    // If regSize is unavailable due to implicit operands (pop for example),
    // assign it here.
    if (regSize <= 1) {
      regSize = newSize;
      offset = newOffset;
    }

    if (regSize <= 1) {
      errs() << "ERROR  in fast path with regSize \n";
      MI->dump();
    }
    
    
    assert(regSize > 0 && "TASE: We should have some size information to poison check an instruction");
    assert(regSize > 1 && "TASE: We should not be in the fast path unless we have at-least 2 bytes");
    EmitAndCountInstruction(MCInstBuilder(MOVrr[newOffset])
			    .addReg(R15_SIZED[newOffset])
			    .addReg(newReg));
  } else {
    assert(regSize > 0 && "TASE: We should have some size information to poison check an instruction");
    // Slow case
    // The second parameter (opcode) is unused on x86.
    int firstOpIndex = X86II::getMemoryOperandNo(MI->getDesc().TSFlags, 0);
    firstOpIndex += X86II::getOperandBias(MI->getDesc());

    // The displacement could be an immediate or a symbol expression.  So explicitly
    // lower it using our MCIL.
    const MachineOperand &MODisp = MI->getOperand(firstOpIndex + X86::AddrDisp);
    // For a byte value access, perform an aligned 2 byte read instead by using a
    // lea (address expression), r15
    // and then carefuly mask out the bottom bit of the address without affecting
    // any flags.  The address is calculated identically in both cases before masking
    // is applied.
    const unsigned int firstOpcode = (regSize == 1) ? static_cast<unsigned int>(X86::LEA64r) : MOVrm[offset];
    const unsigned int destReg = (regSize == 1) ? static_cast<unsigned int>(X86::R15) : R15_SIZED[offset];

    EmitAndCountInstruction(MCInstBuilder(firstOpcode)
      .addReg(destReg)
      .addReg(MI->getOperand(firstOpIndex + X86::AddrBaseReg).getReg())      // BaseReg
      .addImm(MI->getOperand(firstOpIndex + X86::AddrScaleAmt).getImm())     // Scale
      .addReg(MI->getOperand(firstOpIndex + X86::AddrIndexReg).getReg())     // IndexReg
      .addOperand(MCIL.LowerMachineOperand(MI, MODisp).getValue())           // Displacement
      .addReg(MI->getOperand(firstOpIndex + X86::AddrSegmentReg).getReg())); // SegmentReg

    if (regSize == 1) {
      // Shift the address right by one, then left by one to clear the bottom bit without
      // setting any EFLAGS.  This uses BMI2 instructions and uses r14 (which is otherwise
      // used to save rax across transaction boundaries).  We can assume that r14 is available
      // to us because we are not in the fast path (and hence running before the instruction
      // is emitted) and transaction batching is performed after this step.
      //
      // I believe we can also get this flag preserving
      // behavior in two other ways:
      // a) Manually saving the flags to memory and using andq (which is super slow)
      // b) Using pinsr and pandn to load the address in xmm3 and then mask out
      // the address using SIMD instructions (slightly faster).
      // TODO: Optimization opportunity: If we run our backwards liveness analysis and
      // conclude the EFLAGS is not live, we can use and -2, r15 directly.
      // TODO: Optimization opportunity: If we are using a fixed displacement with no offset
      // or can verify that the offset has no base register and scale is > 2, then we can
      // completely bypass this and statically emit a 2-byte aligned address.
      EmitAndCountInstruction(MCInstBuilder(X86::MOV32ri)
          .addReg(X86::R14D)
          .addImm(1));
      EmitAndCountInstruction(MCInstBuilder(X86::SHRX64rr)
          .addReg(X86::R15)
          .addReg(X86::R15)
          .addReg(X86::R14));
      EmitAndCountInstruction(MCInstBuilder(X86::SHLX64rr)
          .addReg(X86::R15)
          .addReg(X86::R15)
          .addReg(X86::R14));
      // Dereference the aligned address and reset regSize so that it gets handles as a
      // 2 byte read down below.
      EmitAndCountInstruction(MCInstBuilder(X86::MOV16rm)
          .addReg(X86::R15W)
          .addReg(X86::R15)          // BaseReg
          .addImm(0)                 // Scale
          .addReg(X86::NoRegister)   // IndexReg
          .addImm(0)                 // Displacement
          .addReg(X86::NoRegister)); // SegmentReg

      regSize = 2;
    }
  }

  // TODO: Use OutStreamer->AddComment to annotate cache way usage to help debuging this.

  // PINSR always takes 32-bit operand name except for PINSRQ.
  EmitAndCountInstruction(MCInstBuilder(PINSR[offset])
    .addReg(POISON_STORE[offset])
    .addReg(POISON_STORE[offset])
    .addReg(offset == 3 ? X86::R15 : X86::R15D)
    .addImm(SimdIndex[offset]));

  // Increment our save index and do a poison check now if we've filled up our poison register.
  SimdIndex[offset] = (SimdIndex[offset] + 1) % (16 / regSize);
  EmitPoisonAccumulate(offset);
}


// This function is run twice - once before and once after instruction emission.
void X86AsmPrinter::EmitPoisonInstrumentation(const MachineInstr *MI, X86MCInstLower &MCIL, bool before) {
  // We check both reads and writes for taint.
  // Idea here is to make sure we don't write a
  // concrete poison value to memory, since interpreter
  // wouldn't be able to tell if the destination had been
  // concretized.

  // These are some special and common "fast-case" operations, where
  // we can grab the value read from memory after it's stored in a register
  // or grab a value register value being written to memory after it executes
  // and store it for poison checking.  That's a LOT faster than paying for
  // an extra read from memory.  At some point we'll want to try and include
  // more instructions for this optimization.
  bool isFastPath = std::find(std::begin(FAST_OPS), std::end(FAST_OPS), MI->getOpcode()) != std::end(FAST_OPS);
  // Fast path instructions are checked after they are run. Hence delay any other
  // fall-through block termination poison accumulation logic until after the instruction.
  // Normal load checking occurs before the instruction executes.  Normal store check
  // occurs after the instruction executes.  Don't re-examine the instruction otherwise.
  // Never process instructions that neither loads nor stores unless its a control flow
  // instruction.
  bool needsCheck = false;

  // TODO: More special instructions - like idiv or (rep) movs
  if (isFastPath) {
    needsCheck = !before;
  } else if (MI->isTerminator() || MI->isCall()) {
    // Well I guess we could jmp using a symbolic address - but ignore that
    // for now.
  } else if (before) {
    if (MI->mayLoad() && MI->mayStore()) {
      DEBUG(dbgs() << "TASE: Instruction both loads and stores.  Check output:");
      DEBUG(MI->dump());
    }
    needsCheck = MI->mayLoad();
  } else {
    needsCheck = MI->mayStore();
  }

  if (needsCheck) {
    DEBUG(dbgs() << "TASE: Inserting poison check " << (before ? "before :" : "after :"));
    DEBUG(MI->dump());
    EmitPoisonCheck(MI, MCIL, isFastPath);
  }

  bool needsAccumulate = false;
  const MachineInstr &LastMI = MI->getParent()->instr_back();
  if (MI->isTerminator() || MI->isCall()) {
    // All instructions that alter control flow must check for poison
    // and clear the accumulator registers before the instruction is executed.
    needsAccumulate = before;
  } else if (MI == &LastMI) {
    // For a non-branching instruction at the end of a block (i.e. a
    // fallthrough basic block), accumulate after the instruction in case
    // we checked for poison after it.
    needsAccumulate = !before;
  }

  if (needsAccumulate) {
    for (unsigned int i = 0; i < sizeof(SimdIndex)/sizeof(SimdIndex[0]); i++) {
      // If the index is 0, then the accumulator has either not been used in
      // this basic block or it has already been verified as part of a poison check.
      if (SimdIndex[i] != 0) {
        SimdIndex[i] = 0;
        EmitPoisonAccumulate(i);
      }
    }
  }
}

#undef DEBUG_TYPE

// This is where the upstream LLVM code begins for EmitInstruction.
void X86AsmPrinter::EmitInstructionCore(const MachineInstr *MI, X86MCInstLower &MCInstLowering) {
  const X86RegisterInfo *RI = MF->getSubtarget<X86Subtarget>().getRegisterInfo();

  switch (MI->getOpcode()) {
  case TargetOpcode::DBG_VALUE:
    llvm_unreachable("Should be handled target independently");

  // Emit nothing here but a comment if we can.
  case X86::Int_MemBarrier:
    OutStreamer->emitRawComment("MEMBARRIER");
    return;


  case X86::EH_RETURN:
  case X86::EH_RETURN64: {
    // Lower these as normal, but add some comments.
    unsigned Reg = MI->getOperand(0).getReg();
    OutStreamer->AddComment(StringRef("eh_return, addr: %") +
                            X86ATTInstPrinter::getRegisterName(Reg));
    break;
  }
  case X86::TAILJMPr:
  case X86::TAILJMPm:
  case X86::TAILJMPd:
  case X86::TAILJMPr64:
  case X86::TAILJMPm64:
  case X86::TAILJMPd64:
  case X86::TAILJMPr64_REX:
  case X86::TAILJMPm64_REX:
  case X86::TAILJMPd64_REX:
    // Lower these as normal, but add some comments.
    OutStreamer->AddComment("TAILCALL");
    break;

  case X86::TLS_addr32:
  case X86::TLS_addr64:
  case X86::TLS_base_addr32:
  case X86::TLS_base_addr64:
    return LowerTlsAddr(MCInstLowering, *MI);

  case X86::MOVPC32r: {
    // This is a pseudo op for a two instruction sequence with a label, which
    // looks like:
    //     call "L1$pb"
    // "L1$pb":
    //     popl %esi

    // Emit the call.
    MCSymbol *PICBase = MF->getPICBaseSymbol();
    // FIXME: We would like an efficient form for this, so we don't have to do a
    // lot of extra uniquing.
    EmitAndCountInstruction(MCInstBuilder(X86::CALLpcrel32)
      .addExpr(MCSymbolRefExpr::create(PICBase, OutContext)));

    // Emit the label.
    OutStreamer->EmitLabel(PICBase);

    // popl $reg
    EmitAndCountInstruction(MCInstBuilder(X86::POP32r)
                            .addReg(MI->getOperand(0).getReg()));
    return;
  }

  case X86::ADD32ri: {
    // Lower the MO_GOT_ABSOLUTE_ADDRESS form of ADD32ri.
    if (MI->getOperand(2).getTargetFlags() != X86II::MO_GOT_ABSOLUTE_ADDRESS)
      break;

    // Okay, we have something like:
    //  EAX = ADD32ri EAX, MO_GOT_ABSOLUTE_ADDRESS(@MYGLOBAL)

    // For this, we want to print something like:
    //   MYGLOBAL + (. - PICBASE)
    // However, we can't generate a ".", so just emit a new label here and refer
    // to it.
    MCSymbol *DotSym = OutContext.createTempSymbol();
    OutStreamer->EmitLabel(DotSym);

    // Now that we have emitted the label, lower the complex operand expression.
    MCSymbol *OpSym = MCInstLowering.GetSymbolFromOperand(MI->getOperand(2));

    const MCExpr *DotExpr = MCSymbolRefExpr::create(DotSym, OutContext);
    const MCExpr *PICBase =
      MCSymbolRefExpr::create(MF->getPICBaseSymbol(), OutContext);
    DotExpr = MCBinaryExpr::createSub(DotExpr, PICBase, OutContext);

    DotExpr = MCBinaryExpr::createAdd(MCSymbolRefExpr::create(OpSym,OutContext),
                                      DotExpr, OutContext);

    EmitAndCountInstruction(MCInstBuilder(X86::ADD32ri)
      .addReg(MI->getOperand(0).getReg())
      .addReg(MI->getOperand(1).getReg())
      .addExpr(DotExpr));
    return;
  }
  case TargetOpcode::STATEPOINT:
    return LowerSTATEPOINT(*MI, MCInstLowering);

  case TargetOpcode::FAULTING_LOAD_OP:
    return LowerFAULTING_LOAD_OP(*MI, MCInstLowering);

  case TargetOpcode::STACKMAP:
    return LowerSTACKMAP(*MI);

  case TargetOpcode::PATCHPOINT:
    return LowerPATCHPOINT(*MI, MCInstLowering);

  case X86::MORESTACK_RET:
    EmitAndCountInstruction(MCInstBuilder(getRetOpcode(*Subtarget)));
    return;

  case X86::MORESTACK_RET_RESTORE_R10:
    // Return, then restore R10.
    EmitAndCountInstruction(MCInstBuilder(getRetOpcode(*Subtarget)));
    EmitAndCountInstruction(MCInstBuilder(X86::MOV64rr)
                            .addReg(X86::R10)
                            .addReg(X86::RAX));
    return;

  case X86::SEH_PushReg:
    OutStreamer->EmitWinCFIPushReg(RI->getSEHRegNum(MI->getOperand(0).getImm()));
    return;

  case X86::SEH_SaveReg:
    OutStreamer->EmitWinCFISaveReg(RI->getSEHRegNum(MI->getOperand(0).getImm()),
                                   MI->getOperand(1).getImm());
    return;

  case X86::SEH_SaveXMM:
    OutStreamer->EmitWinCFISaveXMM(RI->getSEHRegNum(MI->getOperand(0).getImm()),
                                   MI->getOperand(1).getImm());
    return;

  case X86::SEH_StackAlloc:
    OutStreamer->EmitWinCFIAllocStack(MI->getOperand(0).getImm());
    return;

  case X86::SEH_SetFrame:
    OutStreamer->EmitWinCFISetFrame(RI->getSEHRegNum(MI->getOperand(0).getImm()),
                                    MI->getOperand(1).getImm());
    return;

  case X86::SEH_PushFrame:
    OutStreamer->EmitWinCFIPushFrame(MI->getOperand(0).getImm());
    return;

  case X86::SEH_EndPrologue:
    OutStreamer->EmitWinCFIEndProlog();
    return;

  case X86::SEH_Epilogue: {
    MachineBasicBlock::const_iterator MBBI(MI);
    // Check if preceded by a call and emit nop if so.
    for (MBBI = PrevCrossBBInst(MBBI); MBBI; MBBI = PrevCrossBBInst(MBBI)) {
      // Conservatively assume that pseudo instructions don't emit code and keep
      // looking for a call. We may emit an unnecessary nop in some cases.
      if (!MBBI->isPseudo()) {
        if (MBBI->isCall())
          EmitAndCountInstruction(MCInstBuilder(X86::NOOP));
        break;
      }
    }
    return;
  }

    // Lower PSHUFB and VPERMILP normally but add a comment if we can find
    // a constant shuffle mask. We won't be able to do this at the MC layer
    // because the mask isn't an immediate.
  case X86::PSHUFBrm:
  case X86::VPSHUFBrm:
  case X86::VPSHUFBYrm: {
    if (!OutStreamer->isVerboseAsm())
      break;
    assert(MI->getNumOperands() > 5 &&
           "We should always have at least 5 operands!");
    const MachineOperand &DstOp = MI->getOperand(0);
    const MachineOperand &SrcOp = MI->getOperand(1);
    const MachineOperand &MaskOp = MI->getOperand(5);

    if (auto *C = getConstantFromPool(*MI, MaskOp)) {
      SmallVector<int, 16> Mask;
      DecodePSHUFBMask(C, Mask);
      if (!Mask.empty())
        OutStreamer->AddComment(getShuffleComment(DstOp, SrcOp, Mask));
    }
    break;
  }
  case X86::VPERMILPSrm:
  case X86::VPERMILPDrm:
  case X86::VPERMILPSYrm:
  case X86::VPERMILPDYrm: {
    if (!OutStreamer->isVerboseAsm())
      break;
    assert(MI->getNumOperands() > 5 &&
           "We should always have at least 5 operands!");
    const MachineOperand &DstOp = MI->getOperand(0);
    const MachineOperand &SrcOp = MI->getOperand(1);
    const MachineOperand &MaskOp = MI->getOperand(5);

    if (auto *C = getConstantFromPool(*MI, MaskOp)) {
      SmallVector<int, 16> Mask;
      DecodeVPERMILPMask(C, Mask);
      if (!Mask.empty())
        OutStreamer->AddComment(getShuffleComment(DstOp, SrcOp, Mask));
    }
    break;
  }

    // For loads from a constant pool to a vector register, print the constant
    // loaded.
  case X86::MOVAPDrm:
  case X86::VMOVAPDrm:
  case X86::VMOVAPDYrm:
  case X86::MOVUPDrm:
  case X86::VMOVUPDrm:
  case X86::VMOVUPDYrm:
  case X86::MOVAPSrm:
  case X86::VMOVAPSrm:
  case X86::VMOVAPSYrm:
  case X86::MOVUPSrm:
  case X86::VMOVUPSrm:
  case X86::VMOVUPSYrm:
  case X86::MOVDQArm:
  case X86::VMOVDQArm:
  case X86::VMOVDQAYrm:
  case X86::MOVDQUrm:
  case X86::VMOVDQUrm:
  case X86::VMOVDQUYrm:
    if (!OutStreamer->isVerboseAsm())
      break;
    if (MI->getNumOperands() > 4)
    if (auto *C = getConstantFromPool(*MI, MI->getOperand(4))) {
      std::string Comment;
      raw_string_ostream CS(Comment);
      const MachineOperand &DstOp = MI->getOperand(0);
      CS << X86ATTInstPrinter::getRegisterName(DstOp.getReg()) << " = ";
      if (auto *CDS = dyn_cast<ConstantDataSequential>(C)) {
        CS << "[";
        for (int i = 0, NumElements = CDS->getNumElements(); i < NumElements; ++i) {
          if (i != 0)
            CS << ",";
          if (CDS->getElementType()->isIntegerTy())
            CS << CDS->getElementAsInteger(i);
          else if (CDS->getElementType()->isFloatTy())
            CS << CDS->getElementAsFloat(i);
          else if (CDS->getElementType()->isDoubleTy())
            CS << CDS->getElementAsDouble(i);
          else
            CS << "?";
        }
        CS << "]";
        OutStreamer->AddComment(CS.str());
      } else if (auto *CV = dyn_cast<ConstantVector>(C)) {
        CS << "<";
        for (int i = 0, NumOperands = CV->getNumOperands(); i < NumOperands; ++i) {
          if (i != 0)
            CS << ",";
          Constant *COp = CV->getOperand(i);
          if (isa<UndefValue>(COp)) {
            CS << "u";
          } else if (auto *CI = dyn_cast<ConstantInt>(COp)) {
            CS << CI->getZExtValue();
          } else if (auto *CF = dyn_cast<ConstantFP>(COp)) {
            SmallString<32> Str;
            CF->getValueAPF().toString(Str);
            CS << Str;
          } else {
            CS << "?";
          }
        }
        CS << ">";
        OutStreamer->AddComment(CS.str());
      }
    }
    break;
  }

  MCInst TmpInst;
  MCInstLowering.Lower(MI, TmpInst);

  // Stackmap shadows cannot include branch targets, so we can count the bytes
  // in a call towards the shadow, but must ensure that the no thread returns
  // in to the stackmap shadow.  The only way to achieve this is if the call
  // is at the end of the shadow.
  if (MI->isCall()) {
    // Count then size of the call towards the shadow
    SMShadowTracker.count(TmpInst, getSubtargetInfo());
    // Then flush the shadow so that we fill with nops before the call, not
    // after it.
    SMShadowTracker.emitShadowPadding(*OutStreamer, getSubtargetInfo());
    // Then emit the call
    OutStreamer->EmitInstruction(TmpInst, getSubtargetInfo());
    return;
  }
  //printf(" Pre-emit and count : \n");
  //MI->dump();
  EmitAndCountInstruction(TmpInst);
}
