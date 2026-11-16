// SPDX-License-Identifier: BSD-2-Clause-Patent

#define THOR_FULL_RAM_REQUESTED  BIT57
#define THOR_FULL_RAM_RESERVED   BIT58
#define THOR_FULL_RAM_TRANSLATED BIT59
#define THOR_FULL_RAM_TOUCHED    BIT60
#define THOR_FULL_RAM_ACCEPTED   BIT61
#define THOR_FULL_RAM_HANDED_OFF BIT62

UINT32 EFIAPI ThorHighRamTouch (UINT64 Address);
extern CONST UINT8 ThorHighRamTouchLoad;
extern CONST UINT8 ThorHighRamTouchStore;
extern CONST UINT8 ThorHighRamTouchFailure;

STATIC volatile UINT64 mHighRamTouchAddress;

STATIC VOID EFIAPI
ThorHighRamFault (
  EFI_EXCEPTION_TYPE ExceptionType,
  EFI_SYSTEM_CONTEXT SystemContext
  )
{
  EFI_SYSTEM_CONTEXT_AARCH64 *Context = SystemContext.SystemContextAArch64;
  CONST UINT64 Load = (UINTN)&ThorHighRamTouchLoad;
  CONST UINT64 Store = (UINTN)&ThorHighRamTouchStore;
  CONST UINT64 Address = mHighRamTouchAddress;
  // Recover only from a data abort on our exact bounded load or store.
  // A fault without a valid FAR is still tied to the access by x0 and ELR.
  if (ExceptionType == EXCEPT_AARCH64_SYNCHRONOUS_EXCEPTIONS &&
      Context != NULL && Address != 0 && Context->X0 == Address &&
      ((Context->ESR >> 26) & 0x3F) == 0x25 &&
      ((Context->ESR & BIT10) || Context->FAR == Address) &&
      (Context->ELR == Load || Context->ELR == Store)) {
    Context->ELR = (UINTN)&ThorHighRamTouchFailure;
    return;
  }
  CpuDeadLoop ();
}

STATIC BOOLEAN
ThorFullRamPageTranslated (UINT64 Address)
{
  UINT64 ReadPar, WritePar;

  ThorAuditTranslateReadWrite (Address, &ReadPar, &WritePar);
  return ThorLowTranslation (Address, ReadPar) && ThorLowTranslation (Address, WritePar);
}

STATIC BOOLEAN
ThorFullRamCheckAccess (THOR_MEMORY_AUDIT *Audit, UINT64 Start, UINT64 Limit)
{
  EFI_CPU_ARCH_PROTOCOL *Cpu;
  EFI_TPL OldTpl;
  EFI_STATUS Status;
  BOOLEAN Ready = TRUE;

  if (DarwinCurrentEl () != 4 || !(READ_SYSREG (sctlr_el1) & 1)) {
    return FALSE;
  }
  for (UINT64 Address = Start; Address < Limit; Address += BLOCK_SIZE) {
    if (!ThorFullRamPageTranslated (Address) ||
        !ThorFullRamPageTranslated (Address + BLOCK_SIZE - EFI_PAGE_SIZE)) {
      return FALSE;
    }
  }
  Audit->Flags |= THOR_FULL_RAM_TRANSLATED;

  Status = gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **)&Cpu);
  if (EFI_ERROR (Status) || Cpu == NULL || Cpu->RegisterInterruptHandler == NULL) {
    return FALSE;
  }
  // Run only on the EFI boot CPU, without event callbacks during the test.
  OldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);
  Status = Cpu->RegisterInterruptHandler (Cpu, EXCEPT_AARCH64_SYNCHRONOUS_EXCEPTIONS, ThorHighRamFault);
  if (EFI_ERROR (Status)) {
    gBS->RestoreTPL (OldTpl);
    return FALSE;
  }
  for (UINT64 Address = Start; Address < Limit; Address += BLOCK_SIZE) {
    mHighRamTouchAddress = Address;
    if (!ThorHighRamTouch (mHighRamTouchAddress)) {
      Ready = FALSE;
      break;
    }
    mHighRamTouchAddress = Address + BLOCK_SIZE - EFI_PAGE_SIZE;
    if (!ThorHighRamTouch (mHighRamTouchAddress)) {
      Ready = FALSE;
      break;
    }
  }
  mHighRamTouchAddress = 0;
  Status = Cpu->RegisterInterruptHandler (Cpu, EXCEPT_AARCH64_SYNCHRONOUS_EXCEPTIONS, NULL);
  gBS->RestoreTPL (OldTpl);
  return Ready && !EFI_ERROR (Status);
}

STATIC BOOLEAN
ThorFullRamDisjoint (
  CONST PONG_RAM_BANK *Owned,
  UINTN Count,
  CONST UINT64 Video[6], UINT64 Start, UINT64 Limit
  )
{
  if (Count == 0 || Count > PONG_RAM_MAX - 2) {
    return FALSE;
  }
  if (Video[0] && (!Video[2] || !Video[4] ||
      Video[4] > (MAX_UINT64 - Video[0]) / Video[2] ||
      ThorLowOverlap (Start, Limit - Start, Video[0], Video[2] * Video[4]))) {
    return FALSE;
  }
  for (UINTN Index = 0; Index < Count; Index++) {
    if (ThorLowOverlap (Start, Limit - Start, Owned[Index].Start, Owned[Index].Size)) {
      return FALSE;
    }
  }
  return TRUE;
}
