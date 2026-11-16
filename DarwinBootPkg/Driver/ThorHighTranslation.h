// SPDX-License-Identifier: BSD-2-Clause-Patent
// Temporarily install stage-1 translations for Bank B. AT probes translation
// only. No instruction reads or writes the candidate and no EFI resource is
// added. The original live table entry is restored before freeing the table.

// Bits 29–34 in the wire receipt already describe the low-memory lease.
#define THOR_HIGH_REQUESTED BIT37
#define THOR_HIGH_SOURCES   BIT38
#define THOR_HIGH_GEOMETRY  BIT39
#define THOR_HIGH_UNMAPPED  BIT40
#define THOR_HIGH_RO_WB     BIT41
#define THOR_HIGH_RESTORED  BIT42

#define THOR_HIGH_TT_TABLE  3ULL
#define THOR_HIGH_TT_BLOCK  (BIT54 | BIT53 | BIT10 | BIT9 | BIT8 | BIT7 | BIT0)
#define THOR_HIGH_TCR_WB    (BIT13 | BIT12 | BIT10 | BIT8)

STATIC BOOLEAN
ThorHighPageWb (UINT64 Page, UINT64 Par)
{
  return !(Par & 1) && (Par & THOR_AUDIT_PHYS_PAGE_MASK) == Page &&
         (Par >> 56) == 0xff && (Par & 0x180) == 0x180;
}

STATIC BOOLEAN
ThorHighTablePage (UINT64 Page)
{
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR Gcd;
  UINT64 ReadPar, WritePar;
  if (!Page || (Page & EFI_PAGE_MASK) || Page >= BASE_4GB ||
      gDS == NULL || gDS->GetMemorySpaceDescriptor == NULL ||
      EFI_ERROR (gDS->GetMemorySpaceDescriptor (Page, &Gcd)) ||
      Gcd.GcdMemoryType != EfiGcdMemoryTypeSystemMemory ||
      Gcd.BaseAddress > MAX_UINT64 - Gcd.Length ||
      !ThorAuditInside (Page, EFI_PAGE_SIZE, Gcd.BaseAddress, Gcd.BaseAddress + Gcd.Length)) {
    return FALSE;
  }
  ThorAuditTranslateReadWrite (Page, &ReadPar, &WritePar);
  return ThorHighPageWb (Page, ReadPar) && ThorHighPageWb (Page, WritePar);
}

STATIC volatile UINT64 *
ThorHighTableSlot (UINT64 Tcr, UINT64 Ttbr)
{
  const UINT64 WalkMask = BIT15 | BIT14 | BIT13 | BIT12 | BIT11 | BIT10 | BIT9 | BIT8 | BIT7;
  UINTN VaBits = 64 - (Tcr & 63);
  UINT64 Page = Ttbr & THOR_AUDIT_PHYS_PAGE_MASK;
  if (VaBits < 36 || VaBits > 48 || (Tcr & BIT59) ||
      (Tcr & WalkMask) != THOR_HIGH_TCR_WB || (Ttbr & 0xffe) ||
      !ThorHighTablePage (Page)) {
    return NULL;
  }
  if (VaBits > 39) {
    UINT64 Entry = *(CONST volatile UINT64 *)(UINTN)Page;
    if ((Entry & ~THOR_AUDIT_PHYS_PAGE_MASK) != THOR_HIGH_TT_TABLE) {
      return NULL;
    }
    Page = Entry & THOR_AUDIT_PHYS_PAGE_MASK;
    if (!ThorHighTablePage (Page)) {
      return NULL;
    }
  }
  // 0x840000000 is in L1 slot 33, distinct from the 0x800000000 RAM slot.
  return (volatile UINT64 *)(UINTN)Page + ((THOR_AUDIT_B_BASE >> 30) & 511);
}

STATIC VOID
ThorHighSetSlot (volatile UINT64 *Slot, UINT64 Value)
{
  *Slot = Value;
  // The page-table walker is inner-shareable and WB. No firmware calls
  // or allocator operations are allowed while the temporary entry is live.
  __asm__ __volatile__ ("dsb ishst\n\t"
                        "tlbi vmalle1is\n\t"
                        "dsb ish\n\t"
                        "isb" ::: "memory");
}

STATIC BOOLEAN
ThorHighAtFailed (UINT64 Page, UINT32 Fault)
{
  UINT64 ReadPar, WritePar;
  ThorAuditTranslateReadWrite (Page, &ReadPar, &WritePar);
  return (ReadPar & 0x37f) == ((Fault << 1) | 1) &&
         (WritePar & 0x37f) == ((Fault << 1) | 1);
}

STATIC BOOLEAN
ThorHighAtReadOnly (UINT64 Page)
{
  UINT64 ReadPar, WritePar;
  ThorAuditTranslateReadWrite (Page, &ReadPar, &WritePar);
  return ThorHighPageWb (Page, ReadPar) && (WritePar & 0x37f) == 0x1d;
}

STATIC BOOLEAN
ThorHighCandidateAbsent (CONST THOR_MEMORY_AUDIT *Audit, CONST EFI_MEMORY_DESCRIPTOR *Map,
                         UINTN MapSize, UINTN Stride)
{
  if (Audit->FdtStatus != 0 || Audit->FdtHits != 1 || Audit->ReservedHits ||
      EFI_ERROR (Audit->SmemStatus) || Audit->SmemVersion != 3 ||
      Audit->SmemHits != 1 || Audit->SmemBase != THOR_AUDIT_B_BASE ||
      Audit->SmemDomain != 0 || Audit->SmemAttribute != 1 ||
      !(Audit->Flags & THOR_AUDIT_SMEM_B_AVAILABLE) ||
      EFI_ERROR (Audit->GcdStatus) || !(Audit->Flags & 0x40ULL) ||
      Audit->Gcd.GcdMemoryType != EfiGcdMemoryTypeNonExistent ||
      !Map || Stride < sizeof (*Map) || MapSize % Stride) {
    return FALSE;
  }
  for (UINTN Offset = 0; Offset < MapSize; Offset += Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *D = (CONST VOID *)((CONST UINT8 *)Map + Offset);
    UINT64 End;
    if (!DescriptorEnd (D, &End) ||
        (D->PhysicalStart < THOR_AUDIT_B_BASE + THOR_AUDIT_B_BYTES && End > THOR_AUDIT_B_BASE)) {
      return FALSE;
    }
  }
  return TRUE;
}

STATIC VOID
ThorHighProbe (THOR_MEMORY_AUDIT *Audit, CONST EFI_MEMORY_DESCRIPTOR *Map, UINTN MapSize, UINTN Stride)
{
  const UINT64 LastPage = THOR_AUDIT_B_BASE + THOR_AUDIT_B_BYTES - EFI_PAGE_SIZE;
  EFI_PHYSICAL_ADDRESS Table = BASE_4GB - 1;
  UINT64 Tcr, Ttbr, Mair, Daif;
  UINTN AttrIndex;
  volatile UINT64 *Slot;
  BOOLEAN ReadOnly, KeepTable = FALSE;

  if (DarwinCurrentEl () != 4 || !(READ_SYSREG (sctlr_el1) & 1) ||
      !ThorHighCandidateAbsent (Audit, Map, MapSize, Stride)) {
    return;
  }
  Audit->Flags |= THOR_HIGH_SOURCES;
  Tcr = READ_SYSREG (tcr_el1);
  Ttbr = READ_SYSREG (ttbr0_el1);
  Mair = READ_SYSREG (mair_el1);
  Slot = ThorHighTableSlot (Tcr, Ttbr);
  for (AttrIndex = 0; AttrIndex < 8; AttrIndex++) {
    if (((Mair >> (8 * AttrIndex)) & 0xff) == 0xff) {
      break;
    }
  }
  if (!Slot || *Slot || AttrIndex == 8 ||
      EFI_ERROR (gBS->AllocatePages (AllocateMaxAddress, EfiLoaderData, 1, &Table))) {
    return;
  }
  if (!ThorHighTablePage (Table)) {
    gBS->FreePages (Table, 1);
    return;
  }
  Audit->Flags |= THOR_HIGH_GEOMETRY;

  UINT64 *Blocks = (UINT64 *)(UINTN)Table;
  ZeroMem (Blocks, EFI_PAGE_SIZE);
  for (UINTN Index = 0; Index < THOR_AUDIT_B_BYTES / SIZE_2MB; Index++) {
    Blocks[Index] = (THOR_AUDIT_B_BASE + Index * SIZE_2MB) | (AttrIndex << 2) | THOR_HIGH_TT_BLOCK;
  }
  FlushRange (Table, EFI_PAGE_SIZE);

  // The expected status code for the vacant L1 entry is a level-1 walk
  // fault. Once installed, reads must return the same WB PA, and writes
  // must fail with a permission fault at L2. No target data access is needed.
  __asm__ __volatile__ ("mrs %0, daif\n\t"
                        "msr daifset, #15\n\t"
                        "isb" : "=r"(Daif) :: "memory");
  if (Tcr == READ_SYSREG (tcr_el1) && Ttbr == READ_SYSREG (ttbr0_el1) &&
      Mair == READ_SYSREG (mair_el1) && *Slot == 0 &&
      ThorHighAtFailed (THOR_AUDIT_B_BASE, 5) && ThorHighAtFailed (LastPage, 5)) {
    Audit->Flags |= THOR_HIGH_UNMAPPED;
    ThorHighSetSlot (Slot, Table | THOR_HIGH_TT_TABLE);
    ReadOnly = TRUE;
    for (UINT64 Page = THOR_AUDIT_B_BASE; Page <= LastPage; Page += SIZE_2MB) {
      if (!ThorHighAtReadOnly (Page) || !ThorHighAtReadOnly (Page + SIZE_2MB - EFI_PAGE_SIZE)) {
        ReadOnly = FALSE;
        break;
      }
    }
    ThorHighSetSlot (Slot, 0);
    KeepTable = TRUE;
    if (ReadOnly) {
      Audit->Flags |= THOR_HIGH_RO_WB;
    }
    if (*Slot == 0 && ThorHighAtFailed (THOR_AUDIT_B_BASE, 5) && ThorHighAtFailed (LastPage, 5)) {
      Audit->Flags |= THOR_HIGH_RESTORED;
      KeepTable = FALSE;
    }
  }
  __asm__ __volatile__ ("msr daif, %0\n\t"
                        "isb" :: "r"(Daif) : "memory");
  if (!KeepTable) {
    gBS->FreePages (Table, 1);
  }
  Print (L"THOR MEM: B temporary EL1 translation flags=%lx\n", Audit->Flags);
}
