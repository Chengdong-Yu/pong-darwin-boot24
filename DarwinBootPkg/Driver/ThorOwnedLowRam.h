// SPDX-License-Identifier: BSD-2-Clause-Patent
// Opt-in Thor DXE heap lease. Only already-present, mapped, conventional
// pages can be leased. The accepted ExitBootServices map decides handoff.

#define THOR_LOW_LEASE_BYTES SIZE_16MB
#define THOR_LOW_EXPANDED_BYTES (SIZE_32MB + SIZE_4MB)
#define THOR_LOW_HEADROOM    SIZE_64MB

STATIC BOOLEAN
ThorLowOverlap (UINT64 First, UINT64 Size, UINT64 Other, UINT64 OtherSize)
{
  if (!Size || !OtherSize) {
    return FALSE;
  }
  if (First > MAX_UINT64 - Size || Other > MAX_UINT64 - OtherSize) {
    return TRUE;
  }
  return First < Other + OtherSize && Other < First + Size;
}

STATIC BOOLEAN
ThorLowMapType (CONST EFI_MEMORY_DESCRIPTOR *D, UINT32 Type)
{
  // The UEFI memory map can report WB together with other supported cache
  // policies and WP capability. Verify the live translation separately.
  return D->Type == Type && (D->Attribute & EFI_MEMORY_WB) &&
         !(D->Attribute & (EFI_MEMORY_RUNTIME | EFI_MEMORY_RP | EFI_MEMORY_RO));
}

// DXE returns descriptors in allocation order. Validate intersecting
// physical ranges separately so overlap cannot inflate available headroom.
STATIC BOOLEAN
ThorLowCandidate (CONST EFI_MEMORY_DESCRIPTOR *Map, UINTN MapSize, UINTN Stride,
                  UINT64 LeaseBytes, UINT64 *Candidate, UINT64 *Conventional)
{
  *Candidate = 0;
  *Conventional = 0;
  if (Map == NULL || Stride < sizeof (EFI_MEMORY_DESCRIPTOR) || MapSize % Stride) {
    return FALSE;
  }
  for (UINTN Offset = 0; Offset < MapSize; Offset += Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *D = (CONST VOID *)((CONST UINT8 *)Map + Offset);
    UINT64 End;
    if (!DescriptorEnd (D, &End)) {
      return FALSE;
    }
    UINT64 Start = MAX (D->PhysicalStart, THOR_LOW_BASE);
    End = MIN (End, THOR_LOW_END);
    if (Start >= End) {
      continue;
    }
    for (UINTN Previous = 0; Previous < Offset; Previous += Stride) {
      CONST EFI_MEMORY_DESCRIPTOR *P = (CONST VOID *)((CONST UINT8 *)Map + Previous);
      UINT64 PreviousEnd;
      if (!DescriptorEnd (P, &PreviousEnd) ||
          (P->PhysicalStart < End && PreviousEnd > Start)) {
        return FALSE;
      }
    }
    if (ThorLowMapType (D, EfiConventionalMemory)) {
      *Conventional += End - Start;
      if (End - Start >= LeaseBytes) {
        *Candidate = MAX (*Candidate, End - LeaseBytes);
      }
    }
  }
  return TRUE;
}

STATIC BOOLEAN
ThorLowTranslation (UINT64 Page, UINT64 Par)
{
  return (Par & 1) == 0 && (Par & THOR_AUDIT_PHYS_PAGE_MASK) == Page &&
         (Par >> 56) == 0xff && (Par & 0x180) == 0x180;
}

STATIC BOOLEAN
ThorLowIdentityWb (UINT64 Base, UINT64 Bytes)
{
  if (DarwinCurrentEl () != 4 || !(READ_SYSREG (sctlr_el1) & 1)) {
    return FALSE;
  }
  for (UINT64 Page = Base; Page < Base + Bytes; Page += EFI_PAGE_SIZE) {
    UINT64 ReadPar, WritePar;
    ThorAuditTranslateReadWrite (Page, &ReadPar, &WritePar);
    if (!ThorLowTranslation (Page, ReadPar) || !ThorLowTranslation (Page, WritePar)) {
      return FALSE;
    }
  }
  return TRUE;
}

STATIC BOOLEAN
ThorLowSafeRange (UINT64 Base, UINT64 Bytes, CONST PONG_RAM_BANK *Owned, UINTN Count,
                  CONST UINT64 Video[6], CONST THOR_MEMORY_AUDIT *Audit)
{
  if (!ThorAuditInside (Base, Bytes, THOR_LOW_BASE, THOR_LOW_END) || !Count ||
      Count >= PONG_RAM_MAX || (Video[0] && (!Video[2] || !Video[4] ||
      Video[4] > (MAX_UINT64 - Video[0]) / Video[2]))) {
    return FALSE;
  }
  if ((Video[0] && ThorLowOverlap (Base, Bytes, Video[0], Video[2] * Video[4])) ||
      ThorLowOverlap (Base, Bytes, Audit->FdtAddress, Audit->FdtBytes) ||
      ThorLowOverlap (Base, Bytes, Audit->ReservedSmemBase, Audit->ReservedSmemBytes)) {
    return FALSE;
  }
  for (UINTN Index = 0; Index < Count; Index++) {
    if (ThorLowOverlap (Base, Bytes, Owned[Index].Start, Owned[Index].Size)) {
      return FALSE;
    }
  }
  return TRUE;
}

STATIC PONG_RAM_BANK
ThorTryLeaseLowRam (CONST EFI_MEMORY_DESCRIPTOR *Map, UINTN MapSize, UINTN Stride,
                    CONST PONG_RAM_BANK *Owned, UINTN Count, CONST UINT64 Video[6],
                    THOR_MEMORY_AUDIT *Audit)
{
  PONG_RAM_BANK None = {0, 0};
  CONST UINT64 LeaseSizes[] = { THOR_LOW_EXPANDED_BYTES, THOR_LOW_LEASE_BYTES };
  if (Audit->FdtStatus != 0 || Audit->LowFdtHits != 1 || Audit->LowFixedConflict) {
    return None;
  }
  Audit->Flags |= THOR_LOW_FDT_CLEAR;
  for (UINTN Index = 0; Index < ARRAY_SIZE (LeaseSizes); Index++) {
    CONST UINT64 Bytes = LeaseSizes[Index];
    UINT64 Base, Free;
    EFI_GCD_MEMORY_SPACE_DESCRIPTOR Gcd;
    if (!ThorLowCandidate (Map, MapSize, Stride, Bytes, &Base, &Free)) {
      return None;
    }
    if (Free < Bytes + THOR_LOW_HEADROOM ||
        !ThorLowSafeRange (Base, Bytes, Owned, Count, Video, Audit)) {
      continue;
    }
    Audit->Flags |= THOR_LOW_CONVENTIONAL;
    if (gDS == NULL || gDS->GetMemorySpaceDescriptor == NULL ||
        EFI_ERROR (gDS->GetMemorySpaceDescriptor (Base, &Gcd)) ||
        Gcd.GcdMemoryType != EfiGcdMemoryTypeSystemMemory || Gcd.DeviceHandle != NULL ||
        !(Gcd.Capabilities & EFI_MEMORY_WB) ||
        (Gcd.Attributes & (EFI_MEMORY_RUNTIME | EFI_MEMORY_RP | EFI_MEMORY_RO | EFI_MEMORY_WP)) ||
        Gcd.BaseAddress > MAX_UINT64 - Gcd.Length ||
        !ThorAuditInside (Base, Bytes, Gcd.BaseAddress, Gcd.BaseAddress + Gcd.Length) ||
        !ThorLowIdentityWb (Base, Bytes)) {
      continue;
    }
    Audit->Flags |= THOR_LOW_IDENTITY_WB;
    EFI_PHYSICAL_ADDRESS Address = Base;
    if (EFI_ERROR (gBS->AllocatePages (AllocateAddress, EfiLoaderData,
                                      EFI_SIZE_TO_PAGES (Bytes), &Address))) {
      continue;
    }
    if (Address != Base) {
      return None;
    }
    Audit->Flags |= THOR_LOW_LEASED;
    return (PONG_RAM_BANK){Base, Bytes};
  }
  return None;
}

STATIC BOOLEAN
ThorLowAcceptedLease (CONST EFI_MEMORY_DESCRIPTOR *Map, UINTN MapSize, UINTN Stride,
                      CONST PONG_RAM_BANK *Lease, CONST PONG_RAM_BANK *Owned, UINTN Count,
                      CONST UINT64 Video[6], CONST THOR_MEMORY_AUDIT *Audit)
{
  UINT64 Candidate, Free;
  if ((Lease->Size != THOR_LOW_LEASE_BYTES && Lease->Size != THOR_LOW_EXPANDED_BYTES) ||
      !ThorLowSafeRange (Lease->Start, Lease->Size, Owned, Count, Video, Audit) ||
      !ThorLowCandidate (Map, MapSize, Stride, Lease->Size, &Candidate, &Free) || Free < THOR_LOW_HEADROOM) {
    return FALSE;
  }
  BOOLEAN Seen = FALSE;
  for (UINTN Offset = 0; Offset < MapSize; Offset += Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *D = (CONST VOID *)((CONST UINT8 *)Map + Offset);
    UINT64 End;
    if (!DescriptorEnd (D, &End)) {
      return FALSE;
    }
    if (ThorLowOverlap (Lease->Start, Lease->Size, D->PhysicalStart, End - D->PhysicalStart)) {
      if (Seen || !ThorLowMapType (D, EfiLoaderData) ||
          !ThorAuditInside (Lease->Start, Lease->Size, D->PhysicalStart, End)) {
        return FALSE;
      }
      Seen = TRUE;
    }
  }
  return Seen;
}
