// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Include after DescriptorEnd and the platform audit helpers. This is a
// private DXE reservation, not a general EFI RAM registration. The caller
// validates the live board policy and qualifies access before handing it off.

#define THOR_PRIVATE_RAM_BASE       0x840000000ULL
#define THOR_PRIVATE_RAM_END        0xa60000000ULL
#define THOR_PRIVATE_RAM_BYTES      (THOR_PRIVATE_RAM_END - THOR_PRIVATE_RAM_BASE)
// Keep a 2 MiB gap so DXE cannot coalesce the independent ownership
// records. A rejected extension leaves the qualified prefix intact.
#define THOR_PRIVATE_TAIL_BASE      (THOR_PRIVATE_RAM_END + BLOCK_SIZE)
#define THOR_PRIVATE_TAIL_END       THOR_AUDIT_BANK_C_END
#define THOR_PRIVATE_RAM_ATTRIBUTES (EFI_MEMORY_WB | EFI_MEMORY_XP)

STATIC BOOLEAN
ThorPrivateHighRamDescriptor (
  UINT64 Start, UINT64 Limit, OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR *Gcd
  )
{
  return gDS != NULL &&
         !EFI_ERROR (gDS->GetMemorySpaceDescriptor (Start, Gcd)) &&
         Gcd->GcdMemoryType == EfiGcdMemoryTypeReserved &&
         Gcd->BaseAddress == Start &&
         Gcd->Length == (Limit - Start) &&
         Gcd->DeviceHandle == NULL;
}

STATIC BOOLEAN
ThorPrivateHighRamOwned (UINT64 Start, UINT64 Limit)
{
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR Gcd;

  return mImage != NULL && ThorPrivateHighRamDescriptor (Start, Limit, &Gcd) &&
         Gcd.ImageHandle == mImage &&
         Gcd.Attributes == THOR_PRIVATE_RAM_ATTRIBUTES;
}

STATIC BOOLEAN
ThorCheckPrivateHighRamMap (
  CONST EFI_MEMORY_DESCRIPTOR *Map,
  UINTN                        MapSize,
  UINTN                        Stride,
  BOOLEAN                      RequireReservation,
  UINT64                       Start,
  UINT64                       Limit
  )
{
  UINT64 Covered = 0;

  if (Map == NULL || MapSize == 0 || Stride < sizeof (*Map) ||
      MapSize % Stride != 0 ||
      (((UINTN)Map | Stride) & (sizeof (UINT64) - 1)) != 0) {
    return FALSE;
  }

  for (UINTN Offset = 0; Offset < MapSize; Offset += Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *D = (CONST VOID *)((CONST UINT8 *)Map + Offset);
    UINT64 End;

    if (!DescriptorEnd (D, &End)) {
      return FALSE;
    }
    if (D->PhysicalStart >= Limit || End <= Start) {
      continue;
    }
    // Pinned Mu CoreGetMemoryMap clears EFI_MEMORY_ACCESS_MASK in the
    // exported map. The GCD check before GetMemoryMap still requires XP.
    if (!RequireReservation ||
        D->PhysicalStart < Start || End > Limit ||
        D->Type != EfiReservedMemoryType ||
        D->Attribute != EFI_MEMORY_WB || D->VirtualStart != 0) {
      return FALSE;
    }
    if (End - D->PhysicalStart > (Limit - Start) - Covered) {
      return FALSE;
    }
    // The EFI map need not be sorted. Exact coverage plus pairwise
    // non-overlap accepts a coalesced descriptor and equivalent fragments.
    for (UINTN Prior = 0; Prior < Offset; Prior += Stride) {
      CONST EFI_MEMORY_DESCRIPTOR *P = (CONST VOID *)((CONST UINT8 *)Map + Prior);
      UINT64 PriorEnd;

      if (!DescriptorEnd (P, &PriorEnd) ||
          (P->PhysicalStart < End && PriorEnd > D->PhysicalStart)) {
        return FALSE;
      }
    }
    Covered += End - D->PhysicalStart;
  }

  return !RequireReservation || Covered == (Limit - Start);
}

STATIC EFI_STATUS
ThorPreparePrivateHighRam (
  CONST EFI_MEMORY_DESCRIPTOR *Map,
  UINTN                        MapSize,
  UINTN                        Stride,
  BOOLEAN                      BoardReservationsValidated,
  UINT64                       Start,
  UINT64                       Limit
  )
{
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS Base = Start;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR Gcd;

  if (!BoardReservationsValidated || mImage == NULL || gDS == NULL ||
      !ThorCheckPrivateHighRamMap (Map, MapSize, Stride, FALSE, Start, Limit) ||
      EFI_ERROR (gDS->GetMemorySpaceDescriptor (Base, &Gcd)) ||
      Gcd.GcdMemoryType != EfiGcdMemoryTypeNonExistent ||
      Gcd.ImageHandle != NULL || Gcd.DeviceHandle != NULL ||
      Gcd.BaseAddress > MAX_UINT64 - Gcd.Length ||
      !ThorAuditInside (Base, (Limit - Start), Gcd.BaseAddress,
                        Gcd.BaseAddress + Gcd.Length)) {
    return EFI_ACCESS_DENIED;
  }

  // Reserve B and C as one interval. Adding SystemMemory would make these
  // unqualified pages visible to the DXE page allocator.
  Status = gDS->AddMemorySpace (EfiGcdMemoryTypeReserved, Base,
                                (Limit - Start), THOR_PRIVATE_RAM_ATTRIBUTES);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gDS->AllocateMemorySpace (EfiGcdAllocateAddress, EfiGcdMemoryTypeReserved,
                                     EFI_PAGE_SHIFT, (Limit - Start), &Base,
                                     mImage, NULL);
  if (EFI_ERROR (Status)) {
    // Before attempting any MMU change, revoke only our exact unowned,
    // still-unmapped GCD record.
    if (ThorPrivateHighRamDescriptor (Start, Limit, &Gcd) && Gcd.ImageHandle == NULL && !Gcd.Attributes) {
      (VOID)gDS->RemoveMemorySpace (Start, (Limit - Start));
    }
    return Status;
  }
  if (Base != Start ||
      !ThorPrivateHighRamDescriptor (Start, Limit, &Gcd) || Gcd.ImageHandle != mImage) {
    return EFI_COMPROMISED_DATA;
  }

  Status = gDS->SetMemorySpaceAttributes (Base, (Limit - Start),
                                          THOR_PRIVATE_RAM_ATTRIBUTES);
  if (EFI_ERROR (Status)) {
    // The MMU operation may have changed some PTEs. Retain Reserved for
    // this boot because removing the GCD record would not undo the PTEs.
    return Status;
  }

  return ThorPrivateHighRamOwned (Start, Limit) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
}

// Check ownership immediately before GetMemoryMap. After successful EBS check
// only the accepted snapshot; the stored map does not identify the GCD owner.
STATIC BOOLEAN
ThorAcceptPrivateHighRamMap (
  CONST EFI_MEMORY_DESCRIPTOR *Map,
  UINTN                        MapSize,
  UINTN                        Stride,
  UINT64                       Start,
  UINT64                       Limit
  )
{
  return ThorCheckPrivateHighRamMap (Map, MapSize, Stride, TRUE, Start, Limit);
}
