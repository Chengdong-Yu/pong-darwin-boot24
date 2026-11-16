// SPDX-License-Identifier: BSD-2-Clause-Patent
// Read-only Thor early-boot ownership evidence. Never maps or reads candidate
// RAM. Results are diagnostic only and cannot alter ClaimPongRam decisions.
#include <PiDxe.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/HobLib.h>
#include <Protocol/EFISmem.h>

#define THOR_AUDIT_BYTES             224U
#define THOR_AUDIT_OFFSET            3872U
#define THOR_AUDIT_B_BASE            0x840000000ULL
#define THOR_AUDIT_B_BYTES           0x10000000ULL
#define THOR_AUDIT_FDT_MAX           0x200000ULL
#define THOR_AUDIT_PHYS_PAGE_MASK    0x0000fffffffff000ULL
#define THOR_AUDIT_SMEM_MAX          4096U
#define THOR_AUDIT_SMEM_BASE         0x80900000ULL
#define THOR_AUDIT_SMEM_BYTES        0x00200000U
#define THOR_AUDIT_SMEM_ITEM         402U
#define THOR_AUDIT_SMEM_APERTURE     0x800ULL
#define THOR_AUDIT_SMEM_RAW_TRIED    0x1000ULL
#define THOR_AUDIT_SMEM_RAW_VALID    0x2000ULL
#define THOR_AUDIT_SMEM_B_PHYSICAL   0x4000ULL
#define THOR_AUDIT_SMEM_C_PHYSICAL   0x8000ULL
#define THOR_AUDIT_SMEM_B_AVAILABLE  0x10000ULL
#define THOR_AUDIT_SMEM_C_AVAILABLE  0x20000ULL
#define THOR_AUDIT_SMEM_HEADER_BYTES 24U
#define THOR_AUDIT_SMEM_MAX_ROWS     32U
#define THOR_AUDIT_BANK_C_BASE       0x900000000ULL
#define THOR_AUDIT_BANK_C_END        0xA80000000ULL

// First-page probe, flags in the existing TRAM v1 record. A successful AT
// describes the currently installed translation only. It grants no RAM.
#define THOR_TRIAL_REQUESTED         0x00040000ULL
#define THOR_TRIAL_DYNAMIC_DISJOINT  0x00080000ULL
#define THOR_TRIAL_DYNAMIC_POSSIBLE  0x00100000ULL
#define THOR_TRIAL_RESERVATION_BAD   0x00200000ULL
#define THOR_TRIAL_AT_ATTEMPTED      0x00400000ULL
#define THOR_TRIAL_AT_READ_WB        0x00800000ULL
#define THOR_TRIAL_AT_WRITE_WB       0x01000000ULL
#define THOR_TRIAL_AT_READ_FAULT     0x02000000ULL
#define THOR_TRIAL_AT_WRITE_FAULT    0x04000000ULL
#define THOR_TRIAL_GCD_WB            0x08000000ULL
#define THOR_TRIAL_EFI_WB            0x10000000ULL

// The Thor stock and current FD both use this exact DXE heap. tmlow=1
// tests an existing allocator-owned subrange, independently of Bank B.
#define THOR_LOW_BASE                0xF8000000ULL
#define THOR_LOW_END                 0xFFC00000ULL
#define THOR_LOW_REQUESTED           0x20000000ULL
#define THOR_LOW_FDT_CLEAR           0x40000000ULL
#define THOR_LOW_CONVENTIONAL        0x80000000ULL
#define THOR_LOW_IDENTITY_WB          0x100000000ULL
#define THOR_LOW_LEASED               0x200000000ULL
#define THOR_LOW_HANDED_OFF           0x400000000ULL

// Raw libfdt API supplied by the pinned MdePkg BaseFdtLib.
extern int fdt_check_full (const void *, UINTN);
extern const void *fdt_getprop (const void *, int, const char *, int *);
extern const char *fdt_get_name (const void *, int, int *);
extern int fdt_node_check_compatible (const void *, int, const char *);
extern int fdt_first_subnode (const void *, int);
extern int fdt_next_subnode (const void *, int);
extern int fdt_subnode_offset (const void *, int, const char *);
extern UINT32 fdt_get_phandle (const void *, int);
extern int fdt_next_node (const void *, int, int *);
extern int fdt_first_property_offset (const void *, int);
extern int fdt_next_property_offset (const void *, int);
extern const void *fdt_getprop_by_offset (const void *, int, const char **, int *);
extern int fdt_num_mem_rsv (const void *);
extern int fdt_get_mem_rsv (const void *, int, UINT64 *, UINT64 *);

typedef struct {
  UINT64 Flags, FdtAddress, ReservedSmemBase, ReservedSmemBytes;
  UINT32 FdtBytes, FdtStatus, FdtCrc, FdtBanks, FdtHits, ReservedHits;
  UINT32 LowFdtHits;
  BOOLEAN LowFixedConflict;
  BOOLEAN TailFdtClear;
  BOOLEAN TailSmemClear;
  EFI_STATUS GcdStatus, SmemStatus, SmemProtocolStatus;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR Gcd;
  UINT32 SmemBytes, SmemVersion, SmemEntries, SmemHits, SmemRawFormat;
  UINT64 SmemBase, SmemLength, SmemAvailable;
  UINT32 SmemAttribute, SmemCategory, SmemDomain, SmemType;
} THOR_MEMORY_AUDIT;

STATIC BOOLEAN
ThorAuditInside (UINT64 Start, UINT64 Length, UINT64 Base, UINT64 End)
{
  return Length != 0 && Start >= Base && Start < End && Length <= End - Start;
}

STATIC BOOLEAN
ThorAuditOverlap (UINT64 Start, UINT64 Length)
{
  return Length != 0 && Start <= MAX_UINT64 - Length &&
         Start < THOR_AUDIT_B_BASE + THOR_AUDIT_B_BYTES &&
         THOR_AUDIT_B_BASE < Start + Length;
}

// Check only a previously verified low, reserved input span. The address
// translation checks do not themselves load the addressed bytes. Preserve
// PAR_EL1 and DAIF across the bounded walk's individual translations.
STATIC BOOLEAN
ThorAuditMapped (UINT64 Start, UINT64 Length)
{
  UINT64 End;
  if (!Length || Start > MAX_UINT64 - Length || Start + Length > 0x100000000ULL ||
      DarwinCurrentEl () != 4) {
    return FALSE;
  }
  End = Start + Length;
  for (UINT64 Page = Start & ~((UINT64)EFI_PAGE_MASK); Page < End; Page += EFI_PAGE_SIZE) {
    UINT64 Daif, SavedPar, Par;
    __asm__ __volatile__ (
      "mrs %0, daif\n\t"
      "msr daifset, #3\n\t"
      "isb\n\t"
      "mrs %1, par_el1\n\t"
      "at s1e1r, %3\n\t"
      "isb\n\t"
      "mrs %2, par_el1\n\t"
      "msr par_el1, %1\n\t"
      "isb\n\t"
      "msr daif, %0\n\t"
      "isb"
      : "=&r"(Daif), "=&r"(SavedPar), "=&r"(Par) : "r"(Page) : "memory"
      );
    if ((Par & 1) || (Par & THOR_AUDIT_PHYS_PAGE_MASK) != Page) {
      return FALSE;
    }
  }
  return TRUE;
}

STATIC UINT32 ThorAuditBig32 (CONST UINT8 *P)
{
  return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) | ((UINT32)P[2] << 8) | P[3];
}

STATIC UINT64 ThorAuditCells (CONST UINT8 *P, UINT32 Count)
{
  UINT64 Value = ThorAuditBig32 (P);
  if (Count == 2) {
    Value = (Value << 32) | ThorAuditBig32 (P + 4);
  }
  return Value;
}

STATIC BOOLEAN ThorAuditPropertyIs (CONST UINT8 *P, int Len, CONST CHAR8 *Value)
{
  UINTN Size = AsciiStrSize (Value);
  return P != NULL && Len >= 0 && (UINTN)Len == Size && CompareMem (P, Value, Size) == 0;
}

STATIC BOOLEAN ThorAuditNodeEnabled (CONST VOID *Fdt, int Node)
{
  int Len;
  CONST UINT8 *P = fdt_getprop (Fdt, Node, "status", &Len);
  return (P == NULL && Len == -1) || ThorAuditPropertyIs (P, Len, "okay") ||
         ThorAuditPropertyIs (P, Len, "ok");
}

STATIC BOOLEAN ThorAuditCellCounts (CONST VOID *Fdt, int Node, UINT32 *Address, UINT32 *Size)
{
  int Len;
  CONST UINT8 *P = fdt_getprop (Fdt, Node, "#address-cells", &Len);
  if (P == NULL || Len != 4) {
    return FALSE;
  }
  *Address = ThorAuditBig32 (P);
  P = fdt_getprop (Fdt, Node, "#size-cells", &Len);
  if (P == NULL || Len != 4) {
    return FALSE;
  }
  *Size = ThorAuditBig32 (P);
  return (*Address == 1 || *Address == 2) && (*Size == 1 || *Size == 2);
}

STATIC BOOLEAN ThorAuditListHasSmem (CONST UINT8 *P, int Len)
{
  if (P == NULL || Len <= 0) {
    return FALSE;
  }
  while (Len > 0) {
    CONST UINT8 *End = ScanMem8 (P, (UINTN)Len, 0);
    if (End == NULL) {
      return FALSE;
    }
    int Size = (int)(End - P) + 1;
    if (ThorAuditPropertyIs (P, Size, "qcom,smem")) {
      return TRUE;
    }
    P += Size;
    Len -= Size;
  }
  return FALSE;
}

// The Thor Recovery DT declares this exact no-map shared-memory aperture.
// Require the live boot DT to resolve the same enabled binding before using it.
STATIC VOID
ThorAuditFdtSmem (THOR_MEMORY_AUDIT *Audit, CONST VOID *Fdt, int Reserve, UINT32 A, UINT32 S)
{
  int Soc = fdt_subnode_offset (Fdt, 0, "soc");
  UINT32 Phandle = 0;
  if (Soc < 0 || !ThorAuditNodeEnabled (Fdt, Soc)) {
    return;
  }
  for (int Node = fdt_first_subnode (Fdt, Soc); Node >= 0; Node = fdt_next_subnode (Fdt, Node)) {
    int Len;
    CONST UINT8 *P = fdt_getprop (Fdt, Node, "compatible", &Len);
    if (!ThorAuditListHasSmem (P, Len) || !ThorAuditNodeEnabled (Fdt, Node)) {
      continue;
    }
    P = fdt_getprop (Fdt, Node, "memory-region", &Len);
    if (Phandle != 0 || P == NULL || Len != 4) {
      return;
    }
    Phandle = ThorAuditBig32 (P);
    if (Phandle == 0 || Phandle == MAX_UINT32) {
      return;
    }
  }
  if (Phandle == 0) {
    return;
  }

  int Resource = -1;
  for (int Node = fdt_first_subnode (Fdt, Reserve); Node >= 0; Node = fdt_next_subnode (Fdt, Node)) {
    int Len;
    CONST UINT8 *P = fdt_getprop (Fdt, Node, "phandle", &Len);
    if (P == NULL || Len != 4 || ThorAuditBig32 (P) != Phandle) {
      continue;
    }
    if (Resource >= 0) {
      return;
    }
    Resource = Node;
  }
  if (Resource < 0 || !ThorAuditNodeEnabled (Fdt, Resource)) {
    return;
  }
  int Len;
  CONST UINT8 *P = fdt_getprop (Fdt, Resource, "no-map", &Len);
  if (P == NULL || Len != 0) {
    return;
  }
  P = fdt_getprop (Fdt, Resource, "reg", &Len);
  if (P == NULL || Len != (int)(4 * (A + S)) ||
      ThorAuditCells (P, A) != THOR_AUDIT_SMEM_BASE ||
      ThorAuditCells (P + 4 * A, S) != THOR_AUDIT_SMEM_BYTES) {
    return;
  }
  Audit->ReservedSmemBase = THOR_AUDIT_SMEM_BASE;
  Audit->ReservedSmemBytes = THOR_AUDIT_SMEM_BYTES;
  Audit->Flags |= THOR_AUDIT_SMEM_APERTURE;
}

STATIC VOID ThorAuditReserved (THOR_MEMORY_AUDIT *Audit, UINT64 Base, UINT64 Size)
{
  if (!Size || Base > MAX_UINT64 - Size) {
    Audit->Flags |= 0x20ULL;
    Audit->LowFixedConflict = TRUE;
    return;
  }
  if (Base < THOR_LOW_END && THOR_LOW_BASE < Base + Size) {
    Audit->LowFixedConflict = TRUE;
  }
  if (ThorAuditOverlap (Base, Size)) {
    Audit->ReservedHits++;
    Audit->Flags |= 0x10ULL;
  }
}

// Addressless DT allocations describe where a later OS may choose memory,
// not a fixed reservation. Keep the main audit's incomplete-reservation
// bit even if all bounds here are structurally valid.
STATIC UINT64
ThorTrialDynamicReservation (CONST VOID *Fdt, int Node, UINT32 A, UINT32 S)
{
  int Len;
  CONST UINT8 *Size = fdt_getprop (Fdt, Node, "size", &Len);
  if (Size == NULL || Len != (int)(4 * S) || ThorAuditCells (Size, S) == 0) {
    return THOR_TRIAL_RESERVATION_BAD;
  }
  CONST UINT8 *Alignment = fdt_getprop (Fdt, Node, "alignment", &Len);
  if (Alignment != NULL) {
    if (Len != (int)(4 * S)) {
      return THOR_TRIAL_RESERVATION_BAD;
    }
    UINT64 Align = ThorAuditCells (Alignment, S);
    if (Align == 0 || (Align & (Align - 1)) != 0) {
      return THOR_TRIAL_RESERVATION_BAD;
    }
  } else if (Len != -1) {
    return THOR_TRIAL_RESERVATION_BAD;
  }

  CONST UINT8 *Ranges = fdt_getprop (Fdt, Node, "alloc-ranges", &Len);
  if (Ranges == NULL) {
    return Len == -1 ? THOR_TRIAL_DYNAMIC_POSSIBLE : THOR_TRIAL_RESERVATION_BAD;
  }
  UINT32 Stride = 4 * (A + S);
  if (Len <= 0 || (UINT32)Len % Stride) {
    return THOR_TRIAL_RESERVATION_BAD;
  }
  BOOLEAN Possible = FALSE;
  for (UINT32 Index = 0; Index < (UINT32)Len; Index += Stride) {
    UINT64 Start = ThorAuditCells (Ranges + Index, A);
    UINT64 Bytes = ThorAuditCells (Ranges + Index + 4 * A, S);
    if (Bytes == 0 || Start > MAX_UINT64 - Bytes) {
      return THOR_TRIAL_RESERVATION_BAD;
    }
    if (Start < THOR_AUDIT_B_BASE + EFI_PAGE_SIZE && Start + Bytes > THOR_AUDIT_B_BASE) {
      Possible = TRUE;
    }
  }
  return Possible ? THOR_TRIAL_DYNAMIC_POSSIBLE : THOR_TRIAL_DYNAMIC_DISJOINT;
}

STATIC VOID ThorAuditWalkFdt (THOR_MEMORY_AUDIT *Audit, CONST VOID *Fdt)
{
  UINT32 A, S, RA, RS;
  int Reserve, Len, Count;
  CONST UINT8 *P;
  if (!ThorAuditCellCounts (Fdt, 0, &A, &S)) {
    Audit->Flags |= 0x20ULL;
    return;
  }
  UINT32 Stride = 4 * (A + S);
  for (int Node = fdt_first_subnode (Fdt, 0); Node >= 0; Node = fdt_next_subnode (Fdt, Node)) {
    P = fdt_getprop (Fdt, Node, "device_type", &Len);
    if (!ThorAuditPropertyIs (P, Len, "memory") || !ThorAuditNodeEnabled (Fdt, Node)) {
      continue;
    }
    P = fdt_getprop (Fdt, Node, "reg", &Len);
    if (P == NULL || Len <= 0 || (UINT32)Len % Stride) {
      Audit->Flags |= 0x20ULL;
      Audit->LowFixedConflict = TRUE;
      continue;
    }
    for (UINT32 Index = 0; Index < (UINT32)Len; Index += Stride) {
      UINT64 Base = ThorAuditCells (P + Index, A);
      UINT64 Size = ThorAuditCells (P + Index + 4 * A, S);
      if (Size && Base <= MAX_UINT64 - Size) {
        Audit->FdtBanks++;
        if (Base <= THOR_LOW_BASE && Base + Size >= THOR_LOW_END) {
          Audit->LowFdtHits++;
        }
        if (ThorAuditInside (THOR_AUDIT_B_BASE, THOR_AUDIT_B_BYTES, Base, Base + Size)) {
          Audit->FdtHits++;
          Audit->Flags |= 0x8ULL;
        }
      } else {
        Audit->Flags |= 0x20ULL;
        Audit->LowFixedConflict = TRUE;
      }
    }
  }
  Count = fdt_num_mem_rsv (Fdt);
  if (Count < 0 || Count > 256) {
    Audit->Flags |= 0x20ULL;
    Audit->LowFixedConflict = TRUE;
  } else for (int Index = 0; Index < Count; Index++) {
    UINT64 Base, Size;
    if (fdt_get_mem_rsv (Fdt, Index, &Base, &Size) != 0) {
      Audit->Flags |= 0x20ULL;
      Audit->LowFixedConflict = TRUE;
      break;
    }
    ThorAuditReserved (Audit, Base, Size);
  }

  Reserve = fdt_subnode_offset (Fdt, 0, "reserved-memory");
  if (Reserve < 0 || !ThorAuditCellCounts (Fdt, Reserve, &RA, &RS) || RA != A || RS != S) {
    Audit->Flags |= 0x20ULL;
    Audit->LowFixedConflict = TRUE;
    return;
  }
  P = fdt_getprop (Fdt, Reserve, "ranges", &Len);
  if (P == NULL || Len != 0) {
    Audit->Flags |= 0x20ULL;
    Audit->LowFixedConflict = TRUE;
    return;
  }
  ThorAuditFdtSmem (Audit, Fdt, Reserve, A, S);
  for (int Node = fdt_first_subnode (Fdt, Reserve); Node >= 0; Node = fdt_next_subnode (Fdt, Node)) {
    // A declaration without a fixed range remains unresolved for ownership.
    P = fdt_getprop (Fdt, Node, "reg", &Len);
    if (P == NULL || Len <= 0 || (UINT32)Len % Stride) {
      Audit->Flags |= 0x20ULL;
      // A missing reg creates no fixed interval. For this low lease,
      // the live conventional map attests that DXE has not allocated it.
      // A malformed explicit reg prevents any donation from the heap.
      if (P != NULL || Len != -1) {
        Audit->LowFixedConflict = TRUE;
      }
      if (Audit->Flags & THOR_TRIAL_REQUESTED) {
        Audit->Flags |= P == NULL && Len == -1
          ? ThorTrialDynamicReservation (Fdt, Node, A, S)
          : THOR_TRIAL_RESERVATION_BAD;
      }
      continue;
    }
    for (UINT32 Index = 0; Index < (UINT32)Len; Index += Stride) {
      UINT64 Base = ThorAuditCells (P + Index, A);
      UINT64 Size = ThorAuditCells (P + Index + 4 * A, S);
      ThorAuditReserved (Audit, Base, Size);
    }
  }
  int Chosen = fdt_subnode_offset (Fdt, 0, "chosen");
  if (Chosen >= 0) {
    int StartLen, EndLen;
    CONST UINT8 *Start = fdt_getprop (Fdt, Chosen, "linux,initrd-start", &StartLen);
    CONST UINT8 *End = fdt_getprop (Fdt, Chosen, "linux,initrd-end", &EndLen);
    if (Start != NULL || End != NULL) {
      if (Start == NULL || End == NULL || StartLen != EndLen ||
          (StartLen != 4 && StartLen != 8)) {
        Audit->Flags |= 0x20ULL;
        Audit->LowFixedConflict = TRUE;
      } else {
        UINT64 Begin = ThorAuditCells (Start, (UINT32)StartLen / 4);
        UINT64 Finish = ThorAuditCells (End, (UINT32)EndLen / 4);
        if (Finish <= Begin) {
          Audit->Flags |= 0x20ULL;
          Audit->LowFixedConflict = TRUE;
        } else {
          ThorAuditReserved (Audit, Begin, Finish - Begin);
        }
      }
    }
  }
}

#include "ThorBankBFdtPolicy.h"

STATIC VOID ThorAuditFdt (THOR_MEMORY_AUDIT *Audit)
{
  VOID *Hob = GetFirstGuidHob (&gSiliciumEntryArgHobGuid);
  UINT64 Bound;
  UINT8 Header[40];
  Audit->FdtStatus = 1;
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (Audit->FdtAddress)) {
    return;
  }
  CopyMem (&Audit->FdtAddress, GET_GUID_HOB_DATA (Hob), sizeof (Audit->FdtAddress));
  Audit->Flags |= 1;
  const UINT64 Source = Audit->FdtAddress;
  if (Source == 0x80600000ULL) {
    Bound = 0x80600000ULL + THOR_AUDIT_FDT_MAX;
  } else if (Source >= 0xA8000000ULL && Source < 0xB8000000ULL) {
    Bound = 0xB8000000ULL;
  } else {
    Audit->FdtStatus = 2;
    return;
  }
  Audit->FdtStatus = 2;
  if ((Source & 7) || Bound - Source < sizeof (Header) ||
      !ThorAuditMapped (Source, sizeof (Header))) {
    return;
  }
  CopyMem (Header, (CONST VOID *)(UINTN)Source, sizeof (Header));
  Audit->FdtStatus = 3;
  UINT32 Total = ThorAuditBig32 (Header + 4);
  if (ThorAuditBig32 (Header) != 0xD00DFEEDU || Total < sizeof (Header) ||
      Total > THOR_AUDIT_FDT_MAX || Total > Bound - Source ||
      !ThorAuditMapped (Source, Total)) {
    return;
  }
  Audit->FdtBytes = Total;
  Audit->FdtStatus = 4;
  VOID *Snapshot = AllocatePool (Total);
  if (Snapshot == NULL) {
    return;
  }
  CopyMem (Snapshot, (CONST VOID *)(UINTN)Source, Total);
  if (CompareMem (Snapshot, Header, sizeof (Header)) == 0 &&
      !EFI_ERROR (gBS->CalculateCrc32 (Snapshot, Total, &Audit->FdtCrc))) {
    Audit->Flags |= 2;
    int Result = fdt_check_full (Snapshot, Total);
    Audit->FdtStatus = (UINT32)Result;
    if (Result == 0) {
      Audit->Flags |= 4;
      ThorAuditWalkFdt (Audit, Snapshot);
      THOR_BANK_B_FDT_RESULT BankB;
      EFI_STATUS Policy = ThorBankBFdtPolicy (Snapshot, &BankB, 0);
      Audit->Flags |= ThorBankBFdtFlags (Policy, &BankB);
      Policy = ThorBankBFdtPolicy (Snapshot, &BankB, THOR_FULL_BANK_C_LIMIT);
      if (Policy == EFI_SUCCESS) {
        Audit->TailFdtClear = ThorBankBFdtPolicy (Snapshot, &BankB, THOR_AUDIT_BANK_C_END) == EFI_SUCCESS;
      }
      Audit->Flags |= THOR_FULL_FDT_CHECKED;
      switch (Policy) {
        case EFI_SUCCESS:
          Audit->Flags |= THOR_FULL_FDT_ACCEPTED;
          break;
        case EFI_ACCESS_DENIED:
          Audit->Flags |= THOR_FULL_FDT_CONFLICT;
          break;
        case EFI_NOT_READY:
          Audit->Flags |= THOR_FULL_FDT_UNRESOLVED;
          break;
        default:
          Audit->Flags |= THOR_FULL_FDT_INVALID;
          break;
      }
    }
  }
  FreePool (Snapshot);
}

typedef struct {
  UINT64 Start, PhysicalEnd, AvailableEnd;
} THOR_SMEM_RANGE;

// Cover a whole interval without assuming that XBL sorted the descriptors.
// Each step advances to a different descriptor end, so Count bounds the walk.
STATIC BOOLEAN
ThorAuditSmemCovers (CONST THOR_SMEM_RANGE *Ranges, UINT32 Count, UINT64 Start,
                    UINT64 End, BOOLEAN Available)
{
  for (UINT32 Step = 0; Start < End && Step < Count; Step++) {
    UINT64 Next = Start;
    for (UINT32 Index = 0; Index < Count; Index++) {
      if (Ranges[Index].Start <= Start) {
        Next = MAX (Next, Available ? Ranges[Index].AvailableEnd : Ranges[Index].PhysicalEnd);
      }
    }
    if (Next == Start) {
      return FALSE;
    }
    Start = Next;
  }
  return Start >= End;
}

STATIC EFI_STATUS
ThorAuditSmemTable (THOR_MEMORY_AUDIT *Audit, CONST UINT8 *P, UINT32 Size)
{
  UINT32 RowSize, AvailableOffset = 0;
  THOR_SMEM_RANGE Ranges[THOR_AUDIT_SMEM_MAX_ROWS];
  UINT32 RangeCount = 0;
  BOOLEAN FullConflict = FALSE, TailConflict = FALSE;

  if (Size < THOR_AUDIT_SMEM_HEADER_BYTES || Size > THOR_AUDIT_SMEM_MAX) {
    return EFI_COMPROMISED_DATA;
  }
  Audit->SmemBytes = Size;
  Audit->SmemVersion = ReadUnaligned32 ((CONST UINT32 *)(P + 8));
  Audit->SmemEntries = ReadUnaligned32 ((CONST UINT32 *)(P + 16));
  if (ReadUnaligned32 ((CONST UINT32 *)P) != 0x9DA5E0A8U ||
      ReadUnaligned32 ((CONST UINT32 *)(P + 4)) != 0xAF9EC4E2U) {
    return EFI_COMPROMISED_DATA;
  }
  switch (Audit->SmemVersion) {
    case 1:
      RowSize = 64;
      break;
    case 2:
      RowSize = 80;
      AvailableOffset = 72;
      break;
    case 3:
      // Qualcomm usable_ram_partition_table_v3. The 2328-byte Thor
      // item is the 24-byte header plus room for 32 72-byte records.
      RowSize = 72;
      AvailableOffset = 64;
      break;
    default:
      return EFI_UNSUPPORTED;
  }
  if (Audit->SmemEntries > THOR_AUDIT_SMEM_MAX_ROWS ||
      Audit->SmemEntries > (Size - THOR_AUDIT_SMEM_HEADER_BYTES) / RowSize) {
    return EFI_COMPROMISED_DATA;
  }

  Audit->Flags |= 0x100ULL;
  for (UINT32 Index = 0; Index < Audit->SmemEntries; Index++) {
    CONST UINT8 *Row = P + THOR_AUDIT_SMEM_HEADER_BYTES + Index * RowSize;
    UINT64 Base = ReadUnaligned64 ((CONST UINT64 *)(Row + 16));
    UINT64 Length = ReadUnaligned64 ((CONST UINT64 *)(Row + 24));
    UINT64 Available = AvailableOffset ? ReadUnaligned64 ((CONST UINT64 *)(Row + AvailableOffset)) : Length;
    UINT32 Attribute = ReadUnaligned32 ((CONST UINT32 *)(Row + 32));
    UINT32 Category = ReadUnaligned32 ((CONST UINT32 *)(Row + 36));
    UINT32 Domain = ReadUnaligned32 ((CONST UINT32 *)(Row + 40));
    UINT32 Type = ReadUnaligned32 ((CONST UINT32 *)(Row + 44));
    BOOLEAN SystemRam = Category == 14 && Type == 1;
    BOOLEAN AppsAvailable = SystemRam && Attribute == 1 &&
                            (Domain == 0 || Domain == 1 || Domain == 3) &&
                            Available != 0 && Available <= Length;
    if (!Length || Base > MAX_UINT64 - Length) {
      FullConflict |= Length != 0 && Base < THOR_FULL_BANK_C_LIMIT;
      TailConflict |= Length != 0 && Base < THOR_AUDIT_BANK_C_END;
      continue;
    }
    if (Base < THOR_FULL_BANK_C_LIMIT && Base + Length > THOR_AUDIT_B_BASE &&
        (!AppsAvailable || Domain == 3 ||
         Base + Available < MIN (Base + Length, THOR_FULL_BANK_C_LIMIT))) {
      FullConflict = TRUE;
    }
    if (Base < THOR_AUDIT_BANK_C_END && Base + Length > THOR_FULL_BANK_C_LIMIT &&
        (!AppsAvailable || Domain == 3 ||
         Base + Available < MIN (Base + Length, THOR_AUDIT_BANK_C_END))) {
      TailConflict = TRUE;
    }
    if (!SystemRam) {
      continue;
    }
    Ranges[RangeCount++] = (THOR_SMEM_RANGE){Base, Base + Length, AppsAvailable ? Base + Available : 0};
    if (!AppsAvailable ||
        !ThorAuditInside (THOR_AUDIT_B_BASE, THOR_AUDIT_B_BYTES, Base, Base + Available)) {
      continue;
    }
    Audit->SmemHits++;
    if (Audit->SmemHits != 1) {
      continue;
    }
    Audit->SmemBase = Base;
    Audit->SmemLength = Length;
    Audit->SmemAvailable = Available;
    Audit->SmemAttribute = Attribute;
    Audit->SmemCategory = Category;
    Audit->SmemDomain = Domain;
    Audit->SmemType = Type;
  }
  if (Audit->SmemHits == 1) {
    Audit->Flags |= 0x200ULL;
  }

  // These are XBL table observations. They cannot grant EL2 access, publish
  // conventional EFI descriptors, or change the list sent to the XNU VM.
  if (ThorAuditSmemCovers (Ranges, RangeCount, THOR_AUDIT_B_BASE, THOR_AUDIT_BANK_C_BASE, FALSE)) {
    Audit->Flags |= THOR_AUDIT_SMEM_B_PHYSICAL;
  }
  if (ThorAuditSmemCovers (Ranges, RangeCount, THOR_AUDIT_BANK_C_BASE, THOR_AUDIT_BANK_C_END, FALSE)) {
    Audit->Flags |= THOR_AUDIT_SMEM_C_PHYSICAL;
  }
  if (ThorAuditSmemCovers (Ranges, RangeCount, THOR_AUDIT_B_BASE, THOR_AUDIT_BANK_C_BASE, TRUE)) {
    Audit->Flags |= THOR_AUDIT_SMEM_B_AVAILABLE;
  }
  if (ThorAuditSmemCovers (Ranges, RangeCount, THOR_AUDIT_BANK_C_BASE, THOR_AUDIT_BANK_C_END, TRUE)) {
    Audit->Flags |= THOR_AUDIT_SMEM_C_AVAILABLE;
  }
  if (Audit->SmemVersion == 3 && !FullConflict &&
      ThorAuditSmemCovers (Ranges, RangeCount, THOR_AUDIT_B_BASE,
                           THOR_FULL_BANK_C_LIMIT, TRUE)) {
    Audit->Flags |= THOR_FULL_SMEM_ACCEPTED;
    Audit->TailSmemClear = !TailConflict &&
        ThorAuditSmemCovers (Ranges, RangeCount, THOR_FULL_BANK_C_LIMIT, THOR_AUDIT_BANK_C_END, TRUE);
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
ThorAuditSmemProtocol (THOR_MEMORY_AUDIT *Audit)
{
  EFI_SMEM_PROTOCOL *Protocol = NULL;
  VOID *Address = NULL;
  unsigned int Size = 0;
  EFI_STATUS Status = gBS->LocateProtocol (&gEfiSMEMProtocolGuid, NULL, (VOID **)&Protocol);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  if (Protocol == NULL || Protocol->Revision != EFI_SMEM_PROTOCOL_REVISION || Protocol->GetFunc == NULL) {
    return EFI_UNSUPPORTED;
  }
  Status = Protocol->GetFunc (THOR_AUDIT_SMEM_ITEM, &Size, &Address);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  const UINT64 Start = (UINT64)(UINTN)Address;
  const UINT64 SmemEnd = Audit->ReservedSmemBase + Audit->ReservedSmemBytes;
  if (Address == NULL || Size < 24 || Size > THOR_AUDIT_SMEM_MAX ||
      (!ThorAuditInside (Start, Size, Audit->ReservedSmemBase, SmemEnd) &&
       !ThorAuditInside (Start, Size, 0xF8000000ULL, 0xFFC00000ULL)) ||
      !ThorAuditMapped (Start, Size)) {
    return EFI_SECURITY_VIOLATION;
  }
  return ThorAuditSmemTable (Audit, Address, Size);
}

// Qualcomm SMEM global layouts used by the Linux qcom-smem provider.
// The caller proves the existing Thor identity mapping before any loads.
// Every offset is an aligned 32-bit word within that SMEM aperture.
STATIC UINT32
ThorAuditSmemRead (CONST volatile UINT32 *Region, UINT32 Offset)
{
  return Region[Offset / sizeof (*Region)];
}

STATIC EFI_STATUS
ThorAuditSmemLegacy (CONST volatile UINT32 *Region, UINT32 *Item, UINT32 *Bytes)
{
  const UINT32 HeapHeader = 208;
  const UINT32 EntryBytes = 16;
  const UINT32 Entry = HeapHeader + THOR_AUDIT_SMEM_ITEM * EntryBytes;
  if (ThorAuditSmemRead (Region, Entry) != 1) {
    return EFI_NOT_FOUND;
  }
  UINT32 Offset = ThorAuditSmemRead (Region, Entry + 4);
  UINT32 Size = ThorAuditSmemRead (Region, Entry + 8);
  UINT32 Aux = ThorAuditSmemRead (Region, Entry + 12) & ~3U;
  UINT32 HeapEnd = ThorAuditSmemRead (Region, 196);
  if ((Aux != 0 && Aux != THOR_AUDIT_SMEM_BASE) ||
      (Offset & 7) != 0 || (Size & 7) != 0 || HeapEnd > THOR_AUDIT_SMEM_BYTES ||
      !ThorAuditInside (Offset, Size, HeapHeader + 512 * EntryBytes, HeapEnd)) {
    return EFI_COMPROMISED_DATA;
  }
  *Item = Offset;
  *Bytes = Size;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
ThorAuditSmemPartition (CONST volatile UINT32 *Region, UINT32 *Item, UINT32 *Bytes)
{
  const UINT32 Toc = THOR_AUDIT_SMEM_BYTES - 0x1000;
  const UINT32 TocHeader = 32, TocEntry = 48, PartitionHeader = 32, Header = 16;
  const UINT32 GlobalHosts = 0xfffefffeU, Canary = 0xa5a5U;
  UINT32 Number = ThorAuditSmemRead (Region, Toc + 8);
  if (ThorAuditSmemRead (Region, Toc) != 0x434f5424U ||
      ThorAuditSmemRead (Region, Toc + 4) != 1 ||
      Number > (0x1000 - TocHeader) / TocEntry) {
    return EFI_COMPROMISED_DATA;
  }
  UINT32 Partition = 0, Size = 0, CacheLine = 0;
  for (UINT32 Index = 0; Index < Number; Index++) {
    UINT32 Entry = Toc + TocHeader + Index * TocEntry;
    if (ThorAuditSmemRead (Region, Entry + 12) != GlobalHosts) {
      continue;
    }
    UINT32 Offset = ThorAuditSmemRead (Region, Entry);
    UINT32 Length = ThorAuditSmemRead (Region, Entry + 4);
    if (Offset == 0 && Length == 0) {
      continue;
    }
    if (Partition != 0 || (Offset & 7) != 0 || (Length & 7) != 0 ||
        Length < PartitionHeader + Header ||
        !ThorAuditInside (Offset, Length, 0x1000, Toc)) {
      return EFI_COMPROMISED_DATA;
    }
    Partition = Offset;
    Size = Length;
    CacheLine = ThorAuditSmemRead (Region, Entry + 16);
  }
  if (Partition == 0) {
    return EFI_NOT_FOUND;
  }
  if (ThorAuditSmemRead (Region, Partition) != 0x54525024U ||
      ThorAuditSmemRead (Region, Partition + 4) != GlobalHosts ||
      ThorAuditSmemRead (Region, Partition + 8) != Size) {
    return EFI_COMPROMISED_DATA;
  }
  UINT32 Uncached = ThorAuditSmemRead (Region, Partition + 12);
  UINT32 Cached = ThorAuditSmemRead (Region, Partition + 16);
  if ((Uncached & 3) != 0 || (Cached & 3) != 0 ||
      Uncached < PartitionHeader || Uncached > Cached || Cached > Size) {
    return EFI_COMPROMISED_DATA;
  }

  UINT32 Count = 0;
  for (UINT32 Entry = PartitionHeader; Entry < Uncached;) {
    if (Uncached - Entry < Header || ++Count > 4096) {
      return EFI_COMPROMISED_DATA;
    }
    UINT32 Tag = ThorAuditSmemRead (Region, Partition + Entry);
    UINT32 Length = ThorAuditSmemRead (Region, Partition + Entry + 4);
    UINT32 Padding = ThorAuditSmemRead (Region, Partition + Entry + 8);
    UINT32 Data = Entry + Header + (Padding >> 16);
    UINT32 Tail = Padding & 0xffffu;
    if ((Tag & 0xffffu) != Canary || (Data & 3) != 0 || (Length & 3) != 0 ||
        Tail > Length || Data > Uncached || Length > Uncached - Data) {
      return EFI_COMPROMISED_DATA;
    }
    if ((Tag >> 16) == THOR_AUDIT_SMEM_ITEM) {
      if (*Item != 0) {
        return EFI_COMPROMISED_DATA;
      }
      *Item = Partition + Data;
      *Bytes = Length - Tail;
    }
    Entry = Data + Length;
  }

  if (Cached != Size) {
    if (CacheLine < 4 || CacheLine > 0x1000 || (CacheLine & (CacheLine - 1)) != 0) {
      return EFI_COMPROMISED_DATA;
    }
    UINT32 Slot = MAX (Header, CacheLine);
    if (Slot >= Size - Cached) {
      return EFI_COMPROMISED_DATA;
    }
    for (UINT32 Entry = Size - Slot; Entry > Cached;) {
      if (++Count > 4096) {
        return EFI_COMPROMISED_DATA;
      }
      UINT32 Tag = ThorAuditSmemRead (Region, Partition + Entry);
      UINT32 Length = ThorAuditSmemRead (Region, Partition + Entry + 4);
      UINT32 Tail = ThorAuditSmemRead (Region, Partition + Entry + 8) & 0xffffu;
      if ((Tag & 0xffffu) != Canary || (Length & 3) != 0 ||
          Tail > Length || Length > Entry - Cached) {
        return EFI_COMPROMISED_DATA;
      }
      UINT32 Data = Entry - Length;
      if ((Tag >> 16) == THOR_AUDIT_SMEM_ITEM) {
        if (*Item != 0) {
          return EFI_COMPROMISED_DATA;
        }
        *Item = Partition + Data;
        *Bytes = Length - Tail;
      }
      if (Data == Cached) {
        break;
      }
      if (Data - Cached <= Slot) {
        return EFI_COMPROMISED_DATA;
      }
      Entry = Data - Slot;
    }
  }
  return *Item == 0 ? EFI_NOT_FOUND : EFI_SUCCESS;
}

STATIC EFI_STATUS
ThorAuditSmemRaw (THOR_MEMORY_AUDIT *Audit)
{
  if (!ThorAuditMapped (Audit->ReservedSmemBase, Audit->ReservedSmemBytes)) {
    return EFI_SECURITY_VIOLATION;
  }
  Audit->Flags |= THOR_AUDIT_SMEM_RAW_TRIED;
  CONST volatile UINT32 *Region = (CONST volatile UINT32 *)(UINTN)Audit->ReservedSmemBase;
  if (ThorAuditSmemRead (Region, 192) != 1 || ThorAuditSmemRead (Region, 204) != 0) {
    return EFI_NOT_READY;
  }
  Audit->SmemRawFormat = ThorAuditSmemRead (Region, 92) >> 16;
  UINT32 Item = 0, Bytes = 0;
  EFI_STATUS Status;
  switch (Audit->SmemRawFormat) {
    case 11:
      Status = ThorAuditSmemLegacy (Region, &Item, &Bytes);
      break;
    case 12:
      Status = ThorAuditSmemPartition (Region, &Item, &Bytes);
      break;
    default:
      return EFI_UNSUPPORTED;
  }
  if (EFI_ERROR (Status)) {
    return Status;
  }
  if ((Item & 3) != 0 || (Bytes & 3) != 0 || Bytes < 24 || Bytes > THOR_AUDIT_SMEM_MAX ||
      !ThorAuditInside (Item, Bytes, 0, THOR_AUDIT_SMEM_BYTES)) {
    return EFI_COMPROMISED_DATA;
  }
  UINT32 Snapshot[THOR_AUDIT_SMEM_MAX / sizeof (UINT32)];
  for (UINT32 Offset = 0; Offset < Bytes; Offset += sizeof (UINT32)) {
    Snapshot[Offset / sizeof (UINT32)] = ThorAuditSmemRead (Region, Item + Offset);
  }
  MemoryFence ();
  for (UINT32 Offset = 0; Offset < Bytes; Offset += sizeof (UINT32)) {
    if (Snapshot[Offset / sizeof (UINT32)] != ThorAuditSmemRead (Region, Item + Offset)) {
      return EFI_NOT_READY;
    }
  }
  Status = ThorAuditSmemTable (Audit, (CONST UINT8 *)Snapshot, Bytes);
  if (!EFI_ERROR (Status)) {
    Audit->Flags |= THOR_AUDIT_SMEM_RAW_VALID;
  }
  return Status;
}

STATIC VOID
ThorAuditSmem (THOR_MEMORY_AUDIT *Audit)
{
  Audit->SmemProtocolStatus = ThorAuditSmemProtocol (Audit);
  Audit->SmemStatus = Audit->SmemProtocolStatus;
  if (Audit->SmemStatus == EFI_NOT_FOUND && (Audit->Flags & THOR_AUDIT_SMEM_APERTURE)) {
    Audit->SmemStatus = ThorAuditSmemRaw (Audit);
  }
}

STATIC BOOLEAN
ThorAuditHasOption (CONST CHAR8 *CommandLine, CONST CHAR8 *Option)
{
  const UINTN Length = AsciiStrLen (Option);
  CONST CHAR8 *Match = CommandLine;
  while ((Match = AsciiStrStr (Match, Option)) != NULL) {
    if ((Match == CommandLine || Match[-1] == ' ' || Match[-1] == '\t') &&
        (Match[Length] == 0 || Match[Length] == ' ' || Match[Length] == '\t')) {
      return TRUE;
    }
    Match += Length;
  }
  return FALSE;
}

STATIC BOOLEAN
ThorTrialNormalWb (UINT64 Par)
{
  // AT encodes the effective memory attribute at [63:56]. The existing
  // Thor window probe requires normal inner/outer WB, inner shareable.
  return (Par & 1) == 0 &&
         (Par & THOR_AUDIT_PHYS_PAGE_MASK) == THOR_AUDIT_B_BASE &&
         (Par >> 56) == 0xff && (Par & 0x180) == 0x180;
}

STATIC BOOLEAN
ThorTrialWb (UINT64 Attributes)
{
  const UINT64 Cache = EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT |
                       EFI_MEMORY_WB | EFI_MEMORY_UCE;
  const UINT64 Denied = EFI_MEMORY_RUNTIME | EFI_MEMORY_RO | EFI_MEMORY_RP | EFI_MEMORY_WP;
  return (Attributes & Cache) == EFI_MEMORY_WB && !(Attributes & Denied);
}

STATIC VOID
ThorAuditTranslateReadWrite (UINT64 Page, UINT64 *Read, UINT64 *Write)
{
  UINT64 Daif, SavedPar, ReadPar, WritePar;
  __asm__ __volatile__ (
    "mrs %0, daif\n\t"
    "msr daifset, #15\n\t"
    "isb\n\t"
    "mrs %1, par_el1\n\t"
    "at s1e1r, %4\n\t"
    "isb\n\t"
    "mrs %2, par_el1\n\t"
    "at s1e1w, %4\n\t"
    "isb\n\t"
    "mrs %3, par_el1\n\t"
    "msr par_el1, %1\n\t"
    "isb\n\t"
    "msr daif, %0\n\t"
    "isb"
    : "=&r"(Daif), "=&r"(SavedPar), "=&r"(ReadPar), "=&r"(WritePar)
    : "r"(Page) : "memory"
    );
  *Read = ReadPar;
  *Write = WritePar;
}

STATIC VOID
ThorTrialFirstPage (THOR_MEMORY_AUDIT *Audit)
{
  const EFI_GCD_MEMORY_SPACE_DESCRIPTOR *D = &Audit->Gcd;
  if (!EFI_ERROR (Audit->GcdStatus) && D->BaseAddress <= MAX_UINT64 - D->Length &&
      ThorAuditInside (THOR_AUDIT_B_BASE, EFI_PAGE_SIZE, D->BaseAddress,
                       D->BaseAddress + D->Length) &&
      D->GcdMemoryType == EfiGcdMemoryTypeSystemMemory && ThorTrialWb (D->Attributes)) {
    Audit->Flags |= THOR_TRIAL_GCD_WB;
  }

  if (DarwinCurrentEl () != 4 || !(READ_SYSREG (sctlr_el1) & 1) ||
      Audit->FdtStatus != 0 || Audit->FdtHits != 1 || Audit->ReservedHits != 0 ||
      Audit->SmemStatus != EFI_SUCCESS || Audit->SmemVersion != 3 ||
      Audit->SmemHits != 1 || !(Audit->Flags & THOR_AUDIT_SMEM_B_AVAILABLE)) {
    return;
  }

  // No page is mapped, allocated, loaded, or written by this observation.
  // Both AT instructions use the current EL1 regime; save and restore
  // interrupt masks and PAR_EL1 as for the established low-input probe.
  UINT64 ReadPar, WritePar;
  ThorAuditTranslateReadWrite (THOR_AUDIT_B_BASE, &ReadPar, &WritePar);
  Audit->Flags |= THOR_TRIAL_AT_ATTEMPTED;
  if (ReadPar & 1) {
    Audit->Flags |= THOR_TRIAL_AT_READ_FAULT;
  } else if (ThorTrialNormalWb (ReadPar)) {
    Audit->Flags |= THOR_TRIAL_AT_READ_WB;
  }
  if (WritePar & 1) {
    Audit->Flags |= THOR_TRIAL_AT_WRITE_FAULT;
  } else if (ThorTrialNormalWb (WritePar)) {
    Audit->Flags |= THOR_TRIAL_AT_WRITE_WB;
  }
  Print (L"THOR MEM: first page EL1 AT R=%lx W=%lx, flags=%lx; observation only\n",
         ReadPar, WritePar, Audit->Flags);
}

STATIC VOID
ThorAuditCollect (THOR_MEMORY_AUDIT *Audit, CONST CHAR8 *CommandLine)
{
  ZeroMem (Audit, sizeof (*Audit));
  if (ThorAuditHasOption (CommandLine, "tmprobe=1")) {
    Audit->Flags |= THOR_TRIAL_REQUESTED;
  }
  if (ThorAuditHasOption (CommandLine, "tmlow=1")) {
    Audit->Flags |= THOR_LOW_REQUESTED;
  }
  ThorAuditFdt (Audit);
  Audit->GcdStatus = EFI_NOT_FOUND;
  if (gDS != NULL && gDS->GetMemorySpaceDescriptor != NULL) {
    Audit->GcdStatus = gDS->GetMemorySpaceDescriptor (THOR_AUDIT_B_BASE, &Audit->Gcd);
    if (!EFI_ERROR (Audit->GcdStatus) && Audit->Gcd.BaseAddress <= MAX_UINT64 - Audit->Gcd.Length &&
        ThorAuditInside (THOR_AUDIT_B_BASE, THOR_AUDIT_B_BYTES, Audit->Gcd.BaseAddress,
                         Audit->Gcd.BaseAddress + Audit->Gcd.Length)) {
      Audit->Flags |= 0x40ULL;
      if (Audit->Gcd.GcdMemoryType == EfiGcdMemoryTypeSystemMemory &&
          (Audit->Gcd.Attributes & EFI_MEMORY_WB) && !(Audit->Gcd.Attributes & EFI_MEMORY_RUNTIME)) {
        Audit->Flags |= 0x80ULL;
      }
    }
  }
  ThorAuditSmem (Audit);
  if (Audit->Flags & THOR_TRIAL_REQUESTED) {
    ThorTrialFirstPage (Audit);
  }
  Print (L"THOR MEM: B preview %lx + %lx flags=%lx FDT=%u/%lx GCD=%r SMEM=%r; no RAM claim\n",
         THOR_AUDIT_B_BASE, THOR_AUDIT_B_BYTES, Audit->Flags, Audit->FdtStatus,
         Audit->FdtAddress, Audit->GcdStatus, Audit->SmemStatus);
}

STATIC VOID
ThorAuditWrite (UINT8 *Wire, CONST THOR_MEMORY_AUDIT *Audit, CONST EFI_MEMORY_DESCRIPTOR *Map,
                UINTN MapSize, UINTN Stride)
{
  UINT64 Conventional = 0, Other = 0, Flags = Audit->Flags;
  UINT32 PageDescriptors = 0;
  BOOLEAN PageWb = FALSE;
  const UINT64 Limit = THOR_AUDIT_B_BASE + THOR_AUDIT_B_BYTES;
  UINT64 Next = THOR_AUDIT_B_BASE;
  // This loop scans the complete accepted EFI map, independent of the first
  // 120 descriptor records in the adjacent DB24 diagnostics array.
  for (UINTN Offset = 0; Offset < MapSize; Offset += Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *D = (CONST VOID *)((CONST UINT8 *)Map + Offset);
    UINT64 End;
    if (!DescriptorEnd (D, &End)) {
      continue;
    }
    if ((Flags & THOR_TRIAL_REQUESTED) &&
        D->PhysicalStart < THOR_AUDIT_B_BASE + EFI_PAGE_SIZE && End > THOR_AUDIT_B_BASE) {
      PageDescriptors++;
      PageWb = D->Type == EfiConventionalMemory && ThorTrialWb (D->Attribute) &&
               ThorAuditInside (THOR_AUDIT_B_BASE, EFI_PAGE_SIZE, D->PhysicalStart, End);
    }
    UINT64 Base = MAX (D->PhysicalStart, THOR_AUDIT_B_BASE);
    End = MIN (End, Limit);
    if (Base >= End) {
      continue;
    }
    if (D->Type == EfiConventionalMemory && (D->Attribute & EFI_MEMORY_WB) &&
        !(D->Attribute & EFI_MEMORY_RUNTIME)) {
      Conventional += End - Base;
      if (Base == Next) {
        Next = End;
      }
    } else {
      Other += End - Base;
    }
  }
  if (Conventional == THOR_AUDIT_B_BYTES && Other == 0 && Next == Limit) {
    Flags |= 0x400ULL;
  }
  if (PageDescriptors == 1 && PageWb) {
    Flags |= THOR_TRIAL_EFI_WB;
  }
  ZeroMem (Wire, THOR_AUDIT_BYTES);
  WriteUnaligned32 ((UINT32 *)(Wire + 0), 0x4d415254U);
  WriteUnaligned32 ((UINT32 *)(Wire + 4), 1);
  WriteUnaligned64 ((UINT64 *)(Wire + 8), Flags);
  WriteUnaligned64 ((UINT64 *)(Wire + 16), THOR_AUDIT_B_BASE);
  WriteUnaligned64 ((UINT64 *)(Wire + 24), THOR_AUDIT_B_BYTES);
  WriteUnaligned64 ((UINT64 *)(Wire + 32), Audit->FdtAddress);
  WriteUnaligned32 ((UINT32 *)(Wire + 40), Audit->FdtBytes);
  WriteUnaligned32 ((UINT32 *)(Wire + 44), Audit->FdtStatus);
  WriteUnaligned32 ((UINT32 *)(Wire + 48), Audit->FdtCrc);
  WriteUnaligned32 ((UINT32 *)(Wire + 52), Audit->FdtBanks);
  WriteUnaligned32 ((UINT32 *)(Wire + 56), Audit->FdtHits);
  WriteUnaligned32 ((UINT32 *)(Wire + 60), Audit->ReservedHits);
  WriteUnaligned64 ((UINT64 *)(Wire + 64), Audit->GcdStatus);
  WriteUnaligned32 ((UINT32 *)(Wire + 72), Audit->Gcd.GcdMemoryType);
  WriteUnaligned64 ((UINT64 *)(Wire + 80), Audit->Gcd.BaseAddress);
  WriteUnaligned64 ((UINT64 *)(Wire + 88), Audit->Gcd.Length);
  WriteUnaligned64 ((UINT64 *)(Wire + 96), Audit->Gcd.Attributes);
  WriteUnaligned64 ((UINT64 *)(Wire + 104), Audit->Gcd.Capabilities);
  WriteUnaligned64 ((UINT64 *)(Wire + 112), Audit->SmemStatus);
  WriteUnaligned32 ((UINT32 *)(Wire + 120), Audit->SmemBytes);
  WriteUnaligned32 ((UINT32 *)(Wire + 124), Audit->SmemVersion);
  WriteUnaligned32 ((UINT32 *)(Wire + 128), Audit->SmemEntries);
  WriteUnaligned32 ((UINT32 *)(Wire + 132), Audit->SmemHits);
  WriteUnaligned64 ((UINT64 *)(Wire + 136), Audit->SmemBase);
  WriteUnaligned64 ((UINT64 *)(Wire + 144), Audit->SmemLength);
  WriteUnaligned64 ((UINT64 *)(Wire + 152), Audit->SmemAvailable);
  WriteUnaligned32 ((UINT32 *)(Wire + 160), Audit->SmemAttribute);
  WriteUnaligned32 ((UINT32 *)(Wire + 164), Audit->SmemCategory);
  WriteUnaligned32 ((UINT32 *)(Wire + 168), Audit->SmemDomain);
  WriteUnaligned32 ((UINT32 *)(Wire + 172), Audit->SmemType);
  WriteUnaligned64 ((UINT64 *)(Wire + 176), Conventional);
  WriteUnaligned64 ((UINT64 *)(Wire + 184), Other);
  WriteUnaligned64 ((UINT64 *)(Wire + 192), Audit->SmemProtocolStatus);
  WriteUnaligned64 ((UINT64 *)(Wire + 200), Audit->ReservedSmemBase);
  WriteUnaligned64 ((UINT64 *)(Wire + 208), Audit->ReservedSmemBytes);
  WriteUnaligned64 ((UINT64 *)(Wire + 216), Audit->SmemRawFormat);
}
