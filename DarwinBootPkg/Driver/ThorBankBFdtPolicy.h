// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Include after the FDT decoding helpers in ThorMemoryAudit.h. Invoke on
// the same immutable, bounded ABL DT snapshot after fdt_check_full succeeds.
// This checks live DT reservations. SMEM, OEM policy, GCD, and physical
// accessibility remain separate qualifications.

#define THOR_FDT_B_CHECKED        BIT43
#define THOR_FDT_B_FIXED_CLEAR    BIT44
#define THOR_FDT_B_LINUX_CMA      BIT45
#define THOR_FDT_B_TRUST_UI       BIT46
#define THOR_FDT_B_RAMOOPS        BIT47
#define THOR_FDT_B_OTHER          BIT48
#define THOR_FDT_B_FIXED_CONFLICT BIT49
#define THOR_FDT_B_INVALID        BIT50
// libfdt's status for a valid node or property that is absent.
#define THOR_FDT_B_NOT_FOUND      (-1)

#define THOR_FULL_FDT_CHECKED       BIT51
#define THOR_FULL_FDT_ACCEPTED      BIT52
#define THOR_FULL_FDT_CONFLICT      BIT53
#define THOR_FULL_FDT_INVALID       BIT54
#define THOR_FULL_FDT_UNRESOLVED    BIT55
#define THOR_FULL_SMEM_ACCEPTED     BIT56
#define THOR_FULL_BANK_C_LIMIT      0xA60000000ULL

STATIC BOOLEAN
ThorFullFdtAliasProperties (CONST VOID *Fdt, int Node, BOOLEAN TrustUi)
{
  int Offset;
  for (Offset = fdt_first_property_offset (Fdt, Node); Offset >= 0;
       Offset = fdt_next_property_offset (Fdt, Offset)) {
    CONST CHAR8 *Name;
    int Length;
    if (fdt_getprop_by_offset (Fdt, Offset, &Name, &Length) == NULL ||
        (AsciiStrCmp (Name, "phandle") != 0 &&
         AsciiStrCmp (Name, "linux,phandle") != 0 &&
         (TrustUi ?
          AsciiStrCmp (Name, "no-map") != 0 :
          (AsciiStrCmp (Name, "compatible") != 0 &&
           AsciiStrCmp (Name, "alloc-ranges") != 0 &&
           AsciiStrCmp (Name, "mem-type") != 0)))) {
      return FALSE;
    }
  }
  return Offset == THOR_FDT_B_NOT_FOUND;
}

STATIC BOOLEAN
ThorFullFdtTrustConsumer (
  CONST VOID *Fdt,
  int         Node,
  UINT32      Handle,
  CONST CHAR8 *Compatible
  )
{
  int Length;
  CONST UINT8 *Value = fdt_getprop (Fdt, Node, "memory-region", &Length);
  if (Value == NULL || Length != 4 || ThorAuditCells (Value, 1) != Handle ||
      fdt_node_check_compatible (Fdt, Node, Compatible) != 0) {
    return FALSE;
  }
  Value = fdt_getprop (Fdt, Node, "qcom,vmid", &Length);
  if (Value == NULL || Length != 4 || ThorAuditCells (Value, 1) != 45) {
    return FALSE;
  }
  Value = fdt_getprop (Fdt, Node, "qcom,firmware-name", &Length);
  return ThorAuditPropertyIs (Value, Length, "trustedvm");
}

STATIC BOOLEAN
ThorFullFdtTrustAlias (CONST VOID *Fdt, int Node)
{
  UINT32 Handle = fdt_get_phandle (Fdt, Node);
  int Soc = fdt_subnode_offset (Fdt, 0, "soc");
  if (!Handle || Soc < 0 || !ThorFullFdtAliasProperties (Fdt, Node, TRUE)) {
    return FALSE;
  }
  int Secure = fdt_subnode_offset (Fdt, Soc, "qcom,gh_vm_loader_sec@e0b00000");
  int Guest = fdt_subnode_offset (Fdt, Soc, "qcom,guestvm_loader@e0b00000");
  if (Secure < 0 || Guest < 0 ||
      !ThorFullFdtTrustConsumer (Fdt, Secure, Handle, "qcom,gh-vm-loader-sec") ||
      !ThorFullFdtTrustConsumer (Fdt, Guest, Handle, "qcom,guestvm-loader")) {
    return FALSE;
  }

  int Other;
  for (Other = fdt_next_node (Fdt, -1, NULL); Other >= 0;
       Other = fdt_next_node (Fdt, Other, NULL)) {
    if (Other != Node && fdt_get_phandle (Fdt, Other) == Handle) {
      return FALSE;
    }
    if (Other == Secure || Other == Guest) {
      continue;
    }
    int Length;
    CONST UINT8 *Value = fdt_getprop (Fdt, Other, "memory-region", &Length);
    if (Value == NULL) {
      if (Length != THOR_FDT_B_NOT_FOUND) {
        return FALSE;
      }
      continue;
    }
    if (Length % 4 != 0) {
      return FALSE;
    }
    for (int Offset = 0; Offset < Length; Offset += 4) {
      if (ThorAuditCells (Value + Offset, 1) == Handle) {
        return FALSE;
      }
    }
  }
  return Other == THOR_FDT_B_NOT_FOUND;
}

STATIC BOOLEAN
ThorFullFdtRamoopsAlias (CONST VOID *Fdt, int Node)
{
  if (!ThorFullFdtAliasProperties (Fdt, Node, FALSE)) {
    return FALSE;
  }
  int Length;
  CONST UINT8 *Value = fdt_getprop (Fdt, Node, "alloc-ranges", &Length);
  if (Value == NULL || Length != 16 ||
      ThorAuditCells (Value, 2) != 0 || ThorAuditCells (Value + 8, 2) != MAX_UINT64) {
    return FALSE;
  }
  Value = fdt_getprop (Fdt, Node, "mem-type", &Length);
  if (Value == NULL || Length != 4 || ThorAuditCells (Value, 1) != 2) {
    return FALSE;
  }
  int Reserved = fdt_subnode_offset (Fdt, 0, "reserved-memory");
  int Backend = fdt_subnode_offset (Fdt, Reserved, "ramoops@0xa7000000");
  if (Backend < 0 || !ThorAuditNodeEnabled (Fdt, Backend) ||
      fdt_node_check_compatible (Fdt, Backend, "ramoops") != 0) {
    return FALSE;
  }
  Value = fdt_getprop (Fdt, Backend, "reg", &Length);
  return Value != NULL && Length == 16 &&
         ThorAuditCells (Value, 2) == 0xA7000000ULL &&
         ThorAuditCells (Value + 8, 2) == 0x400000ULL;
}

typedef struct {
  BOOLEAN FixedClear;
  UINT32  LinuxCmaMayChooseBankB;
  UINT32  AddresslessTrustUi;
  UINT32  AddresslessRamoops;
  UINT32  OtherUnresolved;
} THOR_BANK_B_FDT_RESULT;

STATIC EFI_STATUS
ThorBankBCheckRange (UINT64 Base, UINT64 Length, UINT64 FullEnd)
{
  if (!Length || Base > MAX_UINT64 - Length) {
    return EFI_COMPROMISED_DATA;
  }
  BOOLEAN Overlap = FullEnd ?
    Base < FullEnd && Base + Length > THOR_AUDIT_B_BASE :
    ThorAuditOverlap (Base, Length);
  return Overlap ? EFI_ACCESS_DENIED : EFI_SUCCESS;
}

STATIC EFI_STATUS
ThorBankBCollectDynamic (
  CONST VOID             *Fdt,
  int                     Node,
  THOR_BANK_B_FDT_RESULT *Result,
  UINT64                 FullEnd
  )
{
  int SizeLen, RangeLen, AlignLen, NoMapLen, ReusableLen;
  CONST UINT8 *Size = fdt_getprop (Fdt, Node, "size", &SizeLen);
  CONST UINT8 *Range = fdt_getprop (Fdt, Node, "alloc-ranges", &RangeLen);
  CONST UINT8 *Align = fdt_getprop (Fdt, Node, "alignment", &AlignLen);
  CONST VOID *NoMap = fdt_getprop (Fdt, Node, "no-map", &NoMapLen);
  CONST VOID *Reusable = fdt_getprop (Fdt, Node, "reusable", &ReusableLen);
  BOOLEAN CanChooseBankB = Range == NULL;
  int NameLen;
  CONST CHAR8 *Name = fdt_get_name (Fdt, Node, &NameLen);

  if (Name == NULL ||
      (Size == NULL && SizeLen != THOR_FDT_B_NOT_FOUND) ||
      (Range == NULL && RangeLen != THOR_FDT_B_NOT_FOUND) ||
      (Align == NULL && AlignLen != THOR_FDT_B_NOT_FOUND) ||
      (NoMap == NULL ? NoMapLen != THOR_FDT_B_NOT_FOUND : NoMapLen != 0) ||
      (Reusable == NULL ? ReusableLen != THOR_FDT_B_NOT_FOUND : ReusableLen != 0) ||
      (NoMap != NULL && Reusable != NULL)) {
    return EFI_COMPROMISED_DATA;
  }
  if (Align != NULL) {
    if (AlignLen != 8) {
      return EFI_COMPROMISED_DATA;
    }
    UINT64 Value = ThorAuditCells (Align, 2);
    if (!Value || (Value & (Value - 1)) != 0) {
      return EFI_COMPROMISED_DATA;
    }
  }
  if (Range != NULL) {
    if (RangeLen <= 0 || RangeLen % 16 != 0) {
      return EFI_COMPROMISED_DATA;
    }
    for (int Offset = 0; Offset < RangeLen; Offset += 16) {
      UINT64 Base = ThorAuditCells (Range + Offset, 2);
      UINT64 Length = ThorAuditCells (Range + Offset + 8, 2);
      EFI_STATUS Status = ThorBankBCheckRange (Base, Length, FullEnd);
      if (Status == EFI_COMPROMISED_DATA) {
        return Status;
      }
      CanChooseBankB |= Status == EFI_ACCESS_DENIED;
    }
  }

  if (Size == NULL) {
    // These are the two known addressless signatures in the saved Thor
    // Recovery DT. A name or phandle cannot establish a physical interval.
    if (NoMap != NULL && Range == NULL && Align == NULL &&
        AsciiStrCmp (Name, "trust_ui_vm_region@e0b00000") == 0 &&
        (!FullEnd || ThorFullFdtTrustAlias (Fdt, Node))) {
      Result->AddresslessTrustUi++;
    } else if (NoMap == NULL && Range != NULL &&
               AsciiStrCmp (Name, "ramoops_region") == 0 &&
               fdt_node_check_compatible (Fdt, Node, "ramoops") == 0 &&
               (!FullEnd || ThorFullFdtRamoopsAlias (Fdt, Node))) {
      Result->AddresslessRamoops++;
    } else {
      Result->OtherUnresolved++;
    }
    return EFI_SUCCESS;
  }
  if (SizeLen != 8 || !ThorAuditCells (Size, 2)) {
    return EFI_COMPROMISED_DATA;
  }
  if (!CanChooseBankB) {
    return EFI_SUCCESS;
  }
  if (NoMap == NULL && Reusable != NULL &&
      fdt_node_check_compatible (Fdt, Node, "shared-dma-pool") == 0) {
    // An addressless reusable Linux CMA request has no assigned physical
    // address. Explicit memreserve/reg entries are still checked separately.
    Result->LinuxCmaMayChooseBankB++;
  } else {
    Result->OtherUnresolved++;
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
ThorBankBFdtPolicy (
  CONST VOID             *Fdt,
  THOR_BANK_B_FDT_RESULT *Result,
  UINT64                 FullEnd
  )
{
  CONST UINT64 Start[] = { THOR_AUDIT_B_BASE, THOR_AUDIT_BANK_C_BASE };
  CONST UINT64 End[] = {
    FullEnd ? THOR_AUDIT_BANK_C_BASE : THOR_AUDIT_B_BASE + THOR_AUDIT_B_BYTES,
    FullEnd
  };
  UINT32 AddressCells, SizeCells;
  BOOLEAN Containing[2] = { FALSE, FALSE };
  int Node, Len;

  ZeroMem (Result, sizeof (*Result));
  if (!ThorAuditCellCounts (Fdt, 0, &AddressCells, &SizeCells) ||
      AddressCells != 2 || SizeCells != 2) {
    return EFI_COMPROMISED_DATA;
  }

  for (Node = fdt_first_subnode (Fdt, 0);
       Node >= 0; Node = fdt_next_subnode (Fdt, Node)) {
    CONST UINT8 *Kind = fdt_getprop (Fdt, Node, "device_type", &Len);
    if (!ThorAuditPropertyIs (Kind, Len, "memory") || !ThorAuditNodeEnabled (Fdt, Node)) {
      continue;
    }
    CONST UINT8 *Reg = fdt_getprop (Fdt, Node, "reg", &Len);
    if (Reg == NULL || Len <= 0 || Len % 16 != 0) {
      return EFI_COMPROMISED_DATA;
    }
    for (int Offset = 0; Offset < Len; Offset += 16) {
      UINT64 Base = ThorAuditCells (Reg + Offset, 2);
      UINT64 Length = ThorAuditCells (Reg + Offset + 8, 2);
      EFI_STATUS Status = ThorBankBCheckRange (Base, Length, FullEnd);
      if (Status == EFI_COMPROMISED_DATA) {
        return Status;
      }
      for (UINTN Index = 0; Index < (FullEnd ? 2U : 1U); Index++) {
        if (Base >= End[Index] || Base + Length <= Start[Index]) {
          continue;
        }
        if (Containing[Index] ||
            !ThorAuditInside (Start[Index], End[Index] - Start[Index], Base, Base + Length)) {
          return EFI_COMPROMISED_DATA;
        }
        Containing[Index] = TRUE;
      }
    }
  }
  if (Node != THOR_FDT_B_NOT_FOUND || !Containing[0] || (FullEnd && !Containing[1])) {
    return EFI_COMPROMISED_DATA;
  }

  int Count = fdt_num_mem_rsv (Fdt);
  if (Count < 0 || Count > 256) {
    return EFI_COMPROMISED_DATA;
  }
  for (int Index = 0; Index < Count; Index++) {
    UINT64 Base, Length;
    if (fdt_get_mem_rsv (Fdt, Index, &Base, &Length) != 0) {
      return EFI_COMPROMISED_DATA;
    }
    EFI_STATUS Status = ThorBankBCheckRange (Base, Length, FullEnd);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  int Reserved = fdt_subnode_offset (Fdt, 0, "reserved-memory");
  if (Reserved < 0 || !ThorAuditCellCounts (Fdt, Reserved, &AddressCells, &SizeCells) ||
      AddressCells != 2 || SizeCells != 2 ||
      fdt_getprop (Fdt, Reserved, "ranges", &Len) == NULL || Len != 0) {
    return EFI_COMPROMISED_DATA;
  }
  for (Node = fdt_first_subnode (Fdt, Reserved); Node >= 0;
       Node = fdt_next_subnode (Fdt, Node)) {
    CONST UINT8 *Reg = fdt_getprop (Fdt, Node, "reg", &Len);
    if (Reg == NULL && Len == THOR_FDT_B_NOT_FOUND) {
      EFI_STATUS Status = ThorBankBCollectDynamic (Fdt, Node, Result, FullEnd);
      if (EFI_ERROR (Status)) {
        return Status;
      }
      continue;
    }
    if (Reg == NULL || Len <= 0 || Len % 16 != 0) {
      return EFI_COMPROMISED_DATA;
    }
    for (int Offset = 0; Offset < Len; Offset += 16) {
      EFI_STATUS Status = ThorBankBCheckRange (ThorAuditCells (Reg + Offset, 2),
                                                ThorAuditCells (Reg + Offset + 8, 2), FullEnd);
      if (EFI_ERROR (Status)) {
        return Status;
      }
    }
  }
  if (Node != THOR_FDT_B_NOT_FOUND) {
    return EFI_COMPROMISED_DATA;
  }

  int Chosen = fdt_subnode_offset (Fdt, 0, "chosen");
  if (Chosen >= 0) {
    int StartLen, EndLen;
    CONST UINT8 *Start = fdt_getprop (Fdt, Chosen, "linux,initrd-start", &StartLen);
    CONST UINT8 *End = fdt_getprop (Fdt, Chosen, "linux,initrd-end", &EndLen);
    if (StartLen != THOR_FDT_B_NOT_FOUND || EndLen != THOR_FDT_B_NOT_FOUND) {
      if (Start == NULL || End == NULL || StartLen != EndLen ||
          (StartLen != 4 && StartLen != 8)) {
        return EFI_COMPROMISED_DATA;
      }
      UINT64 Base = ThorAuditCells (Start, (UINT32)StartLen / 4);
      UINT64 Limit = ThorAuditCells (End, (UINT32)EndLen / 4);
      if (Limit <= Base) {
        return EFI_COMPROMISED_DATA;
      }
      EFI_STATUS Status = ThorBankBCheckRange (Base, Limit - Base, FullEnd);
      if (EFI_ERROR (Status)) {
        return Status;
      }
    }
  } else if (Chosen != THOR_FDT_B_NOT_FOUND) {
    return EFI_COMPROMISED_DATA;
  }

  Result->FixedClear = TRUE;
  if (Result->OtherUnresolved ||
      (!FullEnd && (Result->AddresslessTrustUi || Result->AddresslessRamoops))) {
    return EFI_NOT_READY;
  }
  return EFI_SUCCESS;
}

// Called only after this parser has run on a fully validated snapshot.
STATIC UINT64
ThorBankBFdtFlags (
  EFI_STATUS                    Status,
  CONST THOR_BANK_B_FDT_RESULT *Result
  )
{
  UINT64 Flags = THOR_FDT_B_CHECKED;

  if (Status == EFI_ACCESS_DENIED) {
    return Flags | THOR_FDT_B_FIXED_CONFLICT;
  }
  if ((Status != EFI_SUCCESS && Status != EFI_NOT_READY) || !Result->FixedClear) {
    return Flags | THOR_FDT_B_INVALID;
  }

  Flags |= THOR_FDT_B_FIXED_CLEAR;
  if (Result->LinuxCmaMayChooseBankB) { Flags |= THOR_FDT_B_LINUX_CMA; }
  if (Result->AddresslessTrustUi) { Flags |= THOR_FDT_B_TRUST_UI; }
  if (Result->AddresslessRamoops) { Flags |= THOR_FDT_B_RAMOOPS; }
  if (Result->OtherUnresolved) { Flags |= THOR_FDT_B_OTHER; }
  return Flags;
}
