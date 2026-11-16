// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <Uefi.h>
#include <Guid/FileInfo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Protocol/UniXNULoader.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/Cpu.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/SimpleFileSystem.h>
#include "BootArgs.h"
#include "BootVideo.h"
#include "PackedRamdisk.h"
#include "WindowSize.h"

#define WINDOW_SIZE  SIZE_256MB
#define BLOCK_SIZE   SIZE_2MB
#define MAX_SEGMENTS 64

typedef struct {
  UINT64  Address;
  UINT64  Size;
  UINT64  FileOffset;
  UINT64  FileSize;
  UINT32  Protection;
} SEGMENT;

typedef struct {
  SEGMENT  Segments[MAX_SEGMENTS];
  UINTN    Count;
  UINT64   Base;
  UINT64   End;
  UINT64   Entry;
} KERNEL;

STATIC EFI_HANDLE  mImage;
STATIC EFI_HANDLE  mReplacedHandle;
STATIC VOID        *mReplacedLoader;
UINT64 EFIAPI DarwinCurrentEl (VOID);
VOID EFIAPI DarwinEnter (UINT64 Args, UINT64 Entry, UINT64 Memory, UINT64 PopulatedBytes, UINT64 VideoBase, UINT64 VideoBytes);
VOID EFIAPI DarwinEnterEnd (VOID);

STATIC
VOID
FlushRange (UINT64 Base, UINT64 Bytes)
{
  UINT64 Ctr, Line, Address;
  __asm__ volatile ("mrs %0, ctr_el0" : "=r" (Ctr));
  Line = 4ULL << ((Ctr >> 16) & 15);
  __asm__ volatile ("dsb sy" ::: "memory");
  for (Address = Base & ~(Line - 1); Address < Base + Bytes; Address += Line) {
    __asm__ volatile ("dc civac, %0" :: "r" (Address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

#define READ_SYSREG(Name)  ({ UINT64 Value_; __asm__ volatile ("mrs %0, " #Name : "=r" (Value_)); Value_; })

STATIC UINT32 U32 (CONST VOID *P) { return ReadUnaligned32 ((CONST UINT32 *)P); }
STATIC UINT64 U64 (CONST VOID *P) { return ReadUnaligned64 ((CONST UINT64 *)P); }

STATIC
EFI_STATUS
ReadBootVideo (UINT64 Video[6])
{
  EFI_GRAPHICS_OUTPUT_PROTOCOL           *Gop;
  EFI_STATUS                            Status;

  ZeroMem (Video, 6 * sizeof (*Video));
  Status = gBS->HandleProtocol (gST->ConsoleOutHandle, &gEfiGraphicsOutputProtocolGuid, (VOID **)&Gop);
  if (EFI_ERROR (Status)) {
    Status = gBS->LocateProtocol (&gEfiGraphicsOutputProtocolGuid, NULL, (VOID **)&Gop);
  }
  if (Status == EFI_NOT_FOUND) { return EFI_SUCCESS; }
  if (EFI_ERROR (Status)) { return Status; }
  return DarwinBootVideoFromGop (Gop, Video);
}

STATIC
EFI_STATUS
ReadFile (
  EFI_FILE_PROTOCOL *Root,
  CONST CHAR16      *Path,
  UINTN             Limit,
  VOID              **Data,
  UINTN             *Size
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *File;
  EFI_FILE_INFO      *Info;
  UINTN              InfoSize;
  UINTN              Actual;

  *Data = NULL;
  *Size = 0;
  Status = Root->Open (Root, &File, (CHAR16 *)Path, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) { return Status; }
  Info = NULL;
  InfoSize = 0;
  Status = File->GetInfo (File, &gEfiFileInfoGuid, &InfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) { goto Done; }
  Info = AllocatePool (InfoSize);
  if (Info == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  Status = File->GetInfo (File, &gEfiFileInfoGuid, &InfoSize, Info);
  if (EFI_ERROR (Status)) { goto Done; }
  if ((Info->Attribute & EFI_FILE_DIRECTORY) || (Info->FileSize == 0) || (Info->FileSize > Limit)) {
    Status = EFI_BAD_BUFFER_SIZE;
    goto Done;
  }
  *Size = (UINTN)Info->FileSize;
  *Data = AllocatePool (*Size);
  if (*Data == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  Actual = *Size;
  Status = File->Read (File, &Actual, *Data);
  if (!EFI_ERROR (Status) && (Actual != *Size)) { Status = EFI_DEVICE_ERROR; }
Done:
  if (Info != NULL) { FreePool (Info); }
  File->Close (File);
  if (EFI_ERROR (Status) && (*Data != NULL)) { FreePool (*Data); *Data = NULL; }
  return Status;
}

STATIC
EFI_STATUS
ParseKernel (CONST UINT8 *Data, UINTN Size, KERNEL *Kernel)
{
  UINTN    Offset;
  UINTN    End;
  UINTN    Index;
  UINTN    Other;
  UINT32   Count;
  UINT32   Command;
  UINT32   Length;
  SEGMENT  *Segment;
  BOOLEAN  HasEntry;
  BOOLEAN  Executable;

  if ((Size < 32) || (U32 (Data) != 0xfeedfacf) || (U32 (Data + 4) != 0x100000c) ||
      (U32 (Data + 8) != 0) || (U32 (Data + 12) != 2)) {
    return EFI_UNSUPPORTED;
  }
  if (U32 (Data + 20) > Size - 32) { return EFI_LOAD_ERROR; }
  ZeroMem (Kernel, sizeof (*Kernel));
  Count = U32 (Data + 16);
  End = 32 + U32 (Data + 20);
  Offset = 32;
  HasEntry = FALSE;
  for (Index = 0; Index < Count; Index++) {
    if (End - Offset < 8) { return EFI_LOAD_ERROR; }
    Command = U32 (Data + Offset);
    Length = U32 (Data + Offset + 4);
    if ((Length < 8) || (Length & 7) || (Length > End - Offset)) { return EFI_LOAD_ERROR; }
    if (Command == 0x19) {
      if ((Length < 72) || (U32 (Data + Offset + 64) > (Length - 72) / 80) ||
          (Kernel->Count == MAX_SEGMENTS)) { return EFI_LOAD_ERROR; }
      if (U64 (Data + Offset + 32) != 0) {
        Segment = &Kernel->Segments[Kernel->Count++];
        Segment->Address = U64 (Data + Offset + 24);
        Segment->Size = U64 (Data + Offset + 32);
        Segment->FileOffset = U64 (Data + Offset + 40);
        Segment->FileSize = U64 (Data + Offset + 48);
        Segment->Protection = U32 (Data + Offset + 60);
        if ((Segment->Size > WINDOW_SIZE) || (Segment->Address > MAX_UINT64 - Segment->Size) ||
            (Segment->FileSize > Segment->Size) || (Segment->FileOffset > Size) ||
            (Segment->FileSize > Size - Segment->FileOffset)) { return EFI_LOAD_ERROR; }
      }
    } else if (Command == 5) {
      if (HasEntry || (Length != 288) || (U32 (Data + Offset + 8) != 6) ||
          (U32 (Data + Offset + 12) != 68)) { return EFI_LOAD_ERROR; }
      Kernel->Entry = U64 (Data + Offset + 272);
      HasEntry = TRUE;
    }
    Offset += Length;
  }
  if ((Offset != End) || !HasEntry || (Kernel->Count == 0)) { return EFI_LOAD_ERROR; }
  Kernel->Base = MAX_UINT64;
  Executable = FALSE;
  for (Index = 0; Index < Kernel->Count; Index++) {
    Segment = &Kernel->Segments[Index];
    Kernel->Base = MIN (Kernel->Base, Segment->Address);
    Kernel->End = MAX (Kernel->End, Segment->Address + Segment->Size);
    if ((Kernel->Entry >= Segment->Address) && (Kernel->Entry - Segment->Address < Segment->FileSize) &&
        ((Segment->Protection & 4) != 0)) { Executable = TRUE; }
    for (Other = 0; Other < Index; Other++) {
      if ((Segment->Address < Kernel->Segments[Other].Address + Kernel->Segments[Other].Size) &&
          (Kernel->Segments[Other].Address < Segment->Address + Segment->Size)) { return EFI_LOAD_ERROR; }
    }
  }
  if (!Executable || (Kernel->Entry & 3) || (Kernel->Base & EFI_PAGE_MASK) ||
      (Kernel->Base > MAX_UINT64 - WINDOW_SIZE) ||
      (Kernel->End - Kernel->Base > WINDOW_SIZE - SIZE_2MB)) { return EFI_LOAD_ERROR; }
  return EFI_SUCCESS;
}

STATIC UINTN mAudioDmaOffset = MAX_UINTN;
STATIC UINTN mThorScanoutOffset = MAX_UINTN;
#include "UsbOwnership.h"
#define PONG_RAM_MAX 64
#define PONG_RAM_WIRE_SIZE (32 + PONG_RAM_MAX * 16)
STATIC UINTN mRamWireOffset = MAX_UINTN, mRamAllowedOffset = MAX_UINTN, mRamAllowedCount;
STATIC UINTN mRamDiagOffset = MAX_UINTN;
typedef struct { UINT64 Start, Size; } PONG_RAM_BANK;

STATIC
BOOLEAN
AdtNode (CONST UINT8 *Data, UINTN Size, UINTN *Offset, UINTN Depth, UINTN ParentPath, UINTN *RamdiskOffset, UINTN *TrustCacheOffset, UINT64 *WindowSize, BOOLEAN *KeepPacked)
{
  UINT32 Properties;
  UINT32 Children;
  UINT32 Length;
  UINTN  Index;
  UINTN  Path;
  UINTN  Candidate;
  UINTN  TrustCandidate;
  UINTN  MemoryCandidate;
  UINTN  AudioCandidate, ScanoutCandidate, RamCandidate, AllowedCandidate, DiagCandidate, AllowedCount;
  CONST UINT8 *Name;
  UINTN  NameLength;

  Name = NULL;
  NameLength = 0;
  Candidate = MAX_UINTN;
  TrustCandidate = MAX_UINTN;
  MemoryCandidate = MAX_UINTN;
  AudioCandidate = MAX_UINTN;
  ScanoutCandidate = MAX_UINTN;
  RamCandidate = MAX_UINTN;
  DiagCandidate = MAX_UINTN;
  RamCandidate = AllowedCandidate = MAX_UINTN; AllowedCount = 0;
  if ((Depth > 64) || (Size - *Offset < 8)) { return FALSE; }
  Properties = U32 (Data + *Offset);
  Children = U32 (Data + *Offset + 4);
  *Offset += 8;
  if (Properties > (Size - *Offset) / 36) { return FALSE; }
  for (Index = 0; Index < Properties; Index++) {
    if (Size - *Offset < 36) { return FALSE; }
    if (ScanMem8 (Data + *Offset, 32, 0) == NULL) { return FALSE; }
    Length = U32 (Data + *Offset + 32);
    *Offset += 36;
    if (Length > Size - *Offset) { return FALSE; }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "name") == 0) {
      if (Name != NULL) { return FALSE; }
      Name = Data + *Offset;
      NameLength = Length;
    }
    if ((AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "RAMDisk") == 0) ||
        (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "PackedRAMDisk") == 0)) {
      if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "PackedRAMDisk") == 0) {
        if (*KeepPacked) { return FALSE; }
        *KeepPacked = TRUE;
      }
      if ((Candidate != MAX_UINTN) || (Length != 16)) { return FALSE; }
      Candidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "darwinboot-memory-ranges") == 0) {
      if ((mRamWireOffset != MAX_UINTN) || (RamCandidate != MAX_UINTN) || (Length != PONG_RAM_WIRE_SIZE)) { return FALSE; }
      RamCandidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "darwinboot-mem-diag") == 0) {
      if ((mRamDiagOffset != MAX_UINTN) || (DiagCandidate != MAX_UINTN) || (Length != 4096)) { return FALSE; }
      DiagCandidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "pong-allocatable-ram") == 0) {
      if ((mRamAllowedOffset != MAX_UINTN) || (AllowedCandidate != MAX_UINTN) || !Length || Length % 16 || Length / 16 > PONG_RAM_MAX) { return FALSE; }
      AllowedCandidate = *Offset;
      AllowedCount = Length / 16;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "pong-audio-dma") == 0) {
      if ((AudioCandidate != MAX_UINTN) || (Length != 16)) { return FALSE; }
      AudioCandidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "thor-native-scanout") == 0) {
      if (ScanoutCandidate != MAX_UINTN || Length != 16 ||
          U64 (Data + *Offset) != 0 || U64 (Data + *Offset + 8) != 0) { return FALSE; }
      ScanoutCandidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "TrustCache") == 0) {
      if ((TrustCandidate != MAX_UINTN) || (Length != 16)) { return FALSE; }
      TrustCandidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "darwinboot-memory-size") == 0) {
      if ((MemoryCandidate != MAX_UINTN) || (Length != 8)) { return FALSE; }
      MemoryCandidate = *Offset;
    }
    *Offset += Length;
    if (ALIGN_VALUE (*Offset, 4) > Size) { return FALSE; }
    *Offset = ALIGN_VALUE (*Offset, 4);
  }
  Path = 3;
  if (Depth == 0) { Path = 0; }
  if ((Depth == 1) && (ParentPath == 0) && (NameLength == 7) && (CompareMem (Name, "chosen", 7) == 0)) { Path = 1; }
  if ((Depth == 2) && (ParentPath == 1) && (NameLength == 11) && (CompareMem (Name, "memory-map", 11) == 0)) { Path = 2; }
  if ((Path == 2) && (Candidate != MAX_UINTN)) {
    if (*RamdiskOffset != MAX_UINTN) { return FALSE; }
    *RamdiskOffset = Candidate;
  }
  if ((Path == 2) && (TrustCandidate != MAX_UINTN)) {
    if (*TrustCacheOffset != MAX_UINTN) { return FALSE; }
    *TrustCacheOffset = TrustCandidate;
  }
  if (AudioCandidate != MAX_UINTN) {
    if ((Path != 1) || (mAudioDmaOffset != MAX_UINTN)) { return FALSE; }
    mAudioDmaOffset = AudioCandidate;
  }
  if (ScanoutCandidate != MAX_UINTN) {
    if (Path != 1 || mThorScanoutOffset != MAX_UINTN) { return FALSE; }
    mThorScanoutOffset = ScanoutCandidate;
  }
  if (RamCandidate != MAX_UINTN || AllowedCandidate != MAX_UINTN) {
    if (Path != 1 || RamCandidate == MAX_UINTN || AllowedCandidate == MAX_UINTN) { return FALSE; }
    mRamWireOffset = RamCandidate; mRamAllowedOffset = AllowedCandidate; mRamAllowedCount = AllowedCount;
  }
  if (DiagCandidate != MAX_UINTN) {
    if (Path != 1) { return FALSE; }
    mRamDiagOffset = DiagCandidate;
  }
  if (MemoryCandidate != MAX_UINTN) {
    if ((Path != 1) || (*WindowSize != 0)) { return FALSE; }
    *WindowSize = U64 (Data + MemoryCandidate);
    if (!DarwinWindowSizeValid (*WindowSize)) { return FALSE; }
  }
  if (Children > (Size - *Offset) / 8) { return FALSE; }
  for (Index = 0; Index < Children; Index++) {
    if (!AdtNode (Data, Size, Offset, Depth + 1, Path, RamdiskOffset, TrustCacheOffset, WindowSize, KeepPacked)) { return FALSE; }
  }
  return TRUE;
}

STATIC
BOOLEAN
ValidTrustCaches (CONST UINT8 *Data, UINTN Size)
{
  UINTN Count;
  UINTN Index;
  UINTN Start;
  UINTN End;
  UINTN Entries;
  UINTN Entry;

  if (Size < 8) { return FALSE; }
  Count = U32 (Data);
  if ((Count == 0) || (Count > 128) || (Count > (Size - 4) / 4)) { return FALSE; }
  for (Index = 0; Index < Count; Index++) {
    Start = U32 (Data + 4 + Index * 4);
    End = (Index + 1 < Count) ? U32 (Data + 8 + Index * 4) : Size;
    if ((Start < 4 + Count * 4) || (Start & 3) || (End > Size) ||
        (End < Start) || (End - Start < 24) || (U32 (Data + Start) != 2)) { return FALSE; }
    Entries = U32 (Data + Start + 20);
    if ((Entries > (End - Start - 24) / 24) || (End - Start != 24 + Entries * 24)) { return FALSE; }
    for (Entry = 0; Entry < Entries; Entry++) {
      CONST UINT8 *Hash = Data + Start + 24 + Entry * 24;
      if ((Hash[20] < 1) || (Hash[20] > 4) ||
          ((Entry != 0) && (CompareMem (Hash - 24, Hash, 20) >= 0))) { return FALSE; }
    }
  }
  return TRUE;
}

STATIC
EFI_STATUS
GetMap (EFI_MEMORY_DESCRIPTOR **Map, UINTN *Capacity, UINTN *Size, UINTN *Key, UINTN *Stride)
{
  EFI_STATUS Status;
  UINT32     Version;
  UINTN      Attempt;

  for (Attempt = 0; Attempt < 3; Attempt++) {
    *Size = *Capacity;
    Status = gBS->GetMemoryMap (Size, *Map, Key, Stride, &Version);
    if (Status != EFI_BUFFER_TOO_SMALL) { return Status; }
    if (*Map != NULL) { FreePool (*Map); }
    *Capacity = *Size + 32 * sizeof (EFI_MEMORY_DESCRIPTOR);
    *Map = AllocatePool (*Capacity);
    if (*Map == NULL) { return EFI_OUT_OF_RESOURCES; }
  }
  return EFI_OUT_OF_RESOURCES;
}

// Thor stock firmware reserves HYP at 0x830000000. All other high
// ranges require separate ownership and access evidence before use.
#define THOR_HIGH_DRAM_BASE  0x800000000ULL
#define THOR_HIGH_HYP_START  0x830000000ULL
#define THOR_4GB             0x100000000ULL

STATIC
BOOLEAN
DescriptorEnd (CONST EFI_MEMORY_DESCRIPTOR *Descriptor, UINT64 *End)
{
  if (!Descriptor->NumberOfPages ||
      (Descriptor->PhysicalStart & EFI_PAGE_MASK) ||
      Descriptor->NumberOfPages > (MAX_UINT64 - Descriptor->PhysicalStart) / EFI_PAGE_SIZE) {
    return FALSE;
  }
  *End = Descriptor->PhysicalStart + EFI_PAGES_TO_SIZE (Descriptor->NumberOfPages);
  return TRUE;
}

STATIC
BOOLEAN
ConventionalWriteBackEnd (CONST EFI_MEMORY_DESCRIPTOR *Descriptor, UINT64 *End)
{
  return Descriptor->Type == EfiConventionalMemory &&
         (Descriptor->Attribute & EFI_MEMORY_WB) &&
         !(Descriptor->Attribute & EFI_MEMORY_RUNTIME) &&
         DescriptorEnd (Descriptor, End);
}

STATIC
BOOLEAN
WindowDescriptor (CONST EFI_MEMORY_DESCRIPTOR *Descriptor, UINT64 *Start, UINT64 *End)
{
  if (!ConventionalWriteBackEnd (Descriptor, End)) {
    return FALSE;
  }
  *Start = Descriptor->PhysicalStart;
  if (*Start < THOR_4GB) {
    *End = MIN (*End, THOR_4GB);
  } else {
    *Start = MAX (*Start, THOR_HIGH_DRAM_BASE);
    *End   = MIN (*End, THOR_HIGH_HYP_START);
  }
  return *Start < *End;
}

// Firmware can split an otherwise contiguous allocation window across
// adjacent conventional descriptors.
STATIC
UINT64
RunEnd (CONST EFI_MEMORY_DESCRIPTOR *Map, UINTN Size, UINTN Stride, UINT64 End)
{
  BOOLEAN Extended;

  do {
    Extended = FALSE;
    for (UINTN Offset = 0; Offset < Size; Offset += Stride) {
      CONST EFI_MEMORY_DESCRIPTOR *Descriptor =
        (CONST EFI_MEMORY_DESCRIPTOR *)((CONST UINT8 *)Map + Offset);
      UINT64 Start, Next;
      if (WindowDescriptor (Descriptor, &Start, &Next) && Start == End) {
        End = Next;
        Extended = TRUE;
      }
    }
  } while (Extended);
  return End;
}

// Large diagnostic text straight into the GOP framebuffer: the UEFI text console font is too small to
// photograph. 5x12 glyphs from DiagFont.h scaled 4x, white on a black box; wraps at the right edge.
#include "DiagFont.h"
STATIC CONST UINT64 mDiagFont[] = GLYPH_FONT;

STATIC
VOID
DiagDrawVideo (CONST CHAR16 *Text, UINTN Row, CONST UINT64 Video[6])
{
  UINTN                        Scale = 4, X = 0, Y, Index, Gx, Gy, Dx, Dy, Cell, Line;
  UINT32                       *Fb;
  UINT64                       Glyph, Data;
  CHAR16                       Ch;

  Cell = 6 * Scale;
  Line = 14 * Scale;
  Y = Video[4] / 4 + Row * Line;
  Fb = (UINT32 *)(UINTN)Video[0];
  for (Index = 0; Text[Index] != 0; Index++) {
    Ch = Text[Index];
    if ((Ch < 32) || (Ch > 126)) { continue; }
    if (X + Cell > Video[3]) { X = 0; Y += Line; }
    if (Y + Line > Video[4]) { return; }
    Glyph = mDiagFont[Ch - 32];
    for (Gy = 0; Gy < 14 * Scale; Gy++) {
      for (Gx = 0; Gx < Cell; Gx++) {
        Fb[(Y + Gy) * (Video[2] / 4) + X + Gx] = 0xFF000000;
      }
    }
    for (Gy = 0; Gy < 12; Gy++) {
      Data = (Gy < 6) ? ((Glyph >> 32) >> (Gy * 5)) : ((Glyph & 0xFFFFFFFFULL) >> ((Gy - 6) * 5));
      for (Gx = 0; Gx < 5; Gx++) {
        if ((Data >> Gx) & 1) {
          for (Dy = 0; Dy < Scale; Dy++) {
            for (Dx = 0; Dx < Scale; Dx++) {
              Fb[(Y + Gy * Scale + Dy) * (Video[2] / 4) + X + Gx * Scale + Dx] = 0xFFFFFFFF;
            }
          }
        }
      }
    }
    X += Cell;
  }
  FlushRange (Video[0], Video[2] * Video[4]);
}

STATIC
VOID
DiagDraw (CONST CHAR16 *Text, UINTN Row)
{
  UINT64 Video[6];
  if (!EFI_ERROR (ReadBootVideo (Video)) && Video[0]) { DiagDrawVideo (Text, Row, Video); }
}

STATIC
VOID
HandoffStage (CONST UINT64 Video[6], CONST CHAR16 *Text, UINT64 Status)
{
  CHAR16 Line[80];
  if (!Video[0]) { return; }
  UnicodeSPrint (Line, sizeof (Line), L"HANDOFF %s %016lx", Text, Status);
  DiagDrawVideo (Line, 14, Video);
}

STATIC
EFI_STATUS
AllocateWindow (KERNEL *Kernel, UINT64 WindowSize, EFI_PHYSICAL_ADDRESS *Address)
{
  EFI_MEMORY_DESCRIPTOR *Map;
  EFI_MEMORY_DESCRIPTOR *Descriptor;
  EFI_STATUS            Status;
  UINTN                 Capacity;
  UINTN                 Size;
  UINTN                 Key;
  UINTN                 Stride;
  UINTN                 Offset;
  UINT64                Start;
  UINT64                End;
  UINT64                Candidate;
  UINT64                BestStart;
  UINT64                BestBytes;
  UINT64                RunBytes;

  *Address = 0;
  Map = NULL;
  Capacity = 0;
  BestStart = 0;
  BestBytes = 0;
  Status = GetMap (&Map, &Capacity, &Size, &Key, &Stride);
  if (EFI_ERROR (Status)) { if (Map != NULL) { FreePool (Map); } return Status; }
  if (Stride < sizeof (EFI_MEMORY_DESCRIPTOR) || Size % Stride) {
    FreePool (Map);
    return EFI_COMPROMISED_DATA;
  }
  Status = EFI_OUT_OF_RESOURCES;
  for (Offset = 0; Offset < Size; Offset += Stride) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
    if (!WindowDescriptor (Descriptor, &Start, &End)) { continue; }
    End = RunEnd (Map, Size, Stride, End);
    RunBytes = End - Start;
    if (RunBytes > BestBytes) { BestBytes = RunBytes; BestStart = Start; }
    Candidate = ALIGN_VALUE (Start, BLOCK_SIZE) + (Kernel->Base & (BLOCK_SIZE - 1));
    if ((Candidate < Start) || (End < Candidate) || (End - Candidate < WindowSize)) { continue; }
    Status = gBS->AllocatePages (AllocateAddress, EfiLoaderCode, EFI_SIZE_TO_PAGES (WindowSize), &Candidate);
    if (!EFI_ERROR (Status)) { *Address = Candidate; break; }
  }
  if (EFI_ERROR (Status)) {
    CHAR16 Line[96];
    UINTN  Row = 1;
    UnicodeSPrint (Line, sizeof (Line), L"NO WINDOW %lx BIG RUN %lx @ %lx", WindowSize, BestBytes, BestStart);
    DiagDraw (Line, 0);
    for (Offset = 0; Offset + Stride <= Size; Offset += Stride) {
      Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
      if ((Descriptor->Type == EfiConventionalMemory) && (Descriptor->NumberOfPages >= 0x400) && (Row < 8)) {
        UnicodeSPrint (Line, sizeof (Line), L"FREE %lx + %lx", Descriptor->PhysicalStart, EFI_PAGES_TO_SIZE (Descriptor->NumberOfPages));
        DiagDraw (Line, Row++);
      }
    }

  }
  FreePool (Map);
  return Status;
}

// Claim currently free pages, after all image allocations are complete. The primary
// contiguous window remains unchanged: additional DRAM is passed as separate banks.
STATIC
EFI_STATUS
ClaimPongRam (CONST UINT8 *Tree, EFI_MEMORY_DESCRIPTOR *Map, UINTN MapSize, UINTN Stride,
              PONG_RAM_BANK *Owned, UINTN *Count, CONST UINT64 Video[6],
              PONG_RAM_BANK *FirmwarePool)
{
  UINTN Offset, I, J;
  UINT64 PoolStart = 0, PoolEnd = 0, Largest = 0;
  UINT64 FrameEnd = 0;
  UINTN Skipped = 0;
  EFI_STATUS Status;
  if (mRamWireOffset == MAX_UINTN || mRamAllowedOffset == MAX_UINTN) { return EFI_SUCCESS; }
  // Validate the complete contract before taking ownership of any pages.
  if (Stride < sizeof (EFI_MEMORY_DESCRIPTOR) || MapSize % Stride) { return EFI_COMPROMISED_DATA; }
  if (Video[0]) {
    if (!Video[2] || !Video[4] || Video[2] > (MAX_UINT64 - Video[0]) / Video[4]) {
      return EFI_COMPROMISED_DATA;
    }
    FrameEnd = Video[0] + Video[2] * Video[4];
  }
  for (I = 0; I < mRamAllowedCount; I++) {
    UINT64 Base = U64 (Tree + mRamAllowedOffset + I * 16);
    UINT64 Bytes = U64 (Tree + mRamAllowedOffset + I * 16 + 8);
    if (!Bytes || Base > MAX_UINT64 - Bytes || ((Base | Bytes) & EFI_PAGE_MASK)) { return EFI_COMPROMISED_DATA; }
    for (J = 0; J < I; J++) {
      UINT64 Other = U64 (Tree + mRamAllowedOffset + J * 16);
      UINT64 OtherBytes = U64 (Tree + mRamAllowedOffset + J * 16 + 8);
      if (Base < Other + OtherBytes && Other < Base + Bytes) { return EFI_COMPROMISED_DATA; }
    }
  }
  // The qualified FD's DXE heap is below 4 GiB. Do not drain that heap or
  // repurpose low device/uncached aliases while firmware drivers still run.
  // Keep an additional high-memory pool too: final map/pool allocations may
  // be made by firmware callbacks before ExitBootServices has completed.
  for (Offset = 0; Offset + Stride <= MapSize; Offset += Stride) {
    EFI_MEMORY_DESCRIPTOR *D = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
    UINT64 End;
    if (!ConventionalWriteBackEnd (D, &End)) { continue; }
    for (I = 0; I < mRamAllowedCount; I++) {
      UINT64 Base = U64 (Tree + mRamAllowedOffset + I * 16);
      UINT64 Bytes = U64 (Tree + mRamAllowedOffset + I * 16 + 8);
      UINT64 Start = MAX (MAX (Base, D->PhysicalStart), THOR_HIGH_DRAM_BASE);
      UINT64 Stop = MIN (MIN (Base + Bytes, End), THOR_HIGH_HYP_START);
      if (Stop > Start && Stop - Start > Largest) { Largest = Stop - Start; PoolEnd = Stop; }
    }
  }
  if (Largest > SIZE_256MB) {
    PoolStart = PoolEnd - SIZE_256MB;
    *FirmwarePool = (PONG_RAM_BANK){PoolStart, PoolEnd - PoolStart};
  } else { return EFI_SUCCESS; } // no expendable large bank; retain the primary window
  for (Offset = 0; Offset + Stride <= MapSize; Offset += Stride) {
    EFI_MEMORY_DESCRIPTOR *D = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
    UINT64 End;
    if (!ConventionalWriteBackEnd (D, &End)) { continue; }
    for (I = 0; I < mRamAllowedCount; I++) {
      UINT64 Base = U64 (Tree + mRamAllowedOffset + I * 16);
      UINT64 Bytes = U64 (Tree + mRamAllowedOffset + I * 16 + 8);
      UINT64 Start, Stop;
      Start = MAX (MAX (Base, D->PhysicalStart), THOR_HIGH_DRAM_BASE);
      Stop = MIN (MIN (Base + Bytes, End), THOR_HIGH_HYP_START);
      if (Start >= Stop) { continue; }
      if (Start < PoolEnd && PoolStart < Stop) { Stop = PoolStart; }
      if (Start >= Stop) { continue; }
      // The video allocation is never general RAM, even if faulty firmware calls it free.
      if (Start < FrameEnd && Video[0] < Stop) { continue; }
      while (Start < Stop) {
        UINT64 Address = Start, BytesNow = MIN (Stop - Start, SIZE_1GB);
        if (*Count >= PONG_RAM_MAX) { Skipped++; break; }
        Status = gBS->AllocatePages (AllocateAddress, EfiLoaderData, EFI_SIZE_TO_PAGES (BytesNow), &Address);
        if (EFI_ERROR (Status)) { Skipped++; break; }
        // Coalesce adjacent leases without changing the primary bank. Keep
        // firmware calls bounded even when one descriptor exceeds 4 GiB.
        if (*Count > 1 && Owned[*Count - 1].Start + Owned[*Count - 1].Size == Address) {
          Owned[*Count - 1].Size += BytesNow;
        } else { Owned[(*Count)++] = (PONG_RAM_BANK){Address, BytesNow}; }
        Start += BytesNow;
      }
    }
  }
  if (Skipped) { Print (L"DARWINBOOT24: %u additional RAM ranges left with firmware\n", (UINT32)Skipped); }
  return EFI_SUCCESS;
}
// Run after ExitBootServices accepts this exact map. The temporary pool is
// already inside the ADT allowlist. Hand off only its still-conventional
// pages; even boot services and loader allocations in the pool stay excluded.
STATIC
VOID
ReclaimPongRamPool (
  CONST EFI_MEMORY_DESCRIPTOR  *Map,
  UINTN                        MapSize,
  UINTN                        Stride,
  CONST PONG_RAM_BANK          *FirmwarePool,
  PONG_RAM_BANK                *Owned,
  UINTN                        *Count,
  CONST UINT64                 Video[6]
  )
{
  UINT64  FrameStart = 0;
  UINT64  FrameEnd   = 0;
  UINT64  PoolStart;
  UINT64  PoolEnd;

  if (!FirmwarePool->Size || Stride < sizeof (EFI_MEMORY_DESCRIPTOR) ||
      MapSize % Stride || FirmwarePool->Start > MAX_UINT64 - FirmwarePool->Size) {
    return;
  }
  PoolStart = MAX (FirmwarePool->Start, THOR_HIGH_DRAM_BASE);
  PoolEnd   = MIN (FirmwarePool->Start + FirmwarePool->Size, THOR_HIGH_HYP_START);
  if (PoolStart >= PoolEnd) {
    return;
  }

  if (Video[0]) {
    if (!Video[2] || !Video[4] || Video[2] > (MAX_UINT64 - Video[0]) / Video[4]) {
      return;
    }
    FrameStart = Video[0];
    FrameEnd   = Video[0] + Video[2] * Video[4];
  }

  for (UINTN Offset = 0; Offset < MapSize; Offset += Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *Descriptor =
      (CONST EFI_MEMORY_DESCRIPTOR *)((CONST UINT8 *)Map + Offset);
    UINT64 Start, End;
    BOOLEAN Overlap = FALSE;

    if (!ConventionalWriteBackEnd (Descriptor, &End)) {
      continue;
    }

    Start = MAX (PoolStart, Descriptor->PhysicalStart);
    End   = MIN (PoolEnd, End);
    if (Start >= End || (Start < FrameEnd && FrameStart < End)) {
      continue;
    }
    for (UINTN Index = 0; Index < *Count; Index++) {
      if (Start < Owned[Index].Start + Owned[Index].Size && Owned[Index].Start < End) {
        Overlap = TRUE;
        break;
      }
    }
    if (Overlap) {
      continue;
    }
    if (*Count > 1 && Owned[*Count - 1].Start + Owned[*Count - 1].Size == Start) {
      Owned[*Count - 1].Size += End - Start;
    } else if (*Count < PONG_RAM_MAX) {
      Owned[(*Count)++] = (PONG_RAM_BANK){Start, End - Start};
    }
  }
}

STATIC
UINT64
WritePongRam (UINT64 TreeAddress, PONG_RAM_BANK *Owned, UINTN Count)
{
  UINT64 Total = 0;
  UINT8 *Wire = (UINT8 *)(UINTN)(TreeAddress + mRamWireOffset);
  ZeroMem (Wire, PONG_RAM_WIRE_SIZE);
  WriteUnaligned64 ((UINT64 *)Wire, 1);
  WriteUnaligned64 ((UINT64 *)(Wire + 8), Count);
  for (UINTN I = 0; I < Count; I++) {
    WriteUnaligned64 ((UINT64 *)(Wire + 32 + I * 16), Owned[I].Start);
    WriteUnaligned64 ((UINT64 *)(Wire + 40 + I * 16), Owned[I].Size);
    Total += Owned[I].Size;
  }
  WriteUnaligned64 ((UINT64 *)(Wire + 16), Total);
  return Total;
}

#include "ThorMemoryAudit.h"
#include "ThorHighTranslation.h"
#include "ThorOwnedLowRam.h"
#include "ThorPrivateHighRam.h"
#include "ThorFullRamAccess.h"

STATIC
EFI_STATUS
EFIAPI
Boot (
  IN UNIXNU_LOADER_PROTOCOL    *This,
  IN CONST UNIXNU_LOADER_BOOT_REQUEST *Request
  )
{
  EFI_STATUS                      Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
  EFI_FILE_PROTOCOL               *Root;
  VOID                            *Image;
  VOID                            *Tree;
  VOID                            *TrustCaches;
  UINTN                           ImageSize;
  UINTN                           TreeSize;
  UINTN                           TrustCacheSize;
  CHAR16                          *TreePath;
  UINTN                           Length;
  UINTN                           Index;
  UINTN                           Offset;
  KERNEL                          Kernel;
  EFI_PHYSICAL_ADDRESS            Address;
  EFI_PHYSICAL_ADDRESS            AudioAddress = 0;
  EFI_PHYSICAL_ADDRESS            UsbAddress = 0;
  UINT64                          ArgsAddress;
  UINT64                          TreeAddress;
  UINT64                          Used;
  UINT64                          WindowSize;
  UINT64                          RamdiskAddress;
  UINTN                           RamdiskOffset;
  UINTN                           RamdiskBytes;
  UINTN                           RamdiskExpandedSize;
  BOOLEAN                         RamdiskPacked;
  BOOLEAN                         KeepPacked;
  UINTN                           TrustCacheOffset;
  UINT64                          TrustCacheAddress;
  UINT64                          TrampolineAddress;
  UINTN                           TrampolineBytes;
  VOID (EFIAPI *Enter)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
  DARWIN_BOOT_ARGS                *Args;
  EFI_MEMORY_DESCRIPTOR           *Map;
  UINTN                           Capacity;
  UINTN                           MapSize;
  UINTN                           Key;
  UINTN                           Stride;
  UINT32                          Version;
  UINTN                           Attempt;
  CHAR8                           CommandLine[DARWIN_BOOT_LINE_LENGTH];
  UINT64                          Video[6];
  PONG_RAM_BANK                   Owned[PONG_RAM_MAX];
  THOR_MEMORY_AUDIT               MemoryAudit;
  PONG_RAM_BANK                   FirmwareRamPool = { 0, 0 };
  PONG_RAM_BANK                   LowRamLease = { 0, 0 };
  BOOLEAN                         ReclaimRamPool = FALSE;
  BOOLEAN                         AllowLowRamTrial = FALSE;
  UINTN                           OwnedCount = 0;
  BOOLEAN                         FullRamQualified = FALSE;
  BOOLEAN                         FullRamOwnerInMap = FALSE;
  BOOLEAN                         TailRamQualified = FALSE;
  BOOLEAN                         TailRamOwnerInMap = FALSE;
  CONST CHAR16                    *Stage = L"REQUEST";
  CHAR16                          Failure[96];

  (VOID)This;
  if ((Request == NULL) || (Request->Volume == NULL) || (Request->KernelPath == NULL)) { return EFI_INVALID_PARAMETER; }
  DiagDraw (L"DARWINBOOT24 REQUEST", 0);
  if ((Request->KextCount != 0) || (Request->DeviceTree != NULL) || (Request->DeviceTreeSize != 0) ||
      (DarwinCurrentEl () != 4)) {
    Print (L"DARWINBOOT: unsupported inputs or exception level; firmware retained\n");
    return EFI_UNSUPPORTED;
  }
  if (!RamdiskLayout (Request->Ramdisk, Request->RamdiskSize, &RamdiskExpandedSize, &RamdiskPacked)) {
    return EFI_BAD_BUFFER_SIZE;
  }
  ZeroMem (CommandLine, sizeof (CommandLine));
  if (Request->BootArgs != NULL) {
    for (Index = 0; Request->BootArgs[Index] != 0; Index++) {
      if ((Index >= sizeof (CommandLine) - 1) || (Request->BootArgs[Index] > 0x7f)) { return EFI_BAD_BUFFER_SIZE; }
      CommandLine[Index] = (CHAR8)Request->BootArgs[Index];
    }
  }
  Root = NULL;
  Image = NULL;
  Tree = NULL;
  TrustCaches = NULL;
  TreePath = NULL;
  Map = NULL;
  Address = 0;
  Capacity = 0;
  Status = gBS->HandleProtocol (Request->Volume, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (EFI_ERROR (Status)) { return Status; }
  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) { return Status; }
  Stage = L"READ KERNEL";
  DiagDraw (Stage, 0);
  Status = ReadFile (Root, Request->KernelPath, SIZE_128MB, &Image, &ImageSize);
  if (EFI_ERROR (Status)) { goto Fail; }
  Stage = L"PARSE KERNEL";
  Status = ParseKernel (Image, ImageSize, &Kernel);
  if (EFI_ERROR (Status)) { goto Fail; }
  Length = StrSize (Request->KernelPath);
  TreePath = AllocatePool (Length + 11 * sizeof (CHAR16));
  if (TreePath == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Fail; }
  CopyMem (TreePath, Request->KernelPath, Length);
  StrCatS (TreePath, Length / sizeof (CHAR16) + 11, L".adt");
  Stage = L"READ ADT";
  Status = ReadFile (Root, TreePath, SIZE_16MB, &Tree, &TreeSize);
  if (EFI_ERROR (Status)) { goto Fail; }
  AddUsbSlots (&Tree, &TreeSize);
  Offset = 0;
  RamdiskOffset = MAX_UINTN;
  TrustCacheOffset = MAX_UINTN;
  mAudioDmaOffset = MAX_UINTN;
  mThorScanoutOffset = MAX_UINTN;
  mRamWireOffset = mRamAllowedOffset = MAX_UINTN;
  mRamAllowedCount = 0;
  WindowSize = 0;
  KeepPacked = FALSE;
  Stage = L"PARSE ADT";
  if (!AdtNode (Tree, TreeSize, &Offset, 0, 3, &RamdiskOffset, &TrustCacheOffset, &WindowSize, &KeepPacked) || (Offset != TreeSize)) { Status = EFI_COMPROMISED_DATA; goto Fail; }
  if (KeepPacked && (!RamdiskPacked || (RamdiskOffset == MAX_UINTN))) { Status = EFI_COMPROMISED_DATA; goto Fail; }
  if (WindowSize == 0) { WindowSize = WINDOW_SIZE; }
  if (Kernel.Base > MAX_UINT64 - WindowSize) { Status = EFI_LOAD_ERROR; goto Fail; }
  if (Request->Ramdisk != NULL) {
    if ((RamdiskOffset == MAX_UINTN) || (U64 ((UINT8 *)Tree + RamdiskOffset) != 0) ||
        (U64 ((UINT8 *)Tree + RamdiskOffset + 8) != 0)) { Status = EFI_COMPROMISED_DATA; goto Fail; }
  } else if (RamdiskOffset != MAX_UINTN) {
    Status = EFI_UNSUPPORTED;
    goto Fail;
  }
  CopyMem (TreePath, Request->KernelPath, Length);
  StrCatS (TreePath, Length / sizeof (CHAR16) + 11, L".trustcache");
  Stage = L"READ TRUSTCACHE";
  Status = ReadFile (Root, TreePath, SIZE_16MB, &TrustCaches, &TrustCacheSize);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) { goto Fail; }
  if (TrustCaches != NULL) {
    if ((TrustCacheOffset == MAX_UINTN) || (U64 ((UINT8 *)Tree + TrustCacheOffset) != 0) ||
        (U64 ((UINT8 *)Tree + TrustCacheOffset + 8) != 0) || !ValidTrustCaches (TrustCaches, TrustCacheSize)) {
      Status = EFI_COMPROMISED_DATA;
      goto Fail;
    }
  } else if (TrustCacheOffset != MAX_UINTN) {
    Status = EFI_COMPROMISED_DATA;
    goto Fail;
  }
  Status = ReadBootVideo (Video);
  if (EFI_ERROR (Status)) { goto Fail; }
  Stage = L"PRIMARY RAM";
  DiagDrawVideo (Stage, 0, Video);
  Status = AllocateWindow (&Kernel, WindowSize, &Address);
  if (EFI_ERROR (Status)) { goto Fail; }
  // Reserve real conventional low RAM for the DSP's 32-bit period buffer.
  // This allocation follows the owned XNU window, so they cannot overlap.
  // Never borrow a hard-coded Android carveout or an arbitrary low address.
  if (mAudioDmaOffset != MAX_UINTN) {
    AudioAddress = 0xffffffffULL;
    Status = gBS->AllocatePages (AllocateMaxAddress, EfiReservedMemoryType, 16, &AudioAddress);
    if (EFI_ERROR (Status)) { AudioAddress = 0; }
    else {
      ZeroMem ((VOID *)(UINTN)AudioAddress, 65536);
      FlushRange (AudioAddress, 65536);
    }
  }
  ArgsAddress = ALIGN_VALUE (Address + Kernel.End - Kernel.Base, SIZE_16KB);
  if (mUsbDmaOffset != MAX_UINTN) {
    UsbAddress=0xffffffffULL;
    Status=gBS->AllocatePages(AllocateMaxAddress,EfiReservedMemoryType,8,&UsbAddress);
    if(EFI_ERROR(Status))UsbAddress=0;
    else {ZeroMem((VOID *)(UINTN)UsbAddress,32768);FlushRange(UsbAddress,32768);}
  }
  TreeAddress = ArgsAddress + EFI_PAGE_SIZE;
  RamdiskAddress = ALIGN_VALUE (TreeAddress + TreeSize, EFI_PAGE_SIZE);
  RamdiskBytes = ALIGN_VALUE (KeepPacked ? Request->RamdiskSize : RamdiskExpandedSize, EFI_PAGE_SIZE);
  TrustCacheAddress = RamdiskAddress + RamdiskBytes;
  Used = ALIGN_VALUE (TrustCacheAddress + TrustCacheSize, SIZE_16KB) - Address;
  TrampolineAddress = Address + Used;
  TrampolineBytes = (UINTN)DarwinEnterEnd - (UINTN)DarwinEnter;
  if ((TrampolineBytes == 0) || (TrampolineBytes > EFI_PAGE_SIZE)) { Status = EFI_LOAD_ERROR; goto Fail; }
  Used += EFI_PAGE_SIZE;
  if (Used > WindowSize - BLOCK_SIZE) { Status = EFI_BAD_BUFFER_SIZE; goto Fail; }
  Stage = L"COPY PAYLOAD";
  DiagDrawVideo (Stage, 0, Video);
  ZeroMem ((VOID *)(UINTN)Address, (UINTN)Used);
  // The MMU-off transition must run inside the identity-mapped owned window,
  // independently of the firmware's dynamically loaded PE image placement.
  CopyMem ((VOID *)(UINTN)TrampolineAddress, (VOID *)(UINTN)DarwinEnter, TrampolineBytes);
  FlushRange (TrampolineAddress, TrampolineBytes);
  __asm__ volatile ("ic iallu\n\tdsb sy\n\tisb" ::: "memory");
  Enter = (VOID (EFIAPI *)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))(UINTN)TrampolineAddress;
  for (Index = 0; Index < Kernel.Count; Index++) {
    CopyMem ((VOID *)(UINTN)(Address + Kernel.Segments[Index].Address - Kernel.Base),
             (UINT8 *)Image + Kernel.Segments[Index].FileOffset, (UINTN)Kernel.Segments[Index].FileSize);
  }
  Args = (DARWIN_BOOT_ARGS *)(UINTN)ArgsAddress;
  Args->Revision = 2;
  Args->Version = 2;
  Args->VirtualBase = Kernel.Base;
  Args->PhysicalBase = Address;
  Args->MemorySize = WindowSize;
  Args->MemorySizeActual = WindowSize;
  Args->TopOfKernelData = Address + Used;
  CopyMem (Args->Video, Video, sizeof (Video));
  Args->DeviceTree = Kernel.Base + TreeAddress - Address;
  Args->DeviceTreeLength = (UINT32)TreeSize;
  CopyMem (Args->CommandLine, CommandLine, sizeof (CommandLine));
  CopyMem ((VOID *)(UINTN)TreeAddress, Tree, TreeSize);
  if (mAudioDmaOffset != MAX_UINTN) {
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + mAudioDmaOffset), AudioAddress);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + mAudioDmaOffset + 8), AudioAddress ? 65536 : 0);
  }
  if (mUsbDmaOffset != MAX_UINTN) {
    WriteUnaligned64((UINT64 *)(UINTN)(TreeAddress+mUsbDmaOffset),UsbAddress);
    WriteUnaligned64((UINT64 *)(UINTN)(TreeAddress+mUsbDmaOffset+8),UsbAddress?32768:0);
  }
  if (Request->Ramdisk != NULL) {
    if (KeepPacked) { CopyMem ((VOID *)(UINTN)RamdiskAddress, Request->Ramdisk, Request->RamdiskSize); }
    else { CopyRamdisk ((VOID *)(UINTN)RamdiskAddress, Request->Ramdisk, Request->RamdiskSize, RamdiskPacked); }
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + RamdiskOffset), RamdiskAddress);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + RamdiskOffset + 8), KeepPacked ? Request->RamdiskSize : RamdiskBytes);
  }
  if (TrustCaches != NULL) {
    CopyMem ((VOID *)(UINTN)TrustCacheAddress, TrustCaches, TrustCacheSize);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + TrustCacheOffset), TrustCacheAddress);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + TrustCacheOffset + 8), TrustCacheSize);
    FreePool (TrustCaches); TrustCaches = NULL;
  }
  FreePool (Image); Image = NULL;
  FreePool (Tree); Tree = NULL;
  FreePool (TreePath); TreePath = NULL;
  Root->Close (Root); Root = NULL;
  if (mRamDiagOffset != MAX_UINTN) {
    ThorAuditCollect (&MemoryAudit, CommandLine);
  }
  Stage = L"MEMORY MAP";
  Status = GetMap (&Map, &Capacity, &MapSize, &Key, &Stride);
  if (EFI_ERROR (Status)) { goto Fail; }
  if (mRamWireOffset != MAX_UINTN && AsciiStrStr (CommandLine, "pong_ram_banks=0") == NULL) {
    Stage = L"EXTRA RAM";
    DiagDrawVideo (Stage, 0, Video);
    Owned[0] = (PONG_RAM_BANK){Address, WindowSize}; OwnedCount = 1;
    Status = ClaimPongRam ((CONST UINT8 *)(UINTN)TreeAddress, Map, MapSize, Stride,
                           Owned, &OwnedCount, Video, &FirmwareRamPool);
    if (EFI_ERROR (Status)) {
      // Contract validation precedes all extra allocations. A malformed
      // optional bank description must not reject the known primary boot.
      Print (L"DARWINBOOT24: extra RAM SKIP %r; primary window retained\n", Status);
      OwnedCount = 1;
    } else {
      AllowLowRamTrial = TRUE;
      ReclaimRamPool = AsciiStrStr (CommandLine, "pong_ram_reclaim=0") == NULL;
    }
    Args->MemorySizeActual = WritePongRam (TreeAddress, Owned, OwnedCount);
    Print (L"DARWINBOOT24: %u owned RAM banks, %lu MiB usable before kernel reservations\n",
           (UINT32)OwnedCount, Args->MemorySizeActual >> 20);
    // Claiming free descriptors can split the map. Leave room before ExitBootServices.
    Status = GetMap (&Map, &Capacity, &MapSize, &Key, &Stride);
    if (EFI_ERROR (Status)) { goto Fail; }
  }
  Stage = L"READY TO ENTER";
  DiagDrawVideo (Stage, 0, Video);
  Print (L"DARWINBOOT: ARM64 va=0x%lx pa=0x%lx args=0x%lx entry=0x%lx owned=0x%lx\n",
         Kernel.Base, Address, ArgsAddress, Address + Kernel.Entry - Kernel.Base, (UINT64)WindowSize);
  Print (L"DARWINBOOT: video base=0x%lx display=%lu row=%lu width=%lu height=%lu depth=%lu\n",
         Video[0], Video[1], Video[2], Video[3], Video[4], Video[5]);
  Print (L"DARWINBOOT24: command line: %a\n", CommandLine);
  Print (L"DARWINBOOT: inputs validated; exiting boot services\n");
  Print (L"DARWINBOOT24: boot_args size 0x%lx, command line %u bytes\n",
         (UINT64)sizeof (*Args), (UINT32)sizeof (Args->CommandLine));

  //
  // The same facts in large type over the whole screen. The firmware's log
  // draws far larger than the text console, and the form feed clears the
  // screen first. This is what stays visible if the kernel never draws.
  //
  DEBUG ((DEBUG_ERROR, "\fDARWINBOOT: hand-off to the kernel\n\n"));
  DEBUG ((DEBUG_ERROR, "kernel   va 0x%lx  pa 0x%lx\n", Kernel.Base, Address));
  DEBUG ((DEBUG_ERROR, "entry    pa 0x%lx\n", Address + Kernel.Entry - Kernel.Base));
  DEBUG ((DEBUG_ERROR, "args     pa 0x%lx  window 0x%lx bytes\n", ArgsAddress, (UINT64)WindowSize));
  DEBUG ((DEBUG_ERROR, "video    base 0x%lx  %lux%lu  row %lu bytes  %lu bpp\n", Video[0], Video[3], Video[4], Video[2], Video[5]));
  DEBUG ((DEBUG_ERROR, "entry words %08x %08x %08x %08x\n",
          ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + Kernel.Entry - Kernel.Base)),
          ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + Kernel.Entry - Kernel.Base + 4)),
          ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + Kernel.Entry - Kernel.Base + 8)),
          ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + Kernel.Entry - Kernel.Base + 12))));
  DEBUG ((DEBUG_ERROR, "CurrentEL %lu  SCTLR_EL1 0x%lx  TCR_EL1 0x%lx\n", DarwinCurrentEl () >> 2, READ_SYSREG (sctlr_el1), READ_SYSREG (tcr_el1)));
  DEBUG ((DEBUG_ERROR, "ID_AA64MMFR0_EL1 0x%lx  (PARange %lu, 4 KiB granule %a)\n", READ_SYSREG (id_aa64mmfr0_el1),
          READ_SYSREG (id_aa64mmfr0_el1) & 0xF, (((READ_SYSREG (id_aa64mmfr0_el1) >> 28) & 0xF) == 0xF) ? "NOT supported" : "supported"));
  DEBUG ((DEBUG_ERROR, "ID_AA64PFR0_EL1  0x%lx\n", READ_SYSREG (id_aa64pfr0_el1)));
  DEBUG ((DEBUG_ERROR, "owned trampoline pa 0x%lx (%lu bytes)\n", TrampolineAddress, (UINT64)TrampolineBytes));
  DEBUG ((DEBUG_ERROR, "\nExiting boot services. A green bar means the loader\ntrampoline ran; payload entry is not yet confirmed.\n"));
  if(UsbRequested(CommandLine)) {
    DiagDrawVideo(L"USB FIRMWARE RELEASE",0,Video);
    QuiesceUsb(TreeAddress,UsbAddress);
  }
  Status=GetMap(&Map,&Capacity,&MapSize,&Key,&Stride);
  if(EFI_ERROR(Status))goto Fail;
  if (mRamDiagOffset != MAX_UINTN && ThorAuditHasOption (CommandLine, "tmhigh=1")) {
    MemoryAudit.Flags |= THOR_HIGH_REQUESTED;
    ThorHighProbe (&MemoryAudit, Map, MapSize, Stride);
    Status = GetMap (&Map, &Capacity, &MapSize, &Key, &Stride);
    if (EFI_ERROR (Status)) { goto Fail; }
  }
  if (AllowLowRamTrial && mRamAllowedOffset != MAX_UINTN && mRamDiagOffset != MAX_UINTN &&
      (MemoryAudit.Flags & THOR_LOW_REQUESTED)) {
    LowRamLease = ThorTryLeaseLowRam (Map, MapSize, Stride, Owned, OwnedCount, Video, &MemoryAudit);
    // Refresh the map below on every EBS attempt. A lease never enters
    // Owned until EBS has accepted an exact map that still proves it.
  }
  if (mRamAllowedOffset != MAX_UINTN && mRamDiagOffset != MAX_UINTN &&
      ThorAuditHasOption (CommandLine, "tmfull=1")) {
    MemoryAudit.Flags |= THOR_FULL_RAM_REQUESTED;
    // TRAM bits from the validated ABL FDT and live Qualcomm SMEM 402.
    CONST UINT64 Policy = THOR_FULL_FDT_ACCEPTED | THOR_FULL_SMEM_ACCEPTED;
    if ((MemoryAudit.Flags & Policy) == Policy &&
        ThorFullRamDisjoint (Owned, OwnedCount, Video, THOR_PRIVATE_RAM_BASE, THOR_PRIVATE_RAM_END)) {
      Status = GetMap (&Map, &Capacity, &MapSize, &Key, &Stride);
      if (EFI_ERROR (Status)) { goto Fail; }
      Status = ThorPreparePrivateHighRam (Map, MapSize, Stride, TRUE, THOR_PRIVATE_RAM_BASE, THOR_PRIVATE_RAM_END);
      if (!EFI_ERROR (Status)) {
        MemoryAudit.Flags |= THOR_FULL_RAM_RESERVED;
        HandoffStage (Video, L"VERIFYING HIGH RAM", THOR_PRIVATE_RAM_BYTES >> 20);
        FullRamQualified = ThorFullRamCheckAccess (&MemoryAudit, THOR_PRIVATE_RAM_BASE, THOR_PRIVATE_RAM_END);
        if (FullRamQualified) {
          MemoryAudit.Flags |= THOR_FULL_RAM_TOUCHED;
        }
      }
      if (FullRamQualified && MemoryAudit.TailFdtClear && MemoryAudit.TailSmemClear &&
          ThorFullRamDisjoint (Owned, OwnedCount, Video, THOR_PRIVATE_TAIL_BASE, THOR_PRIVATE_TAIL_END)) {
        Status = GetMap (&Map, &Capacity, &MapSize, &Key, &Stride);
        if (EFI_ERROR (Status)) { goto Fail; }
        Status = ThorPreparePrivateHighRam (Map, MapSize, Stride, TRUE, THOR_PRIVATE_TAIL_BASE, THOR_PRIVATE_TAIL_END);
        TailRamQualified = !EFI_ERROR (Status) &&
            ThorFullRamCheckAccess (&MemoryAudit, THOR_PRIVATE_TAIL_BASE, THOR_PRIVATE_TAIL_END);
      }
    }
    // A private mapping can consume EFI page-table pages. Resize the map
    // buffer before the EBS retries, including on a rejected candidate.
    Status = GetMap (&Map, &Capacity, &MapSize, &Key, &Stride);
    if (EFI_ERROR (Status)) { goto Fail; }
  }
  for (Attempt = 0; Attempt < 3; Attempt++) {
    FullRamOwnerInMap = FullRamQualified && ThorPrivateHighRamOwned (THOR_PRIVATE_RAM_BASE, THOR_PRIVATE_RAM_END);
    TailRamOwnerInMap = TailRamQualified && ThorPrivateHighRamOwned (THOR_PRIVATE_TAIL_BASE, THOR_PRIVATE_TAIL_END);
    MapSize = Capacity;
    Status = gBS->GetMemoryMap (&MapSize, Map, &Key, &Stride, &Version);
    if (EFI_ERROR (Status)) {
      HandoffStage (Video, L"GETMAP ERROR", Status);
      if (Attempt == 0) { goto Fail; }
      CpuDeadLoop ();
    }
    HandoffStage (Video, L"EXIT CALL", Attempt);
    /* THOR Phase B v2: write the high-address EFI map diagnostics into the
     * ADT buffer BEFORE EBS (after EBS there is no Print, no boot services;
     * the v1 Print here was dead code). XNU reads the property from the
     * device tree at boot and prints it to its own console (PongConsole).
     * Only the ACCEPTED map (the attempt that EBS succeeds on) is recorded. */
    if (mRamDiagOffset != MAX_UINTN && TreeAddress != 0 &&
        Stride >= sizeof (EFI_MEMORY_DESCRIPTOR) && MapSize % Stride == 0) {
      UINT8 *Diag = (UINT8 *)(UINTN)(TreeAddress + mRamDiagOffset);
      UINT64 HighTotal = 0, HighConv = 0;
      UINT32 Count = 0;
      /* header: total_high(8) conventional_high(8) owned(8) count(4) pad(4) */
      ZeroMem (Diag, 4096);
      for (UINTN Do = 0; Do + Stride <= MapSize && Count < 120; Do += Stride) {
        CONST EFI_MEMORY_DESCRIPTOR *D =
          (CONST EFI_MEMORY_DESCRIPTOR *)((CONST UINT8 *)Map + Do);
        UINT64 End;
        if (!DescriptorEnd (D, &End) || End <= THOR_4GB) { continue; }
        UINT64 Start = MAX (D->PhysicalStart, THOR_4GB);
        UINT64 Bytes = End - Start;
        HighTotal += Bytes;
        if (ConventionalWriteBackEnd (D, &End)) { HighConv += Bytes; }
        /* per-descriptor at offset 32 + i*32: type(4) pad(4) attr(8) start(8) size(8) */
        WriteUnaligned32 ((UINT32 *)(Diag + 32 + Count * 32), (UINT32)D->Type);
        WriteUnaligned64 ((UINT64 *)(Diag + 32 + Count * 32 + 8), (UINT64)D->Attribute);
        WriteUnaligned64 ((UINT64 *)(Diag + 32 + Count * 32 + 16), Start);
        WriteUnaligned64 ((UINT64 *)(Diag + 32 + Count * 32 + 24), Bytes);
        Count++;
      }
      WriteUnaligned64 ((UINT64 *)(Diag + 0), HighTotal);
      WriteUnaligned64 ((UINT64 *)(Diag + 8), HighConv);
      WriteUnaligned64 ((UINT64 *)(Diag + 16), Args->MemorySizeActual);
      WriteUnaligned32 ((UINT32 *)(Diag + 24), Count);
      ThorAuditWrite (Diag + THOR_AUDIT_OFFSET, &MemoryAudit, Map, MapSize, Stride);
    }
    Status = gBS->ExitBootServices (mImage, Key);
    HandoffStage (Video, L"EXIT RETURN", Status);
    if (!EFI_ERROR (Status)) {
      if (ReclaimRamPool && FirmwareRamPool.Size) {
        ReclaimPongRamPool (Map, MapSize, Stride, &FirmwareRamPool, Owned, &OwnedCount, Video);
        Args->MemorySizeActual = WritePongRam (TreeAddress, Owned, OwnedCount);
      }
      BOOLEAN AddedBank = FALSE;
      if (LowRamLease.Size && ThorLowAcceptedLease (Map, MapSize, Stride, &LowRamLease,
                                                   Owned, OwnedCount, Video, &MemoryAudit)) {
        if (mThorScanoutOffset != MAX_UINTN && LowRamLease.Size == THOR_LOW_EXPANDED_BYTES) {
          // The accepted EFI descriptor proves the whole lease. Keep the
          // first half outside VM for a single native display backing.
          CONST UINT64 ScanoutBytes = THOR_LOW_EXPANDED_BYTES / 2;
          UINT8 *Slot = (UINT8 *)(UINTN)(TreeAddress + mThorScanoutOffset);
          WriteUnaligned64 ((UINT64 *)Slot, LowRamLease.Start);
          WriteUnaligned64 ((UINT64 *)(Slot + 8), ScanoutBytes);
          Owned[OwnedCount++] = (PONG_RAM_BANK){LowRamLease.Start + ScanoutBytes,
                                                LowRamLease.Size - ScanoutBytes};
        } else {
          Owned[OwnedCount++] = LowRamLease;
        }
        MemoryAudit.Flags |= THOR_LOW_HANDED_OFF;
        AddedBank = TRUE;
      }
      if (FullRamOwnerInMap && ThorAcceptPrivateHighRamMap (Map, MapSize, Stride, THOR_PRIVATE_RAM_BASE, THOR_PRIVATE_RAM_END)) {
        MemoryAudit.Flags |= THOR_FULL_RAM_ACCEPTED;
        if (ThorFullRamDisjoint (Owned, OwnedCount, Video, THOR_PRIVATE_RAM_BASE, THOR_PRIVATE_RAM_END)) {
          Owned[OwnedCount++] = (PONG_RAM_BANK){THOR_PRIVATE_RAM_BASE, THOR_AUDIT_BANK_C_BASE - THOR_PRIVATE_RAM_BASE};
          Owned[OwnedCount++] = (PONG_RAM_BANK){THOR_AUDIT_BANK_C_BASE, THOR_PRIVATE_RAM_END - THOR_AUDIT_BANK_C_BASE};
          MemoryAudit.Flags |= THOR_FULL_RAM_HANDED_OFF;
          AddedBank = TRUE;
          if (TailRamOwnerInMap && OwnedCount < PONG_RAM_MAX &&
              ThorAcceptPrivateHighRamMap (Map, MapSize, Stride, THOR_PRIVATE_TAIL_BASE, THOR_PRIVATE_TAIL_END)) {
            Owned[OwnedCount++] = (PONG_RAM_BANK){THOR_PRIVATE_TAIL_BASE, THOR_PRIVATE_TAIL_END - THOR_PRIVATE_TAIL_BASE};
          }
        }
      }
      if (AddedBank) {
        Args->MemorySizeActual = WritePongRam (TreeAddress, Owned, OwnedCount);
      }
      if (AddedBank || (MemoryAudit.Flags & THOR_FULL_RAM_ACCEPTED)) {
        UINT8 *Diag = (UINT8 *)(UINTN)(TreeAddress + mRamDiagOffset);
        WriteUnaligned64 ((UINT64 *)(Diag + THOR_AUDIT_OFFSET + 8), MemoryAudit.Flags |
                          ReadUnaligned64 ((CONST UINT64 *)(Diag + THOR_AUDIT_OFFSET + 8)));
      }
      // All writes by this loader are in [Address, Address + Used): Mach-O
      // segments/BSS, args, ADT, initrd, trustcache and copied trampoline.
      // Untouched free pages are not boot input. Clean only populated data,
      // while boot_args still advertises the complete owned window/banks.
      Enter (ArgsAddress, Address + Kernel.Entry - Kernel.Base, Address, Used, Video[0], Video[2] * Video[4]);
      CpuDeadLoop ();
    }
    if (Status != EFI_INVALID_PARAMETER) { CpuDeadLoop (); }
  }
  CpuDeadLoop ();
  return EFI_ABORTED;
Fail:
  if(mUsbStopped && mUsbFunction!=NULL && mUsbFunction->StartController!=NULL) {
    (VOID)mUsbFunction->StartController(mUsbFunction);mUsbStopped=FALSE;
  }
  UnicodeSPrint (Failure, sizeof (Failure), L"BOOT FAILED %s %016lx", Stage, Status);
  DiagDraw (Failure, 0);
  if (Root != NULL) { Root->Close (Root); }
  if (Image != NULL) { FreePool (Image); }
  if (Tree != NULL) { FreePool (Tree); }
  if (TrustCaches != NULL) { FreePool (TrustCaches); }
  if (TreePath != NULL) { FreePool (TreePath); }
  if (Map != NULL) { FreePool (Map); }
  if (LowRamLease.Size) {
    gBS->FreePages (LowRamLease.Start, EFI_SIZE_TO_PAGES (LowRamLease.Size));
  }
  for (Index = 1; Index < OwnedCount; Index++) {
    gBS->FreePages (Owned[Index].Start, EFI_SIZE_TO_PAGES (Owned[Index].Size));
  }
  if (AudioAddress != 0) { gBS->FreePages (AudioAddress, 16); }
  if (UsbAddress != 0) { gBS->FreePages (UsbAddress, 8); }
  if (Address != 0) { gBS->FreePages (Address, EFI_SIZE_TO_PAGES (WindowSize)); }
  Print (L"DARWINBOOT: boot refused: %r; firmware retained\n", Status);
  return Status;
}

STATIC UNIXNU_LOADER_PROTOCOL mLoader = { UNIXNU_LOADER_REVISION, Boot };

STATIC
EFI_STATUS
EFIAPI
Unload (EFI_HANDLE ImageHandle)
{
  if (mReplacedHandle != NULL) {
    return gBS->ReinstallProtocolInterface (mReplacedHandle, &gUniXNULoaderProtocolGuid, &mLoader, mReplacedLoader);
  }
  return gBS->UninstallMultipleProtocolInterfaces (ImageHandle, &gUniXNULoaderProtocolGuid, &mLoader, NULL);
}

EFI_STATUS
EFIAPI
DarwinBootEntry (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_LOADED_IMAGE_PROTOCOL *Loaded;
  EFI_STATUS               Status;
  VOID                     *Existing;
  EFI_HANDLE               *Handles;
  UINTN                    Count;

  (VOID)SystemTable;
  Status = gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Loaded);
  if (EFI_ERROR (Status)) { return Status; }
  Status = gBS->LocateProtocol (&gUniXNULoaderProtocolGuid, NULL, &Existing);
  if (!EFI_ERROR (Status)) {
    // Explicit, volatile replacement for the qualified FD's older loader.
    // Unloading this driver restores it; no firmware or phone storage changes.
    if (((UNIXNU_LOADER_PROTOCOL *)Existing)->Revision != UNIXNU_LOADER_REVISION) { return EFI_UNSUPPORTED; }
    Status = gBS->LocateHandleBuffer (ByProtocol, &gUniXNULoaderProtocolGuid, NULL, &Count, &Handles);
    if (EFI_ERROR (Status)) { return Status; }
    if (Count != 1) { FreePool (Handles); return EFI_UNSUPPORTED; }
    Status = gBS->ReinstallProtocolInterface (Handles[0], &gUniXNULoaderProtocolGuid, Existing, &mLoader);
    if (!EFI_ERROR (Status)) {
      mReplacedHandle = Handles[0];
      mReplacedLoader = Existing;
      mImage = ImageHandle;
      Loaded->Unload = Unload;
      Print (L"DARWINBOOT24: replaced loader in RAM; Darwin 24 ABI, EL%u\n", (UINT32)(DarwinCurrentEl () >> 2));
    }
    FreePool (Handles);
    return Status;
  }
  if (Status != EFI_NOT_FOUND) { return Status; }
  mImage = ImageHandle;
  Status = gBS->InstallMultipleProtocolInterfaces (&ImageHandle, &gUniXNULoaderProtocolGuid, &mLoader, NULL);
  if (!EFI_ERROR (Status)) {
    Loaded->Unload = Unload;
    Print (L"DARWINBOOT24: Darwin 24 loader installed EL%u\n", (UINT32)(DarwinCurrentEl () >> 2));
  }
  return Status;
}
