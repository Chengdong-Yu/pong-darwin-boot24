// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <AsmMacroLib.h>

// A qualified DDR page is read and the identical word is stored back.
// The handler recognizes only these two instruction addresses.
ASM_FUNC(ThorHighRamTouch)
  ASM_GLOBAL ASM_PFX(ThorHighRamTouchLoad)
ASM_PFX(ThorHighRamTouchLoad):
  ldr x1, [x0]
  ASM_GLOBAL ASM_PFX(ThorHighRamTouchStore)
ASM_PFX(ThorHighRamTouchStore):
  str x1, [x0]
  dsb sy
  mov w0, #1
  ret

ASM_FUNC(ThorHighRamTouchFailure)
  mov w0, #0
  ret
