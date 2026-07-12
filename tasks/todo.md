# win32k font support: host ftfd.dll → InitFontSupport → InitVideo

## Findings
- ftfd.dll (1000960 B, size_of_image=0xf8000=248 frames) imports only 8 syms, all from win32k.sys:
  EngAllocMem/EngFreeMem/EngMapFontFileFD/EngUnmapFontFileFD/EngDebugPrint (real win32k code),
  EngMultiByteToUnicodeN→NTOSKRNL.RtlMultiByteToUnicodeN, EngBugCheckEx→NTOSKRNL.KeBugCheckEx,
  RtlUnwind→NTOSKRNL.RtlUnwind (forwarders).
- win32k STATICALLY imports 34 FT_* from ftfd.dll (currently no-op → FT_Init_FreeType fails).
- InitFontSupport (freetype.c:948): FT_Init_FreeType must succeed; IntLoadFontsInRegistry / IntLoadSystemFonts
  / FontLink_* all degrade gracefully IF ZwOpenKey/ZwOpenFile FAIL (not falsely succeed). Returns TRUE without fonts.

## Steps
- [x] 1. Stage ftfd.dll (submodule scripts) — committed 54ca19b
- [x] 2. Executive: FTFDBUF constants + storage_probe read (::FTFD.DLL → STORAGE_SHARED+0x88) + map into exec VSpace
- [x] 3. win32k_host.rs: FTFD_VA/frames; load_driver_into win32k.sys import source + pe_export_lookup NTOSKRNL/HAL forwarders; patch_win32k_ftfd_imports (34 patched)
- [x] 4. Executive bring-up: load ftfd + patch win32k IAT
- [x] 5. Trampolines: RtlMultiByteToUnicodeN, RtlCreateUnicodeString
- [x] 6. KPCR CurrentThread (gs:[0x188]=PH_ETHREAD) → font-mutex assert passes; ZwOpenFile→FAIL → IntLoadSystemFonts skips
- [x] InitFontSupport PASSES; InitializeGreCSRSS returns TRUE; NtUserInitialize → UserInitialize

## Result (gate 106/93, winsrv ON)
InitFontSupport passes. Next wall = UserCreateWinstaDirectory (RVA 0xfc2f0, called at 0xc43a5),
the function IMMEDIATELY BEFORE InitVideo (0x6e0b0). It null-derefs the inlined
PsGetCurrentProcessSessionId = [[gs:0x30]+0x60]->SessionId@0x2c0 because the fake KPCR's
self-pointer (gs:[0x30]) is 0. NAIVE FIX (set KPCR gs:[0x30]=self + gs:[0x60]=EPROCESS) REGRESSES
the NtUserProcessConnect (0x10FA) path → gate 104. So reaching InitVideo needs proper per-context
KPCR/current-process modeling (the display/window-station chunk) — reverted, left green.
