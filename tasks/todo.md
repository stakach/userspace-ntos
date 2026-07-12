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

## Result — InitVideo REACHED (gate 106 PASS / 0 FAIL, winsrv ON)
- InitFontSupport passes (ftfd hosted + KPCR CurrentThread + ZwOpenFile-fail).
- Per-context current-process model (setup_dispatch_context): at DISPATCH time (not bring-up attach,
  which is happy with gs:[0x30]=0), set the chain win32k's inlined accessors read:
  gs:[0x30] (KPCR.Used_Self)=self; [KPCR+0x60]=PH_EPROCESS; SessionId(0x2c0)=0; PH_EPROCESS[+0x20]=Q;
  Q[+0x80]=&emptyWStr. Fixes UserCreateWinstaDirectory (0xfc2f0, SessionId read) + the process-env
  getter (0x13d285) without disturbing bring-up. Bookkeeping: "/93" is a stale summary denominator;
  real signal = 106 PASS / 0 FAIL, winsrv ON.
- UserCreateWinstaDirectory PASSES (session-0 winsta path) → InitVideo (display.c:151, RVA 0x6e0b0)
  RUNS: "VGA mode requested" (display.c:164), EngpUpdateGraphicsDeviceList (empty list), returns
  STATUS_SUCCESS. Then UserInitialize → GreCreateBitmap (gpsi->hbrGray) fails ("Failed to allocate a
  brush", brush.cpp:219 → STATUS_INSUFFICIENT_RESOURCES 0xc000009a) — no PDEV.

## STOP boundary reached = framebuf.dll display-driver chunk (overseer directs)
InitVideo runs but has no real display device/PDEV → GDI can't allocate bitmaps/brushes → no pixels.
Next = host framebuf.dll via the driver-loader + wire win32k's Eng* DDI → Phase-0a fb (0x80000000).
