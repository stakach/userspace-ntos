# Task: SERVICE 10 — lsass.exe as the 5th hosted process (pi 4)

Baseline: main @ 0b8e162, gate 163/96, paint 768/768 @ 0x003a6ea5, sel4test byte-identical, exit 3.

## Root cause of malformed lsass path
- winlogon StartLsass = CreateProcessW(L"lsass.exe") (bare name). kernel32 SearchPathW
  tries CWD first = CurrentDirectory.DosPath. img_spawn.rs:464 sets DosPath="C:\Windows"
  WITHOUT a trailing backslash -> CWD-join yields `\??\C:\Windowslsass.exe` (proc.c:2745
  Open file failed c0000034). ReactOS path.c:541 strips the expected trailing `\` (Length-=2),
  proving DosPath must be backslash-terminated. Also the BASE_STATIC_SERVER_DATA
  WindowsDirectory Length field (exec_handler.rs:708/712) is 1 wchar short.
- services.exe (same bare CreateProcessW) worked because is_services substring matched
  regardless; lsass just needs is_lsass recognition + a findable file.

## Plan
- [ ] FIX 1 (root path bug): img_spawn.rs:464 CurrentDirectory.DosPath "C:\Windows" -> "C:\Windows\"
- [ ] FIX 2 (Length fields): exec_handler.rs:708 9*2->10*2, :712 18*2->19*2
- [ ] Add "lsass.exe" to SYSTEM32_FILES (main.rs)
- [ ] Constants (main.rs): LSASS_BADGE=8, LSASS_*_MIRROR / ENV_SCRATCH / SCRATCH_BASE (pi 4)
- [ ] Statics: NEXT_LSASS_ALLOC, LSASS_SPAWNED, LSASS_FAULTS, LSASS_CREATE_STARTED
- [ ] Grow arrays [;4]->[;5]: PM_PIDS, PM_TIDS, PM_POOL_TID, PFILLED, procs, dll_pd_created, dll_mapped_bits
- [ ] nt-dll-registry PI_SLOTS 4->5
- [ ] Boot EPROCESS: pm.create_process("lsass.exe", Some(winlogon_pid), None) -> PM_PIDS[4]
- [ ] Badge->pi arm: badge==LSASS_BADGE -> pi 4; ACTIVE_*_MIRROR pi==4 arms; pe select pi 4
- [ ] File-open fake: is_lsass probe; lsass_file_handle/section tracking in ctx
- [ ] NtQuerySection lsass arm (pi==2, subsystem/version patch)
- [ ] NtCreateProcessEx(50) spawn arm: winlogon spawns lsass badge 8 pi 4, prio 104
- [ ] alloc bump pi==4 -> NEXT_LSASS_ALLOC
- [ ] Add specs + grow existing count gates
- [ ] Build + boot; grind lsass loader/init as far as green; NtWaitForSingleObject IMMEDIATE
- [ ] Verify paint 768/768, gate green, pi 0-3 unaffected, sel4test byte-identical; commit

## Review
- lsass spawned as pi 4 (badge 8), dynamic pid, demand-faulted 49 pages of its ntdll loader.
  Gate 165/96 (+2: exec_lsass_spawned, exec_lsass_loader_running), 0 FAIL, paint 768/768.
- ROOT CAUSE of the boot hang (took the whole session): adding the 5th hosted process pushed
  service_sec_image's stack frame over the 16 KiB (4-page) rootserver stack on the DEEP FS-walk
  call chain (fat_open_path -> dir_find_lfn), corrupting dir_find_lfn's cluster-chain loop var ->
  infinite FAT loop (100% CPU, NO panic, silent). Isolated by DBG prints (hang between "before
  csrss load" and the FS-by-path print, in fat_open_path) + confirmed by an 8-page kernel stack
  making the boot green. FIX (executive-side, no kernel change): moved the 2 KiB `filled_pages`
  working buffer OFF the stack into a `static mut FILLED_WORK` (single active pi/iteration).
- The winlogon lsass PATH bug (`\??\C:\Windowslsass.exe`, missing sep) turned out NOT to need the
  root path fix: the `is_lsass` substring open-fake matches "lsass" regardless (like services). The
  CurrentDirectory-trailing-backslash + BASE_STATIC_SERVER_DATA Length fixes were REVERTED (they
  affected all processes and weren't needed). USER POINT (registry-derived Windows dir) NOT yet
  addressed — flagged as follow-up.
- FRONTIER: lsass walls at lsasrv.dll DLL_NOT_FOUND (\Windows\System32\lsasrv.dll) — its static
  import isn't registered in the 16-slot DLL registry. Next real service = stage+register
  lsasrv.dll + samsrv.dll (like csrss's ServerDlls). Then LsapInitLsa -> LSA RPC server ->
  LSA_RPC_SERVER_ACTIVE = the step-2 reply-cap-parking boundary.
