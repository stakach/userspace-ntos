# Spawn services.exe as the 4th hosted process (badge 6, pi 3)

Frontier: winlogon (badge 4) walls at SSN 98 NtIsProcessInJob = kernel32 CreateProcessInternalW
spawning services.exe (winlogon.c StartServicesManager). Service the Win32 create chain, spawn
services.exe via spawn_sec_image(pi=3), get its ntdll loader running. Land committed-green.

## VA design (pi 3, badge 6)
- SERVICES_BADGE = 6
- SERVICES_SCRATCH_BASE = 0x…1140_0000 (PT2 of smss's pre-mapped 8-PT scratch range, free)
- SERVICES_STACK_MIRROR_VA = 0x…106D_0000 (FILEBUF PT, present)
- SERVICES_HEAP_MIRROR_VA  = 0x…1260_0000 (own PT via spawn_sec_image)
- SERVICES_IMAGE_MIRROR_VA = 0x…1280_0000 (own PT via spawn_sec_image)
- services env scr_base     = 0x…1076_0000 (FILEBUF PT, between smss 0x1074 / csrss 0x1078)
- NEXT_SERVICES_ALLOC, prio 103

## Steps
- [ ] G1 constants
- [ ] G2 nt-dll-registry PI_SLOTS 3→4
- [ ] G3 static arrays 3→4 (PM_PIDS/PM_TIDS/PM_POOL_TID/PFILLED)
- [ ] G4 pm init: 4th create_process(services.exe, parent winlogon) + expect/pids/reserve arrays
- [ ] G5 procs [4]; dll_pd_created/dll_mapped_bits [4]; ExecLoopCtx field types
- [ ] G6 badge→pi + ACTIVE_*_MIRROR + PE-select add pi 3 arms
- [ ] G7 services_pe load (load_dll_from_fs by path) + loop_ctx services_file/section_handle + services_pe
- [ ] G8 NtOpenFile is_services; NtCreateSection services tracking; alloc pi==3
- [ ] G9 raw arms: 98 NtIsProcessInJob; 50 NtCreateProcessEx→services spawn inline; grind child-AS syscalls
- [ ] G10 sec-stop services name; specs 0b111→0b1111, count 4, SERVICES_SPAWNED
- [x] build + run_specs (green: paint 0x003a6ea5, [microtest done], services spawned + loader running)

## REVIEW — MILESTONE LANDED (gate 149/94, 0 FAIL, desktop 0x003a6ea5 768/768, exit 3)
services.exe is the 4th hosted process (badge 6, pi 3). winlogon's real Win32 CreateProcessW
(StartServicesManager) drove the full CreateProcessInternalW chain to NtCreateProcessEx(50), which
spawned services via spawn_sec_image(pi=3); its ntdll loader ran (46 pages, loading its DLLs
OpenFile→CreateSection→QuerySection→MapView→Protect). NO rust-micro/src change → sel4test byte-identical.

Walls ground through (all in winlogon's Win32 create path, between the SSN-98 frontier and NtCreateProcessEx):
1. NtIsProcessInJob(98) — serviced (not-in-job).
2. BasepIsProcessAllowed c0000002 — the broad empty-name NtOpenKey→MACHINE_ROOT_HANDLE fallback made
   AppCertDlls spuriously succeed → RtlQueryRegistryValues failed. Gated the fallback OFF once services
   create starts (SERVICES_CREATE_STARTED); keyboard path runs earlier so it's unaffected.
3. NtApphelpCacheControl(19) — serviced SUCCESS (no shim; BaseCheckRunApp returns TRUE without apphelp.dll).
4. STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE — KUSER_SHARED_DATA.ImageNumberLow/High were 0 (zeroed page);
   set 0x014c..0x8664 in spawn_sec_image (offsets 0x2c/0x2e per ReactOS KUSER layout, NOT 0x260).
5. SubSystemType/version reject (proc.c:3504/3544) — image_info hardcoded NATIVE(1)/v0.0; services is
   CUI(3). Added PeFile::subsystem()/subsystem_version() + patched the services NtQuerySection info.

NEW FRONTIER: services.exe faults at cr2=0x04000000 (the CSR connect ViewBase/StaticData region) doing
its kernel32 CSR client connect (NtSecureConnectPort → \Windows\ApiPort). Needs per-process CSR connect
regions for services (the winlogon WINLOGON_CSR_HEAP_VA/STATIC_VA recipe, per-pi) — the next real service.
