# winlogon bring-up increment 2 — wire its Win32 client stack

## Goal
winlogon's ntdll loader RESOLVES all 8 static imports + COMPLETES → its entry runs; advance init.

## Facts
- winlogon.exe imports: advapi32, kernel32, mpr, msvcrt, ntdll, rpcrt4, user32, userenv.
- Already staged: advapi32, kernel32, msvcrt, ntdll, rpcrt4, user32 (+ vista shims).
- MISSING: userenv.dll (169984 B, entry 0x14b40, SizeOfImage 0x2e000),
  mpr.dll (109568 B, entry 0x107a0, SizeOfImage 0x20000).
- userenv/mpr transitive imports all already staged.

## Tasks
- [ ] Stage userenv + mpr: fetch_reactos.sh + make_image.sh (rust-micro submodule)
- [ ] main.rs: USERENV_WIN32BUF_OFFSET=0x680000, MPR_WIN32BUF_OFFSET=0x6C0000 consts
- [ ] storage_probe: read USERENV (+0x98) + MPR (+0x9c); fix NTDLLVIS cap
- [ ] main.rs: parse userenv_pe + mpr_pe; grow dll arrays 14->16
- [ ] Extend DLL resolution to winlogon: pi==1 -> pi>=1 (NtOpenFile/NtQueryAttributesFile/dll_for_page)
- [ ] Per-process DLL PD/PT: dll_pd_created bool->[bool;3] + dll_mapped_bits [u32;3]
- [ ] Build + keep 113/113 green; report new winlogon wall

## Review — DONE (gate 113/113, 0 FAIL, paint 0x003a6ea5 768/768, sentinel; committed f71b5bc + submodule 2acff16)
- Staged userenv.dll (169984 B) + mpr.dll (109568 B) into WIN32BUF (offsets 0x680000/0x6C0000);
  storage_probe reads them (STORAGE_SHARED +0x98/+0x9c); parsed userenv_pe/mpr_pe; DLL arrays 14->16.
  All winlogon transitive imports already staged -> no other DLLs needed.
- Extended DLL resolution pi==1 -> pi>=1 (NtOpenFile resolve_name, NtQueryAttributesFile dll_exists,
  fault router dll_for_page) so winlogon (pi==2) resolves the shared Win32 stack.
- PER-PROCESS DLL PD/PT reservation (dll_pd_created bool->[bool;3] + dll_mapped_bits [u32;3]) — csrss +
  winlogon load an overlapping DLL set at IDENTICAL fixed bases into DISTINCT VSpaces, so the page-table
  reservation is per-process; registry global `mapped` stays for base-identical dll_for_page. Shared RX
  text cache reused across both (winlogon fills only 46 pages; RX text = csrss's cached frames).
- RESULT: winlogon resolves ALL 8 static imports (no DLL_NOT_FOUND), maps kernel32 at 0x83000000 in its
  OWN VSpace, snaps IAT (NtProtectVM 143 / NtFlushInstructionCache 82), runs into kernel32's DllMain to
  the CSR client connect (NtSecureConnectPort 218 -> \Windows\ApiPort). Then blocks; bounded demo ends at
  smss NtQuerySection(175). NO rust-micro/src changes -> sel4test byte-identical.

## NEW WALL (next increment)
winlogon's kernel32 DllMain CSR client connect: NtSecureConnectPort(218) -> \Windows\ApiPort, then the
CSR connect request/reply (NtRequestWaitReplyPort 208, unregistered). This is the DIRECT cross-badge CSR
message plane (project_lpc's anticipated bulk) — csrss owns \Windows\ApiPort but is parked. winlogon's
entry (wWinMainCRTStartup) is NOT yet running (blocked in kernel32 DllMain). Options: model the CSR
connect (auto-accept + CSR_API_CONNECTINFO reply) OR drive csrss's CSR API loop like sm_rendezvous drives
smss's SmpApiLoop.
