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

## Review
(to fill)
