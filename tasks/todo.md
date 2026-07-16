# Step 4.B — wire our ntdll's REAL loader live (in-process LoaderHost)

Baseline: main @ 83e1084, gate 174/98, paint 768/768 @ 0x003a6ea5, sel4test byte-identical.

## Goal
Replace the 4.A marker-then-return in the cdylib's `LdrpInitialize` with a real
in-process drive: heap over NtAllocateVirtualMemory + snap smss's ntdll-only imports
against OUR export table (direct IAT writes) + transfer to smss's entry (NtProcessStartup).
Flag-gated (SMSS_USE_OUR_NTDLL); committed state green via flag OFF.

## Architecture (in-process, like real ntdll)
- Our LdrpInitialize runs IN smss's VSpace (4.A proved it).
- Nt* stubs = syscall trap → serviced by executive (NtAllocateVirtualMemory works).
- smss + ntdll BOTH already mapped by the executive. map_image = no-op.
- IAT pages are RW (.rdata) + demand-faulted → direct in-process writes OK.
- Resolve smss's imports against OUR export directory (mapped at NTDLL_BASE).

## Slices
### Slice 1 — heap + in-process import snap
- [ ] cdylib `syscalls` module: NtAllocateVirtualMemory in-process caller.
- [ ] Real #[global_allocator] over nt_ntdll::heap on an NtAllocateVirtualMemory region.
- [ ] In-process mapped-PE walk: our export dir (name→rva) + smss import dir + IAT slot rvas.
- [ ] Snap: write NTDLL_BASE+export_rva into each smss ntdll IAT slot (direct in-proc write).
- [ ] LdrpInitialize: marker → heap → snap → return to trampoline.
- [ ] Boot flag ON: heap ok + IAT snapped. COMMIT flag OFF (green).

### Slice 2 — transfer to entry
- [ ] Trampoline chains to smss entry (RCX=PEB) → NtProcessStartup under our ntdll.
- [ ] Boot flag ON: smss reaches NtProcessStartup, first syscalls appear. COMMIT flag OFF.

## Verify
- Gate green flag OFF: 174/98 + paint 768/768; sel4test byte-identical; cargo test -p nt-ntdll = 145.

## Review (DONE 2026-07-16)
- Slice 1 + Slice 2 BOTH landed in one pass.
- Flag ON boot log: `snap resolved=103 missing=0 spot=0x0000010000803060` (all smss ntdll imports
  snapped in-process against OUR export table; spot IAT points into our ntdll = NTDLL_BASE+0x3060).
- smss reached NtProcessStartup (rip=0x…572ee0) + called back into our ntdll (rip=0x…808260) via the
  snapped IAT.
- Committed flag OFF: gate 174/98, paint 768/768 @ 0x003a6ea5, exit=3. sel4test byte-identical (only
  executive change is inside the ldrpinit_rva!=0 branch, dead on flag-OFF; no rust-micro/src change).
- nt-ntdll host tests 145/145. DLL rebuilt (254 exports, LdrpInitialize RVA 0x1050, 2048 relocs).
- Files: crates/nt-ntdll-dll/src/on_target.rs (new), crates/nt-ntdll-dll/src/lib.rs (heap allocator +
  LdrpInitialize drive), components/ntos-executive/src/img_spawn.rs (R8=smss base, flag-gated).
