# ALPC last-mile wrap-up (register NtAlpc* SSNs + two-VSpace cross-AS section view)

## Item (a) — register NtAlpc* SSNs
- [x] Extract NtAlpc* SSNs from references/ntdll.dll (real Win7 ntdll) — NOT hardcoded
- [x] FINDING: ros-ntdll.dll (what live smss/csrss/winlogon run) exports NO NtAlpc*; the Win7
      ALPC SSN block (111..131) COLLIDES with the live ReactOS SSN space (Win7 NtAlpcConnectPort=113
      == live ReactOS NtMapViewOfSection=113). => a live dispatcher arm keyed on raw SSN would
      HIJACK live ReactOS syscalls. Register as a dedicated recognizer, gated by ALPC-process
      identity (dormant — no ALPC binary yet), proven by counted spec.
- [ ] Add SSN consts + `alpc_ssn_to_opcode` recognizer + `try_route_alpc_ssn` (guarded, dormant)
- [ ] Counted specs: SSN->opcode table correct + NtAlpcCreatePort SSN routes to adapter -> port

## Item (b) — two-VSpace cross-AS ALPC section view (the meaningful capability)
- [ ] `alpc_cross_vspace_selftest()` post-loop (after reclaim self-test), byte-identical boot
- [ ] Two throwaway endpoint VSpaces; real section backing frames; copy_cap+page_map into BOTH at view VA
- [ ] Writer thread in A writes; reader thread in B reads back through ITS OWN mapping (fault-report)
- [ ] Reclaim throwaway VSpaces + section frames (CNodeDelete); spec exec_alpc_section_view_cross_vspace

## Discipline
- Gate 137 -> additive; winsrv ON, sentinel, desktop paint 0x003a6ea5; ANY regression = REVERT
- SUBMODULE rust-micro build; verify rootserver.elf mtime.

## REVIEW (landed green — gate 140/94, 0 FAIL)
- Item (a) DONE: SSN consts extracted from references/ntdll.dll + `alpc_ssn_to_opcode` recognizer +
  `try_route_alpc_ssn` guarded dormant arm wired into the fault dispatch loop (ALPC_HOST_PRESENT
  never set at boot → byte-identical). Specs `exec_alpc_ssn_registered` + `exec_alpc_ssn_routes_to_adapter`
  PASS. Live hosted native-ABI caller documented as arriving with a real Win7-ntdll ALPC binary
  (the SSN-collision with the live ReactOS space forbids a raw-SSN live arm for the 3 ReactOS procs).
- Item (b) DONE: `alpc_cross_vspace_selftest` — two SEPARATE throwaway VSpaces map the SAME section
  frames at the view VA (copy_cap + page_map); writer thread in A wrote (m0=0xA), reader thread in B
  read both pages back through ITS OWN mapping (m0=m3=0xCAFEBABE_DEADBEEF == the write). ok=0x3F.
  Throwaway VSpaces + section frames reclaimed. Spec `exec_alpc_section_view_cross_vspace` PASS.
- Boot byte-identical: csrss 339/handle 0x2c, winlogon 230, smss 136, reclaim 0x3F, paint 0x003a6ea5
  768/768, winsrv ON, [microtest done], exit 3. NO rust-micro/src change → sel4test byte-identical.
