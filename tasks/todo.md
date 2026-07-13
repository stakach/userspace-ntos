# winlogon bringup — increment 5: win32k 2nd GUI client

## Goal
Extend hosted win32k to serve winlogon as a 2nd GUI client so winlogon's
`NtUserProcessConnect(0x10FA)` succeeds, then advance winlogon's user32 DllMain +
WinMain toward WinSta0/Default/desktop-graphics. Gate MUST stay 115/115, 0 FAIL,
desktop paint 0x003a6ea5 768/768, no hang.

## Key findings (research)
- Reply routing ALREADY generalizes: every main-loop recv (reply_recv_badge /
  recv_full_r12) sets r12=REPLY_MAIN, so each caller's Call binds REPLY_MAIN. The
  routed_win32k path resumes via send_on_reply(REPLY_MAIN) = the current caller
  (winlogon or csrss). One outer caller at a time (FIFO). No clobber. NO HANG risk
  from reply routing — the earlier "spin" was the pre-fix single reply_to bug.
- NtUserProcessConnect handler (ntstubs.c:476) only needs: ObReferenceObjectByHandle
  (winlogon handle -> EPROCESS) + PsGetProcessWin32Process (non-null W32Process, for
  HeapMappings delta) + globals gpsi/gHandleTable. Linear+idempotent -> a 3rd connect
  of the shared fake process returns SUCCESS. Executive rewrites siClient
  client-relative AFTER dispatch anyway.
- win32k_dispatch clean-STOPS (returns 0xC0000001, false) on any unresolved foreign
  fault -> forward arm sets handled=false, stop_ssn=m0. Gate-safe wall, NOT a hang.
- ACTIVE_STACK/IMAGE/HEAP_MIRROR already route to winlogon (pi==2). pml4=pml4s[2].

## Steps
- [x] Research the forward arm, reply caps, connect handler, client-mapping.
- [ ] Sub-step 1: route badge==WINLOGON_BADGE through the win32k forward arm; make
      map_win32k_heap_into_csrss per-pi (map win32k USER heap into winlogon's VSpace).
      Boot, verify winlogon 0x10FA -> SUCCESS, gate 115/115, csrss still connects,
      desktop still paints, NO hang.
- [ ] Grind winlogon's subsequent walls (0x125b etc / WinMain).
- [ ] CHECKPOINT + report at connect success; and at the natural desktop-gfx trigger.

## Review
(pending)
