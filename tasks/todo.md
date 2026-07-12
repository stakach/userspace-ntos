# Fix (B): per-caller reply cap for win32k dispatch (removes nested-fault reply_to clobber)

## Root cause (verified in kernel)
- `finish_call` (rust-micro/src/endpoint.rs:182) UNCONDITIONALLY sets `receiver.reply_to = Some(sender)`.
- So when a win32k SSN handler FAULTS during a nested dispatch (executive mid-servicing csrss),
  the fault Call clobbers the executive's single `reply_to` from csrss -> win32k.
- => A win32k-only reply cap is NOT enough (handoff premise incomplete): csrss's reply ALSO
  must be cap-based so it survives the clobber. Need TWO reply objects.

## Plan (executive-only; rust-micro/src UNTOUCHED -> sel4test byte-identical)
- [ ] Retype two MCS Reply objects at bring-up: REPLY_MAIN_SLOT (main service loop / csrss),
      REPLY_W32_SLOT (win32k dispatch faults). OBJ_REPLY=6, size_bits=0.
- [ ] Add IPC helpers: `recv_full_r12(ep, reply_cptr)` (SYS_RECV with r12=replyRegister) +
      `send_on_reply(reply_cptr, msginfo, r0..r3)` (SYS_SEND on Cap::Reply -> decode_reply).
- [ ] Main loop: bind REPLY_MAIN on every recv (r12 in reply_recv_badge + initial recv).
      Win32k-routed csrss syscall arm: reply via send_on_reply(REPLY_MAIN) instead of reply_to.
- [ ] win32k_dispatch: recv faults with r12=REPLY_W32; reply faults via send_on_reply(REPLY_W32).
- [ ] Synthetic proof: TEST_FAULT_SSN handler in the win32k component touches an un-demand-paged
      data page -> forces a fault through the reply-cap path; bring-up self-test asserts it resolves.

## Verify
- [ ] Gate stays 105/105 + microtest sentinel; +1 for the faulting-dispatch self-test.
- [ ] No rust-micro/src change (byte-identical sel4test).
- [ ] winsrv-ON diagnostic: nested connect still completes (no regression / no hang).

## Discipline
- build order: components/ntos-executive/build.sh THEN rust-micro/scripts/build_kernel.sh
  extern-rootserver THEN run_specs.sh. Synchronous boots.
