# P4 — LPC/ALPC + csrss (Console Subsystem) — STUB

**Goal:** model NT **LPC/ALPC** over SURT and run ReactOS **`csrss.exe`** with a
text **console**, reaching `cmd.exe` at a prompt.

## Status: ~~stub~~ → **LARGELY DONE (2026-07-14)**

### Status (2026-07-14): LARGELY DONE — real csrss + full LPC + ALPC + a LPC↔ALPC bridge
Real ReactOS **csrss.exe** runs `CsrServerInitialization` and loads its
**basesrv.dll + winsrv.dll** ServerDlls (it's a live hosted process alongside smss and
winlogon). The NT LPC layer is built for real, not modeled: an **isolated
`nt-lpc-server` broker** (control plane) + a **peer-direct data plane**, with
**authentic rendezvous on both ends** — a real smss `SmpApiLoop` thread accepts the SM
connect, and a real csrss `CsrApiRequestThread` accepts the CSR connect (commits
`4b29f6d`, `ff484a1`, `a85bc00`). Beyond the original P4 scope (Win7 prep): a full
**ALPC** surface + a **LPC↔ALPC bridge** over a unified `nt-port-core`, with
two-VSpace section-view shared memory proven (`nt-alpc*`, commits `f67d470`..`eb648c4`,
`cbf2620`; gate 140/140). csrss's natural flow drives winlogon + win32k (P6).
**Residuals (deferred, PARTIAL):** the SM→SB session-registration plane /
`CsrSrvCreateProcess`, and the original console/`cmd.exe` MVP (the stack went straight
to the graphical winlogon desktop instead of a text console — the console path is
still open should a text MVP be wanted).

## Sketch
- **LPC/ALPC over SURT:** connection ports (`NtCreatePort`/`NtConnectPort`/
  `NtAcceptConnectPort`), synchronous `NtRequestWaitReplyPort`, shared-section
  message passing. Map NT's port + message semantics onto SURT rings + a shared
  data frame; the executive brokers the connection like it brokers service rings.
- **csrss:** run `csrss.exe` as a user process (P3 machinery); its subsystem
  init, the CSR API port, and the console driver path (text only — no win32k
  yet). Console screen buffer + input.
- **cmd.exe:** launched via csrss/base subsystem; console read/write round-trips.

## Exit criteria
- `cmd.exe` runs in a text console served by `csrss` over LPC-on-SURT; typed
  input and program output round-trip. QEMU-verified.

## E2E test
`e2e-console`: boot → smss → csrss → cmd → run a trivial command → assert output.
