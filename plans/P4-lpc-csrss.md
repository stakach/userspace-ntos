# P4 — LPC/ALPC + csrss (Console Subsystem) — STUB

**Goal:** model NT **LPC/ALPC** over SURT and run ReactOS **`csrss.exe`** with a
text **console**, reaching `cmd.exe` at a prompt.

## Status: stub (expand when P3 nears exit)

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
