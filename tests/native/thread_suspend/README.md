# Native Thread Suspension Acceptance

This standalone AMD64 NT 5.2 native-subsystem PE exercises the real ntdll exports and
executive thread-suspension adapter. It has no CRT, private syscall numbers,
synthetic replies, or direct TCB controls. It is not installed into production
BootExecute, and building or statically verifying it is not a runtime pass.

## Build

Build the repository's ntdll DLL first, then run this command serially with other
repository builds and specs:

```sh
bash tests/native/thread_suspend/build.sh
```

The default input is `.tmp/nt-ntdll.dll`; output is
`.tmp/native-thread-suspend/thread_suspend.exe`. `NTDLL` selects another already
built DLL, and an optional positional argument selects the output directory.
`CLANG`, `LLVM_DLLTOOL`, and `RUST_LLD` override tool discovery. The build
uses LLVM's Windows cross compiler/import librarian and the repository's nightly
Rust linker. The verifier is a separate binary in the existing
`ntdll-dll-verify` package; it uses the executive's canonical `nt-pe-loader`.
No packages or prerequisite DLL artifacts are installed by this script.

The verifier checks the actual PE subsystem, executable entry, exact twelve
imports, and resolution of every import to executable code in the supplied
ntdll. It maps both images at nonpreferred bases and binds/readbacks every IAT slot through
`nt-pe-loader`. No dynamic-loader APIs, forwarded imports, delay imports, or other DLLs
are accepted. It prints both artifact hashes for correlation with a later run.

```sh
cargo run -p ntdll-dll-verify --bin nt-native-test-verify -- \
  .tmp/native-thread-suspend/thread_suspend.exe .tmp/nt-ntdll.dll
```

## Runtime Contract

Launch through the ordinary native process loader, for example a deliberately
configured test image's real SMSS BootExecute path. Do not replace SMSS, invent
an executable identity, bypass the current dispatcher, or change production
registry defaults merely to run this fixture. See ReactOS
`base/system/smss/sminit.c` and `sdk/include/ndk` for the native startup/API
contracts. Current boot blockers must be repaired before claiming acceptance.

One program performs three cases and exits the process coherently:

- Self-suspend: create a suspended worker using `RtlCreateUserThread`; initial
  resume returns previous count 1. The worker's real `NtSuspendThread` call
  publishes previous count 0 but cannot return. Nested suspend/resume return
  previous counts 1 and 2; the final resume returns 1 and permits exactly one
  return through the original native Reply.
- Object completion while held: worker uses `NtSignalAndWaitForSingleObject`
  to establish an atomic event handshake. After two suspends, the controller
  signals the auto-reset target. A zero-timeout poll must see TIMEOUT, proving
  the held original waiter already consumed the signal. The intermediate
  resume cannot execute the worker; final resume produces exactly one return
  with the original successful wait result, without a second signal.
- Object wait surviving final resume: suspend an established waiter, then
  immediately release the final hold while its target remains nonsignaled.
  The worker must still be waiting. Only a subsequent real event signal may
  complete it. Both object cases first check that a zero-count resume does not
  cancel the wait or manufacture completion.

All cases check previous counts, absence of early completion, one entry/return,
the original call status, worker termination, and handle closure. Shared counters
use aligned atomic operations. The self-suspend admission observation uses the
real writable PreviousSuspendCount output, not a diagnostic kernel endpoint.
Individual waits use ten-second relative deadlines; polling and early-return
observation are bounded. A kernel-level deadlock can prevent timeout delivery,
so the VM runner must also enforce an external watchdog (at most the repository's
one-hour boot limit).

Success requires all three case PASS lines, the final
`[thread-suspend] PASS all native acceptance cases 0x00000003` line, and genuine
process exit status zero. Any FAIL line, timeout, fault, or missing exit fails
acceptance. On failure the program requests process termination with
STATUS_UNSUCCESSFUL rather than releasing holds using a private cleanup path.

File acquisition/retry and LPC wait completion while held are deliberately
future cases. This fixture does not claim coverage for those owners, APCs,
cross-process suspension, count overflow, or desktop rendering.
