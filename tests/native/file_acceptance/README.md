# Native File Acceptance

`file_acceptance.exe` is a freestanding AMD64 NT 5.2 native-subsystem executable.
Its exact twenty imports resolve to our real ntdll. There are no private syscall
numbers, executive test endpoints, injected replies or driver-name routing rules.

Build serially after our ntdll is built:

```sh
bash tests/native/file_acceptance/build.sh
```

The optional output directory defaults to `.tmp/native-file-acceptance`. `NTDLL`,
`CLANG`, `LLVM_DLLTOOL` and `RUST_LLD` select existing tools/artifacts. Static
verification uses the existing `nt-native-test-verify` PE/IAT/relocation checks
with an explicit `file-acceptance` import contract. It is not execution evidence.
The build needs a Windows-target-capable Clang and the existing Rust linker. When
`llvm-dlltool` is unavailable, the existing fixture pattern generates `ntdll.lib`
from an assembly trap DLL with rust-lld. That `import-only-ntdll.dll` stays in the
build directory and is NEVER staged: the profile copies only `file_acceptance.exe`.
Static IAT validation still resolves every import against our actual built ntdll.

Run a fresh isolated image with:

```sh
bash tests/native/file_acceptance/run.sh --build-only
bash tests/native/file_acceptance/run.sh
bash tests/native/file_acceptance/run.sh --verify-log .tmp/run-file-acceptance-LOG.log
```

The `file-acceptance` profile stages only this executable and installs a test-only
`BootExecute` REG_MULTI_SZ containing `file_acceptance`. Real ReactOS SMSS resolves,
launches and waits for it through the ordinary process loader. Production profile
metadata and files are unchanged. The fixture uses `\SystemRoot\Fonts`, not a
hardcoded installation drive/path. It creates a test-only relative overlay child
with DELETE_ON_CLOSE, and never modifies installed font bytes.

## Assertions

Every observation is `[file-acceptance] case=NAME field=FIELD actual=0xHEX
expected=0xHEX` (one physical line).
The actual NtDisplayString transport may prepend exactly `[smss] `; the parser
accepts that framing, not arbitrary substring matches. The fixture emits LF only.
Any mismatch terminates the real process with STATUS_UNSUCCESSFUL. Nineteen completed groups are required:

- Relative CREATE/reopen/read through a real absolute parent directory handle.
- Read-only File write denial and nondirectory RootDirectory rejection.
- Parent handle closure while the child remains live and queryable.
- FileAll EOF/current position/mode, bounded UTF-16 filename suffix and exact
  Information extent, with buffer canaries.
- Mode changes and rejected transitions preserve the canonical File body across a
  duplicated handle and FileAll queries; restoring mode is visible through both handles.
- FileMode input Length eight with a readable four-byte scalar and trailing NOACCESS or
  GUARD page: exact failure status, untouched IOSB, and unchanged shared mode and position.
- Immediate IOSB completion preserves the AMD64 padding adjacent to the 32-bit Status.
- Short Standard query must leave IOSB/output untouched.
- Query class/length/probe ordering versus Read/Write handle/access-before-probe ordering,
  including a read-only handle with inaccessible IOSB, data, offset and key pointers.
- NOACCESS and GUARD output spans across an actual VM page boundary.
- READ output, WRITE input and IOSB spans crossing into a protected page.
- Failed probes leave current position/content unchanged and supplied Event
  nonsignaled; successful readback proves real stored bytes are intact.
- A real `RtlCreateUserThread` worker opens `\Registry\Machine\Software\Classes`.
  `NtQueryKey(KeyNameInformation,NULL,0,&stack_ResultLength)` must return
  BUFFER_TOO_SMALL and the exact required length. A full query checks that length,
  canonical full name case-insensitively, and guard canaries. The main thread waits
  ten seconds at most on the real worker thread handle and reads its released result.

ABI and fault precedence come from ReactOS `ntoskrnl/io/iomgr/iofunc.c`:
`NtQueryInformationFile` validates class/length, probes IOSB/output, then resolves
the handle; `NtReadFile`/`NtWriteFile` resolve the File/access first, then probe
IOSB/data. Those SEH boundaries return the actual exception code. Thus the fixture
expects STATUS_ACCESS_VIOLATION or STATUS_GUARD_PAGE_VIOLATION returns, not a
manufactured exception in user mode. `sdk/include/reactos/probe.h` probes the
complete sixteen-byte IOSB before provider entry. The returned FileAll layout is
from `sdk/include/xdk/iotypes.h`; IopGetFileMode includes DELETE_ON_CLOSE.
Registry sizing follows `ntoskrnl/config/ntapi.c:NtQueryKey` and
`ntoskrnl/config/cmapi.c:CmpQueryNameInformation`: ResultLength is written before
BUFFER_TOO_SMALL for a zero-length name query, with four bytes of header plus the
full UTF-16 path and no terminator. Successful names may differ in letter case.

## Evidence Limits

`case=PASS field=cases actual=...0013 expected=...0013` and `EXIT-REQUEST` mean the
assertions completed and termination was requested. They are NOT alone proof of
process exit, completed SMSS wait, desktop or whole-OS acceptance. The parser
requires every expected group, rejects every actual/expected mismatch and failure
marker, and correlates the PID returned by genuine ProcessBasicInformation with
an actual `[process-terminal-committed]` zero exit/signaled receipt and subsequent
`[process-delete] retired` for the exact same PI/PID/generation. Thread counts are
actual retirement evidence, not assumed to include workers already retired earlier.
The runner separately retains the unchanged desktop/sentinel verdict and requires
the fixture parser too. Screenshots remain necessary when claiming desktop.
`run.sh` keeps the one-hour maximum;
timeouts are failures, not evidence of successful ownership cleanup.

This first slice proves real user syscall probing and observable file effects.
It does not claim native filter SET16 propagation, controlled pending completion,
late IOSB Information-before-Status faults, no-duplicate provider dispatch counters
or uncertain-effect failure injection. Those require a genuinely pending WDM
provider fixture and exact native owner receipts; host or AST specs cannot replace
that evidence. Host parser tests (`python3 -m unittest discover -s
tests/native/file_acceptance -p 'test_*.py'`) use explicit synthetic log snippets
only to prove parser rejection/acceptance, never to claim native execution.
