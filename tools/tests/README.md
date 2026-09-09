# Native Artifact Probes

`ntdll_capture_context.c` and its assembly caller execute the built PE export itself, not a
second implementation of its assembly. The bounded PE mapper does not initialize the DLL or
resolve imports. It is suitable only for the audited, dependency-free `RtlCaptureContext`
export and its relative tail jump. An artifact that introduces dependencies requires a new
review, not permissive loader fallbacks.

On macOS with the x86-64 SDK and Rosetta installed, from the repository root:

```sh
clang -arch x86_64 -Wall -Wextra -Werror -O2 tools/tests/ntdll_capture_context.c tools/tests/ntdll_capture_context.S -o .tmp/ntdll_capture_context
arch -x86_64 .tmp/ntdll_capture_context /absolute/path/to/ntdll.dll
```

The caller observes the actual post-call RIP/RSP, snapshots current segment selectors and
flags, and compares against a real FXSAVE of its known x87/XMM state. Hardware masks and
reserved x87-slot padding are not assigned fabricated expected values. All 16 XMM registers
and eight 80-bit x87 registers are checked. The harness restores its original hardware FP
state before returning to C and preserves the host ABI's nonvolatile registers.

This is an artifact semantics test, not an NT syscall/loader integration test. It neither
proves native context restoration nor substitutes for the kernel's context invocation tests.

## Native Syscall Producers

`ntdll_native_stubs.py` executes unmodified PE stub instructions under Unicorn, intercepting
only SYSCALL with a destructive transport test double. It checks exact argument vectors across
retries, both legacy main-thread TEB layouts and a worker, preserved Windows nonvolatiles,
composed receive destinations, stack canaries, and exact terminal/retry framing. Malformed
replies must stop at UD2, not replay or return a fabricated status.

```sh
python3 -m venv .tmp/native-stub-oracle-venv
.tmp/native-stub-oracle-venv/bin/pip install -r tools/tests/ntdll_native_stubs.requirements.txt
.tmp/native-stub-oracle-venv/bin/python tools/tests/ntdll_native_stubs.py .tmp/nt-ntdll.dll
```

For a regression negative control, preserve the DLL built before producer consolidation
(parent commit `a646ffcf`) and pass its path with `--negative-dll`. That artifact must fail
both composed-destination and retry-vector checks; missing files or unrelated failures do not
count as a successful negative control. The test does not modify either artifact.

These probes have instruction and wall-clock limits. They do not prove microkernel IPC,
callback ownership, scheduling, or desktop boot. Run them serially with other builds/tests.

## Native Stub Unwinding

`ntdll_native_unwind.py` records actual instruction-boundary contexts and stack bytes while the
producer executes two destructive retries and a terminal return. It then invokes the same DLL's
unmodified `RtlVirtualUnwind` export over those snapshots, using the emitted PE exception-directory
rows and unwind records. It contains no replacement unwind interpreter. The unwinder must execute
without syscalls or external dependencies and must preserve its own Windows ABI state.

```sh
.tmp/native-stub-oracle-venv/bin/python tools/tests/ntdll_native_unwind.py .tmp/nt-ntdll.dll --all-services
```

The default sweeps `NtMapViewOfSection`; `--all-services` sweeps all eight arity fixtures. Every
prologue and epilogue instruction boundary must be covered, with both NULL and non-NULL
ContextPointers. Assertions include caller nonvolatiles, RIP/RSP, establisher frame, untouched
context fields, and stack/output canaries. Saved integer-register pointers must name the exact
producer stack slots; unrestored integer and all floating slots retain their input values.
The native stubs do not save XMM registers, so populated floating pointers are covered separately
by the host `nt-unwind` tests rather than claimed by this artifact probe.

For the metadata negative control, pass a DLL built at `91d99245` with `--negative-dll`: its
missing native runtime records must fail explicitly. A DLL built at `6de2cd5d` can be passed with
`--negative-pointers-dll`: it must have valid metadata and unwind correctly with NULL, then fail
only because non-NULL ContextPointers remains untouched. Both controls can run in one invocation.
The test does not prove foreign SEH crossing Rust ABI boundaries, kernel hardware-fault delivery,
or exception resume.
