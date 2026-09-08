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
