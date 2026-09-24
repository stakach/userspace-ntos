# Native Driver SEH Fixture

This freestanding AMD64 `.sys` is a test driver built with compiler-emitted C SEH metadata. Its
`DriverEntry` raises `STATUS_ACCESS_DENIED` inside a `__try/__finally`, catches that status in an
outer `__try/__except`, and returns success only if the finalizer and exception body each ran once
and control did not return from `ExRaiseStatus`. `SehFixtureEvidence` is an exported volatile data
record, and emits the checked counters through the real `DbgPrint` provider import.

The fixture also targets `RtlUnwindEx` directly and then starts a nested unwind from an active
termination callback. That collided path uses an assembly C scope and finalizer with explicit
`.pdata`/`.xdata`: the compiler's outlined finalizer can allocate a frame without emitting unwind
metadata. The nested unwind must cross `SehCallFinally`, resume the saved dispatcher exactly once,
and reach the target without returning from either unwind call.

Build and statically verify the image with:

```sh
bash tests/native/driver_seh/build.sh
```

The output is `.tmp/native-driver-seh/driver_seh.sys`. The script compiles for the MSVC x64 ABI,
generates an `ntoskrnl.exe` import library (using `llvm-dlltool` or a build-only trap DLL), then
links and verifies the fixture. The trap DLL stays in the output directory and is never staged.
The structured verifier checks the actual PE imports, evidence export, exception directory, C
scope tables, and `nt-unwind` image admission at a nonpreferred component load base. It also
checks the compiled COFF object's relocations so a build with absolute address references cannot
silently pass despite having no PE base-relocation directory.

The production image does not contain this fixture. For the isolated native runtime gate, run:

```sh
bash scripts/run-seh-driver-integration.sh
```

This compiles and verifies the PE, stages it only under `NTOS_IMAGE_PROFILE=seh-driver`, and
registers it as a system-start file-system driver through generated hive metadata. The gate
requires exact native evidence for the nonreturning raise, FINALLY execution, and matching
exception handler, then stops QEMU after the driver-emitted completion marker. Pass `--desktop`
to also require genuine Explorer paint and the QEMU sentinel. The boot readiness timeout defaults
to 900 seconds and cannot exceed the one-hour limit enforced by `run.sh`.
