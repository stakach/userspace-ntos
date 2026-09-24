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

The two terminal cases use separate fixture images and hive profiles. Each executes the same
verified raise, target-unwind, and collided-unwind prefix before `DriverEntry` issues either an
unhandled `ExRaiseStatus` or an exit `RtlUnwindEx`. Run both serially with:

```sh
bash scripts/run-seh-terminal-integration.sh
```

This gate stops QEMU only after the provider bugcheck is logged. It requires the native trigger,
exception code, reporting-thread suspension, and terminal state. A timeout, returned terminal
call, failed prefix, or successful DriverEntry completion fails. Neither terminal fixture is
staged in the production image.

The CPU-fault case rebuilds the isolated `seh-driver` image with a compiler-emitted
`__try/__except` call into a separate PE `ud2` function. Keeping the faulting instruction in an
external call preserves the caller's exception scope at optimization level 2; the static gate
requires that extra scope and an x64 runtime-function row covering `ud2`. The runtime gate
requires the real fault to reach the handler as
`STATUS_ILLEGAL_INSTRUCTION` exactly once; the instruction after `ud2` must not run. Run it
separately from the regular image gate:

```sh
bash scripts/run-seh-fault-integration.sh
```

This variant is never staged in the production image.
