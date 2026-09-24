# Native Driver SEH Fixture

This freestanding AMD64 `.sys` is a test driver built with compiler-emitted C SEH metadata. Its
`DriverEntry` raises `STATUS_ACCESS_DENIED` inside a `__try/__finally`, catches that status in an
outer `__try/__except`, and returns success only if the finalizer and exception body each ran once
and control did not return from `ExRaiseStatus`. `SehFixtureEvidence` is an exported volatile data
record for a future native gate to inspect.

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

This is **not** a runtime pass. The fixture is not added to the boot image or registered as a
service. A native gate must later load and call this real DriverEntry, read the evidence, and prove
the nonreturning context transfer and FINALLY execution before claiming SEH integration.
