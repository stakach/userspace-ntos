# Hosted SEH Linkage Image

This freestanding x64 PE DLL contains two Win64 call frames for invoking a C exception filter or
termination handler. The COFF assembler emits `.pdata` and `.xdata` describing each frame's real
40-byte stack allocation. The image has no imports, entry point, or runtime state.

Build and statically verify it with:

```sh
bash components/nt-seh-linkage/build.sh
```

The output is `.tmp/nt-seh-linkage/nt-seh-linkage.dll`. `seh-linkage-verify` parses it through
`nt-pe-loader`, maps it, admits its exception metadata through `nt-unwind`, and checks both exports
against their actual prologues and unwind records. An optional output directory is the script's
first argument; `CLANG` and `RUST_LLD` select the cross compiler and linker.

This is a **static metadata artifact**, not a live exception dispatcher. Its frames have no
language handler, so nested raises and collided unwinds are not handled. It is not staged into the
OS image or bound to native exports. Runtime acceptance requires the separate dispatcher, sealed
image mapping, and a compiled driver fixture proving a caught raise and `__finally` execution.
