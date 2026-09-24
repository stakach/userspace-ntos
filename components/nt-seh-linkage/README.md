# Hosted SEH Linkage Image

This freestanding x64 PE DLL contains Win64 call frames for invoking a C exception filter,
termination handler, or language handler. Each callback frame saves its dispatcher-context pointer;
filter and exception-handler frames share a private nested-exception handler, while finally and
unwind-handler frames share a private collided-unwind handler. The COFF assembler
emits `.pdata` and `.xdata` describing the 40-byte stack allocations and handler associations.
The image has no imports, entry point, or runtime state.

The callback wrappers take a dispatcher-context pointer in their final argument:

```c
int32_t SehCallFilter(int32_t (*filter)(void *, void *), void *exception_pointers,
                      void *establisher_frame, void *dispatcher_context);
void SehCallFinally(void (*finally)(unsigned char, void *), void *establisher_frame,
                    void *dispatcher_context);
```

Build and statically verify it with:

```sh
bash components/nt-seh-linkage/build.sh
```

The output is `.tmp/nt-seh-linkage/nt-seh-linkage.dll`. `seh-linkage-verify` parses it through
`nt-pe-loader`, maps it, admits its exception metadata through `nt-unwind`, and checks the exports
against their actual prologues and unwind records. An optional output directory is the script's
first argument; `CLANG` and `RUST_LLD` select the cross compiler and linker.

This is a **static metadata artifact**, not a live exception dispatcher. It is not staged into the
OS image or bound to native exports. Runtime acceptance requires the separate dispatcher, sealed
image mapping, and a compiled driver fixture proving a caught raise and `__finally` execution.
