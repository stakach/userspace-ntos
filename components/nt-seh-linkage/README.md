# Hosted SEH Linkage Image

This freestanding x64 PE DLL contains Win64 call frames for invoking a C exception filter,
termination handler, or language handler. Each callback frame saves its dispatcher-context pointer;
filter and exception-handler frames share a private nested-exception handler, while finally and
unwind-handler frames share a private collided-unwind handler. The COFF assembler
emits `.pdata` and `.xdata` describing the call frames and handler associations. The image has
no imports or DLL entry point. Its zero-initialized, read-only dispatch slot is reserved for an
instance-specific native raise dispatcher; it is not bound yet.

The callback wrappers take a dispatcher-context pointer in their final argument:

```c
int32_t SehCallFilter(int32_t (*filter)(void *, void *), void *exception_pointers,
                      void *establisher_frame, void *dispatcher_context);
void SehCallFinally(void (*finally)(unsigned char, void *), void *establisher_frame,
                    void *dispatcher_context);
void SehRaiseStatus(uint32_t status); /* unbound; traps without a dispatcher */
```

Build and statically verify it with:

```sh
bash components/nt-seh-linkage/build.sh
```

The output is `.tmp/nt-seh-linkage/nt-seh-linkage.dll`. `seh-linkage-verify` parses it through
`nt-pe-loader`, maps it, admits its exception metadata through `nt-unwind`, and checks the exports
against their actual prologues and unwind records. An optional output directory is the script's
first argument; `CLANG` and `RUST_LLD` select the cross compiler and linker.

The executive build stages the verified DLL in the OS image and maps it RX/RO_NX into each hosted
driver domain. The raise entry is still **unbound**: runtime acceptance requires an authenticated
retained dispatcher, context writeback and nonreturning restore, then a compiled driver fixture
proving a caught raise and `__finally` execution.
