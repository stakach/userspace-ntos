# Hosted SEH Linkage Image

This freestanding x64 PE DLL contains Win64 call frames for invoking a C exception filter,
termination handler, or language handler. Each callback frame saves its dispatcher-context pointer;
filter and exception-handler frames share a private nested-exception handler, while finally and
unwind-handler frames share a private collided-unwind handler. The COFF assembler
emits `.pdata` and `.xdata` describing the call frames and handler associations. The image has
no imports or DLL entry point. Its two zero-initialized, read-only dispatch slots are bound to
instance-specific native raise and unwind dispatchers after image admission.

The callback wrappers take a dispatcher-context pointer in their final argument:

```c
int32_t SehCallFilter(int32_t (*filter)(void *, void *), void *exception_pointers,
                      void *establisher_frame, void *dispatcher_context);
void SehCallFinally(void (*finally)(unsigned char, void *), void *establisher_frame,
                    void *dispatcher_context);
void SehRaiseStatus(uint32_t status); /* traps without a dispatcher */
void SehUnwindEx(void *target_frame, void *target_ip, void *exception_record,
                 void *return_value, void *context_record, void *history_table);
void SehResumeContext(void *validated_raw_context); /* nonreturning */
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
driver domain. `SehUnwindEx` captures a full caller context on its own stack, copies it to the
caller's aligned `ContextRecord`, and passes a fixed sidecar to its nonreturning dispatch slot.
The sidecar contains the six original Win64 arguments, captured context VA and entry RSP. The
native dispatcher must authenticate that stack frame, the captured context and all target values
before any unwind or restore.
The restore entry accepts only an owned, prevalidated same-thread context; it does not validate
target stack, instruction address, flags, MXCSR, or selectors by itself.
