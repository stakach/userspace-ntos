# Native Mup Provider Fixture

`build.sh` prepares a PE32+ WDM driver without CRT or private executive imports. It does not stage or run the driver. `DriverEntry` creates `\\Device\\NtosUncProbe` and starts a System worker. The worker opens `\\Device\\Mup` and sends ReactOS's `FSCTL_MUP_REGISTER_PROVIDER` with the provider device name. It retains the Mup handle until unload. Mup must open the provider device through ordinary object/file routing before it can register it.

After registration, the worker opens `\\Device\\Mup\\ntos-probe\\share` through the real ZwCreateFile path. This triggers Mup's provider query and rerouted CREATE. For `IOCTL_REDIR_QUERY_PATH`, the fixture accepts only the `\\ntos-probe` server prefix with a retained security context, returns its UTF-16 byte length in `QUERY_PATH_RESPONSE`, and completes the actual IRP. It maintains a bounded FileObject-backed namespace entry for `\\ntos-probe\\share`, validates one buffered WRITE through Mup, and counts CREATE/CLEANUP/CLOSE. Other names and write bytes are rejected. `MupProviderEvidence` is exported for gate inspection; `DbgPrint` emits registration, accepted-query, write, and probe records.

The native gate must load Mup and this fixture and check the accepted query, Mup's query completion, the rerouted FileObject's CREATE/CLEANUP/CLOSE sequence, and the exact WRITE bytes and Information. A successful registration log alone is not forwarding proof. The fixture also exposes a separate `\ntos-probe\section` file with a 4096-byte EOF and stable internal index. It is not a general filesystem.

Pending success operations use initialized auto-reset synchronization Events, not
worker polling. Dispatch marks the stack location `SL_PENDING_RETURNED` before
publishing the retained IRP with a release compare-exchange, then signals its Event.
The worker waits and takes that exact IRP with an acquire exchange before completion.
An Event signaled before the wait remains signaled, so publication cannot lose its
wakeup. A rejected publication restores the stack flag and does not signal.

## Controlled Terminal Errors

The test-only `\ntos-probe\terminal-failure` file accepts separate READ, FLUSH and
`FileStandardInformation` QUERY IRPs. Each dispatch marks the actual IRP pending,
retains it for the provider worker, and completes it after an explicit release and delay with
`STATUS_IO_DEVICE_ERROR` (`0xc0000185`) and Information zero. READ and QUERY poison
their provider buffers before completing. The source waits for the real completion
Event and requires the exact error IOSB, zero Information, and unchanged output and
guard bytes. This matches ReactOS `ntoskrnl/io/iomgr/irp.c` buffered completion:
error-severity statuses do not copy SystemBuffer back to UserBuffer.

Before release, the source requires a zero-time Event wait to return TIMEOUT and
the stack IOSB and output to remain untouched. It then sends a real two-byte
buffered WRITE (`0xa7`, operation index) on the same File. The provider validates
the exact pending owner and permits one release per operation; duplicate releases
are rejected. These three control WRITEs are additional genuine IRPs, not output
or completion substitutes.

Each pending operation records its exact File context pointer, monotonic generation
and per-File CLEANUP/CLOSE counters. Completion requires that identity and counters
to remain unchanged; unrelated File activity cannot affect this decision. Separate
failure counters leave the existing success counters unchanged. Only after all
three completions does the source close its handle while retaining the File pointer,
then release that pointer. A real FileInternalInformation IRP first retrieves the
provider's File context generation. Source and provider receipts carry that generation
and their own File pointers; distinct virtual addresses are not treated as identical
across VSpaces. The strict parser requires pending, unchanged precompletion visibility,
explicit release, provider terminal intent, actual source result, and source verification
in causal order for all three operations. Provider intent is printed before
IofCompleteRequest and is not a completion acknowledgement.

Source handle-close and pointer-release intent/return receipts bracket real ZwClose
and ObfDereferenceObject calls. The parser requires actual successful handle close,
one exact provider CLEANUP after handle-close intent, and one exact CLOSE after
pointer-release intent; CLEANUP and CLOSE may arrive after those calls return.
Malformed, duplicate, stale-generation, early-CLOSE, or failure records reject the
proof. The runner invokes this parser in addition to the existing successful IRP gates.

Standalone log verification (does not build or boot):

```sh
python3 tests/native/mup_provider/verify_log.py --verify-log .tmp/mup-provider.log
```

Parser host regressions:

```sh
python3 -m unittest discover -s tests/native/mup_provider -p test_verify_log.py
```

These checks exercise retained ownership through genuine delayed terminal errors.
They do not prove uncertain native-effect quarantine, stale protocol replay denial,
or absence of every canonical reference leak. Those require exact canonical
completion/ACK/retirement observations or separate admitted failure injection;
withholding a completion alone is not such proof.

The `mup-provider` image profile stages this fixture and a separate `read_forward.sys` source driver. Run `tests/native/mup_provider/run_kernel_only.sh` for a bounded native gate. It builds the real Mup and both fixture binaries, defers win32k initialization, leaves SMSS suspended, and runs the genuine native driver service loop. The READ source opens the provider device, references a consumer File projection, allocates a buffered IRP, and calls `IofCallDriver` into the distinct provider domain. Its `UserBuffer` and `UserIosb` must contain the provider's exact 10-byte result after completion. On that same handle it also calls `ZwQueryInformationFile(FileStandardInformation)` and explicit-offset `ZwReadFile`, checking their IOSBs and output bytes. The source then opens `\Device\Mup\ntos-probe\section` and sends separate buffered IRPs for pending `FileStandardInformation` (class 5), immediate `FileInternalInformation` (class 6), and one pending 4096-byte READ at offset zero. It checks the exact return statuses, Information lengths, metadata, and all page bytes. These are provider-level IRP proofs, not `NtCreateSection`, `NtMapViewOfSection`, or a live page fault. The kernel-only gate has no hosted Section caller, and the Mup redirector is not registered as a Section mount. The runner requires an accepted Mup query with a security context (which proves provider registration), exact WRITE and READ completion, successful rerouted CREATE/CLEANUP, and final CLOSE. Serial DbgPrint lines may interleave, so the registration status line alone is not a gate. The current hosted ZwWriteFile and ZwReadFile routes support explicit-offset buffered I/O; synchronous file-position, append, Event, and APC modes are rejected pending their complete NT semantics. Driver ZwQueryInformationFile currently admits FileStandardInformation only; the class-6 check uses a direct IRP. Production images retain strict win32k import admission and resume SMSS. Both fixture workers also avoid a separate startup-pump limitation: a retained `ZwCreateFile` issued synchronously inside `DriverEntry` cannot be redriven until that pump yields; issue #81 tracks that contract.
