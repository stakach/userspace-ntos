# Native Source IRP Fixture

The target is a freestanding AMD64 WDM driver. Its ordinary `DriverEntry` creates a buffered
device and a completion worker. It accepts fileless READ/WRITE and four IOCTL transfer methods
only when their lengths, offsets, input bytes, MDL layout and File fields satisfy the fixture
contract. It writes bounded output, sets the real IOSB and calls `IofCompleteRequest`.
No kernel route recognizes the fixture's image or device name.

The caller PE exports `SourceIrpProbe(DEVICE_OBJECT *device, uint32_t pending)` and
`SourceIrpEvidence`. The function must execute inside an authenticated win32k dispatch activation
with the actual win32k ntoskrnl import bindings. The integration owner passes an exact retained
canonical device projection; the source neither opens a name nor constructs an executive request.
Each invocation uses the real builders and `IofCallDriver`, waits on its native Event, checks the
IOSB and bytes, and checks that output canaries beyond `Information` are unchanged. METHOD_IN_DIRECT
requires the target to read the seeded second buffer without modifying it.

Mode 0 completes inline. Mode 1 queues each actual IRP to the target's System worker using a
single-slot atomic mailbox and a synchronization Event. The source expects `STATUS_PENDING` and
retains its stack Event, IOSB and buffers until completion. READ/WRITE mode is offset 0/1; IOCTL
function numbers are 0x880/0x881, with all four method bits tested independently. ABI layout
assertions in `contract.h` follow ReactOS's AMD64 WDM declarations.

`SourceIrpEvidence` contains `uint32_t attempts[2][6]` at offset 0, `completed[2][6]` at offset 48,
and `failed` at offset 96. Offset 104 starts `observations[2][6]`: each 24-byte record contains
actual `int32_t call, wait, iosb_status`, `uint32_t bytes_valid`, and `uint64_t information` at
offset 16. Total size is 392 bytes. The root observer reads the retained admitted data export
after the native function returns and prints these actual values through canonical serial;
win32k's limited DbgPrint formatter is not the evidence parser. Operations are READ, WRITE,
BUFFERED, IN_DIRECT, OUT_DIRECT, NEITHER. Exported
target evidence has `uint32_t completed[2][6]` followed by `rejected` (52 bytes). Native logs
provide exact per-operation IOSB/byte assertions; kernel milestone counters independently prove
origin commit, canonical commit and retirement. Completion counters increment only after the
actual IOSB, byte and canary assertions succeed.

Build with `bash tests/native/source_irp/build.sh`; this prepares files only. The source has no
`DriverEntry` and must never be launched as a filesystem driver. `source-irp-integration` image
and executive feature select the ordinary target service and probe metadata. Production hives,
image staging and executive features omit the fixture. The import-only trap DLL used when
`llvm-dlltool` is unavailable remains in the build directory and is never staged.

Run `bash tests/native/source_irp/run.sh` for the isolated profile. The runner requires all twelve
native operations, all source commit/retirement milestones and all four IOCTL method counters,
alongside the normal desktop gate. Boot is limited to one hour by `run.sh`; the source uses an
unbounded NT wait rather than returning with possibly live stack storage after a timeout.
