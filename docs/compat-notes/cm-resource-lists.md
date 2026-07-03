# CM_RESOURCE_LIST — compatibility notes

The WDK `CM_RESOURCE_LIST` layout a PnP function driver reads from
`Parameters.StartDevice.AllocatedResourcesTranslated` during `IRP_MN_START_DEVICE`
(spec: NT PnP Manager, Milestone 12). Encoded by `nt-cm-resources`.

## Layout (implemented, Milestone 12.1 — `nt-cm-resources`)

- `#pragma pack(4)`: a `CM_PARTIAL_RESOURCE_DESCRIPTOR` is **20 bytes** (4-byte
  header + a 16-byte union; the interrupt variant `Level(4)+Vector(4)+Affinity(8)` is
  the largest). A one-memory + one-interrupt list is **60 bytes**.
- Offsets: `CM_RESOURCE_LIST.Count`@0; `CM_FULL_RESOURCE_DESCRIPTOR`
  (InterfaceType@4, BusNumber@8, PartialResourceList@12: Version@12, Revision@14,
  Count@16); Memory descriptor@20 (Type=3@20, Start:u64@24, Length:u32@32); Interrupt
  descriptor@40 (Type=2@40, Level@44, Vector@48, Affinity:u64@52).
- Resource types: Memory=3, Interrupt=2 (Port=1, Dma=4, DeviceSpecific=5,
  BusNumber=6). Interrupt flags: LevelSensitive=0, Latched=1.
- `build_memory_interrupt_list` encodes into a caller byte buffer (no allocation, no
  raw pointers — copyable straight into Driver Host memory);
  `decode_memory_interrupt_list` reads it back the way a WDK-compiled driver does.
  `Affinity` is a `u64` at a 4-aligned offset (pack(4)) — read unaligned on x86. 3
  tests (round-trip, WDK offsets, small-buffer rejection).
