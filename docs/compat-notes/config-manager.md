# Configuration Manager (registry) — compatibility notes

The NT Configuration Manager: the isolated registry/configuration authority drivers read via
Zw*/WdfRegistry* and the PnP/interface APIs (spec: NT Configuration Manager Service). Owns
metadata only — no handles, IRPs, or driver pointers.

## Registry core (implemented, Milestones 17.1-17.3/17.6 — `nt-config-manager`)

- `registry::Registry`: a case-insensitive, case-preserving key/value tree.
  - Keys: `create_key`/`open_key` by NT path (`\Registry\Machine\…`, creates intermediates),
    `create_subkey`/`open_subkey`, `key_path`, `enum_subkeys`, `delete_key` (recursive guard).
    Required root keys created at boot (`…\Services`, `…\Enum`, `…\Control\DeviceClasses`).
  - Values: REG_* types (None/Sz/ExpandSz/Binary/Dword/MultiSz/Qword), `set_value`/`query_value`
    + `set_dword`/`set_qword`/`set_string` + `query_dword`/`query_qword`/`query_string`,
    `delete_value`, `enum_values`. Strings stored as UTF-16LE + NUL (spec §8.4).
- `ConfigManager`: the registry + higher-level records.
  - Services (§9): `register_service` (→ `Services\<Name>` + `Parameters` + ImagePath/Start/
    ErrorControl/Class), `service_key_path` (DriverEntry RegistryPath, case-preserved),
    `service_parameters_key`, `set_service_parameter` (fixture loading).
  - Devnodes (§10): `register_devnode` (→ `Enum\<InstanceId>` + Service/PdoName),
    `devnodes_for_service` (PnP enumeration input).
  - Device interfaces (§11): `register_interface` (→ `Control\DeviceClasses\<Guid>` + symbolic
    link `\??\<guid>#<instance>#<ref>`), `set_interface_state`, `interfaces_by_guid` (enabled-only).
- 8 unit tests incl. the §21 fixture (service Parameters Answer=42/Greeting, devnode enumeration,
  interface enable/disable). Driver-facing Zw*/WdfRegistry* exports + isolated SURT service:
  pending a registry-using driver artifact.

## Configuration Manager component (implemented, Milestones 17.1-17.2 — `configuration-manager`)

`components/configuration-manager` boots the registry authority bare-metal on seL4 (v0.1
in-process model, spec §5.1/§20.1), seeds the §21 fixture, and verifies the registry the way a
driver + the PnP/interface managers would. **9/9 checks pass in QEMU.**

- root keys present; service registration + DriverEntry RegistryPath (case-preserved);
  query Answer=42 + Greeting="hello registry"; driver writes SeenByDriver back; PnP enumerates
  the devnode by service; devnode Service value; interface registered+enabled; disable hides it.
- Driver-facing Zw*/WdfRegistry* exports + the isolated SURT service boundary await a
  registry-using driver artifact (`KmdfInterfaceRegistryTest.sys`).

## WDF runtime registry/interface/property (implemented, M18 host support — `nt-wdf-runtime`)

`WdfRuntime` gains a `ConfigManager` + the KMDF registry/interface/property bridge (spec: NT
Device Interface / Registry / Property, §8-§11):
- `config()`/`config_mut()` (the Driver Host seeds fixtures), `set_driver_service`,
  `link_device_devnode`.
- Registry (§10): `open_driver_parameters_key` (WdfDriverOpenParametersRegistryKey → WDFKEY),
  `open_device_registry_key` (DEVICE=devnode Enum / DRIVER=service key),
  `registry_query_ulong`/`registry_assign_ulong` (STATUS_OBJECT_NAME_NOT_FOUND /
  STATUS_OBJECT_TYPE_MISMATCH), `registry_query_string`/`registry_assign_string`.
  WDFKEY/WDFSTRING are WDF objects wrapping a RegistryKeyId / String; pruned on delete.
- Device interface (§8): `create_device_interface` (WdfDeviceCreateDeviceInterface),
  `set_device_interface_state`, `device_interface_link`.
- Property (§11): `assign_device_property` (WdfDeviceAssignProperty, DEVPROPKEY),
  `query_device_property`, `set/query_legacy_device_property` (FriendlyName, …).

## Driver Host registry/interface/property integration (implemented, M18 — `driver-host-direg`)

`components/driver-host-direg` loads the real `KmdfInterfaceRegistryTest.sys` and runs it
against the in-process `WdfRuntime` + Configuration Manager. **20/20 checks pass in QEMU, no
#GP.** The Driver Host seeds the §21 fixture (service Parameters Answer=42 / Greeting="hello
registry" + a devnode) then the real driver reads/writes it.

- 14 new WDF thunks: WdfDriverOpenParametersRegistryKey / WdfDeviceOpenRegistryKey,
  WdfRegistryQuery/AssignULong + Query/AssignString + Close, WdfStringCreate /
  WdfStringGetUnicodeString (with a UNICODE_STRING projection), WdfDeviceCreateDeviceInterface /
  RetrieveDeviceInterfaceString, WdfDeviceAssignProperty, WdfDeviceInitAssignName. Helpers
  read a driver UNICODE_STRING + format a 16-byte GUID to `{…}`.
- EvtDeviceAdd runs the real registry flow: reads Answer=42 + Greeting, writes SeenByDriver=1 +
  DeviceSeenByDriver=1 + RuntimeValue=0, creates the interface (auto-enabled — the driver never
  calls SetDeviceInterfaceState), assigns FriendlyName + a custom DEVPROPKEY (=Answer/UINT32).
- IOCTLs: PING (0x4946_4B4D "MKFI"), GET_CONFIG (Answer=42/SeenByDriver=1/DeviceSeenByDriver=1),
  GET_GREETING ("hello registry") + GET_INTERFACE_STRING (require a 0x20C output buffer),
  SET/GET_REG_DWORD round-trip, ECHO. REMOVE disables the interface + deletes the device
  (WDFKEY/WDFSTRING are driver-scoped, so they outlive the device — correct KMDF behaviour).

Milestone 18 complete: nt-config-manager property store + the WdfRuntime registry/interface/
property bridge (17 host tests) + this component (20/20 QEMU) — a real KMDF driver on the
Configuration Manager registry.

## Persistence / hive store (implemented, Milestones 19.1-19.6 — `nt-config-store`)

Durable storage for the Configuration Manager (spec: NT Configuration Manager Persistence).
Explicit TLV wire format (never Rust struct layout), little-endian, UTF-16LE, CRC-32C; every
read bounds-checked (safe to parse from untrusted bytes).

- `ConfigStore` trait + backends: `MemoryStore` (in-memory / seL4 in-process v0.1), `FaultStore`
  (crash-consistency injection). Snapshot read/write-atomic, journal read/append/truncate,
  fsync, lock.
- **Snapshot** (spec §9): a `USNTCM\0\1` header {schema, generation, base_journal_sequence,
  record_count, payload_len, payload_crc32c, header_crc32c} + TLV records (RegistryKey /
  Service / Devnode / Interface / LegacyProperty / DevProp). `snapshot::encode(cm,gen,base)` /
  `parse_header` (validates both CRCs + schema) / `decode` → a fresh `ConfigManager`.
- **Journal** (spec §10): a `CJR1` per-record header {op, sequence, txn, payload_crc, record_crc}
  + payload. Ops REG_CREATE_KEY / SET_VALUE / DELETE_VALUE. `journal::replay` applies records with
  sequence > base (idempotent, spec §10.5) and stops cleanly at a torn/invalid trailing record
  (spec §21.2).
- **`Persistence<S>` engine** (spec §11, §18-§20): `boot` (load+validate snapshot → replay journal),
  `mutate` (append record + fsync in Strict + apply), `compact` (fresh snapshot + truncate journal).
- 7 unit tests: snapshot round-trip, checksum/magic/truncation rejection, boot-replays-journal,
  compaction-truncates-journal, idempotent replay, torn-record ignored, snapshot-write-fault
  preserves the previous snapshot.
