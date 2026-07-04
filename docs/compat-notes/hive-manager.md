# Hive Manager + Hive I/O Provider — compatibility notes

The registry expressed as NT hives (spec: NT Hive Manager + Configuration Manager Hive I/O
Provider). A hive is a cell arena persisted through a versioned image + append-only log behind a
pluggable I/O provider.

## nt-hive-core (implemented, Milestones 21.1-21.8)

- Cell model (§6): `Hive` = a cell arena of key/value cells addressed by `CellId` (never a raw
  pointer). Registry ops navigate by relative path: `create_key`/`open_key`/`create_subkey`,
  `set_value`/`query_value`/`query_dword`, `enum_subkeys`/`enum_values`, `key_path`, dirty
  tracking (§13.1). Case-insensitive lookup.
- Mount table + resolver (§6.2, §8): `HiveMountTable.mount`/`resolve` (longest-root-wins) maps a
  full NT path → (HiveId, relative path), applying the `CurrentControlSet` → `ControlSet001`
  alias (`apply_ccs_alias`). SYSTEM_HIVE_PATH is the v0.1 required hive.
- Image codec (§11): `UNTHIVE1` header {schema, hive_kind, generation, sequence, root_cell,
  record_count, payload_len, payload+header CRC-32C} + KeyCell/ValueCell TLV records
  (subkey/value links reconstructed from parent IDs). `encode_image`/`decode_image` round-trips a
  hive; both CRCs + schema validated.
- Log codec (§12): `HLR1` per-record header + payload; ops CreateKey/SetValue/DeleteValue.
  `encode_log_record`/`replay_log` (sequence > base, idempotent, stops at a torn/invalid tail).
- I/O providers (§10): `HiveIoProvider` trait + `MemoryHiveIoProvider` (RAM),
  `FaultInjectionHiveIoProvider` (fail Nth image write; previous image preserved),
  `NtFileHiveIoProvider` (compiled but `NotSupported` until a filesystem exists, §10.6).
- `HiveManager` engine (§13, §16): `boot` (load+validate image → replay log), `mutate` (append
  log record + flush + apply), `flush` (checkpoint: fresh image + truncate log + clear dirty).
- 8 unit tests incl. create/open/set/query, CCS resolver (Services through CurrentControlSet),
  image round-trip + checksum/magic rejection, manager boot/mutate/flush survives restart, log
  replay idempotent + torn, image-write fault preserves previous, NtFile NotSupported.
