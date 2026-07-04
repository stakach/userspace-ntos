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
