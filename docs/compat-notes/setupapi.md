# User-mode device discovery (SetupAPI / CfgMgr32) — compatibility notes

The Win32 device-discovery surface a user program uses to enumerate device interfaces + resolve
their device paths (spec: NT User-Mode Device Discovery), backed by the Configuration Manager.

## nt-setupapi (implemented, Milestones 20.1-20.5)

- Error model (§7.1): `ConfigRet` (CR_SUCCESS/INVALID_POINTER/INVALID_FLAG/NO_SUCH_DEVINST/
  BUFFER_SMALL/…), Win32 error constants, `configret_to_win32_error`.
- Path mapping: `device_path` maps a CM kernel symbolic link `\??\…` to the Win32 `\\?\…` form (§13).
- CfgMgr32 (§9): `cm_get_device_interface_list_size` / `cm_get_device_interface_list` — the
  MULTI_SZ list of interface paths for a class GUID (present/enabled filter unless ALL_DEVICES;
  optional case-insensitive device-ID filter; empty list = a single NUL; CR_BUFFER_SMALL sizing;
  null-GUID → CR_INVALID_POINTER, unknown flags → CR_INVALID_FLAG).
- SetupAPI (§10-§11): an `HDEVINFO` handle table (`DevInfoSets`, generation-validated) —
  `get_class_devs` (requires DIGCF_DEVICEINTERFACE, snapshots matching interfaces),
  `enum_device_interfaces` (index → InterfaceElement / None past the end),
  `get_device_interface_detail` (the two-call sizing pattern: ERROR_INSUFFICIENT_BUFFER + required
  WCHARs, then the NUL-terminated path), `destroy_device_info_list` (stale handle rejected).
- 6 unit tests: enabled-only + ALL_DEVICES listing, empty=single-NUL, edge cases, device-ID
  filter, SetupAPI enumerate+two-call detail+destroy, NT→Win32 path mapping.
