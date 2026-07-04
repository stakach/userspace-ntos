# NT File Object + File System Runtime — compatibility notes

The NT filesystem layer (spec: NT File Object + File System Runtime). An in-memory volume (MemFs)
under the Zw* native file APIs, with a real hive I/O provider persisting through those APIs — the
storage seam the M21 Hive Manager reserved.

## nt-fs (implemented, Milestones 22.1-22.7)

- Path + Mount Manager (§7, §13): `MountManager` resolves an NT path → (volume device,
  volume-relative path) by longest-prefix match, with the required v0.1 mounts
  (`\SystemRoot` → `\Device\MemFsVolume0\Windows`, `\??\C:` → `\Device\MemFsVolume0`,
  `\DosDevices\C:` alias). Separator normalization (`/`→`\`, collapse runs).
- MemFs (§12): an in-memory `NtFileSystemRuntime` — node tree + create-disposition semantics
  (FILE_OPEN/CREATE/OPEN_IF/OVERWRITE[_IF]/SUPERSEDE → FILE_OPENED/CREATED/OVERWRITTEN/…),
  directory vs file intent, a `with_fixture` tree (`\Windows\System32\Config\{SYSTEM,…}` + `\Temp`).
- Zw* file APIs (§8-§9) on `FileSystem`: `zw_create_file` (resolve + disposition → handle +
  Information), `zw_read_file`/`zw_write_file` (explicit or advancing FILE_OBJECT offset,
  STATUS_END_OF_FILE at EOF, directory ops → STATUS_INVALID_DEVICE_REQUEST),
  `zw_flush_buffers_file`, `zw_query_standard_information` (FileStandardInformation),
  `zw_close` (cleanup-before-close). Handle table of file objects.
- `NtFileHiveIoProvider` (§14.1): the real hive I/O provider — image at the hive path, log at
  `<path>.LOG`, both via ZwCreateFile/ReadFile/WriteFile/FlushBuffersFile/Close. Implements
  `nt_hive_core::HiveIoProvider`, so a `HiveManager` persists through the filesystem.
- 5 unit tests incl. mount resolver, create dispositions, read/write offset + EOF, directory
  rejects data ops, and the §14.2 acceptance: HiveManager writes/reads a hive image + log through
  the Zw* APIs on MemFs and survives a restart (image + replayed log).
