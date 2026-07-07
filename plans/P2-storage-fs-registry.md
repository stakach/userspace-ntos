# P2 — Storage + Filesystem + Real Registry

**Goal:** a real storage stack so the kernel reads **real data stores**: a
boot‑time disk (QEMU) → storage driver (isolated host) → partition/volume → a
real filesystem → registry hives + system files.

**Why:** the ReactOS boot chain reads its system volume and registry from disk;
this is where "real data stores" testing begins.

## Status: not started

## Background to reuse
- `nt-fs` (NT File Object + path/mount resolver + MemFs + `Zw*` file APIs),
  `nt-cache-manager` (SharedCacheMap), `nt-io-*` (device/driver/file/IRP +
  dispatch), `nt-hive-core` (cell arena / hive image+log), `nt-config-store`
  (snapshot + append-only journal), `nt-config-manager` (registry authority).
- `docs/architecture/filesystem.md`, `hive-manager.md`, `cache-manager.md`,
  `io-manager.md`.

## Tasks
- [ ] **Block device abstraction:** an Io-level block device object (read/write by
      LBA) that a storage driver host backs. Define its `nt-io-abi` opcodes.
- [ ] **Storage driver (isolated host):** AHCI or IDE against the QEMU disk.
      Options: (a) host ReactOS `uniata`/`atapi`/`storahci`; (b) a KMDF storage
      driver built in `ntdriver`; (c) a native Rust block backend for the FS while
      driver hosting matures. Prefer a real driver to validate the I/O path.
- [ ] **Partition + volume:** parse the MBR/GPT + BPB; present volume device
      objects (`\Device\HarddiskVolume1`), mount points, `\SystemRoot`.
- [ ] **Real filesystem:** read a real **FAT** volume. Options: (a) host ReactOS
      `fastfat.sys` (validates a real FS driver over our Io + Cc); (b) extend
      `nt-fs` with a FAT reader over the block device. Do (a) if the driver-host
      FS path is ready, else (b) first and (a) as a milestone.
- [ ] **Cache integration:** file reads go through `nt-cache-manager` over the
      volume; verify cached vs. uncached reads.
- [ ] **Registry from real hives:** point `nt-config-store` at hive files on the
      volume (`\SystemRoot\System32\config\SYSTEM`, `SOFTWARE`); load them via
      `nt-hive-core` into `nt-config-manager`. Read real keys/values.

## Real data to test against
- A **ReactOS‑produced FAT image** (fixture) with a known directory tree +
  `SYSTEM`/`SOFTWARE` hives — the ground truth for Io/Fs/Cc/Cm.
- Cross-check parsed hive contents against a host-side reader.

## Exit criteria
- Boot QEMU with a disk holding a ReactOS FAT volume; the executive brings up the
  storage host + FS; `NtCreateFile("\SystemRoot\…")` reads real file bytes; the
  `SYSTEM` hive loads into Cm and a known value (e.g. a service's `Start`) reads
  back correctly — verified in QEMU.

## E2E test
`e2e-storage`: mount the fixture FAT image → open + read a file → load the SYSTEM
hive → query a registry value → assert against known-good values. Composed kernel
build gated by `--features e2e-storage`.

## Notes / findings
_(append as work proceeds)_
