# P2 — Storage + Filesystem + Real Registry

**Goal:** a real storage stack so the kernel reads **real data stores**: a
boot‑time disk (QEMU) → storage driver (isolated host) → partition/volume → a
real filesystem → registry hives + system files.

**Why:** the ReactOS boot chain reads its system volume and registry from disk;
this is where "real data stores" testing begins.

## Status: ~~not started~~ → **LARGELY DONE (2026-07-14)**

### Status (2026-07-14): LARGELY DONE — full disk→volume→FS→registry chain, end to end
The whole storage vertical shipped (PLAN §10 entries 2026-07-08):
- **Block device / storage driver (isolated):** the AHCI controller (00:3.0) is brought
  up and sector 0 read via a real ATA READ DMA EXT, then the whole stack (AHCI +
  sector read + FAT32 + file read) was moved OUT of the trusted executive into a
  **crash-contained storage host** (own CSpace/VSpace, granted only the AHCI BAR + DMA
  frame) with **VT-d-confined DMA** (kernel `ecaceef`, exec `639e356`/`4f2367c`/`d54ddd2`).
- **Filesystem:** a FAT32 reader (`fat_read_sector`/`fat_next`/`dir_find`/`fat_read_file`)
  parses the BPB, walks the root dir + cluster chains, and reads real files off the boot
  disk (BOOTBOOT/INITRD, and later SMSS.EXE / NTDLL.DLL / SYSTEM.DAT) (exec `4896dd0`).
- **Registry from real hives:** a real NT hive is read off the FAT32 FS and Config Manager
  `decode_image()`s it — `ControlSet001\Services\NtosTest\Answer = 42` reads back
  (exec `47c9dc9`, kernel `ae58471`). Separately, smss/csrss read+enumerate the **real
  204 KB ReactOS SYSTEM hive** via `nt-hive-regf` (::ROSSYS.HIV) in P3.
The live System32 file-existence authority is `nt-fs` (MemFs). **What's left / PARTIAL:**
the disk is a FAT32 superfloppy so MBR/GPT **partition/volume** objects (item 7) are N/A
here; hosting the real ReactOS `fastfat.sys` (vs our reader) and full cache-manager
integration over the volume remain as later fidelity upgrades, not blockers.

## Background to reuse
- `nt-fs` (NT File Object + path/mount resolver + MemFs + `Zw*` file APIs),
  `nt-cache-manager` (SharedCacheMap), `nt-io-*` (device/driver/file/IRP +
  dispatch), `nt-hive-core` (cell arena / hive image+log), `nt-config-store`
  (snapshot + append-only journal), `nt-config-manager` (registry authority).
- `docs/architecture/filesystem.md`, `hive-manager.md`, `cache-manager.md`,
  `io-manager.md`.

## Tasks
- [x] **Block device abstraction:** AHCI block read (LBA → DMA frame) backs the FS;
      the storage host owns it. (exec `639e356`)
- [x] **Storage driver (isolated host):** real AHCI bring-up + ATA READ DMA EXT in a
      **crash-contained storage host** (own CSpace/VSpace, VT-d-confined DMA), option
      (c)+ toward (a). (exec `4f2367c`, `d54ddd2`)
- [~] **Partition + volume:** BPB parsed; MBR/GPT partition/volume objects **N/A**
      on this FAT32 superfloppy — deferred until a partitioned disk is needed.
- [x] **Real filesystem:** a FAT32 reader over the block device reads real files
      (option (b)); hosting `fastfat.sys` (option (a)) remains a fidelity upgrade.
      (exec `4896dd0`)
- [~] **Cache integration:** `nt-cache-manager` exists + is unit-proven; wiring file
      reads through it over the live volume is a later upgrade.
- [x] **Registry from real hives:** a real NT hive read off the FS + `decode_image()`d
      by Config Manager (`Answer=42`); smss/csrss read the real ReactOS SYSTEM hive via
      `nt-hive-regf`. (exec `47c9dc9`, kernel `ae58471`)

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
