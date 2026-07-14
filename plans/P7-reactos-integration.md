# P7 — ReactOS Integration & Image Build — STUB

**Goal:** boot a **real ReactOS user space** on our kernel and produce a bootable
disk image (BOOTBOOT + rust-micro + `ntos-executive` + ReactOS user-space volume).
The **P7 foundation** (this doc's active work) = move binary loading from a curated
STAGED SUBSET (each binary at a flat `::NAME` on the disk, read into a fixed buffer)
to loading ANY ReactOS binary **BY PATH** from a real FS holding the full `\reactos`
install tree.

## Status: **FOUNDATION — FS MIGRATION LANDED (2026-07-14)** — the whole stack loads from the real FS by path

### P7-A DONE (green, 142/142, desktop 0x003a6ea5, `./run.sh` SUCCESS): sub-steps A+B+C
The storage host reads EVERY ReactOS binary BY PATH from the full `\reactos` tree on a 256 MiB
FAT32 superfloppy; the flat `::NAME` staging is retired.
- **A — full-FS image** (rust-micro `6a4fdd7`): `fetch_reactos.sh` extracts the complete `reactos/`
  tree (171 MiB / 1011 files, `.fulltree-ok` marker); `make_image.sh` grew the superfloppy 64→256
  MiB + `mcopy -s`'s the whole tree to `::reactos`. BOOTBOOT + the LBA48 AHCI reader handle it.
- **B — LFN in dir_find** (executive `25f07c9`): `dir_find_lfn` reassembles VFAT long names so
  `kernel32_vista.dll`/`advapi32_vista.dll`/… resolve by real name. **Load-bearing collision fix:**
  the 8.3 fallback is gated on `fits_83` — a long target truncates via `name_to_83`
  (`kernel32_vista.dll`→`KERNEL32DLL`) and would falsely match `kernel32.dll` (2.7 MB > the 64 KB
  vista slot → read skipped → csrss vista forwarder breaks → no winlogon/desktop). Long names match
  ONLY via LFN. (Caught by the gate: 8 regressions incl. the desktop; fixed before commit.)
- **C — source everything by path + retire flat staging** (executive `25f07c9` + rust-micro
  `7122b67`): `storage_probe` reads all 31 binaries via `open_sys32`/`fat_open_path`; `make_image.sh`
  no longer stages flat `::NAME` (only `::SYSTEM.DAT` synthetic hive + `::IMPORTS.BIN` remain flat —
  both build-generated, non-tree). New spec **`exec_full_stack_from_fs`** (verdict 0x200 = 31 hits /
  0 fallbacks). `STAGE_FLAT_REACTOS=1` re-stages the flat copies for A/B debugging.

**REMAINING (P7-A completion — the on-demand generalization; DEFERRED for review):** the ~15 fixed
dual-mapped buffers + the name-scoped `NtOpenFile`/`NtQueryAttributesFile`/`NtCreateSection` fakes
still exist — the host fills the buffers from FS-by-path reads AT BOOT, and the executive PE-parses
each at a hardcoded offset. Retiring the BUFFERS means resolving `\SystemRoot\system32\X` at
NtOpenFile TIME → `fat_open_path` → on-demand read → PE-parse. The mapping agent confirmed this is
feasible WITHOUT a new IPC channel (the executive already owns the AHCI BAR cap; needs to map the
DMA frame into its own VSpace + keep a `Fat32` handle post-boot + call the FS fns from the fake).
This removes the 4-place add-a-binary contract — the real unlock for P5 (add services.exe/lsass by
path, no new buffer). Deep refactor of the delicate loader — **hold for review before proceeding.**

### P7-A history / audit (first increment)

### P7-A: FS-backed-by-path loading (in progress)

**AUDIT (done, code-grounded):**
- **Staged-load path today** = a one-shot batch, NOT a by-path FS. An isolated
  `storage-host` component (`storage_host.rs` + `storage_probe` in
  `components/ntos-executive/src/main.rs:10143`) reads a **hardcoded list of ~35
  well-known 8.3 filenames** off the FAT32 root into ~15 fixed dual-mapped buffers
  (`FILEBUF`/`SRVBUF`/`WIN32BUF`/`WIN32KBUF`/`WINLOGONBUF`/`NTDLLBUF`/`HIVEBUF`/NLS…,
  consts `main.rs:374–473`), publishes each byte-count through a shared mailbox frame
  (`STORAGE_SHARED`), signals **one** notification, then `park()`s. The executive
  PE-parses each buffer once at a hardcoded offset (`service_sec_image`, `main.rs:5428`)
  and answers the hosted loaders' `NtOpenFile`/`NtQueryAttributesFile`/`NtCreateSection`
  with **name-substring fakes** (`"csrss"`/`"winlogon"`/`"system32"`; `main.rs:4739`,
  `:4806`, `:5020`) backed by a compile-time `SYSTEM32_FILES` table (`main.rs:3003`)
  seeded into a real `nt-fs` MemFs (the System32 **existence** authority) + a
  `nt-dll-registry` base/geometry table. **The seam** = the fixed
  `dir_find`+`fat_read_file` calls in `storage_probe` (name→bytes) bound to the
  `dll_pes`/`dll_buf_va`/`STORAGE_SHARED`-offset tables in `service_sec_image`
  (bytes→parsed image).
- **P2 FS primitives** (all in `main.rs`): `ahci_read_sector` (:9972, any LBA),
  `fat_read_sector`/`fat_next`/`dir_find`/`fat_read_file` (:10053–10117). Capable of
  arbitrary-LBA reads, cluster-chain following, and nested-directory navigation
  (`dir_find` on any cluster) — but **8.3 names only** (LFN entries skipped) and the
  only multi-level walk was hand-inlined for `BOOTBOOT/INITRD` (depth 2). **Gaps to
  by-path:** a path-string→components walker, LFN reassembly (for names without clean
  8.3 aliases), offset/streaming reads, and a live request channel (the host↔exec
  channel is one-shot — one `dma_paddr` in, fixed size slots out).
- **ISO / sizing:** `fetch_reactos.sh` pulls a pinned GPL x64 livecd `.7z` (~29 MiB) →
  ISO (176 MiB) and `bsdtar`-extracts ~35 named files (~12 MiB) to `.tmp/reactos/ros-*`.
  **Full `\reactos` tree = 171.3 MiB / 1011 files** (`system32/` 146 MiB incl.
  `drivers/` 12.8 MiB + `config/` hives 0.8 MiB; `Fonts/` 13.5 MiB). Current disk =
  **64 MiB FAT32 superfloppy** (`dd bs=1M count=64` + `mkfs.vfat -F 32`, no partition
  table — the host reads FAT32 from offset 0). Full tree needs the image to grow to
  **~256 MiB** (`count=256`; superfloppy = no partition/alignment changes).

**FIRST INCREMENT (done, gate green 141/141):**
- `make_image.sh` (rust-micro `815adb4`): also stages ntdll at its real path
  `::reactos/system32/ntdll.dll` (verified: mcopy writes uppercased 8.3 short entries
  `REACTOS`/`SYSTEM32`/`NTDLL   DLL` alongside LFN — `dir_find` matches the short entry).
- Executive: new `name_to_83` + `fat_open_path(fs, path)` path-walker (splits on `\`/`/`,
  8.3-per-component `dir_find` from root, dir-attr checks) in `main.rs`; `storage_probe`
  now resolves ntdll from `\reactos\system32\ntdll.dll` BY PATH (verdict bit `0x100`),
  falling back to the flat `::NTDLL.DLL` so boot stays green. **New counted spec
  `exec_ntdll_loaded_from_fs_by_path`.** Bytes are identical, so the whole boot is
  unchanged; desktop still paints `0x003a6ea5`.

**DESIGN for the bulk (awaiting review before migration):**
- **Image:** extract the full `\reactos` tree (`bsdtar -xf ISO reactos/`) → a 256 MiB
  FAT32 superfloppy via `mcopy -s .tmp/reactos/reactos ::` (recursive, preserves the
  tree). Pick FAT32-image over reading ISO9660 directly: the storage host already reads
  FAT32, ISO9660 would be a second reader; superfloppy avoids partition-table work.
  Trade-off = +171 MiB `.tmp` + disk build time (boot runtime barely affected — FAT
  reads are on-demand). LFN support in `dir_find` needed for names without clean 8.3
  (e.g. `kernelbase.dll`).
- **FS-backed loader seam:** generalize `fat_open_path` into a path→bytes read the
  executive drives on demand, replacing the four-place staged contract
  (`SYSTEM32_FILES` seed + `dll_buf_va`/offset tables + `dir_find` line). Resolve
  `\SystemRoot\system32\X` / `\??\C:\...` through the DOS-device map → FS; keep the
  proven staged set during migration (hybrid), then retire the buffers file-by-file.

### Legacy status (2026-07-14): production image build — NOT STARTED

### Status (2026-07-14): NOT STARTED
The production image build — strip `freeldr` + `ntoskrnl.exe` + `hal.dll`, keep + host
the `.sys` drivers, and produce a single bootable `scripts/build-image.sh` — has **not
begun**. Most inputs now exist: BOOTBOOT + rust-micro + `ntos-executive` boot and run the
real ReactOS user space (smss → csrss → winlogon → win32k → a painted desktop) off a real
FAT32 disk, and `./run.sh` already fetches ReactOS + builds + packs the dev image. What P7
adds is the *integration* recipe (the two image profiles, the boot-driver manifest, the
compat-notes tracking) rather than new runtime capability. This is a good "make it a real
bootable artifact" phase once P5 (SCM) fills in the service startup.

## Sketch
- **Boot chain:** BOOTBOOT (UEFI) → `rust-micro` → `ntos-executive` → HAL (P1) →
  storage + mount the ReactOS **system volume** (P2) → registry (P2) → native
  surface (P3) → launch ReactOS `smss.exe` from the volume → its user space runs
  (P4–P5, P6 for GUI).
- **Image recipe (scripted under `scripts/`):**
  1. Start from a ReactOS `bootcd`/`livecd` (built with RosBE + CMake: `configure`
     then `ninja bootcd`).
  2. **Remove** from the boot set only: `freeldr`, `ntoskrnl.exe`, `hal.dll` (we
     replace these). Do **not** remove the kernel drivers — we host them.
  3. **Keep** everything else: the user-space files (`ntdll.dll`, `smss`, `csrss`,
     `win32`, `services`, `lsass`, `explorer`, apps) **and the kernel driver
     `.sys` files** — we run each in its own isolated driver host. The only `.sys`
     files that won't load are ones needing in-kernel shared-address-space /
     undocumented access (AV/anti-cheat/rootkit/internal-structure filters);
     those are expected fails, tracked in `docs/compat-notes/`.
  4. Lay down our boot: BOOTBOOT + `rust-micro` kernel + `ntos-executive` image
     (embedding or loading the service/driver-host ELFs).
  5. Produce a bootable disk (GPT + FAT ESP for BOOTBOOT + the NT system volume).
- **Two image profiles:** dev/e2e (test specs baked in, gated features) vs.
  integration (kernel + executive + ReactOS user space).
- **Compat notes:** track which ReactOS drivers/services work isolated and which
  don't (AV/anti-cheat/rootkit-style — expected fails) in `docs/compat-notes/`.

## Exit criteria
- A single `scripts/build-image.sh` produces a bootable disk that boots our kernel
  and reaches a usable ReactOS prompt (text MVP) or desktop (with P6).

## E2E test
`e2e-boot-reactos`: build the integration image → boot in QEMU → assert the
ReactOS user space reaches a known checkpoint (login prompt / shell).
