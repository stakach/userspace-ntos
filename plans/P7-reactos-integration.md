# P7 — ReactOS Integration & Image Build — STUB

**Goal:** boot a **real ReactOS user space** on our kernel and produce a bootable
disk image (BOOTBOOT + rust-micro + `ntos-executive` + ReactOS user-space volume).

## Status: **NOT STARTED (2026-07-14)** (the final image build; dependencies largely met)

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
