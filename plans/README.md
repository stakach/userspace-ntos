# plans/ — sub-plans for [PLAN.md](../PLAN.md)

One file per phase. Each carries tasks, exit criteria, and its end-to-end test.
Keep the parent `PLAN.md` high-level; put detail here. Update the relevant
sub-plan **and** `PLAN.md`'s changelog at every step (PLAN.md §10).

**Status snapshot (2026-07-14):** P0–P4 + P6 are done / largely-done; the gate is
~140 specs, prints **SUCCESS**, and the Windows desktop **paints** authentically
(`./run.sh`, or `./run.sh --desktop` to see it). P5 (SCM/services) and P7 (image
build) are the remaining not-started phases. See PLAN.md §10 (2026-07-14 entry).

| Phase | File | Status | Exit criterion (one line) |
|-------|------|--------|---------------------------|
| P0 | [P0-executive-core.md](P0-executive-core.md) | **DONE** (functionally; broker-migration deferred) | Two real services under `ntos-executive` over SURT; native front-end routes some `Nt*` |
| P1 | [P1-hardware-hal.md](P1-hardware-hal.md) | **DONE** (functionally; NDIS deferred) | Real isolated driver toggles real QEMU MMIO + takes a real interrupt |
| P2 | [P2-storage-fs-registry.md](P2-storage-fs-registry.md) | **LARGELY DONE** | Mount a real FAT volume, read `\SystemRoot`, load the `SYSTEM` hive |
| P3 | [P3-native-syscall-process.md](P3-native-syscall-process.md) | **DONE** | Run ReactOS `smss.exe` to session-create + start `csrss` |
| P4 | [P4-lpc-csrss.md](P4-lpc-csrss.md) | **LARGELY DONE** (LPC + ALPC + real csrss; console residuals) | `cmd.exe` in a text console |
| P5 | [P5-services-startup.md](P5-services-startup.md) | **NOT STARTED** (natural-boot frontier) | SCM boots + starts a service from the registry |
| P6 | [P6-win32k-graphical.md](P6-win32k-graphical.md) | **DONE** — the desktop paints | `explorer` draws (isolated win32k) |
| P7 | [P7-reactos-integration.md](P7-reactos-integration.md) | **NOT STARTED** | ReactOS user space boots on our kernel; image build scripted |
| P8 | [P8-win7-pivot.md](P8-win7-pivot.md) | **stub / new direction** | Host a first real Windows 7 binary/driver |

Critical path P0 → P1 → P2 → P3 is **complete**. The forward direction is now
the **Win7 pivot** (P8) alongside the residual ReactOS-boot phases (P5, P7).
