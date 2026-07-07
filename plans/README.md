# plans/ — sub-plans for [PLAN.md](../PLAN.md)

One file per phase. Each carries tasks, exit criteria, and its end-to-end test.
Keep the parent `PLAN.md` high-level; put detail here. Update the relevant
sub-plan **and** `PLAN.md`'s changelog at every step (PLAN.md §10).

| Phase | File | Status | Exit criterion (one line) |
|-------|------|--------|---------------------------|
| P0 | [P0-executive-core.md](P0-executive-core.md) | not started | Two real services under `ntos-executive` over SURT; native front-end routes some `Nt*` |
| P1 | [P1-hardware-hal.md](P1-hardware-hal.md) | not started | Real isolated driver toggles real QEMU MMIO + takes a real interrupt |
| P2 | [P2-storage-fs-registry.md](P2-storage-fs-registry.md) | not started | Mount a real FAT volume, read `\SystemRoot`, load the `SYSTEM` hive |
| P3 | [P3-native-syscall-process.md](P3-native-syscall-process.md) | not started | Run ReactOS `smss.exe` to session-create + start `csrss` |
| P4 | [P4-lpc-csrss.md](P4-lpc-csrss.md) | stub | `cmd.exe` in a text console |
| P5 | [P5-services-startup.md](P5-services-startup.md) | stub | SCM boots + starts a service from the registry |
| P6 | [P6-win32k-graphical.md](P6-win32k-graphical.md) | stub | `explorer` draws (isolated win32k) |
| P7 | [P7-reactos-integration.md](P7-reactos-integration.md) | stub | ReactOS user space boots on our kernel; image build scripted |

Critical path: **P0 → P1 → P2 → P3**. P4+ layer on top.
