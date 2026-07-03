# driver-host-svc component

**Runs a real Windows kernel driver inside an ISOLATED seL4 component.**

A broker root task spawns a fully-isolated child (its own CSpace + VSpace) whose
VSpace includes an executable region. The child maps the real MSVC-built
`SurtTest.sys` into it and runs its `DriverEntry` + IRP dispatch under the
Microsoft x64 ABI — so a driver fault is contained to the child, not the broker.

This is **Driver Host M9 step 3 (phase 3a)**: real-driver execution inside an
isolated component. (The in-root-task executor is `components/driver-host-exec`.)

## Run

```sh
# from the repo root:
./scripts/run-driver-host-svc.sh
```

Expected tail:

```
[ntos-dhs] real WDM driver in an ISOLATED seL4 component
  PASS driver_entry_success
  PASS dispatch_create
  PASS dispatch_device_control
  PASS io_create_device
  PASS io_create_symbolic_link
  PASS irp_create
  PASS ioctl_ping
  PASS ioctl_get_version
  PASS ioctl_echo
[ntos-dhs summary: 9 passed, 0 failed]
```

## How it works

- **Broker** (`src/main.rs`): the same cap-transfer machinery as the other isolated
  components, plus (a) an RW `STATE_VADDR` page for the child's driver-runtime state
  (the child's image `.bss` is mapped read-only), and (b) a fresh RWX region at
  `CODE_VADDR` (`0x140000000`, its own PDPT/PD/PT) for the driver image. The child is
  given only a `CT_PML4` + a result endpoint.
- **Child** (`src/driver_host.rs`): copies the laid-out `SurtTest.sys` into the RWX
  region, patches its IAT to native `extern "win64"` NT export stubs, seeds the
  `/GS` cookie, calls `DriverEntry`, drives `IRP_MJ_CREATE` + the three IOCTLs into
  the driver's dispatch routines, and reports the pass count to the broker over the
  endpoint.

## Scope

- **3a (this)**: the real driver runs in an isolated, fault-contained child.
- **3b (next)**: drive the IRPs *from a separate component* over the SURT `DH_OP_*`
  transport, rather than from within the Driver Host child.
