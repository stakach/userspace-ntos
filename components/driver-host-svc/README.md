# driver-host-svc component

**Runs a real Windows kernel driver inside an ISOLATED seL4 component.**

A broker root task spawns a fully-isolated child (its own CSpace + VSpace) whose
VSpace includes an executable region. The child maps the real MSVC-built
`SurtTest.sys` into it and runs its `DriverEntry` + IRP dispatch under the
Microsoft x64 ABI — so a driver fault is contained to the child, not the broker.

This is **Driver Host M9 step 3**: real-driver execution inside an isolated
component, driven over the SURT `DH_OP_*` transport from a separate `io_side`
component. (The in-root-task executor is `components/driver-host-exec`.)

## Run

```sh
# from the repo root:
./scripts/run-driver-host-svc.sh
```

Expected tail:

```
[ntos-dhs] real WDM driver in an isolated component, driven over SURT
  PASS ioctl_ping
  PASS ioctl_get_version
  PASS ioctl_echo
[ntos-dhs summary: 3 passed, 0 failed]
```

## How it works

- **Broker** (`src/main.rs`): the SURT cap-transfer machinery (a ring pair +
  request/reply data frames + notifications shared between the two children), plus
  for the Driver Host child (a) an RW `STATE_VADDR` page for the driver-runtime
  state (its image `.bss` is mapped read-only) and (b) a fresh RWX region at
  `CODE_VADDR` (`0x140000000`, its own PDPT/PD/PT) for the driver image.
- **`driver_host`** (`src/driver_host.rs`): copies `SurtTest.sys` into the RWX
  region, patches its IAT to native `extern "win64"` NT export stubs, seeds the
  `/GS` cookie, runs `DriverEntry`, then serves `DH_OP_DISPATCH_IRP` off the ring —
  building an `IRP` + `IO_STACK_LOCATION`, calling the driver's dispatch routine,
  and replying with the completion.
- **`io_side`** (`src/io_side.rs`): sends `DH_OP_DISPATCH_IRP` requests
  (`IOCTL_SURT_PING`/`GET_VERSION`/`ECHO`) over SURT, verifies the replies, and
  reports the verdict to the broker.
