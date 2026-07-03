# driver-host-exec component

**Runs a real Windows kernel driver's machine code on seL4.**

A bare-metal root task that maps the real MSVC-built `SurtTest.sys` (a WDM driver,
<https://github.com/stakach/ntdriver>) into its own VSpace **executable**,
relocates it, patches its imports to native `extern "win64"` NT export stubs, and
calls the driver's `DriverEntry` under the Microsoft x64 calling convention — then
verifies the driver installed its dispatch table + created its device.

This is **Driver Host M9 step 1**: the proof that Windows driver semantics can be
projected into an isolated seL4 user-space component while the NT executive state
stays canonical elsewhere.

## Run

```sh
# from the repo root:
./scripts/run-driver-host-exec.sh
```

Expected tail:

```
[ntos-dhx] Driver Host executor: load + run real SurtTest.sys
  PASS parse
  PASS map
  PASS patch_iat
  PASS driver_entry_success
  PASS dispatch_create
  PASS dispatch_device_control
  PASS io_create_device
  PASS io_create_symbolic_link
  device: \Device\SurtTest
  PASS irp_create
  PASS ioctl_ping
  PASS ioctl_get_version
  PASS ioctl_echo
[microtest done]
```

## How it works

1. **Executable mapping** (`map_region`): retype fresh PDPT/PD/PT + 4 KiB frames
   from the initial untyped and map them RW(X) at the driver's preferred base
   (`0x140000000`) in the root's own VSpace (`CAP_INIT_THREAD_VSPACE`). x86_64 pages
   are executable unless mapped `ExecuteNever`. Mapping at the preferred base means
   relocation delta 0.
2. **Load** (`nt-pe-loader`): parse + map the PE, copy the laid-out image into the
   executable region.
3. **IAT patch**: each `ntoskrnl.exe` import slot is pointed at a native
   `extern "win64"` stub (`ntos_io_create_device`, `ntos_rtl_init_unicode_string`,
   `ntos_io_create_symbolic_link`, …) that implements the NT export against a local
   runtime.
4. **Security cookie**: seed `__security_cookie` (`.data` RVA `0x3000`) — the MSVC
   `GsDriverEntry` wrapper fastfails (`int 0x29`) if the loader left it 0.
5. **Call** `DriverEntry(DriverObject, RegistryPath)` via a transmuted
   `extern "win64" fn`. The driver runs its real machine code, calls back through
   the patched IAT, fills `MajorFunction[]`, and creates `\Device\SurtTest` +
   `\DosDevices\SurtTest`.

## Scope + next steps

- **Step 1 (this)**: real `DriverEntry` execution + trampoline callbacks, in the
  root task. Proves executable mapping, the x64 ABI call gate, and the IAT-callback
  mechanism on hardware.
- **Step 2 (done)**: real IRPs driven into the driver's dispatch routines — an
  `IRP` + `IO_STACK_LOCATION` built at real addresses, `MajorFunction[major]`
  called; `IOCTL_SURT_PING` returns `"SURT"`, `GET_VERSION` returns `{0,1,0,9}`,
  `ECHO` round-trips, and `IofCompleteRequest` calls back into the runtime.
- **Step 3**: isolate as a child component with the SURT `DH_OP_*` transport to a
  separate I/O Manager component (the `nt-driver-abi` protocol).

v0.1 uses an RWX mapping + a hard-coded cookie RVA + one driver; a production Driver
Host would map W^X, resolve the cookie via the PE load-config directory, and host
arbitrary WDM images.
