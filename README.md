# userspace-ntos

A from-scratch reimplementation of the **Windows NT kernel personality in user
space**, running on the [rust-micro](https://github.com/stakach/rust-micro) seL4
microkernel. Everything is Rust.

NT's executive is a set of cooperating subsystems (Object Manager, Memory
Manager, Process/Thread manager, I/O manager, …) layered over a small kernel.
This project rebuilds that personality as **isolated user-space components on a
capability microkernel** — the microkernel provides threads, address spaces, IPC,
and capabilities; the NT semantics live entirely in user space. The first
component is the **NT Object Manager** (the `\ObjectDirectory` namespace, typed
objects, handles, symbolic links).

## Repository layout

```
rust-micro/            the seL4-style microkernel (git submodule, pinned)
Cargo.toml             workspace for the host-testable NT crates (cargo test on the host)
crates/
  nt-status/           NTSTATUS-style status codes                       no_std
  nt-types/            ids, access masks, UnicodeString, NtPath parser   no_std + alloc
  nt-object-abi/       fixed-layout SURT wire ABI (opcodes + structs)    no_std
  nt-object-manager/   the Object Manager core (store/handles/namespace/symlinks/access)
  nt-object-server/    transport-agnostic service dispatcher (decode/validate/dispatch)
  nt-object-client/    ergonomic client stub over a pluggable transport backend
  ntos-root/           the root task the kernel boots (standalone, custom target)
components/
  object-manager/      the Object Manager as a seL4 component (runs the stack on the kernel)
  object-service/      client + server as TWO isolated components over SURT rings
  io-manager/          the I/O Manager (over an embedded OM) as isolated components over SURT
  driver-host/         the I/O Manager dispatching IRPs to an isolated driver peer over SURT
  driver-host-exec/    runs a REAL WDM .sys driver's DriverEntry on seL4 (x64 exec)
  driver-host-svc/     runs the real WDM driver in an ISOLATED seL4 child component
scripts/
  run.sh               build the hello root task + kernel and boot QEMU
  run-object-manager.sh  build + boot the Object Manager component in QEMU
  run-object-service.sh  build + boot the isolated client/server (over SURT) in QEMU
  run-io-manager.sh      build + boot the isolated I/O Manager client/server in QEMU
  run-driver-host.sh     build + boot the I/O Manager + isolated driver peer in QEMU
  run-driver-host-exec.sh  build + boot the real-driver executor (runs SurtTest.sys on seL4)
  run-driver-host-svc.sh   build + boot the real driver in an isolated child component
docs/compat-notes/     behavioural compatibility notes vs Windows NT
references/            NT/ReactOS/driver reference trees (gitignored, local only)
```

The **host-testable NT core** (`nt-status`, `nt-types`, `nt-object-abi`,
`nt-object-manager`) is a normal cargo workspace — `cargo test` on your laptop,
no seL4 or QEMU. The kernel-bound bins (`ntos-root`, `components/*`) are
standalone crates built for the microkernel's bare-metal target and excluded from
the workspace. Implementation follows the milestones in
[`references/nt-object-manager-spec.md`](references/nt-object-manager-spec.md) §22.

The kernel is a **pinned git submodule**, not vendored source: `userspace-ntos`
depends on an exact kernel SHA (its syscall/invocation ABI is tightly coupled),
and the NTOS components consume the kernel's ABI through one shared crate,
`rust-micro/crates/sel4-rt`, rather than re-hand-rolling it.

## Building & running

Requires the Rust **nightly** toolchain with `rust-src` (for `-Z build-std`), and
the QEMU + image tooling the kernel's scripts use (see the submodule's README).

```sh
git clone --recursive https://github.com/stakach/userspace-ntos.git
cd userspace-ntos
./scripts/run.sh
```

Already cloned without `--recursive`? Fetch the kernel:

```sh
git submodule update --init --recursive
```

Expected boot output:

```
[ntos] userspace-ntos root task alive on rust-micro
[ntos]   node 0/4, first empty slot 34, ipc_buffer @ 0x...
[ntos]   5 untyped(s), 9 image frame cap(s)
[ntos] boot smoke-test OK
```

`scripts/run.sh` builds the `ntos-root` ELF (a minimal boot smoke-test), stages
it as the kernel's rootserver, and drives the kernel's build+image+QEMU pipeline
in `extern-rootserver` mode (bring your own root task).

## Running the hosted ReactOS desktop (quick start)

The headline demo boots the rust-micro microkernel hosting **real, unmodified
GPL ReactOS binaries** — `smss.exe → csrss.exe → winlogon.exe → win32k.sys` —
all the way to a **painted Windows desktop**. One command from a fresh clone:

```sh
git clone --recursive https://github.com/stakach/userspace-ntos.git
cd userspace-ntos
./run.sh                # headless serial gate (default)
./run.sh --desktop      # boot with a QEMU window so you SEE the painted desktop
```

`./run.sh` (at the repo root — distinct from `scripts/run.sh` above) is a
self-contained launcher that:

1. **Preflight-checks every prerequisite** (QEMU, `mkfs.vfat`/dosfstools,
   `mmd`/`mcopy`/mtools, `bsdtar`/libarchive, `python3`, the Rust **nightly**
   toolchain + `rust-src`, and OVMF/edk2 UEFI firmware). If anything is missing
   it prints a per-platform `brew install …` / `apt install …` remediation table
   and stops — no cryptic mid-build failure.
2. **Checks out the `rust-micro` submodule** if you forgot `--recursive`.
3. **Fetches the ReactOS binaries** on first run (a ~30 MiB GPL ReactOS x64
   livecd, `reactos-livecd-0.4.17-dev-478-g4117217`, from
   [iso.reactos.org](https://iso.reactos.org/livecd/); cached under
   `rust-micro/.tmp/reactos/`, extracted with `bsdtar`). Override the URL with
   `REACTOS_7Z_URL=…`. ReactOS is GPL, so its binaries are freely
   redistributable — the executive loads them via `SEC_IMAGE` and runs their
   real user-mode binaries through this project's Rust `ntdll.dll` implementation.
4. **Builds** the Rust `ntdll.dll`, `ntos-executive` (the NT executive that
   hosts the ReactOS processes), and the kernel, then packs the FAT32/UEFI disk image.
5. **Boots QEMU.**

### What you should see

Headless (default) — the serial log streams to your terminal and ends with the
executive's success sentinel; `run.sh` then prints a clear verdict:

```
  PASS exec_win32k_desktop_painted
[ntos-exec] desktop-bg match 768/768 px, px0=0x003a6ea5 (expected 0x003a6ea5)
[user-callback] rendezvous=119 winlogon-api0=117 table-nonzero-aligned=1 real-api0-redirects=1 real-api0-returns=1 continuation-pushes=7 continuation-unwinds=7 nested-dispatches=5 nested-ssn-1298=1 nested-ssn-126b=4 sequence-completions=1
  PASS exec_user_callback_real_api0_nested_roundtrip
[ntos-exec summary: 188/99 executive->isolated-service checks passed]
[microtest done]
SUCCESS — the ReactOS stack booted and the win32k desktop painted (0x003a6ea5).
```

`--desktop` — a QEMU window opens showing the **real painted desktop**: win32k
authentically fills the BOOTBOOT GOP framebuffer with the ReactOS desktop
background colour `0x003a6ea5` (RGB 58,110,165) via winlogon's natural
`SwitchDesktop` flow. This is a genuine graphics path (the real ReactOS
`win32k.sys` + `framebuf.dll` display driver + `ftfd.dll`/Arial font stack), not
a stub or a mock. This mode intentionally does not exit at `[microtest done]`; the
terminal remains attached to QEMU and the window persists so you can inspect it.
Close the QEMU window to quit. Use the default headless mode for an automated
pass/fail result.

**Expected run time:** the headless gate can take several minutes under QEMU TCG, especially on
Apple Silicon, and DLL-loading phases can be quiet for tens of seconds. `--desktop` opens the
window before win32k paints it; use the serial `desktop-bg match 768/768` line as the ready signal.
The first run also adds the one-time ReactOS download and a full `cargo` build.

**Gotchas:**

- The kernel is a **git submodule** (`rust-micro`); the build target is
  `userspace-ntos/rust-micro`, not any standalone checkout. A clone without
  `--recursive` needs `git submodule update --init --recursive` (the launcher
  does this for you).
- Some ReactOS binaries are only staged onto the disk image **if they were
  fetched first** — a fresh clone that skips the fetch step boots the kernel
  *without* the hosted processes. Always let `./run.sh` run the fetch (it is
  idempotent and cached).

## Updating the kernel

```sh
cd rust-micro && git checkout <new-sha> && cd ..
git add rust-micro && git commit -m "bump kernel to <new-sha>"
```

Pin to SHAs at milestones; point the submodule at a kernel branch during active
co-development of kernel + NTOS.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. This is an independent, clean-room
reimplementation of NT *concepts*; it contains no Microsoft code and is not
affiliated with or endorsed by Microsoft. "Windows" and "Windows NT" are
trademarks of Microsoft Corporation.
