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
  nt-object-manager/   the Object Manager core (store/handles/namespace) [in progress]
  ntos-root/           the root task the kernel boots (standalone, custom target)
components/            seL4 service components (e.g. object-manager)      [later]
scripts/
  run.sh               build the root task + kernel (via the submodule) and boot QEMU
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

`run.sh` builds the `ntos-root` ELF, stages it as the kernel's rootserver, and
drives the kernel's build+image+QEMU pipeline in `extern-rootserver` mode (bring
your own root task).

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
