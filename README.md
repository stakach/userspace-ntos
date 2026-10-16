# userspace-ntos

A from-scratch reimplementation of the **Windows NT kernel personality in user
space**, running on the [rust-micro](https://github.com/stakach/rust-micro) seL4
microkernel. The personality and matching `ntdll.dll` are implemented in Rust;
The pinned LiberNT installed image supplies the hosted drivers, applications and shell.

NT's executive is a set of cooperating subsystems (Object Manager, Memory
Manager, Process/Thread manager, I/O manager, …) layered over a small kernel.
This project rebuilds that personality as **isolated user-space components on a
capability microkernel** — the microkernel provides threads, address spaces, IPC,
and capabilities; the NT semantics live entirely in user space. Focused,
host-testable crates implement Object, Process/Thread, Memory and I/O contracts;
native service adapters retain capabilities and continuations across callbacks,
faults and cleanup. The matching `ntdll.dll` exposes those contracts to hosted
user-mode code.

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
the workspace. Work is tracked in [GitHub milestones](https://github.com/stakach/userspace-ntos/milestones)
and [issues](https://github.com/stakach/userspace-ntos/issues), not Markdown progress ledgers.

## Crate specs

[CI](https://github.com/stakach/userspace-ntos/actions/workflows/ci.yml) runs these
commands sequentially on stable Rust:

```sh
RUST_TEST_THREADS=1 cargo test --workspace --locked --no-fail-fast
RUST_TEST_THREADS=1 cargo test -p nt-ntdll --features native_transport --locked
```

A clean checkout also needs the public ReactOS source fixtures at the pinned
revision and INF staging shown in [the CI setup steps](.github/workflows/ci.yml).
No kernel build or proprietary Windows binaries are required. The optional
Windows 7 export test requires a locally supplied `references/ntdll.dll`:
`cargo test -p nt-pe-loader --test ntdll_exports -- --ignored`.
Native builds and end-to-end CI are separate follow-ups, not covered by these specs.
Disk-backed `SEC_IMAGE` sources retain their exact opened File, capture bounded PE
metadata, and fill image pages from validated File spans. Mutable sources retain
admission snapshots; the process constructor owns its separate loader snapshot.
Media registry values select the real setup and shell startup paths. The kernel
does not convert a LiveCD into installed-system state or override setup queries
according to the caller's executable.
Hive cell storage grows in bounded pages. Prepared value edits reserve live
resources before journal I/O; uncertain append or flush effects retain their exact
record and block mutation, checkpoint acknowledgement and hive retirement.
The real USER driver owns window-station and desktop assignment; the host does
not seed process bindings or restore thread bindings from a global desktop cache.
Additional hosted threads receive fresh canonical ETHREAD identities. A retired
execution window can be reused while handles retain the previous terminated
thread; its object, exit status and identity are not reset. Physical execution
windows remain bounded independently of canonical thread-object lifetimes.
CI also checks native acceptance log parsing and fixture lifetimes through Clang's
source AST. These host-only checks do not prove guest execution.
The local `tests/native/mup_provider/run_kernel_only.sh` gate checks real
cross-domain driver READ, FLUSH, and buffered QUERY_INFORMATION requests,
including immediate and pending completion through the source driver's event
and IOSB. READ and QUERY_INFORMATION check exact output bytes; FLUSH checks
zero completion information.
Forwarded pending dispatch returns independently of terminal completion. Registered
ordinary workers execute source completion routines, retaining exact IRP ownership
and callback continuations without serializing unrelated jobs behind a waiting worker.
Nested work uses bounded scheduling passes and reports only actual phase changes or
acknowledged retirement as progress, allowing queued IPC to settle blocked ownership.
Held inline completions retain their source ownership until a genuine resumed
unwind or authenticated stop; caller-owned IRPs remain under their original owner.
Its controlled pending-error checks correlate actual File generations, untouched
precompletion buffers, delivered errors and retained-pointer cleanup ordering;
these are separate from desktop proof and uncertain-effect quarantine.
Hosted driver debug messages are formatted in userspace before one bounded,
non-IPC serial write. The executive frames its own complete diagnostic lines;
the microkernel captures caller-VSpace bytes before emission without changing
IPC or Reply state. Acceptance parsers still reject malformed or split records.
GUI receive continuations retain the actual provider execution hold while the root
services an authenticated resident private-page fault. Exact child Reply settlement
precedes parent restoration and receive-only continuation; physical VSpace checks
and the shared ownership journal reject stale identities and aliased roots.
The optional `tests/native/source_irp/run.sh` profile checks real fileless READ/WRITE
and all four IOCTL methods through win32k, including immediate and pending completion.
It verifies bytes, IOSBs and retirement counters; production images omit its fixtures.
The optional [native File acceptance profile](tests/native/file_acceptance/README.md)
launches a public-ntdll-only executable through real SMSS to check relative opens,
FileAll metadata and user-buffer fault precedence. Its process-exit receipts are
separate from the whole-OS and screenshot gates.
The optional `font-cleanup` image profile launches a private-font client through
Explorer's ordinary Run key and checks exact Section-view retirement after process
termination. Rebuild a fresh production image afterwards; fixture profiles are not
production desktop evidence.

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

## Building and running the hosted desktop

The hosted system uses the [pinned LiberNT AMD64 installed release](rust-micro/vendor/libernt/manifest.txt) as its filesystem source. `./run.sh` verifies the archive and contained disk image, extracts the installed `Windows` and `Users` tree, builds this repository's Rust `ntdll.dll` and NT executive, and packs a new UEFI boot image with the rust-micro kernel. The release image and its `acpi.sys` are not modified. The generated image stages our kernel-facing `ntdll.dll` at `Windows/system32/ntdll.dll`.

```sh
git clone --recursive https://github.com/stakach/userspace-ntos.git
cd userspace-ntos
./run.sh --build-only   # verify media, build, and pack the boot image
./run.sh                # headless serial and Explorer acceptance gate
./run.sh --desktop      # same gate with a QEMU display window
```

The launcher needs Rust nightly with `rust-src`, QEMU and OVMF, a C compiler, Python 3, `bsdtar`, and `7zz`. The first run downloads the pinned release; later runs use the verified cache under `rust-micro/.tmp/libernt/`. The generated image is `rust-micro/.tmp/disk.img`. Keep at least several gigabytes free for the archive, extracted tree, build output, and image. Set `BOOT_TIMEOUT_SECONDS` to a value up to 3600 to bound a boot attempt.

The cutover is tracked in [issue #310](https://github.com/stakach/userspace-ntos/issues/310). Its current source-built ntdll lacks some LiberNT exports, so the build deliberately stops at the export comparison until that ABI is implemented. A crate build or image pack alone is not desktop proof: acceptance requires genuine Winlogon, Userinit, and Explorer execution, an Explorer screenshot, and the complete headless verdict. [Issue #18](https://github.com/stakach/userspace-ntos/issues/18) records the previous ReactOS desktop acceptance; it does not establish a LiberNT desktop boot.

Run focused crate checks with `cargo test --workspace --locked`. Native integration and QEMU validation share generated artifacts, so run them serially. For a release refresh, update the URL, source revision, and SHA-256 values in the [media manifest](rust-micro/vendor/libernt/manifest.txt), then rerun `./run.sh --build-only` and the desktop acceptance gate. Do not edit the published release binaries.

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

The downloaded LiberNT userspace is distributed under [LiberNT's own licenses](https://github.com/ahmedarif193/LiberNT), including GPL-3.0 and licenses retained from ReactOS. It is fetched separately and is not part of this repository's source license.
