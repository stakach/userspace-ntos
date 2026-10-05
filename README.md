# userspace-ntos

A from-scratch reimplementation of the **Windows NT kernel personality in user
space**, running on the [rust-micro](https://github.com/stakach/rust-micro) seL4
microkernel. The personality and matching `ntdll.dll` are implemented in Rust;
ReactOS supplies the hosted drivers, applications and shell.

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
RUST_TEST_THREADS=1 cargo test --workspace --locked
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
The real USER driver owns window-station and desktop assignment; the host does
not seed process bindings or restore thread bindings from a global desktop cache.
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

## Running the hosted ReactOS desktop (quick start)

The desktop target hosts **real, unmodified GPL ReactOS binaries** on rust-micro.
Genuine Explorer and native acceptance are tracked in
[issue #18](https://github.com/stakach/userspace-ntos/issues/18).
[Earlier logon-rendering evidence](docs/evidence/issue18-bounded-source-logon.json)
includes the credential dialog. After removing synthetic USER bindings, the latest
[media-policy boot](docs/evidence/issue18-livecd-setup-file-admission-failure.json)
launched genuine setup but failed a dependency File open. The fresh
[File-capacity boot](docs/evidence/issue18-livecd-theme-helper-startup-failure.json)
progressed into syssetup, then its theme helper faulted at startup. A subsequent
[full USER-range boot](docs/evidence/issue18-livecd-rpcrt4-queued-fault-failure.json)
exposed a queued image-fault race. After that fix, an
[instrumented boot](docs/evidence/issue18-livecd-rundll-activation-frame-failure.json)
ran genuine setup and rundll32 window callbacks, then rundll32 faulted in ntdll
with activation-frame pointer `0xc0` after `WM_CREATE`. A subsequent
[callback-restart boot](docs/evidence/issue18-native-leaf-revoke-cleanup-frontier.json)
passed that frontier: the genuine helper completed its window callbacks and exited
successfully. Native capability cleanup then progressed too slowly; the run was
manually stopped after about 52 minutes, without a guest summary or sentinel.
After the native leaf-revoke fix, a
[font-profile boot](docs/evidence/issue18-client-frame-growth-allocation-failure.json)
reached the genuine helper's client-thread setup, then refused a 3.75 MiB
allocation during client-frame registration. It was manually stopped after about
30 minutes without a guest verdict. With chunked frame storage, a subsequent
[boot](docs/evidence/issue18-chunked-frame-boot-frontier.json) completed the theme
helper's exit and retirement without an allocation-refusal diagnostic, then
reached the natural gate at 218/261. Its screenshot still shows background and
cursor only; font acceptance, Userinit/Explorer, and desktop rendering remain
unproven. The latest [mapping-retirement boot](docs/evidence/issue18-frame-map-font-boot-frontier.json)
also completed the helper's exit and retirement, then reported a directory-query
allocation refusal and Setup's Plug and Play startup failure. It was stopped at
that fatal boundary within the one-hour limit. Native mapping specifications
pass separately; this fresh boot still does not prove font cleanup or Explorer.
Crate CI does not prove desktop boot. To attempt a boot from a fresh clone:

```sh
git clone --recursive https://github.com/stakach/userspace-ntos.git
cd userspace-ntos
./run.sh                # headless serial gate (default)
./run.sh --desktop      # boot with a QEMU window so you SEE the painted desktop
./run.sh --build-only   # stage the boot image without launching QEMU
```

`./run.sh` (at the repo root — distinct from `scripts/run.sh` above) is a
self-contained launcher that:

1. **Preflight-checks every prerequisite** (QEMU, a C compiler, `tar`,
   `bsdtar`/libarchive, `python3`, the Rust **nightly**
   toolchain + `rust-src`, and OVMF/edk2 UEFI firmware). If anything is missing
   it prints a per-platform `brew install …` / `apt install …` remediation table
   and stops — no cryptic mid-build failure.
2. **Checks out the `rust-micro` submodule** if you forgot `--recursive`.
3. **Fetches the ReactOS binaries** on first run (a ~30 MiB GPL ReactOS x64
   livecd, `reactos-livecd-0.4.17-dev-933-ga9fc819`, from
   [iso.reactos.org](https://iso.reactos.org/livecd/); cached under
   `rust-micro/.tmp/reactos/`, extracted with `bsdtar`). Override the URL with
   `REACTOS_7Z_URL=…`. ReactOS is GPL, so its binaries are freely
   redistributable — the executive loads them via `SEC_IMAGE` and runs their
   real user-mode binaries through this project's Rust `ntdll.dll` implementation.
   The requested dev-933 archive currently contains an ISO byte-identical to
   the earlier dev-478 archive; its label does not yet imply a newer payload.
4. **Builds** the Rust `ntdll.dll`, `ntos-executive` (the NT executive that
   hosts the ReactOS processes), the verified `nt-seh-linkage.dll` support image,
   and the kernel, then packs the FAT32/UEFI disk image. The support image is
   mapped into hosted driver domains. The native SEH bridge runs driver C filters,
   termination handlers, explicit target and collided unwinds, and provider CPU-fault
   handlers on the interrupted component thread. Verify these paths with
   `bash scripts/run-seh-driver-integration.sh`,
   `bash scripts/run-seh-terminal-integration.sh`, and
   `bash scripts/run-seh-fault-integration.sh`; pass `--desktop` to also require
   the full Explorer gate.
5. **Boots QEMU.**

### Desktop Acceptance

Headless mode streams the serial log and checks the complete executive summary,
the success sentinel, and `PASS exec_explorer_shell_chrome_painted`. This gate
requires genuine Explorer execution, client callbacks, GDI drawing, and varied
framebuffer pixels. Background painting or a login dialog alone is not desktop proof.

The [feature-off production scanout](docs/images/desktop-production.png) records
genuine Explorer taskbar and Start-button rendering after a fresh profile setup.
The [source-instrumented scanout](docs/images/desktop-source-irp.png) accompanies
the strict native source-IRP completion and retirement gate on the same kernel code.
This is desktop-chrome evidence, not a complete executive-gate pass; remaining
whole-OS acceptance is tracked in [issue #18](https://github.com/stakach/userspace-ntos/issues/18).

`--desktop` opens a QEMU window using the real ReactOS `win32k.sys`, display driver,
and font stack. Boot readiness is the Explorer chrome gate, not the earlier
`desktop-bg match` message. The launcher bounds boot to one hour and allows a short
inspection interval after readiness; close the window to quit. Use headless mode
for an automated pass/fail result.

**Expected run time:** the headless gate can take several minutes under QEMU TCG, especially on
Apple Silicon, and DLL-loading phases can be quiet for tens of seconds. `--desktop` opens the
window before win32k paints it; wait for `PASS exec_explorer_shell_chrome_painted`.
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
