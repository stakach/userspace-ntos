# userspace-ntos

`userspace-ntos` reimplements the Windows NT kernel personality in Rust user-space services on the [rust-micro](https://github.com/stakach/rust-micro) seL4 microkernel. Focused crates implement NT object, process, memory, I/O, registry, and graphics contracts. The matching source-built `ntdll.dll` connects hosted applications to those services.

The hosted filesystem comes from a [pinned LiberNT AMD64 installed release](rust-micro/vendor/libernt/manifest.txt). Image generation verifies the downloaded archive and disk image, preserves LiberNT's released drivers including `acpi.sys`, and stages this repository's `ntdll.dll` at `Windows/system32/ntdll.dll`. The published release binaries are not edited. The build verifies that our DLL covers every named export of the pinned LiberNT DLL, and compiles the release's own api-set contract table (read from its `ntdll.dll`) into ours; live API behavior still requires boot validation.

<img width="1024" height="768" alt="desktop" src="https://github.com/user-attachments/assets/613cc279-4403-4863-b313-f3d15e4bb36c" />

## Build and run

Clone with the pinned kernel submodule, then build and run the desktop image:

```sh
git clone --recursive https://github.com/stakach/userspace-ntos.git
cd userspace-ntos
RUST_TEST_THREADS=1 cargo test --workspace --locked --no-fail-fast
./run.sh --build-only
./run.sh
./run.sh --desktop # optional QEMU display
```

The launcher requires Rust nightly with `rust-src`, QEMU with OVMF, a C compiler, `patch`, Python 3, `bsdtar`, and `7zz`. Its first run downloads the pinned release; later runs use the verified cache in `rust-micro/.tmp/libernt/`. The Simpleboot image creator builds from verified source in the submodule, without a source download during image generation. The generated boot image is `rust-micro/.tmp/disk.img`. Allow several gigabytes for the archive, extracted filesystem, build output, and image. QEMU defaults to 3 GiB of RAM, which gives the executive a 1 GiB root Untyped; set `QEMU_MEMORY` to override it. The kernel hands over the largest aligned power of two that fits, up to 4 GiB: `4096M` yields 2 GiB and `6144M` yields 4 GiB. The hosted build sends kernel diagnostics through QEMU debugcon and leaves COM1 to the released serial driver. `BOOT_TIMEOUT_SECONDS` bounds a boot attempt to at most 3600 seconds. Worker threads of NT processes run on the cores their affinity allows; build with `NTOS_GUEST_WORKER_MULTICORE=0` to keep every guest thread on core 0. Run tests, native builds, image generation, and QEMU serially because they share artifacts.

`./run.sh` checks a headless boot; `./run.sh --desktop` also opens a QEMU display. [LiberNT desktop acceptance](https://github.com/stakach/userspace-ntos/issues/310) requires genuine Winlogon, Userinit, and Explorer execution, a screenshot, and reboot and persistence checks. A successful crate test or image build alone does not establish desktop acceptance. [The previous ReactOS acceptance](https://github.com/stakach/userspace-ntos/issues/18) is separate.

The [Native x86 KVM smoke workflow](.github/workflows/native-kvm-smoke.yml) can continue a stopped writable disk with `resume_run_id` and `resume_run_attempt` when the source and target use the same commit. For a reviewed newer commit, use the separate `migrate_run_id` and `migrate_run_attempt` inputs. Migration is limited to a successful ancestor run on the same branch, production image, pinned LiberNT release, and verified registry-hive provenance. It stages the new kernel and source-built `ntdll.dll` on a copy of the stopped disk and records the disk's origin; two boots of the resulting exact commit are still required for reboot proof.

The workflow is a desktop gate ([scripts/ci_kvm_verdict.py](scripts/ci_kvm_verdict.py)). It passes only when every boot has all of these:

- Explorer seals its desktop paint milestones.
- The scripted interaction completes every step with no input errors.
- The final framebuffer visibly contains the typed `ver` command and its Windows version response; the verdict retains the screenshot hash and OCR transcript.
- The serial log has no executive panic, provider bugcheck, service-loop exit or kernel halt.

Each boot writes `native-kvm-verdict.json`. The workflow defaults to a 1,200-second ceiling per boot. The progress watchdog can stop a stationary guest sooner. After the desktop seals and a 10-second settle period, the runner drives scripted guest input; the `interact` input is on by default, and clearing it fails the gate. The runner pins the PS/2 cursor at the bottom-left corner, aims with small relative moves, sends keys over QMP, and uploads `native-kvm-interact-NN-<step>.ppm` plus `native-kvm-interact.jsonl`. CI uses Tesseract to read the original final PPM and fails closed if the result is absent. Edit the steps in [scripts/kvm_interaction_steps.json](scripts/kvm_interaction_steps.json).

A failed run still publishes its disk for continuation in two cases: it went idle after setup completed and a user logged on, or it ran its whole bound without a fault.

## Update

To update the microkernel, check out the reviewed rust-micro commit in its submodule and commit the new submodule pointer in this repository. To update the LiberNT base, review and change the release URL, source revision, and SHA-256 values in the [media manifest](rust-micro/vendor/libernt/manifest.txt); then rerun the build, crate tests, and desktop acceptance. Push submodule commits before a parent commit that references them.

GitHub [issues](https://github.com/stakach/userspace-ntos/issues) and [milestones](https://github.com/stakach/userspace-ntos/milestones) track implementation and validation. Crate tests run in [CI](https://github.com/stakach/userspace-ntos/actions/workflows/ci.yml).

## License

This repository is licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. It is an independent reimplementation of NT concepts and is not affiliated with Microsoft. Windows and Windows NT are Microsoft trademarks. The vendored [Simpleboot source](rust-micro/vendor/simpleboot/README.md) retains its MIT notices. The downloaded LiberNT userspace has [its own licenses](https://github.com/ahmedarif193/LiberNT), including GPL-3.0 and licenses retained from ReactOS; it is fetched separately and is not covered by this repository's source license.
