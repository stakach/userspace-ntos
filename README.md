# userspace-ntos

`userspace-ntos` reimplements the Windows NT kernel personality in Rust user-space services on the [rust-micro](https://github.com/stakach/rust-micro) seL4 microkernel. Focused crates implement NT object, process, memory, I/O, registry, and graphics contracts. The matching source-built `ntdll.dll` connects hosted applications to those services.

The hosted filesystem comes from a [pinned LiberNT AMD64 installed release](rust-micro/vendor/libernt/manifest.txt). Image generation verifies the downloaded archive and disk image, preserves LiberNT's released drivers including `acpi.sys`, and stages this repository's `ntdll.dll` at `Windows/system32/ntdll.dll`. The published release binaries are not edited. The build verifies that our DLL covers every named export of the pinned LiberNT DLL; live API behavior still requires boot validation.

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

The launcher requires Rust nightly with `rust-src`, QEMU with OVMF, a C compiler, `patch`, Python 3, `bsdtar`, and `7zz`. Its first run downloads the pinned release; later runs use the verified cache in `rust-micro/.tmp/libernt/`. The generated boot image is `rust-micro/.tmp/disk.img`. Allow several gigabytes for the archive, extracted filesystem, build output, and image. `BOOT_TIMEOUT_SECONDS` bounds a boot attempt to at most 3600 seconds. Run tests, native builds, image generation, and QEMU serially because they share artifacts.

`./run.sh` checks a headless boot; `./run.sh --desktop` also opens a QEMU display. [LiberNT desktop acceptance](https://github.com/stakach/userspace-ntos/issues/310) requires genuine Winlogon, Userinit, and Explorer execution, a screenshot, and reboot and persistence checks. A successful crate test or image build alone does not establish desktop acceptance. [The previous ReactOS acceptance](https://github.com/stakach/userspace-ntos/issues/18) is separate.

## Update

To update the microkernel, check out the reviewed rust-micro commit in its submodule and commit the new submodule pointer in this repository. To update the LiberNT base, review and change the release URL, source revision, and SHA-256 values in the [media manifest](rust-micro/vendor/libernt/manifest.txt); then rerun the build, crate tests, and desktop acceptance. Push submodule commits before a parent commit that references them.

GitHub [issues](https://github.com/stakach/userspace-ntos/issues) and [milestones](https://github.com/stakach/userspace-ntos/milestones) track implementation and validation. Crate tests run in [CI](https://github.com/stakach/userspace-ntos/actions/workflows/ci.yml).

## License

This repository is licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. It is an independent reimplementation of NT concepts and is not affiliated with Microsoft. Windows and Windows NT are Microsoft trademarks. The downloaded LiberNT userspace has [its own licenses](https://github.com/ahmedarif193/LiberNT), including GPL-3.0 and licenses retained from ReactOS; it is fetched separately and is not covered by this repository's source license.
