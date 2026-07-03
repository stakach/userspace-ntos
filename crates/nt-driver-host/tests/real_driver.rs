//! Load the **real** MSVC-built `SurtTest.sys` WDM driver through the full Driver
//! Host pipeline (parse → import-check → map → relocate → IAT patch → projections).
//!
//! This build host is aarch64, so `DriverEntry` cannot be executed here — that is
//! proven in QEMU (M9). This test validates the loader + export registry against a
//! real-world x64 kernel binary.

use nt_driver_host::{DriverHost, DriverState};
use nt_driver_test_fixtures::surttest_sys;

const ARENA_BASE: u64 = 0xFFFF_F800_0000_0000;
const TRAMP_BASE: u64 = 0x7F00_0000_0000;

#[test]
fn real_surttest_sys_loads_at_preferred_base() {
    let mut host = DriverHost::new(ARENA_BASE, 256 * 1024, TRAMP_BASE);
    host.load(
        surttest_sys(),
        0x1_4000_0000,
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\SurtTest",
    )
    .expect("real SurtTest.sys should load");
    assert_eq!(host.state(), DriverState::Loaded);

    // All six ntoskrnl.exe imports were resolved + bound to trampolines.
    let bound: Vec<&str> = host
        .bound_trampolines()
        .iter()
        .map(|(_, n, _)| n.as_str())
        .collect();
    for want in [
        "IofCompleteRequest",
        "IoCreateDevice",
        "IoCreateSymbolicLink",
        "IoDeleteDevice",
        "IoDeleteSymbolicLink",
        "RtlInitUnicodeString",
    ] {
        assert!(bound.contains(&want), "import {want} was not bound");
    }

    // DriverEntry is at RVA 0x5000.
    assert_eq!(host.image().unwrap().entry_point(), 0x1_4000_0000 + 0x5000);

    // The /GS cookie is resolvable from the load-config directory (RVA 0x3000).
    let pe = nt_pe_loader::PeFile::parse(surttest_sys()).unwrap();
    assert_eq!(pe.security_cookie_rva(), Some(0x3000));
    assert_eq!(
        pe.protection_at(0x1000),
        nt_pe_loader::Protection::ReadExecute
    ); // .text
    assert_eq!(
        pe.protection_at(0x3000),
        nt_pe_loader::Protection::ReadWrite
    ); // .data (cookie)
}

#[test]
fn real_surttest_sys_relocates_to_a_new_base() {
    // Mapping at a base other than the image's preferred base exercises the real
    // IMAGE_REL_BASED_DIR64 relocation table in the driver.
    let new_base = 0x2_0000_0000u64;
    let mut host = DriverHost::new(ARENA_BASE, 256 * 1024, TRAMP_BASE);
    host.load(surttest_sys(), new_base, "\\Registry\\...")
        .expect("real SurtTest.sys should relocate + load");
    assert_eq!(host.state(), DriverState::Loaded);
    assert_eq!(host.image().unwrap().entry_point(), new_base + 0x5000);
}
