//! Exercise native ACPI port projection with the checksum-valid Q35 DSDT.

use std::process::Command;

#[test]
fn q35_static_system_io_is_projected_with_bounded_authority() {
    let dsdt = include_bytes!("../../nt-acpi/tests/fixtures/qemu-q35-dsdt.aml");
    let resources = nt_acpi::parse_static_system_io_resources(dsdt, 0x3000).unwrap();
    let hotplug = resources
        .iter()
        .find(|resource| resource.hardware_id == "PNP0A06" && resource.region_name == *b"PRST")
        .expect("validated Q35 CPU hotplug SystemIO region");
    let source = include_str!("../../../components/ntos-executive/src/acpi_platform.rs");
    let start = source
        .find("fn project_static_io_ports(")
        .expect("native static I/O projection");
    let end = source[start..]
        .find("\nunsafe fn discover_acpi_platform_authority_inner(")
        .expect("projection boundary")
        + start;
    let function = &source[start..end];
    syn::parse_file(function).expect("extract complete projection function");
    let harness = format!(
        "{STUBS}\nconst HOTPLUG_START: u16 = {start};\nconst HOTPLUG_LENGTH: u16 = {length};\n{function}\n{CASES}",
        start = hotplug.start,
        length = hotplug.length,
    );
    let directory = std::env::temp_dir().join(format!(
        "nt-source-acpi-static-ports-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native ACPI static port fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).arg("--nocapture").output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native static port projection regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const STUBS: &str = r#"
use std::vec::Vec;
mod nt_status {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NtStatus(pub u32);
    impl NtStatus {
        pub const INVALID_PARAMETER: Self = Self(1);
        pub const CONFLICTING_ADDRESSES: Self = Self(2);
        pub const INSUFFICIENT_RESOURCES: Self = Self(3);
    }
}
mod driver_launch { pub const SH_RESOURCE_KIND_CAPACITY: u8 = 16; }
mod nt_acpi {
    pub struct StaticIoResource {
        pub hardware_id: String,
        pub start: u16,
        pub length: u16,
    }
}
#[derive(Clone, Copy)]
struct AcpiPortAuthority {
    resource_index: u8,
    base: u64,
    length: u32,
    platform_reset: bool,
}
"#;

const CASES: &str = r#"
#[cfg(test)] mod cases {
use super::*;
fn resource(id: &str, start: u16, length: u16) -> nt_acpi::StaticIoResource {
    nt_acpi::StaticIoResource { hardware_id: id.into(), start, length }
}
#[test]
fn q35_hotplug_gets_exact_port_authority() {
    let mut ports = Vec::new();
    project_static_io_ports(&mut ports, &[resource("PNP0A06", HOTPLUG_START, HOTPLUG_LENGTH)]).unwrap();
    assert_eq!(ports.len(), 1, "validated Q35 resource must reach native authority");
    assert_eq!((ports[0].resource_index, ports[0].base, ports[0].length, ports[0].platform_reset),
        (0, HOTPLUG_START as u64, HOTPLUG_LENGTH as u32, false));
}
#[test]
fn overlap_with_fixed_register_is_rejected() {
    let mut ports = vec![AcpiPortAuthority {
        resource_index: 0, base: HOTPLUG_START as u64, length: 1, platform_reset: false,
    }];
    assert!(project_static_io_ports(&mut ports,
        &[resource("PNP0A06", HOTPLUG_START, HOTPLUG_LENGTH)]).is_err());
    assert_eq!(ports.len(), 1);
}
#[test]
fn capacity_and_identity_fail_closed() {
    let mut ports = Vec::new();
    project_static_io_ports(&mut ports, &[resource("PNP0C0C", HOTPLUG_START, HOTPLUG_LENGTH)]).unwrap();
    assert!(ports.is_empty());
    ports.extend((0..driver_launch::SH_RESOURCE_KIND_CAPACITY).map(|index| AcpiPortAuthority {
        resource_index: index, base: index as u64 * 16, length: 1, platform_reset: false,
    }));
    assert_eq!(project_static_io_ports(&mut ports,
        &[resource("PNP0A06", HOTPLUG_START, HOTPLUG_LENGTH)]),
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES));
    assert_eq!(ports.len(), driver_launch::SH_RESOURCE_KIND_CAPACITY as usize);
}
}
"#;
