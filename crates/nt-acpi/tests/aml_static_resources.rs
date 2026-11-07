//! QEMU's q35 DSDT fixture comes from
//! https://github.com/qemu/qemu/blob/master/tests/data/acpi/x86/q35/DSDT
//! SHA-256 b5fbc5a9d438ac80308af94efc639248aaeb54e1a4a481130682dcbba450b5ee.

use nt_acpi::{parse_static_system_io_resources, StaticIoResourceError};

const Q35_DSDT: &[u8] = include_bytes!("fixtures/qemu-q35-dsdt.aml");

fn table_with_terms(terms: &[u8]) -> Vec<u8> {
    let mut table = vec![0u8; 36];
    table[..4].copy_from_slice(b"DSDT");
    table.extend_from_slice(terms);
    let length = table.len() as u32;
    table[4..8].copy_from_slice(&length.to_le_bytes());
    table[9] = 0u8.wrapping_sub(table.iter().copied().fold(0u8, u8::wrapping_add));
    table
}

fn table_with_devices(devices: &[Vec<u8>]) -> Vec<u8> {
    let mut terms = Vec::new();
    for device in devices {
        assert!(device.len() + 1 < 64);
        terms.extend_from_slice(&[0x5b, 0x82, (device.len() + 1) as u8]);
        terms.extend_from_slice(device);
    }
    table_with_terms(&terms)
}

fn literal_port_device(port: u16, name_collision: bool) -> Vec<u8> {
    let mut device = b"TST0".to_vec();
    device.extend_from_slice(&[0x08, b'_', b'H', b'I', b'D', 0x0d]);
    device.extend_from_slice(b"PNP0A06\0");
    device.extend_from_slice(&[0x08, b'_', b'C', b'R', b'S', 0x11, 0x0d, 0x0a, 0x0a]);
    device.extend_from_slice(&[0x47, 0x01]);
    device.extend_from_slice(&port.to_le_bytes());
    device.extend_from_slice(&port.to_le_bytes());
    device.extend_from_slice(&[1, 1, 0x79, 0]);
    if name_collision {
        device.extend_from_slice(&[0x08, b'P', b'R', b'S', b'T', 0]);
    }
    device.extend_from_slice(&[0x5b, 0x80, b'P', b'R', b'S', b'T', 1, 0x0b]);
    device.extend_from_slice(&port.to_le_bytes());
    device.extend_from_slice(&[0x0a, 1]);
    device
}

#[test]
fn duplicate_device_path_cannot_authorize_ports() {
    let table = table_with_devices(&[b"TST0".to_vec(), literal_port_device(0xcd8, false)]);
    assert!(parse_static_system_io_resources(&table, 0x5000).is_err());
}

#[test]
fn name_collision_with_operation_region_cannot_authorize_ports() {
    let table = table_with_devices(&[literal_port_device(0xcd8, true)]);
    assert!(parse_static_system_io_resources(&table, 0x5000).is_err());
}

#[test]
fn named_field_collision_with_operation_region_cannot_authorize_ports() {
    let mut device = literal_port_device(0xcd8, false);
    let region = device
        .windows(4)
        .position(|window| window == b"PRST")
        .unwrap();
    device.splice(
        region - 2..region - 2,
        [
            0x5b, 0x81, 0x0b, b'D', b'U', b'M', b'Y', 0, b'P', b'R', b'S', b'T', 8,
        ],
    );
    let table = table_with_devices(&[device]);
    assert!(parse_static_system_io_resources(&table, 0x5000).is_err());
}

#[test]
fn processor_name_collision_with_device_cannot_authorize_ports() {
    let mut terms = vec![0x5b, 0x83, 0x0b, b'T', b'S', b'T', b'0', 0, 0, 0, 0, 0, 0];
    let device = literal_port_device(0xcd8, false);
    terms.extend_from_slice(&[0x5b, 0x82, (device.len() + 1) as u8]);
    terms.extend_from_slice(&device);
    let table = table_with_terms(&terms);
    assert!(parse_static_system_io_resources(&table, 0x5000).is_err());
}

#[test]
fn final_io_port_has_valid_exclusive_end() {
    let table = table_with_devices(&[literal_port_device(0xffff, false)]);
    let resources = parse_static_system_io_resources(&table, 0x5000).unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!((resources[0].start, resources[0].length), (0xffff, 1));
}

#[test]
fn q35_cpu_hotplug_io_is_backed_by_matching_crs_and_operation_region() {
    let resources = parse_static_system_io_resources(Q35_DSDT, 0x7f7a_0000).unwrap();
    let cpu = resources
        .iter()
        .find(|resource| resource.hardware_id == "PNP0A06" && resource.start == 0xcd8)
        .expect("Q35 CPU hotplug resource");
    assert_eq!(cpu.length, 12);
    assert_eq!(cpu.region_name, *b"PRST");
    assert_eq!(cpu.table_address, 0x7f7a_0000);
    assert_eq!(cpu.table_length, Q35_DSDT.len() as u32);
    assert_eq!(cpu.namespace_path, "\\_SB_.PCI0.PRES");
}

#[test]
fn corrupt_table_checksum_cannot_authorize_io() {
    let mut bytes = Q35_DSDT.to_vec();
    bytes[80] ^= 1;
    assert_eq!(
        parse_static_system_io_resources(&bytes, 0x7f7a_0000),
        Err(StaticIoResourceError::InvalidChecksum)
    );
}

#[test]
fn matching_crs_without_region_cannot_authorize_io() {
    let mut bytes = Q35_DSDT.to_vec();
    let position = bytes
        .windows(4)
        .position(|window| window == b"PRST")
        .unwrap();
    assert_eq!(&bytes[position - 2..position], &[0x5b, 0x80]);
    assert_eq!(bytes[position + 4], 1);
    bytes[position + 4] = 0; // SystemMemory is not I/O-port authority.
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().copied().fold(0u8, u8::wrapping_add));
    let resources = parse_static_system_io_resources(&bytes, 0x7f7a_0000).unwrap();
    assert!(
        !resources.iter().any(|resource| resource.start == 0xcd8),
        "{resources:?}"
    );
}

#[test]
fn region_outside_exact_crs_cannot_authorize_io() {
    let mut bytes = Q35_DSDT.to_vec();
    let position = bytes
        .windows(4)
        .position(|window| window == b"PRST")
        .unwrap();
    assert_eq!(&bytes[position + 5..position + 8], &[0x0b, 0xd8, 0x0c]);
    bytes[position + 6] = 0xdc; // Region starts at 0xCDC, while _CRS still starts at 0xCD8.
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().copied().fold(0u8, u8::wrapping_add));
    let resources = parse_static_system_io_resources(&bytes, 0x7f7a_0000).unwrap();
    assert!(!resources.iter().any(|resource| resource.start == 0xcd8));
}

#[test]
fn dynamic_region_operand_fails_closed() {
    let mut bytes = Q35_DSDT.to_vec();
    let position = bytes
        .windows(4)
        .position(|window| window == b"PRST")
        .unwrap();
    bytes[position + 5] = 0x68; // Arg0 is not a literal integer address.
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().copied().fold(0u8, u8::wrapping_add));
    assert!(parse_static_system_io_resources(&bytes, 0x7f7a_0000).is_err());
}

#[test]
fn absolute_hid_outside_device_cannot_pair_with_local_crs_and_region() {
    let mut device = Vec::new();
    device.extend_from_slice(b"TST0");
    device.extend_from_slice(&[0x08, b'\\', 0x2e]);
    device.extend_from_slice(b"OUT__HID");
    device.push(0x0d);
    device.extend_from_slice(b"PNP0A06\0");
    device.push(0x08);
    device.extend_from_slice(b"_CRS");
    device.extend_from_slice(&[
        0x11, 0x0d, 0x0a, 0x0a, 0x47, 0x01, 0xd8, 0x0c, 0xd8, 0x0c, 0x01, 0x0c, 0x79, 0x00,
    ]);
    device.extend_from_slice(&[0x5b, 0x80]);
    device.extend_from_slice(b"PRST");
    device.extend_from_slice(&[0x01, 0x0b, 0xd8, 0x0c, 0x0a, 0x0c]);
    assert!(device.len() + 1 < 64);

    let mut table = vec![0u8; 36];
    table[..4].copy_from_slice(b"DSDT");
    table.extend_from_slice(&[0x5b, 0x82, (device.len() + 1) as u8]);
    table.extend_from_slice(&device);
    let length = table.len() as u32;
    table[4..8].copy_from_slice(&length.to_le_bytes());
    table[9] = 0u8.wrapping_sub(table.iter().copied().fold(0u8, u8::wrapping_add));
    assert!(parse_static_system_io_resources(&table, 0x5000)
        .unwrap()
        .is_empty());
}

#[test]
fn duplicate_device_hid_fails_closed() {
    let mut bytes = Q35_DSDT.to_vec();
    let start = bytes
        .windows(4)
        .position(|window| window == b"PRST")
        .unwrap()
        - 80;
    let uid = bytes[start..]
        .windows(4)
        .position(|window| window == b"_UID")
        .unwrap()
        + start;
    bytes[uid..uid + 4].copy_from_slice(b"_HID");
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().copied().fold(0u8, u8::wrapping_add));
    assert!(parse_static_system_io_resources(&bytes, 0x7f7a_0000).is_err());
}
