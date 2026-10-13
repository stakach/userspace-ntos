use nt_pnp::{
    admit_bus_reported_platform_resources, PlatformInterruptResource, PlatformPortResource,
};

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| (byte as char).to_digit(16).unwrap() as u8;
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn keyboard_reports() -> (Vec<u8>, Vec<u8>) {
    // Exact bus-query bytes captured from the accepted ReactOS ACPI keyboard PDO. Opaque
    // reserved bytes are deliberately retained, including the trailing bytes of port #2.
    (
        hex_bytes("01000000000000000000000001000100030000000102110060000000000000000100000000010000010211006400000000000000010000005026830e020101000100000001000000ffffffffffffffff"),
        hex_bytes("88000000000000000000000000000000000000000000000000000000010000000100010003000000000102001100000001000000010000006000000000000000600000000000000000010200110000000100000001000000640000000000000064000000000000000102010001000000010000000100000000000000000000000000000000000000"),
    )
}

fn mouse_reports() -> (Vec<u8>, Vec<u8>) {
    (
        hex_bytes("0100000000000000000000000100010001000000020101000c0000000c000000ffffffffffffffff"),
        hex_bytes("4800000000000000000000000000000000000000000000006028830e01000000010001000100000001020100010000000c0000000c000000a028830e000100000000000000000000"),
    )
}

fn irq(line: u32, vector: u32) -> PlatformInterruptResource {
    PlatformInterruptResource {
        level: line,
        vector,
        affinity: 1,
        latched: true,
        shared: false,
    }
}

#[test]
fn keyboard_keeps_exact_bus_bytes_and_requires_both_physical_ports() {
    let (raw, requirements) = keyboard_reports();
    let ports = [
        PlatformPortResource { start: 0x60, length: 1 },
        PlatformPortResource { start: 0x64, length: 1 },
    ];
    let admitted = admit_bus_reported_platform_resources(&raw, &requirements, &ports, irq(1, 33))
        .expect("both physical ports and the IRQ admit the accepted PDO");
    assert_eq!(admitted.raw_resources, raw);
    assert_eq!(admitted.resource_requirements, requirements);
    assert_eq!(admitted.ports.iter().map(|port| port.start).collect::<Vec<_>>(), [0x60, 0x64]);
    assert_eq!(admitted.raw_interrupt.vector, 1);
    assert_eq!(admitted.translated_interrupt.vector, 33);

    let root_port_control = [PlatformPortResource { start: 0, length: 0x1_0000 }];
    assert!(admit_bus_reported_platform_resources(&raw, &requirements, &root_port_control, irq(1, 33)).is_ok());

    assert!(admit_bus_reported_platform_resources(&raw, &requirements, &ports[..1], irq(1, 33)).is_err());
    assert!(admit_bus_reported_platform_resources(&raw, &requirements, &ports, irq(12, 33)).is_err());
}

#[test]
fn mouse_accepts_an_interrupt_only_and_rejects_changed_bus_evidence() {
    let (raw, requirements) = mouse_reports();
    let admitted = admit_bus_reported_platform_resources(&raw, &requirements, &[], irq(12, 44))
        .expect("IRQ-only PDO is a valid physical assignment");
    assert!(admitted.ports.is_empty());
    assert_eq!(admitted.raw_resources, raw);
    assert_eq!(admitted.raw_interrupt.level, 12);
    assert_eq!(admitted.translated_interrupt.vector, 44);

    let mut changed_requirements = requirements.clone();
    changed_requirements[52] = 11;
    assert!(admit_bus_reported_platform_resources(&raw, &changed_requirements, &[], irq(12, 44)).is_err());
    let mut unsupported_policy = requirements.clone();
    unsupported_policy[56..64].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    assert!(admit_bus_reported_platform_resources(&raw, &unsupported_policy, &[], irq(12, 44)).is_err());
    assert!(admit_bus_reported_platform_resources(&raw[..raw.len() - 1], &requirements, &[], irq(12, 44)).is_err());
}
