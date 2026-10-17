use nt_pnp::acpi_hal_pci_root::{PciRootDescriptor, PciRootLedger, PciRootOwner};

fn root(segment: u32, bus: u32, start: u32, end: u32) -> [u8; 152] {
    let mut raw = [0u8; 152];
    raw[0..4].copy_from_slice(&segment.to_le_bytes());
    raw[4..8].copy_from_slice(&bus.to_le_bytes());
    raw[8] = 1;
    raw[12..16].copy_from_slice(&start.to_le_bytes());
    raw[16..20].copy_from_slice(&end.to_le_bytes());
    raw[64] = 1; // MemoryWindow.Present
    raw[72..80].copy_from_slice(&0x1000u64.to_le_bytes());
    raw[80..88].copy_from_slice(&0x1fffu64.to_le_bytes());
    raw
}

#[test]
fn validates_pinned_root_layout_and_exact_owner() {
    let owner = PciRootOwner { domain_id: 7, domain_cookie: 11, vspace: 13 };
    let other = PciRootOwner { domain_id: 7, domain_cookie: 12, vspace: 13 };
    let parsed = PciRootDescriptor::decode(&root(0, 2, 2, 4)).unwrap();
    let mut ledger = PciRootLedger::new();
    ledger.publish(owner, parsed).unwrap();
    assert_eq!(ledger.lookup(owner, 0, 2), Some(&parsed));
    assert_eq!(ledger.lookup(other, 0, 2), None);
    assert!(ledger.retire(other).is_empty());
    assert_eq!(ledger.lookup(owner, 0, 2), Some(&parsed));
    assert_eq!(ledger.retire(owner).len(), 1);
    assert_eq!(ledger.lookup(owner, 0, 2), None);
}

#[test]
fn malformed_bus_and_memory_windows_fail_before_publication() {
    assert!(PciRootDescriptor::decode(&root(0x1_0000, 2, 2, 4)).is_err());
    assert!(PciRootDescriptor::decode(&root(0, 256, 2, 4)).is_err());
    assert!(PciRootDescriptor::decode(&root(0, 2, 5, 4)).is_err());
    let mut invalid = root(0, 2, 2, 4);
    invalid[72..80].copy_from_slice(&0x2000u64.to_le_bytes());
    assert!(PciRootDescriptor::decode(&invalid).is_err());
}
