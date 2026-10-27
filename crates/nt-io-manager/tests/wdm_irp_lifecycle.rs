use nt_io_manager::{
    initialize_wdm_irp_packet, reuse_wdm_irp_packet, WdmLayoutError,
    WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE,
};

const IRP: u64 = 0x1234_5000;
const STACKS: u8 = 2;
const SIZE: usize = WDM_X64_IRP_SIZE + STACKS as usize * WDM_X64_IO_STACK_LOCATION_SIZE;

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn initialize_sets_reactos_header_terminal_stack_and_self_linked_thread_entry() {
    let mut bytes = vec![0xcc; SIZE + 16];
    initialize_wdm_irp_packet(&mut bytes, IRP, SIZE as u16, STACKS, 1).unwrap();
    assert_eq!(u16_at(&bytes, 0), 6);
    assert_eq!(u16_at(&bytes, 2), SIZE as u16);
    assert_eq!(bytes[0x42], STACKS);
    assert_eq!(bytes[0x43], STACKS + 1);
    assert_eq!(bytes[0x46], 1);
    assert_eq!(u64_at(&bytes, 0x20), IRP + 0x20);
    assert_eq!(u64_at(&bytes, 0x28), IRP + 0x20);
    assert_eq!(u64_at(&bytes, 0xb8), IRP + SIZE as u64);
    assert!(bytes[..SIZE].iter().enumerate().all(|(i, b)| {
        matches!(i, 0 | 2 | 3 | 0x20..=0x27 | 0x28..=0x2f | 0x42 | 0x43 | 0x46 | 0xb8..=0xbf)
            || *b == 0
    }));
    assert_eq!(&bytes[SIZE..], &[0xcc; 16]);
}

#[test]
fn reuse_resets_packet_and_preserves_only_allocation_flags_and_new_status() {
    let mut bytes = vec![0xcc; SIZE];
    initialize_wdm_irp_packet(&mut bytes, IRP, SIZE as u16, STACKS, 0).unwrap();
    bytes[0x47] = 0x23; // AllocationFlags
    bytes[0x10] = 0xff; // stale Flags
    bytes[WDM_X64_IRP_SIZE] = 0x81; // stale first IO_STACK_LOCATION
    reuse_wdm_irp_packet(&mut bytes, IRP, 0xc000_0010_u32 as i32, false, 1).unwrap();
    assert_eq!(bytes[0x47], 0x23);
    assert_eq!(u16_at(&bytes, 0), 6);
    assert_eq!(u16_at(&bytes, 2), SIZE as u16);
    assert_eq!(bytes[0x42], STACKS);
    assert_eq!(bytes[0x43], STACKS + 1);
    assert_eq!(bytes[0x46], 1);
    assert_eq!(&bytes[0x30..0x34], &0xc000_0010_u32.to_le_bytes());
    assert_eq!(bytes[0x10], 0);
    assert_eq!(bytes[WDM_X64_IRP_SIZE], 0);
    assert_eq!(u64_at(&bytes, 0xb8), IRP + SIZE as u64);
}

#[test]
fn reuse_rejects_active_ownership_cancel_routine_and_queued_thread_without_mutation() {
    let mut bytes = vec![0xcc; SIZE];
    initialize_wdm_irp_packet(&mut bytes, IRP, SIZE as u16, STACKS, 0).unwrap();
    let original = bytes.clone();
    assert_eq!(reuse_wdm_irp_packet(&mut bytes, IRP, 0, true, 0), Err(WdmLayoutError::InvalidField));
    assert_eq!(bytes, original);
    bytes[0x68] = 1; // CancelRoutine
    let original = bytes.clone();
    assert_eq!(reuse_wdm_irp_packet(&mut bytes, IRP, 0, false, 0), Err(WdmLayoutError::InvalidField));
    assert_eq!(bytes, original);
    bytes[0x68] = 0;
    bytes[0x20] = 1; // ThreadListEntry.Flink no longer points to self.
    let original = bytes.clone();
    assert_eq!(reuse_wdm_irp_packet(&mut bytes, IRP, 0, false, 0), Err(WdmLayoutError::InvalidField));
    assert_eq!(bytes, original);
}

#[test]
fn initialize_rejects_short_or_invalid_packet_without_mutation() {
    let mut bytes = vec![0xcc; SIZE];
    let original = bytes.clone();
    assert_eq!(initialize_wdm_irp_packet(&mut bytes, IRP, (SIZE - 1) as u16, STACKS, 0), Err(WdmLayoutError::InvalidField));
    assert_eq!(bytes, original);
    assert_eq!(initialize_wdm_irp_packet(&mut bytes[..SIZE - 1], IRP, SIZE as u16, STACKS, 0), Err(WdmLayoutError::BufferTooSmall));
    assert_eq!(bytes, original);
    assert_eq!(initialize_wdm_irp_packet(&mut bytes, IRP, SIZE as u16, 0, 0), Err(WdmLayoutError::InvalidField));
    assert_eq!(bytes, original);
}
