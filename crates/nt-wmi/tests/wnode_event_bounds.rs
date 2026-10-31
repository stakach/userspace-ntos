use nt_wmi::event::{parse_event_header, WnodeError, WNODE_FLAG_EVENT_ITEM};
use nt_wmi::WmiGuid;

fn event(size: u32, provider: u32, flags: u32) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[0..4].copy_from_slice(&size.to_le_bytes());
    bytes[4..8].copy_from_slice(&provider.to_le_bytes());
    bytes[24..40].copy_from_slice(&[0x42; 16]);
    bytes[44..48].copy_from_slice(&flags.to_le_bytes());
    bytes
}

#[test]
fn wnode_must_fit_the_exact_pool_allocation_before_copy_or_transfer() {
    let mut bytes = event(48, 13, WNODE_FLAG_EVENT_ITEM);
    let parsed = parse_event_header(&bytes, 48).unwrap();
    assert_eq!(parsed.provider_id, 13);
    assert_eq!(parsed.buffer_size, 48);
    assert_eq!(parsed.guid, WmiGuid([0x42; 16]));
    bytes[0..4].copy_from_slice(&49u32.to_le_bytes());
    assert_eq!(parse_event_header(&bytes, 48), Err(WnodeError::Bounds));
    assert_eq!(parse_event_header(&bytes[..47], 48), Err(WnodeError::Bounds));
}

#[test]
fn zero_provider_and_non_event_nodes_cannot_enter_delivery() {
    assert_eq!(parse_event_header(&event(48, 0, WNODE_FLAG_EVENT_ITEM), 48), Err(WnodeError::Provider));
    assert_eq!(parse_event_header(&event(48, 13, 0), 48), Err(WnodeError::Flags));
}
