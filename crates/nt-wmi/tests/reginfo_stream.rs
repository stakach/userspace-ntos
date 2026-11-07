use nt_wmi::{WmiDeviceIdentity, WmiGuid, WmiRegistry, STATUS_INVALID_PARAMETER};

const DEVICE: WmiDeviceIdentity = WmiDeviceIdentity {
    domain: 3,
    generation: 9,
    device_object: 0x4000,
};
const GUID: WmiGuid = WmiGuid([0x5a; 16]);

fn packet() -> Vec<u8> {
    let mut bytes = vec![0; 56];
    bytes[0..4].copy_from_slice(&56u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..40].copy_from_slice(&GUID.0);
    bytes
}

#[test]
fn terminal_packet_streams_in_order_before_guid_publication() {
    let mut registry = WmiRegistry::new();
    let provider = registry.register_device(DEVICE).unwrap();
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    assert_eq!(registry.pending_reginfo_identity(ticket.raw()), Some(DEVICE));
    registry.mark_reginfo_dispatched(ticket).unwrap();
    let bytes = packet();
    registry.stage_reginfo_chunk(ticket, 0, &bytes[..17]).unwrap();
    assert_eq!(registry.stage_reginfo_chunk(ticket, 0, &bytes[..17]), Err(STATUS_INVALID_PARAMETER));
    registry.stage_reginfo_chunk(ticket, 17, &bytes[17..]).unwrap();
    assert!(registry.plan_device_event(provider, GUID, 0).is_err());
    registry.complete_streamed_reginfo(ticket, 0).unwrap();
    assert_eq!(registry.pending_reginfo_identity(ticket.raw()), None);
    assert!(registry.plan_device_event(provider, GUID, 0).is_ok());
}

#[test]
fn failed_terminal_releases_stream_without_publishing() {
    let mut registry = WmiRegistry::new();
    let provider = registry.register_device(DEVICE).unwrap();
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    registry.mark_reginfo_dispatched(ticket).unwrap();
    registry.stage_reginfo_chunk(ticket, 0, &packet()).unwrap();
    assert_eq!(registry.complete_streamed_reginfo(ticket, STATUS_INVALID_PARAMETER), Err(STATUS_INVALID_PARAMETER));
    assert!(registry.plan_device_event(provider, GUID, 0).is_err());
    let next = registry.begin_reginfo(DEVICE).unwrap();
    registry.mark_reginfo_dispatched(next).unwrap();
    registry.stage_reginfo_chunk(next, 0, &packet()).unwrap();
    registry.complete_streamed_reginfo(next, 0).unwrap();
    assert!(registry.plan_device_event(provider, GUID, 0).is_ok());
}
