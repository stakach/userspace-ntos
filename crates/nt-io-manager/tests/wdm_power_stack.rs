use nt_io_manager::{write_wdm_io_stack_location, WdmIoStackLocationInit, WdmIoStackParameters};

#[test]
fn device_power_stack_uses_wdk_pointer_aligned_union_fields() {
    let mut bytes = [0u8; 72];
    write_wdm_io_stack_location(&mut bytes, WdmIoStackLocationInit {
        major: nt_power_types::IRP_MJ_POWER,
        minor: nt_power_types::IRP_MN_SET_POWER,
        parameters: WdmIoStackParameters::Power {
            system_context: 0x1234_5678,
            state_type: 1,
            state: 3,
            shutdown_type: 5,
        },
        ..Default::default()
    }).unwrap();
    assert_eq!(bytes[0], nt_power_types::IRP_MJ_POWER);
    assert_eq!(bytes[1], nt_power_types::IRP_MN_SET_POWER);
    assert_eq!(&bytes[16..20], &1u32.to_le_bytes());
    assert_eq!(&bytes[24..28], &3u32.to_le_bytes());
    assert_eq!(&bytes[8..12], &0x1234_5678u32.to_le_bytes());
    assert_eq!(&bytes[12..16], &[0; 4]);
    assert_eq!(&bytes[32..36], &5u32.to_le_bytes());
}

#[test]
fn wait_wake_uses_system_power_state_at_union_start() {
    let mut bytes = [0u8; 72];
    write_wdm_io_stack_location(&mut bytes, WdmIoStackLocationInit {
        major: nt_power_types::IRP_MJ_POWER,
        minor: nt_power_types::IRP_MN_WAIT_WAKE,
        parameters: WdmIoStackParameters::WaitWake { state: 4 },
        ..Default::default()
    }).unwrap();
    assert_eq!(&bytes[8..12], &4u32.to_le_bytes());
    assert_eq!(&bytes[16..28], &[0; 12]);
}
