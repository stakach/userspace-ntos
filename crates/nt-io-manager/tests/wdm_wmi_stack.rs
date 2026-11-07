use nt_io_manager::{write_wdm_io_stack_location, WdmIoStackLocationInit, WdmIoStackParameters};

#[test]
fn reginfo_stack_has_x64_wmi_parameter_layout() {
    let mut bytes = [0u8; 0x48];
    write_wdm_io_stack_location(
        &mut bytes,
        WdmIoStackLocationInit {
            major: nt_io_abi::major::IRP_MJ_SYSTEM_CONTROL,
            minor: 8,
            flags: 0,
            control: 0,
            device_object: 0x1000,
            file_object: 0,
            parameters: WdmIoStackParameters::Wmi {
                provider_id: 0x1000,
                data_path: 0,
                buffer_size: 0x400,
                buffer: 0x2000,
            },
        },
    )
    .unwrap();
    assert_eq!(bytes[0], nt_io_abi::major::IRP_MJ_SYSTEM_CONTROL);
    assert_eq!(bytes[1], 8);
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0x1000);
    assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 0x400);
    assert_eq!(u64::from_le_bytes(bytes[32..40].try_into().unwrap()), 0x2000);
}
