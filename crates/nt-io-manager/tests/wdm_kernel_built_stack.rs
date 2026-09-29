use nt_io_abi::major;
use nt_io_manager::{
    decode_wdm_kernel_built_io_stack, write_wdm_io_stack_location, WdmIoStackLocationInit,
    WdmIoStackParameters, WdmLayoutError, WDM_X64_IO_STACK_LOCATION_SIZE,
};

fn round_trip(init: WdmIoStackLocationInit) {
    let mut bytes = [0u8; WDM_X64_IO_STACK_LOCATION_SIZE];
    write_wdm_io_stack_location(&mut bytes, init).unwrap();
    assert_eq!(decode_wdm_kernel_built_io_stack(&bytes), Ok(init));
}

#[test]
fn decodes_caller_mutated_target_device_relation_stack() {
    let base = WdmIoStackLocationInit {
        major: major::IRP_MJ_PNP,
        device_object: 0x1000_2000,
        ..WdmIoStackLocationInit::default()
    };
    let mut bytes = [0u8; WDM_X64_IO_STACK_LOCATION_SIZE];
    write_wdm_io_stack_location(&mut bytes, base).unwrap();
    bytes[1] = nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS;
    bytes[0x08..0x0c].copy_from_slice(&nt_pnp_abi::TARGET_DEVICE_RELATION.to_le_bytes());
    assert_eq!(
        decode_wdm_kernel_built_io_stack(&bytes),
        Ok(WdmIoStackLocationInit {
            minor: nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
            parameters: WdmIoStackParameters::PnpQueryDeviceRelations {
                relation_type: nt_pnp_abi::TARGET_DEVICE_RELATION,
            },
            ..base
        })
    );
}

#[test]
fn decodes_read_write_and_control_without_losing_pointer_fields() {
    for init in [
        WdmIoStackLocationInit {
            major: major::IRP_MJ_READ,
            device_object: 0x1000,
            file_object: 0x2000,
            parameters: WdmIoStackParameters::Read {
                length: 123,
                key: 7,
                byte_offset: 0x1_2345_6789,
            },
            ..WdmIoStackLocationInit::default()
        },
        WdmIoStackLocationInit {
            major: major::IRP_MJ_WRITE,
            device_object: 0x3000,
            parameters: WdmIoStackParameters::Write {
                length: 40,
                key: 8,
                byte_offset: 99,
            },
            ..WdmIoStackLocationInit::default()
        },
        WdmIoStackLocationInit {
            major: major::IRP_MJ_DEVICE_CONTROL,
            device_object: 0x4000,
            parameters: WdmIoStackParameters::DeviceControl {
                output_buffer_length: 32,
                input_buffer_length: 16,
                io_control_code: 0x222004,
                type3_input_buffer: 0x5000,
            },
            ..WdmIoStackLocationInit::default()
        },
        WdmIoStackLocationInit {
            major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
            device_object: 0x6000,
            parameters: WdmIoStackParameters::DeviceControl {
                output_buffer_length: 4,
                input_buffer_length: 8,
                io_control_code: 0x800,
                type3_input_buffer: 0,
            },
            ..WdmIoStackLocationInit::default()
        },
    ] {
        round_trip(init);
    }
}

#[test]
fn rejects_short_and_unsupported_stacks() {
    assert_eq!(
        decode_wdm_kernel_built_io_stack(&[0; WDM_X64_IO_STACK_LOCATION_SIZE - 1]),
        Err(WdmLayoutError::BufferTooSmall)
    );
    let mut bytes = [0u8; WDM_X64_IO_STACK_LOCATION_SIZE];
    bytes[0] = major::IRP_MJ_PNP;
    assert_eq!(
        decode_wdm_kernel_built_io_stack(&bytes),
        Err(WdmLayoutError::InvalidField)
    );
    bytes[0] = major::IRP_MJ_READ;
    bytes[1] = 1;
    assert_eq!(
        decode_wdm_kernel_built_io_stack(&bytes),
        Err(WdmLayoutError::InvalidField)
    );
}
