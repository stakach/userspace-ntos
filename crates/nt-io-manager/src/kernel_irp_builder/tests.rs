use super::*;
use crate::{
    decode_wdm_kernel_built_io_stack, initialize_wdm_irp_thread_list, write_wdm_io_stack_location,
    write_wdm_irp, write_wdm_irp_completion_targets, WdmIrpInit, WdmLayoutError,
};

#[test]
fn new_kernel_irp_thread_list_is_self_linked_at_final_address() {
    let base = 0x1000_2000u64;
    let mut packet = [0u8; WDM_X64_IRP_SIZE + WDM_X64_IO_STACK_LOCATION_SIZE];
    let packet_size = packet.len() as u16;
    write_wdm_irp(
        &mut packet,
        WdmIrpInit {
            packet_size,
            stack_count: 1,
            current_location: 2,
            current_stack_location: base + packet_size as u64,
            ..Default::default()
        },
    )
    .unwrap();
    initialize_wdm_irp_thread_list(&mut packet, base).unwrap();
    assert_eq!(
        u64::from_le_bytes(packet[0x20..0x28].try_into().unwrap()),
        base + 0x20
    );
    assert_eq!(
        u64::from_le_bytes(packet[0x28..0x30].try_into().unwrap()),
        base + 0x20
    );
    validate_new_kernel_irp_packet(base, &packet, 1).unwrap();
    assert_eq!(
        initialize_wdm_irp_thread_list(&mut packet, u64::MAX),
        Err(WdmLayoutError::InvalidField)
    );
}

#[test]
fn fsd_read_write_buffer_modes_match_reactos() {
    for major in [major::IRP_MJ_READ, major::IRP_MJ_WRITE] {
        let buffered = plan_synchronous_fsd_request(
            major,
            2,
            DO_BUFFERED_IO | DO_DIRECT_IO,
            0x1000,
            0x2000,
            16,
            Some(0x1234_5678),
        )
        .unwrap();
        assert_eq!(
            buffered.packet_size as usize,
            WDM_X64_IRP_SIZE + 2 * WDM_X64_IO_STACK_LOCATION_SIZE
        );
        assert_eq!(
            buffered.next_stack_offset,
            WDM_X64_IRP_SIZE + WDM_X64_IO_STACK_LOCATION_SIZE
        );
        assert_eq!(buffered.system_buffer_len, 16);
        assert_eq!(buffered.mdl, None);
        if major == major::IRP_MJ_READ {
            assert_eq!(
                buffered.irp_flags,
                IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION
            );
            assert_eq!(buffered.user_buffer, 0x2000);
            assert_eq!(buffered.system_buffer_input_len, 0);
        } else {
            assert_eq!(buffered.irp_flags, IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER);
            assert_eq!(buffered.user_buffer, 0);
            assert_eq!(
                (
                    buffered.system_buffer_input,
                    buffered.system_buffer_input_len
                ),
                (0x2000, 16)
            );
        }

        let direct =
            plan_synchronous_fsd_request(major, 1, DO_DIRECT_IO, 0x1000, 0x2000, 16, Some(9))
                .unwrap();
        assert_eq!(direct.system_buffer_len, 0);
        assert_eq!(direct.irp_flags, 0);
        assert_eq!(
            direct.mdl,
            Some(MdlPlan {
                buffer: 0x2000,
                length: 16,
                access: if major == major::IRP_MJ_READ {
                    MdlAccess::Write
                } else {
                    MdlAccess::Read
                },
            })
        );

        let neither =
            plan_synchronous_fsd_request(major, 1, 0, 0x1000, 0x2000, 16, Some(9)).unwrap();
        assert_eq!(neither.user_buffer, 0x2000);
        assert_eq!(neither.mdl, None);
        assert_eq!(neither.system_buffer_len, 0);
    }
}

#[test]
fn fsd_control_majors_ignore_buffer_and_offset() {
    for major in [
        major::IRP_MJ_PNP,
        major::IRP_MJ_POWER,
        major::IRP_MJ_FLUSH_BUFFERS,
        major::IRP_MJ_SHUTDOWN,
    ] {
        let plan = plan_synchronous_fsd_request(major, 1, DO_BUFFERED_IO, 0x1000, 0x2000, 99, None)
            .unwrap();
        assert_eq!(plan.stack.major, major);
        assert_eq!(plan.stack.parameters, WdmIoStackParameters::None);
        assert_eq!(plan.system_buffer_len, 0);
        assert_eq!(plan.user_buffer, 0);
        assert_eq!(plan.mdl, None);
    }
    assert_eq!(
        plan_synchronous_fsd_request(major::IRP_MJ_READ, 1, 0, 1, 2, 4, None),
        Err(KernelIrpPlanError::MissingStartingOffset)
    );
    assert_eq!(
        plan_synchronous_fsd_request(major::IRP_MJ_CREATE, 1, 0, 1, 2, 4, None),
        Err(KernelIrpPlanError::UnsupportedMajor)
    );
    for size in [0, u8::MAX] {
        assert_eq!(
            plan_synchronous_fsd_request(major::IRP_MJ_PNP, size, 0, 1, 0, 0, None),
            Err(KernelIrpPlanError::InvalidStackSize)
        );
    }
}

#[test]
fn ioctl_methods_have_distinct_transfer_and_access_contracts() {
    for internal in [false, true] {
        for method in [
            ioctl::METHOD_BUFFERED,
            ioctl::METHOD_IN_DIRECT,
            ioctl::METHOD_OUT_DIRECT,
            ioctl::METHOD_NEITHER,
        ] {
            let code = ioctl::ctl_code(0x22, 0x800, method, ioctl::FILE_ANY_ACCESS);
            let plan =
                plan_device_io_control_request(code, internal, 3, 0x1000, 0x2000, 6, 0x3000, 9)
                    .unwrap();
            assert_eq!(
                plan.stack.major,
                if internal {
                    major::IRP_MJ_INTERNAL_DEVICE_CONTROL
                } else {
                    major::IRP_MJ_DEVICE_CONTROL
                }
            );
            assert_eq!(plan.stack.device_object, 0x1000);
            assert_eq!(
                plan.stack.parameters,
                WdmIoStackParameters::DeviceControl {
                    output_buffer_length: 9,
                    input_buffer_length: 6,
                    io_control_code: code,
                    type3_input_buffer: if method == ioctl::METHOD_NEITHER {
                        0x2000
                    } else {
                        0
                    },
                }
            );
            match method {
                ioctl::METHOD_BUFFERED => {
                    assert_eq!(plan.system_buffer_len, 9);
                    assert_eq!(
                        (plan.system_buffer_input, plan.system_buffer_input_len),
                        (0x2000, 6)
                    );
                    assert_eq!(
                        plan.irp_flags,
                        IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION
                    );
                    assert_eq!(plan.user_buffer, 0x3000);
                    assert_eq!(plan.mdl, None);
                }
                ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
                    assert_eq!(plan.system_buffer_len, 6);
                    assert_eq!(plan.irp_flags, IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER);
                    assert_eq!(plan.user_buffer, 0);
                    assert_eq!(
                        plan.mdl,
                        Some(MdlPlan {
                            buffer: 0x3000,
                            length: 9,
                            access: if method == ioctl::METHOD_IN_DIRECT {
                                MdlAccess::Read
                            } else {
                                MdlAccess::Write
                            },
                        })
                    );
                }
                ioctl::METHOD_NEITHER => {
                    assert_eq!(plan.system_buffer_len, 0);
                    assert_eq!(plan.irp_flags, 0);
                    assert_eq!(plan.user_buffer, 0x3000);
                    assert_eq!(plan.mdl, None);
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn ioctl_null_and_zero_buffers_follow_builder_contract() {
    let code = ioctl::ctl_code(0x22, 1, ioctl::METHOD_BUFFERED, 0);
    let empty = plan_device_io_control_request(code, false, 1, 7, 0, 0, 0x2000, 0).unwrap();
    assert_eq!(empty.irp_flags, 0);
    assert_eq!(empty.user_buffer, 0);
    let missing_input = plan_device_io_control_request(code, false, 1, 7, 0, 4, 0, 8).unwrap();
    assert_eq!(missing_input.system_buffer_len, 8);
    assert_eq!(missing_input.system_buffer_input_len, 0);
    assert_eq!(
        missing_input.irp_flags,
        IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER
    );
    let direct =
        plan_device_io_control_request(code | ioctl::METHOD_IN_DIRECT, false, 1, 7, 0, 4, 0, 8)
            .unwrap();
    assert_eq!(direct.system_buffer_len, 0);
    assert_eq!(direct.mdl, None);
}

#[test]
fn planned_irp_and_next_stack_roundtrip_without_clobbering_completion_targets() {
    let plan = plan_synchronous_fsd_request(
        major::IRP_MJ_READ,
        2,
        DO_BUFFERED_IO,
        0x1000,
        0x2000,
        8,
        Some(19),
    )
    .unwrap();
    let mut packet = [0xa5; WDM_X64_IRP_SIZE + 2 * WDM_X64_IO_STACK_LOCATION_SIZE];
    let irp_base = 0x8000u64;
    let next_stack = irp_base + plan.next_stack_offset as u64;
    write_wdm_irp(
        &mut packet[..WDM_X64_IRP_SIZE],
        WdmIrpInit {
            packet_size: plan.packet_size,
            flags: plan.irp_flags,
            system_buffer: 0x9000,
            user_buffer: plan.user_buffer,
            thread: 0xa000,
            stack_count: plan.stack_count,
            current_location: plan.stack_count + 1,
            current_stack_location: irp_base + plan.packet_size as u64,
            ..WdmIrpInit::default()
        },
    )
    .unwrap();
    initialize_wdm_irp_thread_list(&mut packet, irp_base).unwrap();
    write_wdm_irp_completion_targets(&mut packet[..WDM_X64_IRP_SIZE], 0xb000, 0xc000).unwrap();
    write_wdm_io_stack_location(&mut packet[plan.next_stack_offset..], plan.stack).unwrap();
    let u64_at = |offset: usize| u64::from_le_bytes(packet[offset..offset + 8].try_into().unwrap());
    assert_eq!(u64_at(0x48), 0xb000);
    assert_eq!(u64_at(0x50), 0xc000);
    assert_eq!(
        u64_at(0xb8),
        next_stack + WDM_X64_IO_STACK_LOCATION_SIZE as u64
    );
    assert_eq!(packet[0x42], 2);
    assert_eq!(packet[0x43], 3);
    assert_eq!(
        decode_wdm_kernel_built_io_stack(&packet[plan.next_stack_offset..]).unwrap(),
        plan.stack
    );
    assert_eq!(validate_new_kernel_irp_packet(irp_base, &packet, 2), Ok(()));
    assert_eq!(
        validate_new_kernel_irp_packet(irp_base, &packet, 1),
        Err(KernelIrpPlanError::InvalidIrpHeader)
    );
    for offset in [0, 2, 0x20, 0x28, 0x42, 0x43, 0xb8] {
        let mut corrupted = packet;
        corrupted[offset] ^= 1;
        assert_eq!(
            validate_new_kernel_irp_packet(irp_base, &corrupted, 2),
            Err(KernelIrpPlanError::InvalidIrpHeader),
            "offset {offset:#x}"
        );
    }
    let mut short = [0xa5; WDM_X64_IRP_SIZE - 1];
    assert_eq!(
        write_wdm_irp_completion_targets(&mut short, 1, 2),
        Err(WdmLayoutError::BufferTooSmall)
    );
    assert_eq!(short, [0xa5; WDM_X64_IRP_SIZE - 1]);
}
