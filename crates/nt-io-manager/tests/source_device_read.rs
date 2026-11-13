use nt_io_manager::kernel_irp_builder::{
    IRP_BUFFERED_IO, IRP_DEALLOCATE_BUFFER, IRP_INPUT_OPERATION,
    SL_OVERRIDE_VERIFY_VOLUME,
};
use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_device_read::{admit_source_device_read, SourceDeviceReadRequest};
use nt_io_manager::source_irp_auxiliary::{
    SourceIrpAuxiliary, SourceIrpAuxiliaryPhase, SourceIrpCompletionOwner,
    SourceMdlAllocationIdentity, SourceMemoryIdentity, SourcePoolAllocationIdentity,
};
use nt_io_manager::source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner};
use nt_io_manager::{HostedDomainId, HostedDomainIdentity};

const DEVICE: u64 = 0x4000;
const SYSTEM: u64 = 0x9000;
const MDL: u64 = 0xa000;
const OUTPUT: u64 = 0xb000;

fn auxiliary() -> SourceIrpAuxiliary {
    let domain = HostedDomainIdentity {
        domain_id: HostedDomainId(7), cookie: 11,
    };
    SourceIrpAuxiliary {
        source: SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(3), domain,
            component_address: 0x2000, bytes: 0x150,
            stack_count: 2, pool_generation: 4,
        },
        ticket: SourceIrpTicket::new(domain, 5, 6).unwrap(),
        system_buffer: None,
        mdl: None,
        transfer_buffer: Some(SourceMemoryIdentity::MappedRange {
            component_address: OUTPUT, bytes: 512, exec_address: 0xc000,
        }),
        buffered_control: None,
        completion: SourceIrpCompletionOwner {
            thread_handle: 9, thread_object: 0x3000,
            event: SourceMemoryIdentity::MappedRange {
                component_address: 0x5000, bytes: 24, exec_address: 0x6000,
            },
            iosb: SourceMemoryIdentity::MappedRange {
                component_address: 0x7000, bytes: 16, exec_address: 0x8000,
            },
        },
    }
}

fn request(auxiliary: SourceIrpAuxiliary) -> SourceDeviceReadRequest {
    SourceDeviceReadRequest {
        source: auxiliary.source,
        ticket: auxiliary.ticket,
        phase: SourceIrpAuxiliaryPhase::Protected,
        major: nt_io_abi::major::IRP_MJ_READ,
        minor: 0,
        device_object: DEVICE,
        target_device_object: DEVICE,
        file_object: 0,
        length: 512,
        key: 0,
        byte_offset: 0,
        stack_flags: SL_OVERRIDE_VERIFY_VOLUME,
        irp_flags: 0,
        system_buffer: 0,
        mdl: 0,
        user_buffer: OUTPUT,
    }
}

#[test]
fn fileless_read_retains_exact_neither_and_buffered_output_through_completion() {
    let neither = auxiliary();
    let admitted = admit_source_device_read(request(neither), neither).unwrap();
    assert_eq!(admitted.output, neither.transfer_buffer.unwrap());
    assert_eq!(admitted.completion, neither.completion);
    assert_eq!(admitted.byte_offset, 0);

    let mut buffered = auxiliary();
    buffered.system_buffer = Some(SourcePoolAllocationIdentity {
        component_address: SYSTEM, capacity: 512, pool_generation: 8,
    });
    let buffered_request = SourceDeviceReadRequest {
        irp_flags: IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION,
        system_buffer: SYSTEM,
        ..request(buffered)
    };
    let admitted = admit_source_device_read(buffered_request, buffered).unwrap();
    assert_eq!(admitted.output, buffered.transfer_buffer.unwrap());
    assert_eq!(admitted.system_buffer, buffered.system_buffer);
}

#[test]
fn direct_read_requires_the_pinned_mdl_and_output_mapping() {
    let mut direct = auxiliary();
    direct.mdl = Some(SourceMdlAllocationIdentity {
        pool: SourcePoolAllocationIdentity {
            component_address: MDL, capacity: 48, pool_generation: 12,
        },
        registry_generation: 13,
    });
    let direct_request = SourceDeviceReadRequest {
        mdl: MDL, user_buffer: 0,
        ..request(direct)
    };
    let admitted = admit_source_device_read(direct_request, direct).unwrap();
    assert_eq!(admitted.mdl, direct.mdl);
    assert_eq!(admitted.output, direct.transfer_buffer.unwrap());
    assert!(admit_source_device_read(SourceDeviceReadRequest {
        mdl: MDL + 1, ..direct_request
    }, direct).is_none());
    assert!(admit_source_device_read(SourceDeviceReadRequest {
        user_buffer: OUTPUT, ..direct_request
    }, direct).is_none());
}

#[test]
fn read_rejects_wrong_device_source_generation_and_mutated_shape() {
    let auxiliary = auxiliary();
    let valid = request(auxiliary);
    for wrong in [
        SourceDeviceReadRequest { target_device_object: DEVICE + 8, ..valid },
        SourceDeviceReadRequest { file_object: 0x1000, ..valid },
        SourceDeviceReadRequest { major: nt_io_abi::major::IRP_MJ_WRITE, ..valid },
        SourceDeviceReadRequest { length: 513, ..valid },
        SourceDeviceReadRequest { irp_flags: IRP_INPUT_OPERATION, ..valid },
        SourceDeviceReadRequest { system_buffer: SYSTEM, ..valid },
        SourceDeviceReadRequest { stack_flags: 0x80, ..valid },
        SourceDeviceReadRequest { phase: SourceIrpAuxiliaryPhase::Completing, ..valid },
        SourceDeviceReadRequest {
            source: SourceIrpAllocation {
                pool_generation: auxiliary.source.pool_generation + 1,
                ..auxiliary.source
            }, ..valid
        },
        SourceDeviceReadRequest {
            ticket: SourceIrpTicket::new(auxiliary.source.domain, 5, 7).unwrap(), ..valid
        },
    ] {
        assert!(admit_source_device_read(wrong, auxiliary).is_none(), "{wrong:?}");
    }
}
