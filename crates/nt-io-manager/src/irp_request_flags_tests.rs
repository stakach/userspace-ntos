use super::*;
use nt_io_abi::major;

const ORIGINS: [IrpRequestFlags; 9] = [
    IrpRequestFlags::NONE,
    IrpRequestFlags::api(true, false),
    IrpRequestFlags::api(false, true),
    IrpRequestFlags::api(true, true),
    IrpRequestFlags::paging(PagingTransfer::Read),
    IrpRequestFlags::paging(PagingTransfer::SynchronousWrite),
    IrpRequestFlags::paging(PagingTransfer::AsynchronousWrite),
    IrpRequestFlags::file_size_update(),
    IrpRequestFlags::mount_completion(),
];

#[test]
fn values_match_the_wdk_definitions() {
    // ReactOS sdk/include/xdk/iotypes.h, wdm.h.
    assert_eq!(
        (IRP_NOCACHE, IRP_PAGING_IO, IRP_MOUNT_COMPLETION, IRP_SYNCHRONOUS_API),
        (0x1, 0x2, 0x2, 0x4)
    );
    assert_eq!(IRP_SYNCHRONOUS_PAGING_IO, 0x40);
    assert_eq!(IRP_SYNCHRONOUS_PAGING_IO, crate::kernel_irp_builder::IRP_INPUT_OPERATION);
}

#[test]
fn paging_transfers_carry_the_memory_manager_words() {
    // ReactOS iofunc.c IoPageRead/IoSynchronousPageWrite; NT5 iosubs.c IoAsynchronousPageWrite.
    assert_eq!(
        IrpRequestFlags::paging(PagingTransfer::Read).bits(),
        IRP_PAGING_IO | IRP_NOCACHE | IRP_SYNCHRONOUS_PAGING_IO
    );
    assert_eq!(
        IrpRequestFlags::paging(PagingTransfer::SynchronousWrite).bits(),
        IRP_PAGING_IO | IRP_NOCACHE | IRP_SYNCHRONOUS_PAGING_IO
    );
    assert_eq!(
        IrpRequestFlags::paging(PagingTransfer::AsynchronousWrite).bits(),
        IRP_PAGING_IO | IRP_NOCACHE
    );
    assert_eq!(
        IrpRequestFlags::mount_completion().bits(),
        IRP_MOUNT_COMPLETION | IRP_SYNCHRONOUS_PAGING_IO
    );
    assert_eq!(IrpRequestFlags::default().bits(), 0);
    for origin in ORIGINS {
        assert_eq!(
            origin.is_paging_io(),
            origin.paging_transfer().is_some() || origin == IrpRequestFlags::file_size_update(),
            "{origin:?}"
        );
    }
}

#[test]
fn the_memory_managers_file_size_update_is_paging_set_information() {
    // NT5 fsrtl/fastio.c FsRtlSetFileSize: Irp->Flags = IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO.
    let update = IrpRequestFlags::file_size_update();
    assert_eq!(update.bits(), IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO);
    assert!(update.is_paging_io() && update.paging_transfer().is_none());
    for value in 0..=0x1b_u8 {
        assert_eq!(update.admits(value, 0), value == major::IRP_MJ_SET_INFORMATION, "{value:#x}");
    }
    assert_eq!(IrpRequestFlags::from_wire(major::IRP_MJ_SET_INFORMATION, 0, 0x42), Some(update));
    // A filesystem passing it down keeps it, buffered or not: a SET returns no data.
    for raw in [0x42, 0x72] {
        assert_eq!(IrpRequestFlags::from_driver_irp(major::IRP_MJ_SET_INFORMATION, 0, raw)
            .unwrap().request, update);
    }
}

#[test]
fn paging_and_mount_bits_are_confined_to_their_majors() {
    let paging_read = IrpRequestFlags::paging(PagingTransfer::Read);
    let paging_write = IrpRequestFlags::paging(PagingTransfer::AsynchronousWrite);
    assert!(paging_read.admits(major::IRP_MJ_READ, 0));
    assert!(!paging_read.admits(major::IRP_MJ_WRITE, 0));
    assert!(paging_write.admits(major::IRP_MJ_WRITE, 0));
    assert!(!paging_write.admits(major::IRP_MJ_READ, 0));
    let mount = IrpRequestFlags::mount_completion();
    assert!(mount.admits(major::IRP_MJ_FILE_SYSTEM_CONTROL, 1));
    assert!(mount.admits(major::IRP_MJ_FILE_SYSTEM_CONTROL, 2));
    assert!(!mount.admits(major::IRP_MJ_FILE_SYSTEM_CONTROL, 0));
    assert!(!IrpRequestFlags::api(false, true).admits(major::IRP_MJ_QUERY_INFORMATION, 0));
    assert!(IrpRequestFlags::api(true, false).admits(major::IRP_MJ_QUERY_INFORMATION, 0));
    for value in 0..=0x1b_u8 {
        if !matches!(value, major::IRP_MJ_READ | major::IRP_MJ_WRITE) {
            for transfer in [
                PagingTransfer::Read,
                PagingTransfer::SynchronousWrite,
                PagingTransfer::AsynchronousWrite,
            ] {
                assert!(!IrpRequestFlags::paging(transfer).admits(value, 0));
            }
        }
    }
}

#[test]
fn wire_decode_accepts_exactly_the_admitted_words() {
    for value in 0..=0x1b_u8 {
        for minor in 0..4u8 {
            for bits in 0..0x1_0000u32 {
                let expected = ORIGINS
                    .into_iter()
                    .find(|origin| origin.admits(value, minor) && origin.bits() == bits);
                assert_eq!(
                    IrpRequestFlags::from_wire(value, minor, bits),
                    expected,
                    "major={value:#x} minor={minor} bits={bits:#x}"
                );
            }
        }
    }
    for origin in ORIGINS {
        for value in 0..=0x1b_u8 {
            for minor in 0..4u8 {
                if origin.admits(value, minor) {
                    assert_eq!(IrpRequestFlags::from_wire(value, minor, origin.bits()), Some(origin));
                }
            }
        }
    }
    // The aliased bit means paging only on transfers and mount completion only on mount FSCTLs.
    assert_eq!(
        IrpRequestFlags::from_wire(major::IRP_MJ_READ, 0, IRP_PAGING_IO),
        None
    );
    assert_eq!(
        IrpRequestFlags::from_wire(major::IRP_MJ_CREATE, 0, IRP_PAGING_IO | IRP_NOCACHE),
        None
    );
}

const IRP_ASSOCIATED_IRP: u32 = 0x08;
const IRP_CREATE_OPERATION: u32 = 0x80;
const IRP_DEFER_IO_COMPLETION: u32 = 0x800;

fn split(major: u8, raw: u32) -> Option<DriverIrpFlags> {
    IrpRequestFlags::from_driver_irp(major, 0, raw)
}

#[test]
fn builder_irps_carry_only_their_transfer_method() {
    // ReactOS iomgr/irp.c: IoBuildAsynchronousFsdRequest (and IoBuildSynchronousFsdRequest,
    // which wraps it) and IoBuildDeviceIoControlRequest set no request-wide bit.
    use crate::kernel_irp_builder::{
        plan_device_io_control_request, plan_synchronous_fsd_request, DO_BUFFERED_IO,
        DO_DIRECT_IO,
    };
    for device_flags in [DO_BUFFERED_IO, DO_DIRECT_IO, 0] {
        for major in [major::IRP_MJ_READ, major::IRP_MJ_WRITE] {
            let plan = plan_synchronous_fsd_request(
                major, 2, device_flags, 0x200, 0x1000, 0x200, Some(0),
            )
            .unwrap();
            let flags = split(major, plan.irp_flags).expect("builder word");
            assert_eq!(flags.request, IrpRequestFlags::NONE, "{major:#x} {device_flags:#x}");
            assert_eq!(flags.buffer_method, plan.irp_flags);
        }
    }
    // METHOD_BUFFERED with an output buffer sets IRP_INPUT_OPERATION.
    let plan = plan_device_io_control_request(0x0007_0000, false, 2, 0x200, 0x1000, 0x10, 0x2000, 0x20)
        .unwrap();
    assert_ne!(plan.irp_flags & IRP_INPUT_OPERATION, 0);
    let flags = split(major::IRP_MJ_DEVICE_CONTROL, plan.irp_flags).expect("IOCTL word");
    assert_eq!(flags.request, IrpRequestFlags::NONE);
    assert_eq!(flags.buffer_method, plan.irp_flags);
}

#[test]
fn driver_set_request_bits_follow_the_issued_combinations() {
    // A filesystem's paging I/O passed down keeps IoPageRead/IoSynchronousPageWrite's word.
    let paging_read = IrpRequestFlags::paging(PagingTransfer::Read);
    let sync_write = IrpRequestFlags::paging(PagingTransfer::SynchronousWrite);
    let async_write = IrpRequestFlags::paging(PagingTransfer::AsynchronousWrite);
    assert_eq!(split(major::IRP_MJ_READ, 0x43).unwrap().request, paging_read);
    assert_eq!(split(major::IRP_MJ_WRITE, 0x43).unwrap().request, sync_write);
    assert_eq!(split(major::IRP_MJ_WRITE, 0x03).unwrap().request, async_write);
    // A buffered READ's IRP_INPUT_OPERATION is its method bit and implies the synchronous bit.
    let buffered = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
    let read = split(major::IRP_MJ_READ, buffered | IRP_INPUT_OPERATION | 0x03).unwrap();
    assert_eq!((read.request, read.buffer_method), (paging_read, buffered | IRP_INPUT_OPERATION));
    // A buffered WRITE never returns data: 0x40 stays the synchronous paging bit.
    let write = split(major::IRP_MJ_WRITE, buffered | 0x43).unwrap();
    assert_eq!((write.request, write.buffer_method), (sync_write, buffered));
    assert_eq!(split(major::IRP_MJ_WRITE, buffered | 0x03).unwrap().request, async_write);
    // Non-cached I/O a filesystem sends to its volume, and a caller waiting on its own event.
    assert_eq!(split(major::IRP_MJ_READ, IRP_NOCACHE).unwrap().request, IrpRequestFlags::api(false, true));
    assert_eq!(
        split(major::IRP_MJ_DEVICE_CONTROL, IRP_SYNCHRONOUS_API).unwrap().request,
        IrpRequestFlags::api(true, false)
    );
}

#[test]
fn illegal_driver_words_are_refused() {
    for (major, raw) in [
        (major::IRP_MJ_READ, IRP_PAGING_IO),                          // no async page read in NT5
        (major::IRP_MJ_READ, IRP_PAGING_IO | IRP_NOCACHE),
        (major::IRP_MJ_CREATE, IRP_PAGING_IO | IRP_NOCACHE),
        (major::IRP_MJ_DEVICE_CONTROL, IRP_NOCACHE),
        (major::IRP_MJ_DEVICE_CONTROL, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO),
        (major::IRP_MJ_READ, IRP_DEALLOCATE_BUFFER),                  // dealloc needs a buffer
        (major::IRP_MJ_READ, IRP_ASSOCIATED_IRP),
        (major::IRP_MJ_READ, IRP_CREATE_OPERATION),
        (major::IRP_MJ_WRITE, IRP_DEFER_IO_COMPLETION),
        (major::IRP_MJ_WRITE, IRP_INPUT_OPERATION),                   // sync bit without paging
        (major::IRP_MJ_FILE_SYSTEM_CONTROL, IRP_MOUNT_COMPLETION | IRP_SYNCHRONOUS_PAGING_IO),
    ] {
        assert_eq!(split(major, raw), None, "major={major:#x} raw={raw:#x}");
    }
}

#[test]
fn driver_words_round_trip_through_the_request_contract() {
    for major in 0..=0x1b_u8 {
        for minor in 0..4u8 {
            for raw in 0..0x4000u32 {
                let Some(flags) = IrpRequestFlags::from_driver_irp(major, minor, raw) else {
                    continue;
                };
                assert!(flags.request.admits(major, minor), "major={major:#x} raw={raw:#x}");
                let shared = flags.buffer_method & IRP_INPUT_OPERATION;
                assert_eq!((flags.request.bits() & !shared) | flags.buffer_method, raw);
                if raw & IRP_BUFFERED_IO == 0 {
                    assert_eq!(flags.buffer_method, 0);
                    assert_eq!(IrpRequestFlags::from_wire(major, minor, raw), Some(flags.request));
                }
            }
        }
    }
}
