use super::*;
use nt_io_abi::major;

const ORIGINS: [IrpRequestFlags; 8] = [
    IrpRequestFlags::NONE,
    IrpRequestFlags::api(true, false),
    IrpRequestFlags::api(false, true),
    IrpRequestFlags::api(true, true),
    IrpRequestFlags::paging(PagingTransfer::Read),
    IrpRequestFlags::paging(PagingTransfer::SynchronousWrite),
    IrpRequestFlags::paging(PagingTransfer::AsynchronousWrite),
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
            origin.paging_transfer().is_some(),
            "{origin:?}"
        );
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
