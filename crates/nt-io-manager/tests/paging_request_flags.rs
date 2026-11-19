//! Memory Manager paging transfers carry request-wide IRP flags to the driver, as NT's
//! IoPageRead / IoSynchronousPageWrite / IoAsynchronousPageWrite do (ReactOS iofunc.c).

use std::{cell::RefCell, rc::Rc};

use nt_io_abi::major;
use nt_io_manager::irp_request_flags::{IrpRequestFlags, PagingTransfer};
use nt_io_manager::*;
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, NtPath};

#[derive(Default)]
struct Seen {
    calls: Vec<(u8, IrpRequestFlags, u64, Vec<u8>)>,
}

struct Backend(Rc<RefCell<Seen>>);

impl DriverDispatchBackend for Backend {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        if is_create(irp.major) || irp.major == major::IRP_MJ_CLEANUP || irp.major == major::IRP_MJ_CLOSE {
            return Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: Some(0x55),
            });
        }
        if let IoParameters::SetInformation(parameters) = &irp.parameters {
            let input = ctx.system_buffer.to_vec();
            self.0.borrow_mut().calls.push((irp.major, irp.request_flags, parameters.info_class as u64, input));
            return Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            });
        }
        let (IoParameters::Read(parameters) | IoParameters::Write(parameters)) = &irp.parameters else {
            panic!("expected a transfer");
        };
        assert_eq!(irp.user_data, 0x55, "the FILE_OBJECT context reaches the paging IRP");
        let input = ctx.system_buffer.to_vec();
        if irp.major == major::IRP_MJ_READ {
            ctx.system_buffer.fill(0xa5);
        }
        self.0.borrow_mut().calls.push((irp.major, irp.request_flags, parameters.offset, input));
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: parameters.length as u64,
            file_context: None,
        })
    }

    fn cancel_irp(&mut self, _: IrpId) -> Result<(), NtStatus> {
        panic!("not cancelled")
    }
}

fn is_create(value: u8) -> bool {
    value == major::IRP_MJ_CREATE
}

fn fixture() -> (IoManager<MockObjectPort>, ClientId, FileId, DeviceId, Rc<RefCell<Seen>>) {
    let seen = Rc::new(RefCell::new(Seen::default()));
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let driver = io
        .create_driver(&NtPath::parse_str(r"\Driver\Paging").unwrap(), Box::new(Backend(seen.clone())))
        .unwrap();
    io.create_device(
        driver,
        Some(&NtPath::parse_str(r"\Device\Paging").unwrap()),
        DeviceType::DISK_FILE_SYSTEM,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )
    .unwrap();
    let handle = io
        .open(
            client,
            &NtPath::parse_str(r"\Device\Paging").unwrap(),
            AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
            ShareAccess::READ,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
            0,
        )
        .unwrap();
    let (file, device, _) = io
        .reference_open_file_details(client, handle, AccessMask::GENERIC_READ)
        .unwrap();
    seen.borrow_mut().calls.clear();
    (io, client, file, device, seen)
}

#[test]
fn paging_reads_and_writes_reach_the_driver_with_memory_manager_flags() {
    let (mut io, client, file, device, seen) = fixture();
    let mut page = vec![0u8; 0x1000];
    let result = io
        .build_and_dispatch_paging_to_device(
            client, device, file, 9, PagingTransfer::Read, 0x2000, &mut page,
        )
        .unwrap();
    assert!(matches!(result, ExternalDispatchResult::Completed { information: 0x1000, .. }));
    assert!(page.iter().all(|byte| *byte == 0xa5));
    let mut dirty = vec![0x3c; 0x1000];
    for transfer in [PagingTransfer::SynchronousWrite, PagingTransfer::AsynchronousWrite] {
        io.build_and_dispatch_paging_to_device(client, device, file, 9, transfer, 0x3000, &mut dirty)
            .unwrap();
    }
    let calls = &seen.borrow().calls;
    assert_eq!(calls.len(), 3);
    assert_eq!(
        (calls[0].0, calls[0].1, calls[0].2),
        (major::IRP_MJ_READ, IrpRequestFlags::paging(PagingTransfer::Read), 0x2000)
    );
    assert_eq!(calls[0].1.bits(), 0x43, "IRP_PAGING_IO|IRP_NOCACHE|IRP_SYNCHRONOUS_PAGING_IO");
    assert_eq!(calls[1].0, major::IRP_MJ_WRITE);
    assert_eq!(calls[1].1.bits(), 0x43);
    assert_eq!(calls[2].1.bits(), 0x03, "IoAsynchronousPageWrite: IRP_PAGING_IO|IRP_NOCACHE");
    assert!(calls[1].3.iter().all(|byte| *byte == 0x3c), "the dirty page is the write input");
}

#[test]
fn ordinary_transfers_carry_no_paging_bits() {
    let (mut io, client, file, device, seen) = fixture();
    let mut output = vec![0u8; 16];
    io.build_and_dispatch_external_to_device(
        client,
        device,
        Some(file),
        0,
        9,
        major::IRP_MJ_READ,
        IoParameters::Read(ReadWriteParameters { length: 16, key: 0, offset: 0 }),
        0,
        16,
        &mut output,
    )
    .unwrap();
    let calls = &seen.borrow().calls;
    assert_eq!(calls[0].1, IrpRequestFlags::NONE);
    assert!(!calls[0].1.is_paging_io());
}

#[test]
fn paging_transfers_require_a_transfer_on_the_files_own_device() {
    let (mut io, client, file, device, seen) = fixture();
    let mut empty = [];
    assert_eq!(
        io.build_and_dispatch_paging_to_device(client, device, file, 9, PagingTransfer::Read, 0, &mut empty),
        Err(NtStatus::INVALID_PARAMETER)
    );
    let mut page = vec![0u8; 0x1000];
    assert_eq!(
        io.build_and_dispatch_paging_to_device(client, DeviceId(device.raw() + 99), file, 9, PagingTransfer::Read, 0, &mut page)
            .err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
    assert!(seen.borrow().calls.is_empty());
}

#[test]
fn a_file_size_update_is_fsrtl_set_file_size() {
    // NT5 fsrtl/fastio.c FsRtlSetFileSize, as MmCreateSection and MmExtendSection issue it.
    let (mut io, client, file, device, seen) = fixture();
    let result = io.build_and_dispatch_file_size_update(client, device, file, 9, 0x5000).unwrap();
    assert!(matches!(result, ExternalDispatchResult::Completed { status: NtStatus::SUCCESS, .. }));
    let calls = &seen.borrow().calls;
    assert_eq!(
        calls[..],
        [(major::IRP_MJ_SET_INFORMATION, IrpRequestFlags::file_size_update(), 20,
            0x5000i64.to_le_bytes().to_vec())],
        "FileEndOfFileInformation with IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO"
    );
    assert_eq!(calls[0].1.bits(), 0x42);
    drop(calls);
    assert_eq!(
        io.build_and_dispatch_file_size_update(client, device, file, 9, u64::MAX).err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
}
