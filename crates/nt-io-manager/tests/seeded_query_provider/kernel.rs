//! Registered kernel backends receive the same authoritative query seed as driver peers.

use super::{assert_manager_fields, ACCESS, ALIGNMENT, OUTPUT_LENGTH};
use nt_io_abi::major;
use nt_io_manager::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceId, DeviceType, DispatchContext,
    DispatchOutcome, DriverCompletion, DriverDispatchBackend, ExternalDispatchResult, FileId,
    InformationParameters, IoManager, IoParameters, IrpId, IrpProjection, MockObjectPort,
    ReadWriteParameters, ShareAccess, StackFlags,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, NtPath};
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
struct Observed {
    queries: usize,
    pending: Option<IrpId>,
    ready: bool,
}

struct Backend {
    observed: Rc<RefCell<Observed>>,
    pending: bool,
}

impl DriverDispatchBackend for Backend {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        if irp.major != major::IRP_MJ_QUERY_INFORMATION {
            return Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: Some(0x1234),
            });
        }
        assert_eq!(irp.information, 12);
        assert_manager_fields(ctx.system_buffer);
        assert_eq!(ctx.system_buffer[OUTPUT_LENGTH - 1], 0x5a);
        let mut observed = self.observed.borrow_mut();
        observed.queries += 1;
        if self.pending {
            observed.pending = Some(irp.irp_id);
            return Ok(DispatchOutcome::Pending);
        }
        let mut metadata = nt_fs::QueryMetadata::default();
        nt_fs::capture_file_all_io_manager_information(ctx.system_buffer, &mut metadata).unwrap();
        metadata.current_byte_offset = 16;
        metadata.end_of_file = 16;
        let result = nt_fs::encode_named_query_information(
            nt_fs::FILE_ALL_INFORMATION,
            metadata,
            &[b'\\' as u16, b'x' as u16],
            ctx.system_buffer,
        ).unwrap();
        Ok(DispatchOutcome::Completed {
            status: NtStatus(result.status as i32),
            information: result.information as u64,
            file_context: None,
        })
    }

    fn cancel_irp(&mut self, _: IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::NOT_SUPPORTED)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        let mut observed = self.observed.borrow_mut();
        if !observed.ready { return None; }
        observed.ready = false;
        Some(DriverCompletion {
            irp_id: observed.pending.take()?,
            status: NtStatus::SUCCESS,
            information: 104,
            file_context: None,
        })
    }

    fn is_faulted(&self) -> bool { false }
}

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    device: DeviceId,
    file: FileId,
    observed: Rc<RefCell<Observed>>,
}

impl Fixture {
    fn new(pending: bool) -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let observed = Rc::new(RefCell::new(Observed::default()));
        let driver = io.create_driver(
            &NtPath::parse_str(r"\Driver\KernelQuerySeed").unwrap(),
            Box::new(Backend { observed: observed.clone(), pending }),
        ).unwrap();
        let path = NtPath::parse_str(r"\Device\KernelQuerySeed").unwrap();
        let device = io.create_device(
            driver, Some(&path), DeviceType::UNKNOWN, DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO, 0,
        ).unwrap();
        io.device_mut(device).unwrap().alignment_requirement = ALIGNMENT;
        let handle = io.open(
            client, &path, AccessMask::from_bits_retain(ACCESS), ShareAccess::empty(),
            CreateOptions::WRITE_THROUGH | CreateOptions::SYNCHRONOUS_IO_NONALERT, 0,
        ).unwrap();
        let file = io.reference_open_file_details(client, handle, AccessMask::empty()).unwrap().0;
        Self { io, client, device, file, observed }
    }

    fn output(&self) -> Vec<u8> {
        let mut output = vec![0x5a; OUTPUT_LENGTH];
        assert_eq!(self.io.encode_owned_file_query_information(
            self.client, self.file, self.device, ACCESS, nt_fs::FILE_ALL_INFORMATION, &mut output,
        ), Ok(12));
        output
    }

    fn dispatch(&mut self, output: &mut [u8], major: u8, initial: u64)
        -> Result<ExternalDispatchResult, NtStatus>
    {
        self.io.build_and_dispatch_external_to_device_with_stack_flags_and_initial_information(
            self.client, self.device, Some(self.file), 0, 42, major,
            if major == major::IRP_MJ_QUERY_INFORMATION {
                IoParameters::QueryInformation(InformationParameters {
                    info_class: nt_fs::FILE_ALL_INFORMATION, length: output.len() as u32,
                })
            } else { IoParameters::Read(ReadWriteParameters {
                length: output.len() as u32, key: 0, offset: 0,
            }) },
            StackFlags::empty(), 0, output.len() as u32, initial, output,
        )
    }
}

#[test]
fn kernel_file_all_receives_complete_seed_and_initial_information() {
    let mut f = Fixture::new(false);
    let mut output = f.output();
    assert_eq!(f.dispatch(&mut output, major::IRP_MJ_QUERY_INFORMATION, 12),
        Ok(ExternalDispatchResult::Completed {
            status: NtStatus::SUCCESS, information: 104, file_context: None,
        }));
    assert_manager_fields(&output);
    assert_eq!(u64::from_le_bytes(output[80..88].try_into().unwrap()), 16);
    assert_eq!(u32::from_le_bytes(output[96..100].try_into().unwrap()), 4);
    assert_eq!(&output[100..104], &[b'\\', 0, b'x', 0]);
    assert_eq!(output[OUTPUT_LENGTH - 1], 0x5a);
    assert_eq!(f.observed.borrow().queries, 1);
    assert_eq!(f.io.irp_count(), 0);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
}

#[test]
fn pending_kernel_query_preserves_seed_until_real_completion_replaces_information() {
    let mut f = Fixture::new(true);
    let mut output = f.output();
    let before = output.clone();
    let ExternalDispatchResult::Pending { irp_id } =
        f.dispatch(&mut output, major::IRP_MJ_QUERY_INFORMATION, 12).unwrap()
    else { panic!("kernel query must retain its pending IRP"); };
    assert_eq!(output, before);
    assert_eq!(f.io.irp(irp_id).unwrap().information, 12);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 1);
    f.observed.borrow_mut().ready = true;
    f.io.pump();
    assert_eq!(f.io.irp(irp_id).unwrap().information, 104);
    assert_eq!(f.observed.borrow().queries, 1);
}

#[test]
fn invalid_kernel_query_seed_is_refused_before_irp_or_backend_effects() {
    let mut f = Fixture::new(false);
    for (major, initial) in [
        (major::IRP_MJ_QUERY_INFORMATION, OUTPUT_LENGTH as u64 + 1),
        (major::IRP_MJ_QUERY_INFORMATION, u64::MAX),
        (major::IRP_MJ_READ, 1),
    ] {
        let mut output = f.output();
        let before = output.clone();
        assert_eq!(f.dispatch(&mut output, major, initial), Err(NtStatus::INVALID_PARAMETER));
        assert_eq!(output, before);
        assert_eq!(f.io.irp_count(), 0);
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    }
    assert_eq!(f.observed.borrow().queries, 0);
}
