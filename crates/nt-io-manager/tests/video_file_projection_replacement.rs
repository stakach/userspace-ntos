//! Host composition of fresh video File bodies and canonical lifetime primitives.
//! This does not execute native video globals, IPC, or an atomic replacement implementation.

use std::{cell::RefCell, rc::Rc};

use nt_io_abi::major;
use nt_io_manager::file_io_capture::FileIoCaptureTable;
use nt_io_manager::{
    write_wdm_file_object, CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceId, DeviceType,
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, FileId,
    FileReference, FileState, HostedDomainIdentity, HostedFileIdentity, HostedFileUnbindOutcome,
    IoManager, IrpId, IrpProjection, MockDriverBackend, MockObjectPort, ShareAccess,
    WdmFileObjectInit, WDM_X64_FILE_OBJECT_SIZE,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath};

const DEVICE_ADDRESS: u64 = 0x4000;
const OLD_ADDRESS: u64 = 0x5000;
const NEW_ADDRESS: u64 = 0x6000;
const OLD_OPTIONS: CreateOptions = CreateOptions::from_bits_retain(0x22);
const NEW_OPTIONS: CreateOptions = CreateOptions::from_bits_retain(0x14);

type Calls = Rc<RefCell<Vec<(Option<FileId>, u8)>>>;

struct Recording {
    backend: MockDriverBackend,
    calls: Calls,
}

impl DriverDispatchBackend for Recording {
    fn dispatch_irp(
        &mut self,
        context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.calls.borrow_mut().push((irp.file_id, irp.major));
        self.backend.dispatch_irp(context, irp)
    }

    fn cancel_irp(&mut self, id: IrpId) -> Result<(), NtStatus> {
        self.backend.cancel_irp(id)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.backend.poll_completion()
    }

    fn acknowledge_completion(&mut self, id: IrpId) -> Result<(), NtStatus> {
        self.backend.acknowledge_completion(id)
    }
}

struct Projection {
    file: FileId,
    handle: HandleValue,
    reference: FileReference,
    identity: HostedFileIdentity,
    body: [u8; WDM_X64_FILE_OBJECT_SIZE],
}

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    domain: HostedDomainIdentity,
    device: DeviceId,
    path: NtPath,
    calls: Calls,
}

impl Fixture {
    fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\VideoProjection").unwrap(),
                Box::new(Recording {
                    backend: MockDriverBackend::new(),
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let path = NtPath::parse_str(r"\Device\VideoProjection").unwrap();
        let device = io
            .create_device(
                driver,
                Some(&path),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_identity(domain, DEVICE_ADDRESS, device)
            .unwrap();
        Self {
            io,
            client,
            domain,
            device,
            path,
            calls,
        }
    }

    fn stage(&mut self, address: u64, options: CreateOptions) -> Projection {
        let handle = self
            .io
            .open(
                self.client,
                &self.path,
                AccessMask::GENERIC_READ | AccessMask::SYNCHRONIZE,
                ShareAccess::READ | ShareAccess::WRITE,
                options,
                1,
            )
            .unwrap();
        let (file, device, _) = self
            .io
            .reference_open_file_details(self.client, handle, AccessMask::empty())
            .unwrap();
        assert_eq!(device, self.device);
        let reference = self.io.retain_file_reference(file).unwrap();
        let metadata = self.io.owned_file_metadata(self.client, file).unwrap();
        let mut body = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
        write_wdm_file_object(
            &mut body,
            WdmFileObjectInit {
                file_object_address: address,
                create_options: metadata.create_options.bits(),
                opened_case_sensitive: metadata.opened_case_sensitive,
                device_object: DEVICE_ADDRESS,
                fs_context: self
                    .io
                    .external_file_context(self.client, file)
                    .unwrap()
                    .unwrap_or(0),
                ..Default::default()
            },
        )
        .unwrap();
        let identity = self
            .io
            .bind_hosted_file_identity(self.domain, address, file)
            .unwrap();
        Projection {
            file,
            handle,
            reference,
            identity,
            body,
        }
    }

    fn count(&self, file: FileId, operation: u8) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|&&(id, major)| id == Some(file) && major == operation)
            .count()
    }

    fn close_handle_and_reference(&mut self, projection: &mut Projection) {
        self.io.close(self.client, projection.handle).unwrap();
        self.io
            .release_file_reference(&mut projection.reference)
            .unwrap();
        self.io.pump();
    }

    fn retire(&mut self, projection: &mut Projection) {
        self.close_handle_and_reference(projection);
        self.io
            .unbind_hosted_file_identity(projection.identity)
            .unwrap();
        self.io.pump();
        assert!(self.io.file(projection.file).is_none());
    }
}

fn assert_header(body: &[u8], address: u64, flags: u32) {
    assert_eq!(i16::from_le_bytes(body[0..2].try_into().unwrap()), 5);
    assert_eq!(
        u16::from_le_bytes(body[2..4].try_into().unwrap()) as usize,
        WDM_X64_FILE_OBJECT_SIZE
    );
    assert_eq!(
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
        DEVICE_ADDRESS
    );
    assert_eq!(
        u32::from_le_bytes(body[0x50..0x54].try_into().unwrap()),
        flags
    );
    for offset in [0x88, 0x90] {
        assert_eq!(
            u64::from_le_bytes(body[offset..offset + 8].try_into().unwrap()),
            address + 0x88
        );
    }
    for offset in [0xa0, 0xa8] {
        assert_eq!(
            u64::from_le_bytes(body[offset..offset + 8].try_into().unwrap()),
            address + 0xa0
        );
    }
}

#[test]
fn refused_old_unbind_preserves_old_body_while_staged_candidate_retires_independently() {
    let mut f = Fixture::new();
    let mut old = f.stage(OLD_ADDRESS, OLD_OPTIONS);
    let old_body = old.body;
    let mut publication = f.io.lease_hosted_file_identity(old.identity).unwrap();
    let mut candidate = f.stage(NEW_ADDRESS, NEW_OPTIONS);
    assert_ne!(old.file, candidate.file);
    assert_ne!(old.identity.address(), candidate.identity.address());
    assert_header(&old.body, OLD_ADDRESS, 0x12);
    assert_header(&candidate.body, NEW_ADDRESS, 0x26);
    f.close_handle_and_reference(&mut old);
    assert_eq!(f.count(old.file, major::IRP_MJ_CLOSE), 1);
    assert_eq!(
        f.io.unbind_hosted_file_identity(old.identity),
        Err(NtStatus::DELETE_PENDING)
    );
    assert_eq!(old.body, old_body);
    assert_eq!(
        f.io.hosted_file_identity_at(f.domain, old.file, OLD_ADDRESS),
        Ok(Some(old.identity))
    );
    assert!(f.io.file(old.file).is_some());
    f.retire(&mut candidate);
    assert_eq!(f.count(candidate.file, major::IRP_MJ_CLOSE), 1);
    assert_eq!(old.body, old_body);
    assert_eq!(
        f.io.hosted_file_identity_at(f.domain, old.file, OLD_ADDRESS),
        Ok(Some(old.identity))
    );
    f.io.release_hosted_file_publication(&mut publication)
        .unwrap();
    assert_eq!(
        f.io.unbind_hosted_file_identity(old.identity),
        Ok(HostedFileUnbindOutcome::Removed)
    );
    f.io.pump();
    assert!(f.io.file(old.file).is_none());
    assert_eq!(f.count(old.file, major::IRP_MJ_CLOSE), 1);
    assert_eq!(f.io.file_count(), 0);
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn successful_replacement_leaves_distinct_new_file_live_without_rewriting_old_body() {
    let mut f = Fixture::new();
    let mut old = f.stage(OLD_ADDRESS, OLD_OPTIONS);
    let old_body = old.body;
    let mut candidate = f.stage(NEW_ADDRESS, NEW_OPTIONS);
    let new_body = candidate.body;
    assert_ne!(old.file, candidate.file);
    assert_eq!(f.io.file(old.file).unwrap().create_options, OLD_OPTIONS);
    assert_eq!(
        f.io.file(candidate.file).unwrap().create_options,
        NEW_OPTIONS
    );
    f.retire(&mut old);
    assert_eq!(f.io.file(candidate.file).unwrap().state, FileState::Open);
    assert_eq!(
        f.io.hosted_file_by_identity(f.domain, NEW_ADDRESS),
        Some(candidate.file)
    );
    assert_eq!(f.io.hosted_file_by_identity(f.domain, OLD_ADDRESS), None);
    assert_eq!(old.body, old_body);
    assert_eq!(candidate.body, new_body);
    assert_header(&old.body, OLD_ADDRESS, 0x12);
    assert_header(&candidate.body, NEW_ADDRESS, 0x26);
    assert_eq!(f.count(candidate.file, major::IRP_MJ_CLOSE), 0);
    f.retire(&mut candidate);
    assert_eq!(f.count(old.file, major::IRP_MJ_CREATE), 1);
    assert_eq!(f.count(candidate.file, major::IRP_MJ_CREATE), 1);
    assert_eq!(f.count(old.file, major::IRP_MJ_CLOSE), 1);
    assert_eq!(f.count(candidate.file, major::IRP_MJ_CLOSE), 1);
    assert_eq!(f.io.file_count(), 0);
}

#[test]
fn canonical_reference_delays_close_while_consumer_binding_only_delays_final_removal() {
    let mut f = Fixture::new();
    let mut old = f.stage(OLD_ADDRESS, OLD_OPTIONS);
    f.io.close(f.client, old.handle).unwrap();
    f.io.pump();
    assert_eq!(f.count(old.file, major::IRP_MJ_CLEANUP), 1);
    assert_eq!(f.count(old.file, major::IRP_MJ_CLOSE), 0);
    assert_eq!(f.io.file_reference_count(old.file), 1);
    f.io.release_file_reference(&mut old.reference).unwrap();
    f.io.pump();
    assert_eq!(f.count(old.file, major::IRP_MJ_CLOSE), 1);
    assert!(f.io.file(old.file).is_some());
    assert_eq!(
        f.io.hosted_file_identity_at(f.domain, old.file, OLD_ADDRESS),
        Ok(Some(old.identity))
    );
    f.io.unbind_hosted_file_identity(old.identity).unwrap();
    f.io.pump();
    assert!(f.io.file(old.file).is_none());
    assert_eq!(f.count(old.file, major::IRP_MJ_CLOSE), 1);
}

#[test]
fn mismatched_consumer_file_or_device_has_no_authority_to_publish_over_existing_body() {
    let mut f = Fixture::new();
    let mut old = f.stage(OLD_ADDRESS, OLD_OPTIONS);
    let mut candidate = f.stage(NEW_ADDRESS, NEW_OPTIONS);
    let old_body = old.body;
    assert_eq!(
        f.io.hosted_file_identity_at(f.domain, candidate.file, OLD_ADDRESS),
        Ok(None)
    );
    assert_eq!(
        f.io.bind_hosted_file_identity(f.domain, OLD_ADDRESS, candidate.file),
        Err(NtStatus::OBJECT_NAME_COLLISION)
    );
    let driver = f.io.device(f.device).unwrap().driver_id;
    let wrong_device =
        f.io.create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let mut captures = FileIoCaptureTable::new();
    assert!(matches!(
        captures.capture(&mut f.io, old.file, wrong_device, 1),
        Err(NtStatus::INVALID_HANDLE)
    ));
    let mut output = [0xa5; 4];
    assert_eq!(
        f.io.encode_owned_file_query_information(
            f.client,
            old.file,
            wrong_device,
            1,
            nt_fs::FILE_MODE_INFORMATION,
            &mut output
        ),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(output, [0xa5; 4]);
    assert_eq!(old.body, old_body);
    assert_eq!(f.io.file_reference_count(old.file), 1);
    assert_eq!(
        f.io.hosted_file_identity_at(f.domain, old.file, OLD_ADDRESS),
        Ok(Some(old.identity))
    );
    assert_eq!(f.count(old.file, major::IRP_MJ_CLOSE), 0);
    f.retire(&mut candidate);
    f.retire(&mut old);
    assert_eq!(f.io.file_count(), 0);
}
