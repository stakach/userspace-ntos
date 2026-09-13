//! Host composition of the query producer, canonical owner, peer wire and WDM projection.

use std::mem::size_of;

use nt_io_abi::{initial_output_required, major, IrpDispatchRequest, IO_ABI_VERSION};
use nt_io_manager::detached_file_irp::{
    ExternalFileIrpBuffers, ExternalFileIrpOutcome, ExternalFileIrpRequest, ExternalFileIrpResult,
};
use nt_io_manager::file_io_capture::FileIoCaptureTable;
use nt_io_manager::{
    write_wdm_irp, CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, DispatchContext,
    DispatchOutcome, DispatchTarget, DriverCompletion, DriverDispatchBackend, DriverPeerBackend,
    DriverPeerId, DriverPeerTransport, HostedDomainId, HostedDomainIdentity, InformationParameters,
    IoManager, IoParameters, IrpId, MajorFunctionTable, MockDriverBackend, MockDriverPeer,
    MockObjectPort, MockPeerControl, PeerTransferBuffers, ShareAccess, StackFlags, WdmIrpInit,
    WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, NtPath};

const OUTPUT_LENGTH: usize = 128;
const COMPLETED_LENGTH: usize = 104;
const ACCESS: u32 = 0x0012_0089;
const MODE: u32 = nt_fs::FILE_WRITE_THROUGH | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT;
const ALIGNMENT: u32 = 0x1ff;

fn assert_manager_fields(bytes: &[u8]) {
    assert_eq!(&bytes[76..80], &ACCESS.to_le_bytes());
    assert_eq!(&bytes[88..92], &MODE.to_le_bytes());
    assert_eq!(&bytes[92..96], &ALIGNMENT.to_le_bytes());
}

struct InspectingProvider {
    receiver: MockDriverPeer,
    calls: usize,
}

impl DriverPeerTransport for InspectingProvider {
    fn dispatch(
        &mut self,
        request: &IrpDispatchRequest,
        buffers: PeerTransferBuffers<'_>,
    ) -> DispatchOutcome {
        self.calls += 1;
        assert_eq!(request.abi_version, IO_ABI_VERSION as u16);
        assert_eq!(request.abi_size as usize, size_of::<IrpDispatchRequest>());
        assert_eq!(request.major, major::IRP_MJ_QUERY_INFORMATION);
        assert_eq!(request.ioctl_code, nt_fs::FILE_ALL_INFORMATION);
        assert_eq!(request.input_len, 0);
        assert_eq!(request.output_len as usize, OUTPUT_LENGTH);
        assert_eq!(request.initial_information, 12);
        assert!(buffers.direct.is_none());
        assert!(buffers.type3_input.is_none());
        assert!(buffers.user.is_none());

        // Exercise the existing peer receiver's wire validation before projecting a host WDM IRP.
        let accepted = self
            .receiver
            .dispatch(request, PeerTransferBuffers::new(&mut *buffers.system));
        assert!(matches!(
            accepted,
            DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 12,
                file_context: None,
            }
        ));

        let mut provider_output = vec![0xcc; request.output_len as usize];
        assert!(initial_output_required(
            request.major,
            request.ioctl_code,
            request.output_len,
        ));
        if initial_output_required(request.major, request.ioctl_code, request.output_len) {
            provider_output.copy_from_slice(&buffers.system[..request.output_len as usize]);
        }
        assert_manager_fields(&provider_output);
        assert_eq!(provider_output[OUTPUT_LENGTH - 1], 0x5a);

        let mut wdm = [0u8; WDM_X64_IRP_SIZE];
        let stack_count = u8::try_from(request.stack_count).unwrap();
        write_wdm_irp(
            &mut wdm,
            WdmIrpInit {
                packet_size: u16::try_from(
                    WDM_X64_IRP_SIZE
                        + request.stack_count as usize * WDM_X64_IO_STACK_LOCATION_SIZE,
                )
                .unwrap(),
                initial_information: request.initial_information,
                stack_count,
                current_location: stack_count - request.stack_location as u8,
                ..Default::default()
            },
        )
        .unwrap();
        let initial = u64::from_le_bytes(wdm[0x38..0x40].try_into().unwrap());
        assert_eq!(initial, 12);

        // The mock driver fills its name result after observing the manager-owned fields.
        provider_output[96..100].copy_from_slice(&4u32.to_le_bytes());
        provider_output[100..104].copy_from_slice(&[b'x', 0, b'y', 0]);
        let information = initial + (COMPLETED_LENGTH as u64 - 12);
        wdm[0x38..0x40].copy_from_slice(&information.to_le_bytes());
        assert_manager_fields(&provider_output);
        buffers.system.copy_from_slice(&provider_output);
        DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: u64::from_le_bytes(wdm[0x38..0x40].try_into().unwrap()),
            file_context: None,
        }
    }

    fn cancel(&mut self, _irp_id: IrpId) {
        panic!("the inline host provider must not be cancelled");
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        None
    }

    fn is_faulted(&self) -> bool {
        false
    }
}

#[test]
fn file_all_seed_reaches_peer_and_wdm_before_driver_completion() {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let mut majors = MajorFunctionTable::new();
    majors.set_all(DispatchTarget::DriverPeer(DriverPeerId(0)));
    let driver = io
        .create_driver_peer_with_major_table(
            &NtPath::parse_str("\\Driver\\SeededQuery").unwrap(),
            Box::new(MockDriverBackend::new()),
            majors,
        )
        .unwrap();
    let path = NtPath::parse_str("\\Device\\SeededQuery").unwrap();
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
    io.device_mut(device).unwrap().alignment_requirement = ALIGNMENT;
    let handle = io
        .open(
            client,
            &path,
            AccessMask::from_bits_retain(ACCESS),
            ShareAccess::empty(),
            CreateOptions::WRITE_THROUGH | CreateOptions::SYNCHRONOUS_IO_NONALERT,
            0,
        )
        .unwrap();
    let (file, _, _) = io
        .reference_open_file_details(client, handle, AccessMask::from_bits_retain(ACCESS))
        .unwrap();
    let mut captures = FileIoCaptureTable::new();
    let mut capture = captures.capture(&mut io, file, device, ACCESS).unwrap();
    // The provider query owns a pointer, not a live handle; CLEANUP cannot consume it.
    io.close(client, handle).unwrap();
    io.pump();
    assert_eq!(io.file_reference_count(file), 1);
    assert!(!io.file(file).unwrap().close_dispatched);

    let mut output = vec![0x5a; OUTPUT_LENGTH];
    let initial_information = io
        .encode_owned_file_query_information(
            client,
            capture.file_id(),
            capture.device_id(),
            capture.granted_access(),
            nt_fs::FILE_ALL_INFORMATION,
            &mut output,
        )
        .unwrap();
    assert_eq!(initial_information, 12);
    let prepared = io
        .prepare_external_file_irp_owned(
            ExternalFileIrpRequest {
                client,
                device_id: device,
                file_id: Some(file),
                user_data: 0,
                requestor_tid: 42,
                major: major::IRP_MJ_QUERY_INFORMATION,
                parameters: IoParameters::QueryInformation(InformationParameters {
                    info_class: nt_fs::FILE_ALL_INFORMATION,
                    length: OUTPUT_LENGTH as u32,
                }),
                stack_flags: StackFlags::empty(),
                initial_information: initial_information as u64,
            },
            ExternalFileIrpBuffers::new(vec![], output),
        )
        .unwrap();
    let id = prepared.irp_id();
    assert_eq!(io.irp(id).unwrap().information, 12);
    assert_eq!(prepared.projection().information, 12);
    assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 1);
    let mut invocation = io.begin_prepared_external_file_irp(prepared).unwrap();
    let projection = invocation.projection().clone();
    let control = MockPeerControl::new();
    let mut peer = DriverPeerBackend::new(
        InspectingProvider {
            receiver: control.transport(),
            calls: 0,
        },
        HostedDomainIdentity {
            domain_id: HostedDomainId(1),
            cookie: 1,
        },
        None,
    )
    .unwrap();
    let outcome = peer
        .dispatch_irp(
            DispatchContext::new(driver, client, invocation.buffers_mut().split().1),
            &projection,
        )
        .unwrap();
    assert_eq!(peer.transport().calls, 1);
    assert_eq!(control.last_request().unwrap().initial_information, 12);
    let DispatchOutcome::Completed {
        status,
        information,
        file_context,
    } = outcome
    else {
        panic!("expected inline host completion");
    };
    let terminal = match io
        .finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Returned {
            status,
            information,
            file_context,
        }))
        .unwrap()
    {
        ExternalFileIrpResult::Returned(terminal) => terminal,
        other => panic!("unexpected owner: {other:?}"),
    };
    assert_eq!(io.irp(id).unwrap().information, COMPLETED_LENGTH as u64);
    let (receipt, output) = io.retire_external_file_irp_terminal(terminal).unwrap();
    assert_eq!(receipt.completion().information, COMPLETED_LENGTH as u64);
    assert_manager_fields(output.output());
    assert_eq!(&output.output()[100..104], &[b'x', 0, b'y', 0]);
    assert_eq!(output.output()[OUTPUT_LENGTH - 1], 0x5a);
    assert_eq!(io.irp_count(), 0);
    assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 0);
    captures.retire(&mut capture).unwrap();
    captures
        .release_retired(&mut io, capture.identity())
        .unwrap();
    io.pump();
    assert!(io.file(file).is_none());
}
