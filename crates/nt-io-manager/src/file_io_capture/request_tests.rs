//! Captured routes submit canonical IRPs. Only driver execution is a host fixture.

use super::FileIoCaptureTable;
use crate::*;
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;
use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::{AccessMask, NtPath};

struct RecordingDriver {
    lifecycle: MockDriverBackend,
    calls: Rc<RefCell<Vec<IrpProjection>>>,
    expected_input: Vec<u8>,
    pending: bool,
    completions: Vec<DriverCompletion>,
}

impl DriverDispatchBackend for RecordingDriver {
    fn dispatch_irp(
        &mut self,
        context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.calls.borrow_mut().push(irp.clone());
        if matches!(
            irp.major,
            major::IRP_MJ_DIRECTORY_CONTROL
                | major::IRP_MJ_LOCK_CONTROL
                | major::IRP_MJ_QUERY_EA
                | major::IRP_MJ_SET_EA
                | major::IRP_MJ_QUERY_QUOTA
                | major::IRP_MJ_SET_QUOTA
        ) {
            assert_eq!(
                &context.system_buffer[..self.expected_input.len()],
                self.expected_input.as_slice()
            );
            if self.pending {
                self.completions.push(DriverCompletion {
                    irp_id: irp.irp_id,
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                });
                return Ok(DispatchOutcome::Pending);
            }
            return Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            });
        }
        self.lifecycle.dispatch_irp(context, irp)
    }

    fn cancel_irp(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        if let Some(completion) = self.completions.iter_mut().find(|item| item.irp_id == irp) {
            completion.status = NtStatus::CANCELLED;
            return Ok(());
        }
        self.lifecycle.cancel_irp(irp)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.completions
            .pop()
            .or_else(|| self.lifecycle.poll_completion())
    }
}

fn captured_request_lifecycle(
    request_major: u8,
    request_minor: u8,
    parameters: IoParameters,
    flags: StackFlags,
    access: AccessMask,
    input: &[u8],
    output_length: usize,
) {
    for pending in [false, true] {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\CaptureRequest").unwrap(),
                Box::new(RecordingDriver {
                    lifecycle: MockDriverBackend::new(),
                    calls: calls.clone(),
                    expected_input: input.to_vec(),
                    pending,
                    completions: Vec::new(),
                }),
            )
            .unwrap();
        let dispatch = io
            .driver(driver)
            .unwrap()
            .dispatch
            .get(major::IRP_MJ_CREATE);
        io.driver_mut(driver)
            .unwrap()
            .dispatch
            .set(request_major, dispatch);
        let path = NtPath::parse_str(r"\Device\CaptureRequest").unwrap();
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
        let handle = io
            .open(
                client,
                &path,
                access,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        let (file, _) = io
            .reference_open_file(client, handle, AccessMask::empty())
            .unwrap();
        io.file_mut(file).unwrap().driver_context = Some(0x1234);
        let mut captures = FileIoCaptureTable::new();
        let mut capture = captures
            .capture(&mut io, file, device, access.bits())
            .unwrap();
        assert_eq!(io.file_reference_count(file), 1);
        assert_eq!(capture.fs_context(), 0x1234);
        let captured_access = AccessMask::from_bits_retain(capture.granted_access());
        assert_eq!(captured_access, access);
        assert!(match request_major {
            major::IRP_MJ_LOCK_CONTROL => lock_control_access_granted(captured_access),
            major::IRP_MJ_DIRECTORY_CONTROL => directory_notify_access_granted(captured_access),
            major::IRP_MJ_QUERY_EA => query_ea_access_granted(captured_access),
            major::IRP_MJ_SET_EA => set_ea_access_granted(captured_access),
            major::IRP_MJ_QUERY_QUOTA => captured_access.is_empty(),
            major::IRP_MJ_SET_QUOTA => set_quota_access_granted(captured_access),
            _ => panic!("unregistered capture fixture operation"),
        });

        let mut buffer = alloc::vec![0; input.len() + output_length];
        buffer[..input.len()].copy_from_slice(input);
        let result = io
            .build_and_dispatch_external_to_device_with_stack_flags(
                client,
                capture.device_id(),
                Some(capture.file_id()),
                0,
                73,
                request_major,
                parameters.clone(),
                flags,
                input.len() as u32,
                output_length as u32,
                &mut buffer,
            )
            .unwrap();
        let request = calls.borrow().last().unwrap().clone();
        assert_eq!(request.major, request_major);
        assert_eq!(request.minor, request_minor);
        assert_eq!(request.parameters, parameters);
        assert_eq!(request.flags, flags);
        assert_eq!(request.file_id, Some(file));
        assert_eq!(request.device_id, device);
        assert_eq!(request.requestor_tid, 73);

        if pending {
            let ExternalDispatchResult::Pending { irp_id } = result else {
                panic!("driver must retain the canonical request");
            };
            assert_eq!(irp_id, request.irp_id);
            assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 1);
            captures.retire(&mut capture).unwrap();
            captures
                .release_retired(&mut io, capture.identity())
                .unwrap();
            assert_eq!(io.file_reference_count(file), 0);
            io.close(client, handle).unwrap();
            io.pump();
            assert!(
                io.file(file).is_some(),
                "completion still needs consumer ACK"
            );
            assert_eq!(io.completed_irp(irp_id).unwrap().status, NtStatus::SUCCESS);
            io.acknowledge_completed_irp(irp_id).unwrap();
        } else {
            assert!(matches!(
                result,
                ExternalDispatchResult::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                    ..
                }
            ));
            assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 0);
            io.close(client, handle).unwrap();
            assert!(
                io.file(file).is_some(),
                "capture must outlive inline completion"
            );
            captures.retire(&mut capture).unwrap();
            captures
                .release_retired(&mut io, capture.identity())
                .unwrap();
            assert!(io.file(file).is_some(), "capture release only queues CLOSE");
            io.pump();
        }
        assert!(captures.is_empty());
        assert!(io.file(file).is_none());
        let observed: Vec<_> = calls.borrow().iter().map(|irp| irp.major).collect();
        assert_eq!(
            observed,
            [
                major::IRP_MJ_CREATE,
                request_major,
                major::IRP_MJ_CLEANUP,
                major::IRP_MJ_CLOSE
            ]
        );
    }
}

#[test]
fn directory_notify_capture_preserves_filter_and_watch_tree_through_real_irp_lifetime() {
    captured_request_lifecycle(
        major::IRP_MJ_DIRECTORY_CONTROL,
        IRP_MN_NOTIFY_CHANGE_DIRECTORY,
        IoParameters::NotifyDirectory(DirectoryNotifyParameters {
            length: 96,
            completion_filter: 0x53,
        }),
        StackFlags::WATCH_TREE,
        AccessMask::GENERIC_READ,
        &[],
        96,
    );
}

#[test]
fn lock_capture_preserves_range_key_and_flags_through_real_irp_lifetime() {
    captured_request_lifecycle(
        major::IRP_MJ_LOCK_CONTROL,
        IRP_MN_LOCK,
        IoParameters::LockControl(LockControlParameters {
            minor: IRP_MN_LOCK,
            byte_offset: 0x1234_5678_9abc_def0,
            length: 0x1000_0000_0000_0001,
            key: 0x7654_3210,
        }),
        StackFlags::from_bits_retain(SL_FAIL_IMMEDIATELY | SL_EXCLUSIVE_LOCK),
        AccessMask::GENERIC_READ,
        &[],
        0,
    );
}

#[test]
fn unlock_capture_preserves_exact_lock_identity_through_real_irp_lifetime() {
    captured_request_lifecycle(
        major::IRP_MJ_LOCK_CONTROL,
        IRP_MN_UNLOCK_SINGLE,
        IoParameters::LockControl(LockControlParameters {
            minor: IRP_MN_UNLOCK_SINGLE,
            byte_offset: 0x1234_5678_9abc_def0,
            length: 0x1000_0000_0000_0001,
            key: 0x7654_3210,
        }),
        StackFlags::empty(),
        AccessMask::GENERIC_READ,
        &[],
        0,
    );
}

#[test]
fn query_ea_capture_preserves_name_list_index_and_access_through_real_irp_lifetime() {
    let input = [0, 0, 0, 0, 1, b'A', 0];
    validate_get_ea_buffer(&input).unwrap();
    captured_request_lifecycle(
        major::IRP_MJ_QUERY_EA,
        0,
        IoParameters::QueryEa(QueryEaParameters {
            length: 96,
            ea_list_length: input.len() as u32,
            ea_index: 0,
        }),
        StackFlags::RESTART_SCAN | StackFlags::RETURN_SINGLE_ENTRY,
        AccessMask::from_bits_retain(0x08),
        &input,
        96,
    );
}

#[test]
fn set_ea_capture_preserves_update_and_access_through_real_irp_lifetime() {
    let input = [0, 0, 0, 0, 0, 1, 2, 0, b'A', 0, 0xaa, 0xbb];
    validate_ea_buffer(&input).unwrap();
    captured_request_lifecycle(
        major::IRP_MJ_SET_EA,
        0,
        IoParameters::SetEa(SetEaParameters {
            length: input.len() as u32,
        }),
        StackFlags::empty(),
        AccessMask::from_bits_retain(0x10),
        &input,
        0,
    );
}

#[test]
fn query_quota_capture_preserves_sid_list_and_access_through_real_irp_lifetime() {
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut input = alloc::vec![0; 8];
    input[4..8].copy_from_slice(&(sid.len() as u32).to_le_bytes());
    input.extend_from_slice(&sid);
    validate_get_quota_buffer(&input).unwrap();
    captured_request_lifecycle(
        major::IRP_MJ_QUERY_QUOTA,
        0,
        IoParameters::QueryQuota(QueryQuotaParameters {
            length: 128,
            sid_list_length: input.len() as u32,
            start_sid_length: 0,
        }),
        StackFlags::RESTART_SCAN | StackFlags::RETURN_SINGLE_ENTRY,
        AccessMask::empty(),
        &input,
        128,
    );
}

#[test]
fn set_quota_capture_preserves_update_and_access_through_real_irp_lifetime() {
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut input = alloc::vec![0; 40];
    input[4..8].copy_from_slice(&(sid.len() as u32).to_le_bytes());
    input[24..32].copy_from_slice(&0x1000_u64.to_le_bytes());
    input[32..40].copy_from_slice(&0x2000_u64.to_le_bytes());
    input.extend_from_slice(&sid);
    validate_set_quota_buffer(&input).unwrap();
    captured_request_lifecycle(
        major::IRP_MJ_SET_QUOTA,
        0,
        IoParameters::SetQuota(SetQuotaParameters {
            length: input.len() as u32,
        }),
        StackFlags::empty(),
        AccessMask::from_bits_retain(0x02),
        &input,
        0,
    );
}
