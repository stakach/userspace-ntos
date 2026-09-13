use super::*;

fn device(f: &mut Fixture) -> DeviceId {
    f.io.create_device(
        f.driver,
        None,
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )
    .unwrap()
}

fn target_on(f: &mut Fixture, device: DeviceId) -> FileId {
    let target =
        f.io.allocate_external_file(
            f.client,
            device,
            AccessMask::GENERIC_WRITE,
            ShareAccess::READ | ShareAccess::WRITE,
            CreateOptions::DIRECTORY_FILE,
            UnicodeString::from_str("target"),
        )
        .unwrap();
    let mut request = create(f, target);
    request.device_id = device;
    let prepared =
        f.io.prepare_external_file_irp_owned(request, ExternalFileIrpBuffers::new(vec![], vec![]))
            .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let terminal = terminal(f, invocation);
    f.io.retire_external_file_irp_terminal(terminal).unwrap();
    target
}

fn set_target(f: &Fixture, target: FileId) -> ExternalFileIrpRequest {
    ExternalFileIrpRequest {
        major: major::IRP_MJ_SET_INFORMATION,
        parameters: IoParameters::SetInformation(crate::SetInformationParameters {
            info_class: 10,
            length: 24,
            target_file: Some(target),
            control: crate::SetInformationControl::ReplaceIfExists(true),
        }),
        ..read(f)
    }
}

#[test]
fn distinct_base_files_sharing_related_top_retain_set_target_through_pending_ack() {
    let mut f = fixture();
    f.io.file_mut(f.file).unwrap().desired_access |= AccessMask::DELETE;
    let top = device(&mut f);
    f.io.attach_device_to_stack(top, f.device).unwrap();
    let target = target_on(&mut f, top);
    assert_ne!(
        f.io.file(f.file).unwrap().device_id,
        f.io.file(target).unwrap().device_id
    );
    assert_eq!(f.io.related_device_for_file(f.file), Ok(top));
    assert_eq!(f.io.related_device_for_file(target), Ok(top));
    let prepared =
        f.io.prepare_external_file_irp_owned(
            set_target(&f, target),
            ExternalFileIrpBuffers::new(vec![0; 24], vec![]),
        )
        .unwrap();
    assert_eq!(f.io.file(target).unwrap().outstanding_irp_refs, 1);
    let IoParameters::SetInformation(parameters) = &prepared.projection().parameters else {
        panic!("expected SET_INFORMATION")
    };
    assert_eq!(parameters.target_file, Some(target));
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let ExternalFileIrpResult::Pending(retained) =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
            .unwrap()
    else {
        panic!("expected pending SET_INFORMATION")
    };
    f.io.release_external_file(f.client, target).unwrap();
    f.io.pump();
    assert_eq!(f.io.file(target).unwrap().state, FileState::ClosePending);
    assert_eq!(f.io.file(target).unwrap().outstanding_irp_refs, 1);
    complete(&mut f, retained.irp_id());
    let completion = f.io.prepare_external_file_irp_completion(retained).unwrap();
    assert!(completion.capture_complete());
    let ack =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap();
    f.io.finish_external_file_irp_completion(
        ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
    f.io.pump();
    assert!(f.io.file(target).is_none());
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn set_target_admission_follows_live_attachment_and_preserves_topology_errors() {
    let mut f = fixture();
    f.io.file_mut(f.file).unwrap().desired_access |= AccessMask::DELETE;
    let top = device(&mut f);
    let target = target_on(&mut f, top);
    let prepare = |f: &mut Fixture| {
        f.io.prepare_external_file_irp_owned(
            set_target(f, target),
            ExternalFileIrpBuffers::new(vec![0; 24], vec![]),
        )
    };
    assert_eq!(prepare(&mut f).unwrap_err(), NtStatus::INVALID_PARAMETER);
    f.io.attach_device_to_stack(top, f.device).unwrap();
    let prepared = prepare(&mut f).unwrap();
    assert_eq!(f.io.file(target).unwrap().outstanding_irp_refs, 1);
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    f.io.detach_device_from_stack(top).unwrap();
    assert_eq!(prepare(&mut f).unwrap_err(), NtStatus::INVALID_PARAMETER);
    f.io.device_mut(top).unwrap().delete_pending = true;
    assert_eq!(prepare(&mut f).unwrap_err(), NtStatus::DELETE_PENDING);
    f.io.device_mut(top).unwrap().delete_pending = false;
    f.io.file_mut(target).unwrap().device_id = DeviceId::NULL;
    assert_eq!(prepare(&mut f).unwrap_err(), NtStatus::INVALID_PARAMETER);
    f.io.file_mut(target).unwrap().device_id = top;
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert_eq!(f.io.file(target).unwrap().outstanding_irp_refs, 0);
    assert_eq!(f.io.irp_count(), 0);
    f.io.release_external_file(f.client, target).unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
    assert!(f.io.file(target).is_none());
}

fn owned_relative_child(f: &mut Fixture) -> Result<FileId, NtStatus> {
    f.io.allocate_owned_external_relative_file(
        f.client,
        f.file,
        AccessMask::GENERIC_WRITE | AccessMask::SYNCHRONIZE,
        ShareAccess::READ | ShareAccess::WRITE,
        CreateOptions::OPEN_FOR_BACKUP_INTENT,
        UnicodeString::from_str("subdir\\leaf"),
    )
}

#[test]
fn owned_relative_create_after_cleanup_transfers_parent_lifetime_until_ack() {
    let mut f = fixture();
    let mut root_owner = f.io.retain_file_reference(f.file).unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert_eq!(f.io.file(f.file).unwrap().state, FileState::ClosePending);
    assert!(f.io.file(f.file).unwrap().cleanup_dispatched);
    assert_eq!(
        f.io.allocate_external_relative_file(
            f.client,
            f.file,
            AccessMask::GENERIC_WRITE,
            ShareAccess::READ,
            CreateOptions::empty(),
            UnicodeString::from_str("subdir\\leaf"),
        ),
        Err(NtStatus::INVALID_HANDLE)
    );
    let child = owned_relative_child(&mut f).unwrap();
    assert_eq!(f.io.file(child).unwrap().device_id, f.device);
    assert_eq!(
        f.io.file(child).unwrap().file_name,
        UnicodeString::from_str("subdir\\leaf")
    );
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    let name: Vec<u8> = "subdir\\leaf"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut request = create(&f, child);
    request.stack_flags = StackFlags::FORCE_ACCESS_CHECK | StackFlags::OPEN_TARGET_DIRECTORY;
    let prepared = f
        .io
        .prepare_external_file_irp_owned(request, ExternalFileIrpBuffers::new(name.clone(), vec![]))
        .unwrap();
    let IoParameters::Create(parameters) = &prepared.projection().parameters else {
        panic!("expected relative target CREATE")
    };
    assert_eq!(parameters.related_file, Some(f.file));
    assert_eq!(prepared.buffers().input(), name);
    assert_eq!(f.io.file(child).unwrap().related_file, None);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 1);
    f.io.release_file_reference(&mut root_owner).unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_some());
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let ExternalFileIrpResult::Pending(retained) =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
            .unwrap()
    else {
        panic!("expected pending relative CREATE")
    };
    f.trace.borrow_mut().ready.push(DriverCompletion {
        irp_id: retained.irp_id(),
        status: NtStatus::SUCCESS,
        information: 1,
        file_context: Some(0x1234),
    });
    f.io.pump();
    let completion = f.io.prepare_external_file_irp_completion(retained).unwrap();
    assert!(completion.capture_complete());
    let ack =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap();
    f.io.finish_external_file_irp_completion(
        ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
    assert_eq!(f.io.file(child).unwrap().outstanding_irp_refs, 0);
    f.io.release_external_file(f.client, child).unwrap();
    f.io.pump();
    assert!(f.io.file(child).is_none());
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn owned_relative_allocation_rejects_unowned_wrong_client_and_invalid_root_states() {
    let mut f = fixture();
    assert_eq!(owned_relative_child(&mut f), Err(NtStatus::INVALID_HANDLE));
    let mut root_owner = f.io.retain_file_reference(f.file).unwrap();
    let client = f.client;
    f.client = f.io.register_client();
    assert_eq!(owned_relative_child(&mut f), Err(NtStatus::INVALID_HANDLE));
    f.client = client;
    for state in [FileState::Allocated, FileState::CreateIrpDispatched] {
        f.io.file_mut(f.file).unwrap().state = state;
        assert_eq!(owned_relative_child(&mut f), Err(NtStatus::INVALID_HANDLE));
    }
    f.io.file_mut(f.file).unwrap().state = FileState::Closed;
    assert_eq!(owned_relative_child(&mut f), Err(NtStatus::FILE_CLOSED));
    f.io.file_mut(f.file).unwrap().state = FileState::Open;
    f.io.file_mut(f.file).unwrap().close_dispatched = true;
    assert_eq!(owned_relative_child(&mut f), Err(NtStatus::FILE_CLOSED));
    f.io.file_mut(f.file).unwrap().close_dispatched = false;
    let root = f.file;
    f.file = FileId::NULL;
    assert_eq!(owned_relative_child(&mut f), Err(NtStatus::INVALID_HANDLE));
    f.file = root;
    assert_eq!(f.io.file_reference_count(root), 1);
    assert_eq!(f.io.file(root).unwrap().outstanding_irp_refs, 0);
    f.io.release_file_reference(&mut root_owner).unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert!(f.io.file(root).is_none());
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn relative_create_rejects_cross_device_and_closed_parent_without_reference_leaks() {
    let mut f = fixture();
    let mut root_owner = f.io.retain_file_reference(f.file).unwrap();
    let child = owned_relative_child(&mut f).unwrap();
    let other_device =
        f.io.create_device(
            f.driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    f.io.file_mut(child).unwrap().device_id = other_device;
    let mut request = create(&f, child);
    request.device_id = other_device;
    assert_eq!(
        f.io.prepare_external_file_irp_owned(request, ExternalFileIrpBuffers::new(vec![], vec![]),)
            .unwrap_err(),
        NtStatus::INVALID_PARAMETER
    );
    f.io.file_mut(child).unwrap().device_id = f.device;
    for state in [
        FileState::Allocated,
        FileState::CreateIrpDispatched,
        FileState::Closed,
    ] {
        f.io.file_mut(f.file).unwrap().state = state;
        assert_eq!(
            f.io.prepare_external_file_irp_owned(
                create(&f, child),
                ExternalFileIrpBuffers::new(vec![], vec![]),
            )
            .unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );
    }
    f.io.file_mut(f.file).unwrap().state = FileState::Open;
    f.io.file_mut(f.file).unwrap().close_dispatched = true;
    assert_eq!(
        f.io.prepare_external_file_irp_owned(
            create(&f, child),
            ExternalFileIrpBuffers::new(vec![], vec![]),
        )
        .unwrap_err(),
        NtStatus::INVALID_PARAMETER
    );
    f.io.file_mut(f.file).unwrap().close_dispatched = false;
    assert_eq!(f.io.file(child).unwrap().related_file, Some(f.file));
    assert_eq!(f.io.file(child).unwrap().outstanding_irp_refs, 0);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert_eq!(f.io.file_reference_count(f.file), 1);
    f.io.release_external_file(f.client, child).unwrap();
    f.io.release_file_reference(&mut root_owner).unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert!(f.io.file(child).is_none());
    assert!(f.io.file(f.file).is_none());
    assert_eq!(f.io.irp_count(), 0);
}
