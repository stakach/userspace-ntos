use super::*;
use nt_types::ObjectId;

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

fn allocate(f: &mut Fixture, object: ObjectId, name: &str) -> Result<FileId, NtStatus> {
    f.io.allocate_external_file_by_device_object(
        f.client,
        object,
        AccessMask::GENERIC_WRITE | AccessMask::SYNCHRONIZE,
        ShareAccess::READ | ShareAccess::WRITE,
        CreateOptions::OPEN_FOR_BACKUP_INTENT,
        UnicodeString::from_str(name),
    )
}

fn request(f: &Fixture, target: FileId) -> ExternalFileIrpRequest {
    let file = f.io.file(target).unwrap();
    ExternalFileIrpRequest {
        device_id: file.device_id,
        parameters: IoParameters::Create(CreateParameters {
            desired_access: file.desired_access,
            share_access: file.share_access,
            create_options: file.create_options,
            create_disposition: 1,
            ..Default::default()
        }),
        stack_flags: StackFlags::FORCE_ACCESS_CHECK | StackFlags::OPEN_TARGET_DIRECTORY,
        ..create(f, target)
    }
}

#[test]
fn device_object_allocation_preserves_exact_suffix_without_source_route_or_name_lookup() {
    let mut f = fixture();
    let destination = device(&mut f);
    let object = f.io.device(destination).unwrap().object_id;
    assert_ne!(object, ObjectId::NULL);
    assert!(f.io.device(destination).unwrap().name.is_none());
    let source_object = f.io.device(f.device).unwrap().object_id;
    let original_count = f.io.file_count();
    for suffix in [r"\Mixed\Leaf", "plain", "", r"\Device\Unrelated\leaf"] {
        let target = allocate(&mut f, object, suffix).unwrap();
        let file = f.io.file(target).unwrap();
        assert_eq!(file.device_id, destination);
        assert_ne!(file.device_id, f.io.file(f.file).unwrap().device_id);
        assert_eq!(file.related_file, None);
        assert_eq!(file.file_name, UnicodeString::from_str(suffix));
        assert_eq!(
            file.desired_access,
            AccessMask::GENERIC_WRITE | AccessMask::SYNCHRONIZE
        );
        assert_eq!(file.share_access, ShareAccess::READ | ShareAccess::WRITE);
        assert_eq!(file.create_options, CreateOptions::OPEN_FOR_BACKUP_INTENT);
        assert_eq!(file.state, FileState::Allocated);
        assert_eq!(f.io.irp_count(), 0);
        f.io.release_external_file(f.client, target).unwrap();
    }
    let target = allocate(&mut f, source_object, r"\Mixed\Leaf").unwrap();
    assert_eq!(f.io.file(target).unwrap().device_id, f.device);
    f.io.release_external_file(f.client, target).unwrap();
    assert_eq!(f.io.file_count(), original_count);
    assert!(f.trace.borrow().calls.is_empty());
}

#[test]
fn rejected_device_object_allocation_never_creates_a_file_or_irp() {
    let mut f = fixture();
    let destination = device(&mut f);
    let stale = f.io.device(destination).unwrap().object_id;
    f.io.destroy_device(destination).unwrap();
    let count = f.io.file_count();
    for object in [ObjectId::NULL, ObjectId(u64::MAX), stale] {
        assert_eq!(
            allocate(&mut f, object, r"\leaf"),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(f.io.file_count(), count);
        assert_eq!(f.io.irp_count(), 0);
    }
    let source = f.device;
    let object = f.io.device(source).unwrap().object_id;
    assert_eq!(
        f.io.delete_device(source).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert_eq!(
        allocate(&mut f, object, r"\leaf"),
        Err(NtStatus::DELETE_PENDING)
    );
    assert_eq!(f.io.file_count(), count);
    assert_eq!(f.io.irp_count(), 0);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert!(f.trace.borrow().calls.is_empty());
}

#[test]
fn object_selected_target_create_resolves_current_attachment_after_allocation() {
    let mut f = fixture();
    let destination = device(&mut f);
    let first_top = device(&mut f);
    let next_top = device(&mut f);
    let object = f.io.device(destination).unwrap().object_id;
    f.io.attach_device_to_stack(first_top, destination).unwrap();
    let target = allocate(&mut f, object, r"\dir\leaf").unwrap();
    f.io.detach_device_from_stack(first_top).unwrap();
    f.io.attach_device_to_stack(next_top, destination).unwrap();
    let name: Vec<u8> = r"\dir\leaf"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let prepared =
        f.io.prepare_external_file_irp_owned(
            request(&f, target),
            ExternalFileIrpBuffers::new(name.clone(), vec![]),
        )
        .unwrap();
    assert_eq!(prepared.route().device_id(), next_top);
    assert_eq!(f.io.file(target).unwrap().device_id, destination);
    assert_eq!(prepared.buffers().input(), name);
    assert_eq!(
        prepared.projection().flags,
        StackFlags::FORCE_ACCESS_CHECK | StackFlags::OPEN_TARGET_DIRECTORY
    );
    let IoParameters::Create(parameters) = &prepared.projection().parameters else {
        panic!("expected target CREATE");
    };
    assert_eq!(parameters.related_file, None);
    assert_eq!(f.io.file(target).unwrap().outstanding_irp_refs, 1);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    f.io.release_external_file(f.client, target).unwrap();
    assert!(f.io.file(target).is_none());
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn object_selected_target_deleted_before_create_rejects_admission_without_irp_ownership() {
    let mut f = fixture();
    let destination = device(&mut f);
    let object = f.io.device(destination).unwrap().object_id;
    let target = allocate(&mut f, object, r"\dir\leaf").unwrap();
    assert_eq!(
        f.io.delete_device(destination).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert_eq!(
        f.io.prepare_external_file_irp_owned(
            request(&f, target),
            ExternalFileIrpBuffers::new(vec![], vec![]),
        )
        .unwrap_err(),
        NtStatus::DELETE_PENDING
    );
    assert_eq!(f.io.file(target).unwrap().state, FileState::Allocated);
    assert_eq!(f.io.file(target).unwrap().outstanding_irp_refs, 0);
    assert_eq!(f.io.irp_count(), 0);
    f.io.release_external_file(f.client, target).unwrap();
    assert!(f.io.file(target).is_none());
    assert!(f.trace.borrow().calls.is_empty());
}

#[test]
fn cross_device_target_create_preserves_provider_failure_and_delays_topology_postcondition() {
    use crate::pending_set_file_name::PendingSetFileName;
    use crate::SetInformationControl;

    for provider_status in [NtStatus::ACCESS_DENIED, NtStatus::SUCCESS] {
        let mut f = fixture();
        let destination = device(&mut f);
        let object = f.io.device(destination).unwrap().object_id;
        let target = allocate(&mut f, object, r"\dir\leaf").unwrap();
        let name: Vec<u8> = r"\dir\leaf"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let transaction = PendingSetFileName::new(
            f.file.raw(),
            target.raw(),
            10,
            SetInformationControl::ReplaceIfExists(true),
            name.clone(),
            vec![0; 24],
        )
        .unwrap();
        let prepared =
            f.io.prepare_external_file_irp_owned(
                request(&f, target),
                ExternalFileIrpBuffers::new(name, vec![]),
            )
            .unwrap();
        assert_eq!(prepared.route().device_id(), destination);
        let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
        let ExternalFileIrpResult::Returned(terminal) =
            f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Returned {
                status: provider_status,
                information: 1,
                file_context: None,
            }))
            .unwrap()
        else {
            panic!("expected inline CREATE terminal");
        };
        let (receipt, _) = f.io.retire_external_file_irp_terminal(terminal).unwrap();
        assert_eq!(receipt.completion().status, provider_status);
        if provider_status == NtStatus::SUCCESS {
            assert!(f.io.file(target).unwrap().state.is_open());
            assert_eq!(
                transaction.validate_target_open(receipt.completion().information, || {
                    Ok(f.io.related_device_for_file(f.file)?
                        == f.io.related_device_for_file(target)?)
                }),
                Err(NtStatus::NOT_SAME_DEVICE)
            );
        }
        if f.io.file(target).is_some() {
            f.io.release_external_file(f.client, target).unwrap();
        }
        f.io.pump();
        assert!(f.io.file(target).is_none());
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
        assert_eq!(f.io.irp_count(), 0);
        assert!(!f
            .trace
            .borrow()
            .calls
            .contains(&major::IRP_MJ_SET_INFORMATION));
    }
}
