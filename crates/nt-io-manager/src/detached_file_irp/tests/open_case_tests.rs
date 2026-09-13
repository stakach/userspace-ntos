use super::*;

fn case_create(f: &Fixture, file: FileId, major: u8, sensitive: bool) -> ExternalFileIrpRequest {
    let parameters = CreateParameters {
        opened_case_sensitive: sensitive,
        ..Default::default()
    };
    ExternalFileIrpRequest {
        major,
        stack_flags: parameters.case_sensitive_stack_flags(major),
        parameters: IoParameters::Create(parameters),
        ..create(f, file)
    }
}

fn open(f: &mut Fixture, file: FileId, major: u8, sensitive: bool) {
    let prepared =
        f.io.prepare_external_file_irp_owned(
            case_create(f, file, major, sensitive),
            ExternalFileIrpBuffers::new(vec![], vec![]),
        )
        .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let terminal = terminal(f, invocation);
    f.io.retire_external_file_irp_terminal(terminal).unwrap();
}

#[test]
fn all_create_majors_capture_case_policy_independently_of_stack_bit() {
    for major in [
        major::IRP_MJ_CREATE,
        major::IRP_MJ_CREATE_NAMED_PIPE,
        major::IRP_MJ_CREATE_MAILSLOT,
    ] {
        for sensitive in [false, true] {
            let mut f = fixture();
            let file = create_file(&mut f, false);
            let prepared =
                f.io.prepare_external_file_irp_owned(
                    case_create(&f, file, major, sensitive),
                    ExternalFileIrpBuffers::new(vec![], vec![]),
                )
                .unwrap();
            assert_eq!(f.io.file(file).unwrap().opened_case_sensitive(), sensitive);
            assert_eq!(
                prepared
                    .projection()
                    .flags
                    .contains(StackFlags::CASE_SENSITIVE),
                major == major::IRP_MJ_CREATE && sensitive
            );
            let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
            let terminal = terminal(&mut f, invocation);
            f.io.retire_external_file_irp_terminal(terminal).unwrap();
            let mut owner = f.io.retain_file_reference(file).unwrap();
            assert_eq!(
                f.io.owned_file_metadata(f.client, file)
                    .unwrap()
                    .opened_case_sensitive,
                sensitive
            );
            f.io.release_file_reference(&mut owner).unwrap();
            f.io.release_external_file(f.client, file).unwrap();
            f.io.pump();
            assert!(f.io.file(file).is_none());
        }
    }
}

#[test]
fn contradictory_case_stack_flags_are_rejected_before_file_or_root_mutation() {
    for major in [
        major::IRP_MJ_CREATE,
        major::IRP_MJ_CREATE_NAMED_PIPE,
        major::IRP_MJ_CREATE_MAILSLOT,
    ] {
        for sensitive in [false, true] {
            let mut f = fixture();
            let file = create_file(&mut f, true);
            let mut request = case_create(&f, file, major, sensitive);
            request.stack_flags.toggle(StackFlags::CASE_SENSITIVE);
            assert_eq!(
                f.io.prepare_external_file_irp_owned(
                    request,
                    ExternalFileIrpBuffers::new(vec![], vec![])
                )
                .unwrap_err(),
                NtStatus::INVALID_PARAMETER
            );
            let child = f.io.file(file).unwrap();
            assert_eq!(child.state, FileState::Allocated);
            assert!(!child.opened_case_sensitive());
            assert_eq!(child.related_file, Some(f.file));
            assert_eq!(child.outstanding_irp_refs, 0);
            assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
            assert_eq!(f.io.irp_count(), 0);
        }
    }
}

#[test]
fn owned_source_case_policy_survives_cleanup_and_drives_target_not_root() {
    for sensitive in [false, true] {
        let mut f = fixture();
        let source = create_file(&mut f, false);
        open(&mut f, source, major::IRP_MJ_CREATE, sensitive);
        let root = create_file(&mut f, false);
        open(&mut f, root, major::IRP_MJ_CREATE, !sensitive);
        let mut source_owner = f.io.retain_file_reference(source).unwrap();
        let mut root_owner = f.io.retain_file_reference(root).unwrap();
        f.io.release_external_file(f.client, source).unwrap();
        f.io.pump();
        assert!(f.io.file(source).unwrap().cleanup_dispatched);
        let source_metadata = f.io.owned_file_metadata(f.client, source).unwrap();
        assert_eq!(source_metadata.opened_case_sensitive, sensitive);
        assert_eq!(
            f.io.owned_file_metadata(f.client, root)
                .unwrap()
                .opened_case_sensitive,
            !sensitive
        );
        let target =
            f.io.allocate_owned_external_relative_file(
                f.client,
                root,
                AccessMask::from_bits_retain(0x2),
                ShareAccess::READ | ShareAccess::WRITE,
                CreateOptions::OPEN_FOR_BACKUP_INTENT,
                UnicodeString::from_str("MixedCase\\Leaf"),
            )
            .unwrap();
        let mut request = case_create(
            &f,
            target,
            major::IRP_MJ_CREATE,
            source_metadata.opened_case_sensitive,
        );
        request.stack_flags |= StackFlags::OPEN_TARGET_DIRECTORY | StackFlags::FORCE_ACCESS_CHECK;
        let prepared = f
            .io
            .prepare_external_file_irp_owned(request, ExternalFileIrpBuffers::new(vec![], vec![]))
            .unwrap();
        assert_eq!(
            prepared
                .projection()
                .flags
                .contains(StackFlags::CASE_SENSITIVE),
            sensitive
        );
        assert!(prepared
            .projection()
            .flags
            .contains(StackFlags::OPEN_TARGET_DIRECTORY | StackFlags::FORCE_ACCESS_CHECK));
        assert_eq!(
            f.io.file(target).unwrap().opened_case_sensitive(),
            sensitive
        );
        let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
        let terminal = terminal(&mut f, invocation);
        f.io.retire_external_file_irp_terminal(terminal).unwrap();
        f.io.release_external_file(f.client, target).unwrap();
        f.io.release_external_file(f.client, root).unwrap();
        f.io.release_file_reference(&mut source_owner).unwrap();
        f.io.release_file_reference(&mut root_owner).unwrap();
        f.io.pump();
        assert!(f.io.file(source).is_none());
        assert!(f.io.file(root).is_none());
        assert!(f.io.file(target).is_none());
    }
}

#[test]
fn noncreate_stack_bits_never_overwrite_captured_case_policy() {
    for sensitive in [false, true] {
        let mut f = fixture();
        let file = create_file(&mut f, false);
        open(&mut f, file, major::IRP_MJ_CREATE, sensitive);
        let request = ExternalFileIrpRequest {
            file_id: Some(file),
            stack_flags: StackFlags::CASE_SENSITIVE,
            ..read(&f)
        };
        let prepared =
            f.io.prepare_external_file_irp_owned(request, buffers())
                .unwrap();
        assert_eq!(f.io.file(file).unwrap().opened_case_sensitive(), sensitive);
        f.io.discard_prepared_external_file_irp(prepared).unwrap();
        f.io.release_external_file(f.client, file).unwrap();
        f.io.pump();
    }
}
