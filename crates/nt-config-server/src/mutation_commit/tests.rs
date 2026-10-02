use super::test_support::*;
use super::*;

#[test]
fn live_create_key_retains_inherited_security_for_every_new_intermediate() {
    let mut server = server();
    let system = nt_security::AccessToken::system();
    let subject = nt_security::CapturedSubjectTokens {
        primary: &system,
        client: None,
        process_audit_id: 0,
    };
    let descriptor = nt_security::assign_registry_root_security(
        &subject,
        &mut nt_security::SecurityAssignmentAudit::default(),
    ).unwrap();
    {
        let mounted = server.system_hive.as_mut().unwrap();
        for path in ["", "Select", "ControlSet001", r"ControlSet001\Services"] {
            let key = if path.is_empty() { mounted.hive.root() }
                else { mounted.hive.open_key(path).unwrap() };
            assert!(mounted.hive.set_key_security_descriptor(key, &descriptor));
        }
        server.cm = config_manager_from_system_hive(&mounted.hive, &mounted.current_control_set);
    }
    let mutations = alloc::vec![HiveMutation::CreateKey {
        path: String::from(r"\Registry\Machine\System\CurrentControlSet\Services\Live\Nested\Leaf"),
    }];
    let mut replayed = nt_hive_core::decode_image(&nt_hive_core::encode_image(
        &server.system_hive.as_ref().unwrap().hive,
    )).unwrap();
    let replay_start = replayed.sequence;
    let prepared = server.prepare_system_hive_mutations(&mutations).unwrap();
    let replay_journal = prepared.durable_journal.clone();
    let token = server.identities.take().unwrap();
    server.prepared_system_mutation = Some(PreparedSystemHiveMutation {
        token,
        expected_generation: 1,
        next_generation: 2,
        semantic_journal_len: 100,
        mutations: prepared.mutations,
        durable_journal: prepared.durable_journal,
    });
    let request = CmHiveMutationCommitRequest {
        abi_size: core::mem::size_of::<CmHiveMutationCommitRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        operation: operation::COMMIT,
        mount: hive_mount::SYSTEM,
        mutation_token: token,
        expected_generation: 1,
        semantic_journal_len: 100,
        ..CmHiveMutationCommitRequest::default()
    };
    let receipt = exchange(&mut server, request).unwrap();
    assert_eq!(receipt.next_generation, 2);
    nt_hive_core::try_replay_log(&mut replayed, &replay_journal, replay_start).unwrap();
    let hive = &server.system_hive.as_ref().unwrap().hive;
    let parent = hive.open_key(r"ControlSet001\Services").unwrap();
    assert_eq!(hive.key_security_descriptor(parent), Some(descriptor.as_slice()));
    let replayed_parent = replayed.open_key(r"ControlSet001\Services").unwrap();
    assert_eq!(replayed.key_security_descriptor(replayed_parent), Some(descriptor.as_slice()));
    let mut expected = descriptor;
    for path in [
        r"ControlSet001\Services\Live",
        r"ControlSet001\Services\Live\Nested",
        r"ControlSet001\Services\Live\Nested\Leaf",
    ] {
        expected = nt_config_manager::inherit_generated_key_security(&expected).unwrap();
        let key = hive.open_key(path).unwrap();
        let actual = hive.key_security_descriptor(key).expect("live-created key security");
        assert_eq!(actual, expected.as_slice(), "{path}");
        let replayed_key = replayed.open_key(path).expect("replayed intermediate key");
        assert_eq!(replayed.key_security_descriptor(replayed_key), Some(actual), "replay {path}");
        let suffix = path.strip_prefix(r"ControlSet001\").unwrap();
        let projection_path = alloc::format!(r"\Registry\Machine\System\CurrentControlSet\{suffix}");
        let projection = server.cm.registry().open_key(&projection_path).expect("CM projected intermediate");
        assert_eq!(server.cm.registry().key_security_descriptor(projection), Some(actual), "projection {path}");
        assert!(nt_security::authorize_key_open(
            &subject, actual, nt_security::KEY_GENERIC_MAPPING.generic_read,
            nt_security::ProcessorMode::UserMode,
        ).unwrap().granted(), "System must be able to open {path}");
    }
}

#[test]
fn live_create_key_rejects_missing_or_corrupt_parent_before_publication() {
    for corrupt in [false, true] {
        let mut server = server();
        if corrupt {
            let hive = &mut server.system_hive.as_mut().unwrap().hive;
            let parent = hive.open_key(r"ControlSet001\Services").unwrap();
            assert!(hive.set_key_security_descriptor(parent, &[1, 0, 4]));
        }
        let before = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
        let result = server.prepare_system_hive_mutations(&[HiveMutation::CreateKey {
            path: String::from(r"\Registry\Machine\System\CurrentControlSet\Services\Live\Nested"),
        }]);
        assert!(result.is_err(), "corrupt={corrupt}: absent parent authority must not create keys");
        assert_eq!(nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive), before);
        assert_eq!(server.system_hive.as_ref().unwrap().generation, 1);
        assert!(server.prepared_system_mutation.is_none());
        assert!(!server.system_mutation_outcomes.is_pending());
    }
}

#[test]
fn live_create_key_inherits_staged_security_changes_in_batch_order() {
    let mut server = server();
    let security = |token: &nt_security::AccessToken| {
        nt_security::assign_registry_root_security(
            &nt_security::CapturedSubjectTokens {
                primary: token, client: None, process_audit_id: 0,
            },
            &mut nt_security::SecurityAssignmentAudit::default(),
        ).unwrap()
    };
    let initial = security(&nt_security::AccessToken::system());
    let mut updated = security(&nt_security::AccessToken::admin(123));
    let dacl = u32::from_le_bytes(updated[16..20].try_into().unwrap()) as usize;
    updated[dacl + 12..dacl + 16]
        .copy_from_slice(&nt_security::KEY_GENERIC_MAPPING.generic_read.to_le_bytes());
    let explicit = security(&nt_security::AccessToken::admin(456));
    {
        let mounted = server.system_hive.as_mut().unwrap();
        for path in ["", "Select", "ControlSet001", r"ControlSet001\Services"] {
            let key = if path.is_empty() { mounted.hive.root() } else { mounted.hive.open_key(path).unwrap() };
            assert!(mounted.hive.set_key_security_descriptor(key, &initial));
        }
        server.cm = config_manager_from_system_hive(&mounted.hive, &mounted.current_control_set);
    }
    let parent = r"\Registry\Machine\System\CurrentControlSet\Services";
    let early_path = alloc::format!(r"{parent}\Early");
    let mutations = alloc::vec![
        HiveMutation::SetKeySecurity { path: parent.into(), descriptor: updated.clone() },
        HiveMutation::CreateKey { path: alloc::format!(r"{early_path}\Nested") },
        HiveMutation::SetKeySecurity { path: early_path, descriptor: explicit.clone() },
        HiveMutation::CreateKey { path: alloc::format!(r"{parent}\Early\After") },
    ];
    let mut replayed = nt_hive_core::decode_image(&nt_hive_core::encode_image(
        &server.system_hive.as_ref().unwrap().hive,
    )).unwrap();
    let replay_start = replayed.sequence;
    let normalized = server.prepare_system_hive_mutations(&mutations).unwrap();
    assert!(!normalized.mutations.iter().any(|mutation| matches!(mutation, HiveMutation::CreateKey { .. })));
    let journal = normalized.durable_journal.clone();
    let token = server.identities.take().unwrap();
    server.prepared_system_mutation = Some(PreparedSystemHiveMutation {
        token, expected_generation: 1, next_generation: 2, semantic_journal_len: 100,
        mutations: normalized.mutations, durable_journal: normalized.durable_journal,
    });
    exchange(&mut server, CmHiveMutationCommitRequest {
        abi_size: core::mem::size_of::<CmHiveMutationCommitRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        operation: operation::COMMIT, mount: hive_mount::SYSTEM,
        mutation_token: token, expected_generation: 1, semantic_journal_len: 100,
        ..CmHiveMutationCommitRequest::default()
    }).unwrap();
    nt_hive_core::try_replay_log(&mut replayed, &journal, replay_start).unwrap();
    let early_before_change = nt_config_manager::inherit_generated_key_security(&updated).unwrap();
    let nested = nt_config_manager::inherit_generated_key_security(&early_before_change).unwrap();
    let after = nt_config_manager::inherit_generated_key_security(&explicit).unwrap();
    assert_ne!(nested, after, "the staged parent change must affect inherited ACEs");
    for (suffix, expected) in [
        ("Services", updated.as_slice()),
        (r"Services\Early", explicit.as_slice()),
        (r"Services\Early\Nested", nested.as_slice()),
        (r"Services\Early\After", after.as_slice()),
    ] {
        let path = alloc::format!(r"ControlSet001\{suffix}");
        let hive = &server.system_hive.as_ref().unwrap().hive;
        assert_eq!(hive.key_security_descriptor(hive.open_key(&path).unwrap()), Some(expected), "live {path}");
        assert_eq!(replayed.key_security_descriptor(replayed.open_key(&path).unwrap()), Some(expected), "replay {path}");
        let projection = server.cm.registry().open_key(
            &alloc::format!(r"\Registry\Machine\System\CurrentControlSet\{suffix}"),
        ).unwrap();
        assert_eq!(server.cm.registry().key_security_descriptor(projection), Some(expected), "projection {path}");
    }
}

#[test]
fn commit_replays_before_generation_check_and_old_ack_cannot_release_next_result() {
    let mut server = server();
    let request = prepare(&mut server, "First");
    let receipt = exchange(&mut server, request).unwrap();
    let sequence = server.system_hive.as_ref().unwrap().hive.sequence;
    assert_eq!(receipt.next_generation, 2);
    assert_eq!(exchange(&mut server, request), Ok(receipt));
    assert_eq!(server.system_hive.as_ref().unwrap().hive.sequence, sequence);
    for wrong in [
        CmHiveMutationCommitRequest {
            mutation_token: request.mutation_token + 1,
            ..request
        },
        CmHiveMutationCommitRequest {
            expected_generation: 2,
            ..request
        },
        CmHiveMutationCommitRequest {
            semantic_journal_len: 101,
            ..request
        },
    ] {
        assert_eq!(exchange(&mut server, wrong), Err(STATUS_INVALID_PARAMETER));
    }
    assert_eq!(
        exchange(&mut server, ack(receipt)).unwrap().disposition,
        disposition::ACKNOWLEDGED
    );
    assert!(exchange(&mut server, request).is_err());
    // Aborted upload tokens leave holes; receipt generations must not use those token values.
    for _ in 0..4 {
        let token = server.system_mutation_leases.begin(2, 1).unwrap();
        assert!(server.system_mutation_leases.abort(token, 2, 1));
    }
    let next_request = prepare(&mut server, "Second");
    let next = exchange(&mut server, next_request).unwrap();
    assert_eq!(next.receipt_generation, receipt.receipt_generation + 1);
    assert_eq!(
        exchange(&mut server, ack(receipt)).unwrap().disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    assert!(server.system_mutation_outcomes.is_pending());
    assert_eq!(exchange(&mut server, next_request), Ok(next));
    assert_eq!(
        exchange(&mut server, ack(next)).unwrap().disposition,
        disposition::ACKNOWLEDGED
    );
    // Mount identity is intentionally irrelevant to a completed receipt.
    server.system_hive = None;
    assert_eq!(
        exchange(&mut server, ack(receipt)).unwrap().disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
}

#[test]
fn malformed_geometry_and_short_output_have_no_commit_or_ack_effect() {
    let mut server = server();
    let good = prepare(&mut server, "Child");
    let mut invalid = [good; 9];
    invalid[0].abi_size -= 1;
    invalid[1].abi_version += 1;
    invalid[2].mount = 0;
    invalid[3].reserved = 1;
    invalid[4].mutation_token = 0;
    invalid[5].expected_generation = 0;
    invalid[6].semantic_journal_len = 0;
    invalid[7].receipt_bank = 1;
    invalid[8].operation = 99;
    for request in invalid {
        assert_eq!(
            exchange(&mut server, request),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    let mut output = [0; core::mem::size_of::<CmHiveMutationCommitReply>()];
    for input in [
        good.as_bytes()[..47].to_vec(),
        [good.as_bytes(), &[0]].concat(),
    ] {
        assert_eq!(
            server
                .op_system_hive_mutation_commit(&input, &mut output)
                .status,
            STATUS_INVALID_PARAMETER
        );
    }
    assert_eq!(
        server
            .op_system_hive_mutation_commit(good.as_bytes(), &mut output[..55])
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(server.system_hive.as_ref().unwrap().generation, 1);
    assert!(server.prepared_system_mutation.is_some());
    assert!(!server.system_mutation_outcomes.is_pending());
    let receipt = exchange(&mut server, good).unwrap();
    assert_eq!(
        server
            .op_system_hive_mutation_commit(ack(receipt).as_bytes(), &mut output[..55])
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert!(server.system_mutation_outcomes.is_pending());
    let wrong = CmHiveMutationCommitRequest {
        mutation_token: good.mutation_token,
        ..ack(receipt)
    };
    assert_eq!(exchange(&mut server, wrong), Err(STATUS_INVALID_PARAMETER));
    for wrong in [
        CmHiveMutationCommitRequest {
            receipt_bank: receipt.receipt_bank + 1,
            ..ack(receipt)
        },
        CmHiveMutationCommitRequest {
            receipt_generation: receipt.receipt_generation + 1,
            ..ack(receipt)
        },
    ] {
        assert_eq!(exchange(&mut server, wrong), Err(STATUS_INVALID_HANDLE));
    }
    assert!(server.system_mutation_outcomes.is_pending());
}

#[test]
fn failed_application_and_receipt_exhaustion_preserve_exact_preparation() {
    let mut server = server();
    let request = prepare(&mut server, "Child");
    let journal = server
        .prepared_system_mutation
        .as_ref()
        .unwrap()
        .durable_journal
        .clone();
    // Introduce a collision after PREPARE to exercise application failure without publication.
    server
        .system_hive
        .as_mut()
        .unwrap()
        .hive
        .create_key(r"ControlSet001\Services\Child");
    assert!(exchange(&mut server, request).is_err());
    assert_eq!(
        server
            .prepared_system_mutation
            .as_ref()
            .unwrap()
            .durable_journal,
        journal
    );
    assert_eq!(server.system_hive.as_ref().unwrap().generation, 1);
    assert!(!server.system_mutation_outcomes.is_pending());
    server.system_mutation_outcomes.acknowledged = u64::MAX;
    assert_eq!(
        exchange(&mut server, request),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert!(server.prepared_system_mutation.is_some());
    server.system_mutation_outcomes = MutationOutcomeJournal::default();
    server.identities.next_sequence.set(0);
    assert_eq!(
        exchange(&mut server, request),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert!(server.prepared_system_mutation.is_some());
    assert_eq!(server.system_hive.as_ref().unwrap().generation, 1);
}

#[test]
fn pending_terminal_outcome_excludes_import_checkpoint_legacy_commit_and_abort() {
    for op in [operation::COMMIT, operation::ABORT] {
        assert_pending_outcome_excludes_writers(op);
    }
}

fn assert_pending_outcome_excludes_writers(op: u16) {
    let mut server = server();
    let mut request = prepare(&mut server, "Child");
    request.operation = op;
    let receipt = exchange(&mut server, request).unwrap();
    let current_generation = server.system_hive.as_ref().unwrap().generation;
    let mut output = [0; 4096];
    for operation in [hive_import_transfer::BEGIN, hive_import_transfer::COMMIT] {
        let import = CmHiveImportRequest {
            abi_size: core::mem::size_of::<CmHiveImportRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            mount: hive_mount::SYSTEM,
            operation,
            transfer_token: if operation == hive_import_transfer::BEGIN {
                0
            } else {
                1
            },
            total_len_bytes: 1,
            ..CmHiveImportRequest::default()
        };
        assert_eq!(
            server.op_import_hive(import.as_bytes()).status,
            STATUS_DEVICE_BUSY
        );
    }
    let checkpoint = CmHiveCheckpointRequest {
        abi_size: core::mem::size_of::<CmHiveCheckpointRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: hive_checkpoint_transfer::BEGIN,
        expected_generation: current_generation,
        chunk_capacity: 1,
        ..CmHiveCheckpointRequest::default()
    };
    assert_eq!(
        server
            .op_checkpoint_system_hive(checkpoint.as_bytes(), &mut output)
            .status,
        STATUS_DEVICE_BUSY
    );
    for operation in [
        hive_mutation_transfer::BEGIN,
        hive_mutation_transfer::COMMIT,
        hive_mutation_transfer::ABORT,
    ] {
        let mutation = CmHiveMutationRequest {
            abi_size: core::mem::size_of::<CmHiveMutationRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            mount: hive_mount::SYSTEM,
            operation,
            expected_mount: if operation == hive_mutation_transfer::BEGIN {
                server.system_hive.as_ref().unwrap().identity
            } else {
                0
            },
            expected_generation: if operation == hive_mutation_transfer::BEGIN {
                current_generation
            } else {
                1
            },
            lease_token: if operation == hive_mutation_transfer::BEGIN {
                0
            } else {
                request.mutation_token
            },
            journal_len_bytes: 100,
            journal_offset: if operation == hive_mutation_transfer::COMMIT {
                100
            } else {
                0
            },
            ..CmHiveMutationRequest::default()
        };
        assert_ne!(
            server
                .op_mutate_system_hive(mutation.as_bytes(), &mut output)
                .status,
            STATUS_SUCCESS
        );
        assert_eq!(exchange(&mut server, request), Ok(receipt));
    }
}

#[test]
fn reconstructed_server_cannot_reuse_mutation_or_receipt_identity() {
    let mut first = server();
    let request = prepare(&mut first, "First");
    let receipt = exchange(&mut first, request).unwrap();
    let mut next = server();
    next.identities = first.identities.clone();
    next.system_mutation_leases = MutationLeaseBank::new(next.identities.clone());
    let local = prepare(&mut next, "Local");
    assert_ne!(local.mutation_token, request.mutation_token);
    assert_eq!(exchange(&mut next, request), Err(STATUS_INVALID_PARAMETER));
    let local_receipt = exchange(&mut next, local).unwrap();
    assert_ne!(local_receipt.receipt_bank, receipt.receipt_bank);
    assert_eq!(
        exchange(&mut next, ack(receipt)),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(exchange(&mut next, local), Ok(local_receipt));
}

#[test]
fn projection_failure_does_not_publish_device_action_and_exact_retry_can_commit() {
    let mut server = secured_server();
    server.device_action_journal.seed(1, &[]).unwrap();
    let request = prepare(&mut server, "Unused");
    let instance = r"\Registry\Machine\System\ControlSet001\Enum\ROOT\DEVICE\0000";
    let mutations = alloc::vec![
        HiveMutation::CreateKey {
            path: instance.into()
        },
        HiveMutation::SetValue {
            path: instance.into(),
            name: "Service".into(),
            value_type: RegistryValueType::Sz as u32,
            data: "Driver\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        },
        HiveMutation::SetValue {
            path: r"\Registry\Machine\System\ControlSet001\Services".into(),
            name: "Value".into(),
            value_type: RegistryValueType::Dword as u32,
            data: 1u32.to_le_bytes().to_vec(),
        },
        HiveMutation::PublishDeviceAction {
            kind: device_action_kind::ARRIVAL,
            instance_id: r"ROOT\DEVICE\0000".into()
        },
    ];
    let normalized = server.prepare_system_hive_mutations(&mutations).unwrap();
    let durable = normalized.durable_journal;
    let prepared = server.prepared_system_mutation.as_mut().unwrap();
    prepared.mutations = normalized.mutations;
    prepared.durable_journal = durable.clone();
    // Deliberately break only the semantic projection after successful PREPARE. The hive applies
    // successfully, so this catches an event published too early, not an earlier hive failure.
    let services = server
        .cm
        .registry()
        .open_key(r"\Registry\Machine\System\CurrentControlSet\Services")
        .unwrap();
    assert!(server.cm.registry_mut().delete_key(services, false));
    assert_eq!(exchange(&mut server, request), Err(STATUS_REGISTRY_CORRUPT));
    assert_eq!(server.device_action_journal.pending_len(), 0);
    assert!(!server.system_mutation_outcomes.is_pending());
    assert_eq!(
        server
            .prepared_system_mutation
            .as_ref()
            .unwrap()
            .durable_journal,
        durable
    );
    let mounted = server.system_hive.as_ref().unwrap();
    assert_eq!(mounted.generation, 1);
    assert!(mounted
        .hive
        .open_key(r"ControlSet001\Enum\ROOT\DEVICE\0000")
        .is_none());
    server.cm = config_manager_from_system_hive(&mounted.hive, &mounted.current_control_set);
    let receipt = exchange(&mut server, request).unwrap();
    assert_eq!(receipt.has_pending_device_action, 1);
    assert_eq!(server.device_action_journal.pending_len(), 1);
    assert_eq!(exchange(&mut server, request), Ok(receipt));
    assert_eq!(server.device_action_journal.pending_len(), 1);
}

#[test]
fn import_uploaded_before_publication_cannot_remount_until_ack() {
    let mut server = server();
    let image = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
    let mut import = CmHiveImportRequest {
        abi_size: core::mem::size_of::<CmHiveImportRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: hive_import_transfer::BEGIN,
        total_len_bytes: image.len() as u32,
        ..CmHiveImportRequest::default()
    };
    let begun = server.op_import_hive(import.as_bytes());
    assert_eq!(begun.status, STATUS_SUCCESS);
    import.transfer_token = begun.detail1;
    import.operation = hive_import_transfer::PUSH;
    import.chunk_offset = core::mem::size_of::<CmHiveImportRequest>() as u32;
    for chunk in image.chunks(CM_HIVE_IMPORT_CHUNK_BYTES) {
        import.chunk_len_bytes = chunk.len() as u32;
        let input = [import.as_bytes(), chunk].concat();
        assert_eq!(server.op_import_hive(&input).status, STATUS_SUCCESS);
        import.value_offset += chunk.len() as u32;
    }
    import.operation = hive_import_transfer::COMMIT;
    import.chunk_offset = 0;
    import.chunk_len_bytes = 0;
    let request = prepare(&mut server, "Child");
    let receipt = exchange(&mut server, request).unwrap();
    assert_eq!(
        server.op_import_hive(import.as_bytes()).status,
        STATUS_DEVICE_BUSY
    );
    assert_eq!(exchange(&mut server, request), Ok(receipt));
    exchange(&mut server, ack(receipt)).unwrap();
    assert_eq!(
        server.op_import_hive(import.as_bytes()).status,
        STATUS_SUCCESS
    );
    assert_eq!(
        exchange(&mut server, ack(receipt)).unwrap().disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
}
