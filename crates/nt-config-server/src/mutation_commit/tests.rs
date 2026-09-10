use super::test_support::*;
use super::*;

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
    let mut server = server();
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
    let durable = server.prepare_system_hive_mutations(&mutations).unwrap();
    let prepared = server.prepared_system_mutation.as_mut().unwrap();
    prepared.mutations = mutations;
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
