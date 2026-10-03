use super::*;

pub(crate) fn server() -> CmServer {
    let mut server = CmServer::new_for_incarnation(NonZeroU32::MIN);
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key(r"ControlSet001\Services");
    let current_control_set = hive.current_control_set().unwrap();
    let hardware_profile =
        nt_hive_core::HardwareProfileAlias::capture(&hive, &current_control_set).unwrap();
    server.cm = config_manager_from_system_hive(&hive, &current_control_set);
    server.system_hive = Some(MountedSystemHive {
        identity: server.identities.take().unwrap(),
        hive,
        generation: 1,
        current_control_set,
        hardware_profile,
    });
    server
}

pub(crate) fn secure_fixture_hive(hive: &mut Hive) {
    let system = nt_security::AccessToken::system();
    let subject = nt_security::CapturedSubjectTokens {
        primary: &system, client: None, process_audit_id: 0,
    };
    let descriptor = nt_security::assign_registry_root_security(
        &subject, &mut nt_security::SecurityAssignmentAudit::default(),
    ).unwrap();
    let mut pending = alloc::vec![(hive.root(), descriptor)];
    while let Some((key, descriptor)) = pending.pop() {
        assert!(hive.set_key_security_descriptor(key, &descriptor));
        for name in hive.enum_subkeys(key) {
            let child = hive.open_subkey(key, &name).unwrap();
            pending.push((child, nt_config_manager::inherit_generated_key_security(&descriptor).unwrap()));
        }
    }
}

pub(crate) fn secured_server() -> CmServer {
    let mut server = server();
    let mounted = server.system_hive.as_mut().unwrap();
    secure_fixture_hive(&mut mounted.hive);
    server.cm = config_manager_from_system_hive(&mounted.hive, &mounted.current_control_set);
    server
}

pub(super) fn prepare(server: &mut CmServer, name: &str) -> CmHiveMutationCommitRequest {
    let token = server.identities.take().unwrap();
    let expected = server.system_hive.as_ref().unwrap().generation;
    let mutations = alloc::vec![HiveMutation::CreateChild {
        volatile: false,
        authority: crate::mutation::ChildParentAuthority::Path,
        parent: String::from(r"\Registry\Machine\System\ControlSet001\Services"),
        name: String::from(name),
        class_name: Some(String::from("class")),
        descriptor: alloc::vec![1, 2, 3],
    }];
    let prepared = server.prepare_system_hive_mutations(&mutations).unwrap();
    server.prepared_system_mutation = Some(PreparedSystemHiveMutation {
        token,
        expected_generation: expected,
        next_generation: expected + 1,
        semantic_journal_len: 100,
        mutations: prepared.mutations,
        durable_journal: prepared.durable_journal,
    });
    CmHiveMutationCommitRequest {
        abi_size: core::mem::size_of::<CmHiveMutationCommitRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        operation: operation::COMMIT,
        mount: hive_mount::SYSTEM,
        mutation_token: token,
        expected_generation: expected,
        semantic_journal_len: 100,
        ..CmHiveMutationCommitRequest::default()
    }
}

pub(super) fn exchange(
    server: &mut CmServer,
    request: CmHiveMutationCommitRequest,
) -> Result<CmHiveMutationCommitReply, i32> {
    let mut out = [0; core::mem::size_of::<CmHiveMutationCommitReply>()];
    let result = server.dispatch(
        opcode::CM_OP_SYSTEM_HIVE_MUTATION_COMMIT,
        request.as_bytes(),
        &mut out,
    );
    if result.status != STATUS_SUCCESS {
        return Err(result.status);
    }
    assert_eq!(result.information as usize, out.len());
    let body = CmHiveMutationCommitReply::from_bytes(&out).unwrap();
    assert_eq!(
        (result.detail0, result.detail1),
        (body.receipt_bank, body.receipt_generation)
    );
    Ok(body)
}

pub(super) fn ack(receipt: CmHiveMutationCommitReply) -> CmHiveMutationCommitRequest {
    CmHiveMutationCommitRequest {
        abi_size: core::mem::size_of::<CmHiveMutationCommitRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: operation::ACKNOWLEDGE,
        receipt_bank: receipt.receipt_bank,
        receipt_generation: receipt.receipt_generation,
        ..CmHiveMutationCommitRequest::default()
    }
}
