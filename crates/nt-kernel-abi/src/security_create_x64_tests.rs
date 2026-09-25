use super::*;

#[test]
fn initial_create_access_state_retains_desired_access() {
    let access = initial_create_access_state(0x0012_0089);
    assert_eq!(access.remaining_desired_access, 0x0012_0089);
    assert_eq!(access.original_desired_access, 0x0012_0089);
    assert_eq!(access.previously_granted_access, 0);
    assert_eq!(access.subject_security_context, SecuritySubjectContext::default());
    let bytes = bytemuck::bytes_of(&access);
    assert_eq!(&bytes[0x10..0x14], &0x0012_0089u32.to_le_bytes());
    assert_eq!(&bytes[0x18..0x1c], &0x0012_0089u32.to_le_bytes());
}

#[test]
fn pointer_free_access_capture_preserves_distinct_masks_and_audit_flags() {
    let mut source = initial_create_access_state(0x0012_0089);
    source.operation_id = Luid { low_part: 7, high_part: 2 };
    source.security_evaluated = 1;
    source.generate_audit = 1;
    source.flags = 0x80;
    source.remaining_desired_access = 0x89;
    source.previously_granted_access = 0x20000;
    source.audit_privileges = 1;
    source.privileges.privilege_count = 1;
    let captured = capture_pointer_free_access_state(source).unwrap();
    assert_eq!(captured.operation_id, source.operation_id);
    assert_eq!(captured.remaining_desired_access, 0x89);
    assert_eq!(captured.previously_granted_access, 0x20000);
    assert_eq!(captured.original_desired_access, 0x0012_0089);
    assert!(captured.security_evaluated);
    assert!(captured.generate_audit);
    assert!(captured.audit_privileges);
    assert_eq!(captured.privileges.privilege_count, 1);
}

#[test]
fn pointer_free_access_capture_refuses_unowned_nested_memory() {
    let mut source = initial_create_access_state(1);
    source.security_descriptor = GuestAddr(0x1000);
    assert_eq!(capture_pointer_free_access_state(source), Err(CreateSecurityEncodingError::InvalidAccessState));
    source.security_descriptor = GuestAddr::NULL;
    source.aux_data = GuestAddr(0x2000);
    assert_eq!(capture_pointer_free_access_state(source), Err(CreateSecurityEncodingError::InvalidAccessState));
    source.aux_data = GuestAddr::NULL;
    source.privileges_allocated = 1;
    assert_eq!(capture_pointer_free_access_state(source), Err(CreateSecurityEncodingError::InvalidAccessState));
}

#[test]
fn descriptor_capture_separates_source_address_from_access_fields() {
    let mut source = initial_create_access_state(0x0012_0089);
    source.security_descriptor = GuestAddr(0x1000_4000);
    source.security_evaluated = 1;
    source.previously_granted_access = 0x20000;
    let (fields, descriptor) = capture_access_state_with_descriptor(source).unwrap();
    assert_eq!(descriptor, Some(GuestAddr(0x1000_4000)));
    assert_eq!(fields.security_descriptor, GuestAddr::NULL);
    assert_eq!(fields.aux_data, GuestAddr::NULL);
    assert_eq!(fields.original_desired_access, 0x0012_0089);
    assert_eq!(fields.previously_granted_access, 0x20000);
    assert!(fields.security_evaluated);
    assert_eq!(
        capture_pointer_free_access_state(source),
        Err(CreateSecurityEncodingError::InvalidAccessState)
    );

    source.security_descriptor = GuestAddr::NULL;
    let (fields, descriptor) = capture_access_state_with_descriptor(source).unwrap();
    assert_eq!(descriptor, None);
    assert_eq!(fields, capture_pointer_free_access_state(source).unwrap());
}

#[test]
fn descriptor_capture_still_refuses_other_unowned_access_state_graphs() {
    let mut source = initial_create_access_state(1);
    source.security_descriptor = GuestAddr(0x1000);
    source.aux_data = GuestAddr(0x2000);
    assert_eq!(capture_access_state_with_descriptor(source), Err(CreateSecurityEncodingError::InvalidAccessState));
    source.aux_data = GuestAddr::NULL;
    source.privileges_allocated = 1;
    assert_eq!(capture_access_state_with_descriptor(source), Err(CreateSecurityEncodingError::InvalidAccessState));
    source.privileges_allocated = 0;
    source.object_name = UnicodeString::new(GuestAddr(0x3000), 2);
    assert_eq!(capture_access_state_with_descriptor(source), Err(CreateSecurityEncodingError::InvalidAccessState));
    source.object_name = UnicodeString::default();
    source.security_evaluated = 2;
    assert_eq!(capture_access_state_with_descriptor(source), Err(CreateSecurityEncodingError::InvalidAccessState));
}

#[test]
fn qos_capture_checks_nt5_shape() {
    let mut source = SecurityQualityOfService::default();
    source.length = core::mem::size_of::<SecurityQualityOfService>() as u32;
    source.impersonation_level = 2;
    source.context_tracking_mode = 1;
    let captured = capture_create_qos(source).unwrap();
    assert_eq!(captured.impersonation_level, 2);
    source.context_tracking_mode = 2;
    assert_eq!(capture_create_qos(source), Err(CreateSecurityEncodingError::InvalidQos));
}

fn proof() -> SourceSecurityProof {
    SourceSecurityProof {
        ticket_id: 5,
        ticket_generation: 7,
        irp_id: 11,
        irp_generation: 13,
        domain_id: 17,
        domain_cookie: 19,
        security_context_address: 0x1000_8000,
        primary_token_id: 37,
        primary_token_generation: 23,
        client_token_id: 41,
        client_token_generation: 23,
    }
}

fn proof_without_client() -> SourceSecurityProof {
    SourceSecurityProof {
        client_token_id: 0,
        client_token_generation: 0,
        ..proof()
    }
}

fn token(address: u64, id: u64) -> ProviderTokenProjection {
    ProviderTokenProjection {
        address: GuestAddr(address),
        token_id: id,
        token_generation: 23,
        domain_id: 29,
        domain_cookie: 31,
    }
}

fn fields() -> CreateSecurityFields {
    CreateSecurityFields {
        source: proof(),
        provider_domain_id: 29,
        provider_domain_cookie: 31,
        primary_token: token(0x2000_1000, 37),
        client_token: Some((token(0x2000_2000, 41), 2)),
        process_audit_id: GuestAddr(0x2000_3000),
        desired_access: 0x0012_0089,
        full_create_options: 0x0400_0020,
        qos: Some(CreateQosFields {
            length: 12,
            impersonation_level: 2,
            context_tracking_mode: 1,
            effective_only: 0,
        }),
        access: AccessStateFields {
            operation_id: Luid {
                low_part: 0x55aa,
                high_part: 7,
            },
            security_evaluated: true,
            generate_audit: true,
            generate_on_close: false,
            flags: 0x80,
            remaining_desired_access: 0x89,
            previously_granted_access: 0x20000,
            original_desired_access: 0x0012_0089,
            security_descriptor: GuestAddr(0x2000_4000),
            aux_data: GuestAddr(0x2000_5000),
            privileges: InitialPrivilegeSet {
                privilege_count: 1,
                control: 1,
                privileges: [
                    LuidAndAttributes {
                        luid: Luid {
                            low_part: 9,
                            high_part: 0,
                        },
                        attributes: 2,
                    },
                    LuidAndAttributes::default(),
                    LuidAndAttributes::default(),
                ],
            },
            audit_privileges: true,
            object_name: UnicodeString::new(GuestAddr(0x2000_6000), 4),
            object_type_name: UnicodeString::new(GuestAddr(0x2000_7000), 5),
        },
    }
}

#[test]
fn nt5_x64_graph_has_exact_linked_addresses_and_offsets() {
    let base = GuestAddr(0x2000_8000);
    let mut output = [0xa5; CREATE_SECURITY_GRAPH_SIZE + 8];
    encode_create_security_graph(base, proof(), fields(), &mut output).unwrap();
    let graph: CreateSecurityGraph =
        bytemuck::pod_read_unaligned(&output[..CREATE_SECURITY_GRAPH_SIZE]);
    assert_eq!(graph.io.security_qos, GuestAddr(base.0 + 0xb8));
    assert_eq!(graph.io.access_state, GuestAddr(base.0 + 0x18));
    assert!(graph.io.has_embedded_access_state(base));
    assert!(graph.io.has_embedded_qos(base));
    assert!(!graph.io.has_embedded_access_state(GuestAddr(base.0 + 8)));
    assert!(!graph.io.has_embedded_qos(GuestAddr(base.0 + 8)));
    assert_eq!(graph.io.desired_access, 0x0012_0089);
    assert_eq!(graph.io.full_create_options, 0x0400_0020);
    assert_eq!(
        graph.access.subject_security_context.client_token,
        GuestAddr(0x2000_2000)
    );
    assert_eq!(graph.access.subject_security_context.impersonation_level, 2);
    assert_eq!(
        graph.access.subject_security_context.primary_token,
        GuestAddr(0x2000_1000)
    );
    assert_eq!(
        graph.access.subject_security_context.process_audit_id,
        GuestAddr(0x2000_3000)
    );
    assert_eq!(graph.access.privileges.privilege_count, 1);
    assert_eq!(graph.access.privileges.privileges[0].luid.low_part, 9);
    assert_eq!(graph.access.object_name.buffer, GuestAddr(0x2000_6000));
    assert_eq!(graph.qos.impersonation_level, 2);
    assert_eq!(&output[CREATE_SECURITY_GRAPH_SIZE..], &[0xa5; 8]);
}

#[test]
fn absent_optional_client_and_qos_do_not_invent_authority() {
    let mut input = fields();
    input.client_token = None;
    input.source = proof_without_client();
    input.qos = None;
    let mut output = [0xa5; CREATE_SECURITY_GRAPH_SIZE];
    encode_create_security_graph(
        GuestAddr(0x4000),
        proof_without_client(),
        input,
        &mut output,
    )
    .unwrap();
    let graph: CreateSecurityGraph = bytemuck::pod_read_unaligned(&output);
    assert_eq!(graph.io.security_qos, GuestAddr::NULL);
    assert_eq!(
        graph.access.subject_security_context.client_token,
        GuestAddr::NULL
    );
    assert_eq!(graph.access.subject_security_context.impersonation_level, 0);
    assert_eq!(
        graph.access.subject_security_context.primary_token,
        input.primary_token.address
    );
    assert_eq!(graph.qos, SecurityQualityOfService::default());
}

#[test]
fn missing_or_stale_source_identity_never_writes_graph() {
    let baseline = proof();
    let mut candidates = [baseline; 11];
    candidates[0].ticket_id = 0;
    candidates[1].ticket_generation += 1;
    candidates[2].irp_id += 1;
    candidates[3].irp_generation += 1;
    candidates[4].domain_id += 1;
    candidates[5].domain_cookie += 1;
    candidates[6].security_context_address += 8;
    candidates[7].primary_token_id += 1;
    candidates[8].primary_token_generation += 1;
    candidates[9].client_token_id += 1;
    candidates[10].client_token_generation += 1;
    for observed in candidates {
        let mut output = [0xa5; CREATE_SECURITY_GRAPH_SIZE];
        let mut input = fields();
        input.source = observed;
        assert_eq!(
            encode_create_security_graph(GuestAddr(0x4000), baseline, input, &mut output),
            Err(CreateSecurityEncodingError::InvalidSource),
        );
        assert_eq!(output, [0xa5; CREATE_SECURITY_GRAPH_SIZE]);
    }
    let mut output = [0xa5; CREATE_SECURITY_GRAPH_SIZE];
    let mut absent_expected = baseline;
    absent_expected.security_context_address = 0;
    assert_eq!(
        encode_create_security_graph(GuestAddr(0x4000), absent_expected, fields(), &mut output),
        Err(CreateSecurityEncodingError::InvalidSource),
    );
    assert_eq!(output, [0xa5; CREATE_SECURITY_GRAPH_SIZE]);
}

#[test]
fn unbound_or_foreign_token_projection_is_rejected() {
    let mut invalid = fields();
    invalid.primary_token.address = GuestAddr::NULL;
    let mut foreign = fields();
    foreign.primary_token.domain_cookie += 1;
    let mut missing_generation = fields();
    missing_generation
        .client_token
        .as_mut()
        .unwrap()
        .0
        .token_generation = 0;
    let mut invalid_level = fields();
    invalid_level.client_token.as_mut().unwrap().1 = 4;
    let mut wrong_primary = fields();
    wrong_primary.primary_token.token_id += 1;
    let mut wrong_client = fields();
    wrong_client.client_token.as_mut().unwrap().0.token_id += 1;
    let mut missing_client = fields();
    missing_client.client_token = None;
    let mut unsolicited_client = fields();
    unsolicited_client.source = proof_without_client();
    for input in [
        invalid,
        foreign,
        missing_generation,
        invalid_level,
        wrong_primary,
        wrong_client,
        missing_client,
    ] {
        let mut output = [0xa5; CREATE_SECURITY_GRAPH_SIZE];
        assert_eq!(
            encode_create_security_graph(GuestAddr(0x4000), proof(), input, &mut output),
            Err(CreateSecurityEncodingError::InvalidTokenProjection),
        );
        assert_eq!(output, [0xa5; CREATE_SECURITY_GRAPH_SIZE]);
    }
    let mut output = [0xa5; CREATE_SECURITY_GRAPH_SIZE];
    assert_eq!(
        encode_create_security_graph(
            GuestAddr(0x4000),
            proof_without_client(),
            unsolicited_client,
            &mut output,
        ),
        Err(CreateSecurityEncodingError::InvalidTokenProjection),
    );
    assert_eq!(output, [0xa5; CREATE_SECURITY_GRAPH_SIZE]);
}

#[test]
fn malformed_layout_inputs_and_short_output_do_not_partially_write() {
    let mut output = [0xa5; CREATE_SECURITY_GRAPH_SIZE];
    assert_eq!(
        encode_create_security_graph(GuestAddr(0x4000), proof(), fields(), &mut output[..0xbf]),
        Err(CreateSecurityEncodingError::BufferTooSmall),
    );
    assert_eq!(output, [0xa5; CREATE_SECURITY_GRAPH_SIZE]);
    for base in [GuestAddr::NULL, GuestAddr(0x4001), GuestAddr(u64::MAX - 7)] {
        assert_eq!(
            encode_create_security_graph(base, proof(), fields(), &mut output),
            Err(CreateSecurityEncodingError::InvalidProviderAddress),
        );
        assert_eq!(output, [0xa5; CREATE_SECURITY_GRAPH_SIZE]);
    }
    let mut bad_privileges = fields();
    bad_privileges.access.privileges.privilege_count = 4;
    assert_eq!(
        encode_create_security_graph(GuestAddr(0x4000), proof(), bad_privileges, &mut output),
        Err(CreateSecurityEncodingError::InvalidAccessState),
    );
    let mut bad_qos = fields();
    bad_qos.qos.as_mut().unwrap().length = 8;
    assert_eq!(
        encode_create_security_graph(GuestAddr(0x4000), proof(), bad_qos, &mut output),
        Err(CreateSecurityEncodingError::InvalidQos),
    );
    assert_eq!(output, [0xa5; CREATE_SECURITY_GRAPH_SIZE]);
}
