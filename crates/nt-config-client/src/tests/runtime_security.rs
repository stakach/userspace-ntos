use super::*;

#[test]
fn malformed_security_metadata_replies_never_publish_key_identity() {
    struct Fake {
        reply: CmReply,
        bytes: Vec<u8>,
    }
    impl Backend for Fake {
        fn call(&mut self, _: u16, _: &[u8], output: &mut [u8]) -> CmReply {
            let count = output.len().min(self.bytes.len());
            output[..count].copy_from_slice(&self.bytes[..count]);
            self.reply
        }
    }
    let mut real = ConfigClient::new(Framed {
        server: fresh_server(),
    });
    let descriptor = real.query_key_security(r"\Registry\Machine").unwrap();
    let valid = CmReply {
        status: STATUS_SUCCESS,
        information: 0,
        detail0: 7,
        detail1: 1,
    };
    for reply in [
        CmReply {
            detail0: 0,
            ..valid
        },
        CmReply {
            detail1: 2,
            ..valid
        },
        CmReply {
            information: 1,
            ..valid
        },
    ] {
        let mut client = ConfigClient::new(Fake {
            reply,
            bytes: vec![],
        });
        assert_eq!(
            client.create_secured_key_checked_with_class(
                r"\Registry\Machine\Child",
                &descriptor,
                false,
                3,
                1,
                Some("Class")
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    let valid = CmReply {
        information: descriptor.len() as u32,
        ..valid
    };
    for reply in [
        CmReply {
            detail0: 0,
            ..valid
        },
        CmReply {
            detail1: 0,
            ..valid
        },
        CmReply {
            detail1: u64::MAX,
            ..valid
        },
        CmReply {
            information: 0,
            ..valid
        },
        CmReply {
            information: 4097,
            ..valid
        },
    ] {
        let mut client = ConfigClient::new(Fake {
            reply,
            bytes: descriptor.clone(),
        });
        assert_eq!(
            client.query_key_security_snapshot("anything").unwrap_err(),
            STATUS_INVALID_PARAMETER
        );
    }
    let mut client = ConfigClient::new(Fake {
        reply: CmReply {
            information: 20,
            ..valid
        },
        bytes: vec![0; 20],
    });
    assert_eq!(
        client.query_key_security_snapshot("anything").unwrap_err(),
        STATUS_INVALID_PARAMETER
    );
    let mut client = ConfigClient::new(Fake {
        reply: valid,
        bytes: descriptor.clone(),
    });
    assert_eq!(
        client
            .query_key_security_snapshot("anything")
            .unwrap()
            .descriptor,
        descriptor
    );
}

#[test]
fn runtime_classes_and_large_values_roundtrip_without_reopening_paths() {
    use nt_config_abi::runtime_key_op as op;
    let mut client = ConfigClient::new(Framed {
        server: fresh_server(),
    });
    let parent = client
        .query_key_security_snapshot(r"\Registry\Machine")
        .unwrap();
    let path = r"\Registry\Machine\Classed";
    let (key, created) = client
        .create_secured_key_checked_with_class(
            path,
            &parent.descriptor,
            true,
            parent.key,
            parent.generation,
            Some("NativeClass"),
        )
        .unwrap();
    assert!(created);
    assert_eq!(
        client.runtime_key_class(key).unwrap().as_deref(),
        Some("NativeClass")
    );
    let data: Vec<u8> = (0..24_137).map(|index| (index % 251) as u8).collect();
    client
        .runtime_key_operation(key, op::SET_VALUE, 0, "Large", 3, &data)
        .unwrap();
    let (reply, read) = client
        .runtime_key_operation(key, op::VALUE, 0, "Large", 0, &[])
        .unwrap();
    assert_eq!(reply.detail0, 3);
    assert_eq!(read, data);
    let (reply, read) = client
        .runtime_key_operation(key, op::ENUM_VALUE, 0, "", 0, &[])
        .unwrap();
    assert_eq!(&read[reply.detail1 as usize..], data.as_slice());
    let (reply, _) = client
        .runtime_key_operation(parent.key, op::OPEN_RELATIVE, 0, "Classed", 0, &[])
        .unwrap();
    assert_eq!(reply.detail0, key);
    assert_eq!(
        client
            .runtime_key_operation(key, op::OPEN_RELATIVE, 0, "", 0, &[])
            .unwrap()
            .0
            .detail0,
        key
    );
    assert_eq!(
        client
            .runtime_key_operation(key, op::OPEN_RELATIVE, 0, "Missing\\Child", 0, &[])
            .unwrap_err(),
        0xC000_003Au32 as i32
    );
    assert_eq!(
        client
            .runtime_key_operation(key, op::OPEN_RELATIVE, 0, r"\Registry", 0, &[])
            .unwrap_err(),
        STATUS_INVALID_PARAMETER
    );
    let token = client
        .begin_set_value_id_transfer(key, "Pending", 3, 4)
        .unwrap();
    client
        .append_set_value_transfer(token, 0, 4, &[1, 2, 3, 4])
        .unwrap();
    assert!(client
        .backend
        .server
        .config_mut()
        .registry_mut()
        .delete_key(key, false));
    let (replacement, _) = client.create_key_with_options(path, true).unwrap();
    assert_eq!(
        client.commit_set_value_transfer(token, 4),
        Err(0xC000_017Cu32 as i32)
    );
    assert_eq!(
        client
            .runtime_key_operation(replacement, op::VALUE, 0, "Pending", 0, &[])
            .unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        client
            .runtime_key_operation(key, op::OPEN_RELATIVE, 0, "", 0, &[])
            .unwrap_err(),
        0xC000_017Cu32 as i32
    );
}

#[test]
fn runtime_operations_retain_deleted_identity_and_enumerate_actual_data() {
    use nt_config_abi::runtime_key_op as op;
    let mut client = ConfigClient::new(Framed {
        server: fresh_server(),
    });
    let path = r"\Registry\Machine\Identity";
    let (old, _) = client.create_key_with_options(path, true).unwrap();
    client
        .runtime_key_operation(old, op::SET_VALUE, 0, "Value", 4, &17u32.to_le_bytes())
        .unwrap();
    let (reply, bytes) = client
        .runtime_key_operation(old, op::ENUM_VALUE, 0, "", 0, &[])
        .unwrap();
    assert_eq!(reply.detail0, 4);
    assert_eq!(reply.detail1, 10);
    assert_eq!(&bytes[10..], &17u32.to_le_bytes());
    let (_, bytes) = client
        .runtime_key_operation(old, op::INFO, 0, "", 0, &[])
        .unwrap();
    let info = nt_config_abi::CmRuntimeKeyInfo::from_bytes(&bytes).unwrap();
    assert_eq!(info.values, 1);
    assert_eq!(info.max_value_data, 4);
    assert!(client
        .backend
        .server
        .config_mut()
        .registry_mut()
        .delete_key(old, false));
    let (new, _) = client.create_key_with_options(path, true).unwrap();
    assert_ne!(new, old);
    for operation in [
        op::SECURITY,
        op::VALUE,
        op::INFO,
        op::ENUM_KEY,
        op::ENUM_VALUE,
        op::DELETE_VALUE,
    ] {
        assert_eq!(
            client
                .runtime_key_operation(old, operation, 0, "", 0, &[])
                .unwrap_err(),
            0xC000_017Cu32 as i32
        );
    }
    assert_eq!(
        client
            .runtime_key_operation(old, op::SET_VALUE, 0, "Value", 4, &[1])
            .unwrap_err(),
        0xC000_017Cu32 as i32
    );
    assert_eq!(
        client
            .runtime_key_operation(new, op::VALUE, 0, "Value", 0, &[])
            .unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[test]
fn runtime_security_roundtrip_and_atomic_create() {
    let mut client = ConfigClient::new(Framed {
        server: fresh_server(),
    });
    let descriptor = client.query_key_security(r"\Registry\Machine").unwrap();
    assert!(!descriptor.is_empty());
    let path = r"\Registry\Machine\Secured";
    let (id, created) = client.create_secured_key(path, &descriptor, true).unwrap();
    assert!(created);
    assert_eq!(client.query_key_security(path).unwrap(), descriptor);
    assert_eq!(
        client.create_secured_key(path, &descriptor, false),
        Ok((id, false))
    );
    let mut replacement = descriptor.clone();
    replacement[2] |= 1;
    client.set_key_security(path, &replacement).unwrap();
    assert_eq!(client.query_key_security(path).unwrap(), replacement);
    assert!(client.set_key_security(path, &[0; 20]).is_err());
    assert_eq!(client.query_key_security(path).unwrap(), replacement);
    assert!(client
        .create_secured_key(r"\Registry\Missing\Leaf", &descriptor, false)
        .is_err());
    assert!(!client.open_key(r"\Registry\Missing"));
}

#[test]
fn runtime_security_rejects_overlap_and_oversized_frames() {
    use nt_config_abi::{CmKeySecurityRequest, CM_KEY_SECURITY_FRAME_BYTES};
    let mut server = fresh_server();
    let request = CmKeySecurityRequest {
        abi_size: core::mem::size_of::<CmKeySecurityRequest>() as u16,
        flags: 0,
        path_offset: 0,
        path_len_bytes: 0,
        descriptor_offset: 0,
        descriptor_len: 0,
        reserved: 0,
        class_len: 0,
        class_reserved: 0,
        expected_parent: 0,
        expected_parent_generation: 0,
    };
    assert_eq!(
        server
            .dispatch(
                opcode::CM_OP_QUERY_KEY_SECURITY,
                request.as_bytes(),
                &mut [0; 64]
            )
            .status,
        STATUS_INVALID_PARAMETER
    );
    let mut client = ConfigClient::new(Framed { server });
    assert!(client
        .create_secured_key(
            r"\Registry\Machine\TooLarge",
            &vec![0; CM_KEY_SECURITY_FRAME_BYTES],
            false
        )
        .is_err());
    assert!(!client.open_key(r"\Registry\Machine\TooLarge"));
}

#[test]
fn runtime_create_rejects_changed_parent_security_snapshot() {
    let mut client = ConfigClient::new(Framed {
        server: fresh_server(),
    });
    let parent = client
        .query_key_security_snapshot(r"\Registry\Machine")
        .unwrap();
    let mut changed = parent.descriptor.clone();
    changed[2] |= 1;
    client
        .set_key_security(r"\Registry\Machine", &changed)
        .unwrap();
    let path = r"\Registry\Machine\Stale";
    assert_eq!(
        client.create_secured_key_checked(
            path,
            &parent.descriptor,
            false,
            parent.key,
            parent.generation
        ),
        Err(0xC000_022Du32 as i32)
    );
    assert!(!client.open_key(path));
    let current = client
        .query_key_security_snapshot(r"\Registry\Machine")
        .unwrap();
    assert!(client
        .create_secured_key_checked(
            path,
            &parent.descriptor,
            false,
            current.key,
            current.generation
        )
        .is_ok());
}
