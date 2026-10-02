use super::*;
use crate::{
    encode_image, encode_log_record, replay_log, try_encode_log_record, try_replay_log,
    CreateChildError, HiveIoProvider, HiveKind, HiveLogOp, HiveManager, KeyKind,
    MemoryHiveIoProvider, RegistryValueType,
};

fn record() -> Vec<u8> {
    try_encode_log_record(
        &HiveLogOp::CreateChild {
            parent: "Parent",
            name: "Child",
            class_name: Some("class"),
            descriptor: b"assigned security",
        },
        10,
    )
    .unwrap()
}

fn hive() -> Hive {
    let mut hive = Hive::new(HiveKind::System);
    hive.create_key("Parent");
    hive.finish_clean_import();
    hive
}

#[test]
fn every_torn_record_prefix_recovers_no_child_and_complete_record_recovers_all_metadata() {
    let record = record();
    for end in 0..record.len() {
        let mut h = hive();
        let before = encode_image(&h);
        assert_eq!(try_replay_log(&mut h, &record[..end], 0), Ok(0));
        assert_eq!(encode_image(&h), before, "prefix {end}");
        assert_eq!(replay_log(&mut h, &record[..end], 0), 0);
        assert_eq!(encode_image(&h), before);
    }
    let mut h = hive();
    assert_eq!(try_replay_log(&mut h, &record, 0), Ok(10));
    let child = h.open_key("Parent\\Child").unwrap();
    assert_eq!(h.key_class(child), Some("class"));
    assert_eq!(
        h.key_security_descriptor(child),
        Some(&b"assigned security"[..])
    );
    let after = encode_image(&h);
    assert_eq!(try_replay_log(&mut h, &record, 10), Ok(10));
    assert_eq!(encode_image(&h), after);
}

#[test]
fn replay_neither_manufactures_parents_nor_overwrites_existing_children() {
    let mut missing = Hive::new(HiveKind::System);
    let before = encode_image(&missing);
    assert_eq!(
        try_replay_log(&mut missing, &record(), 0),
        Err(HiveLogReplayError::CreateChild(
            CreateChildError::ParentNotFound
        ))
    );
    assert_eq!(encode_image(&missing), before);
    let mut h = hive();
    let child = h.create_key("Parent\\Child");
    h.set_key_security_descriptor(child, b"original");
    let before = encode_image(&h);
    assert_eq!(
        try_replay_log(&mut h, &record(), 0),
        Err(HiveLogReplayError::CreateChild(
            CreateChildError::NameCollision
        ))
    );
    assert_eq!(encode_image(&h), before);
    assert_eq!(replay_log(&mut h, &record(), 0), 0);
    assert_eq!(encode_image(&h), before);
}

#[test]
fn malformed_complete_metadata_and_bad_checksum_publish_nothing() {
    for (parent, name, descriptor) in [
        ("\\\\Parent", "Child", &b"sd"[..]),
        ("Parent\\\\Nested", "Child", &b"sd"[..]),
        ("\\Parent\\\\Nested", "Child", &b"sd"[..]),
        ("Parent\\", "Child", &b"sd"[..]),
        ("Parent", "a\\b", &b"sd"[..]),
        ("Parent", "Child", &b""[..]),
    ] {
        let record = encode_log_record(
            &HiveLogOp::CreateChild {
                parent,
                name,
                class_name: None,
                descriptor,
            },
            10,
        );
        let mut h = hive();
        let before = encode_image(&h);
        assert_eq!(
            try_replay_log(&mut h, &record, 0),
            Err(HiveLogReplayError::InvalidPayload)
        );
        assert_eq!(encode_image(&h), before);
    }
    let mut record = record();
    *record.last_mut().unwrap() ^= 1;
    let mut h = hive();
    let before = encode_image(&h);
    assert_eq!(
        try_replay_log(&mut h, &record, 0),
        Err(HiveLogReplayError::BadChecksum)
    );
    assert_eq!(encode_image(&h), before);
}

#[test]
fn canonical_rooted_parent_journal_recovers_policy_attributes_and_child_metadata() {
    let mut live = Hive::new(HiveKind::Security);
    let mut provider = MemoryHiveIoProvider::new();
    let descriptor = b"assigned policy security";
    for (parent_path, name) in [
        ("", "Policy"),
        ("\\Policy", "PolAcDmN"),
        ("\\Policy", "PolAcDmS"),
    ] {
        let parent = live.open_key(parent_path).unwrap();
        let canonical_parent = live.key_path(parent).unwrap();
        assert_eq!(canonical_parent, parent_path);
        let mut manager = HiveManager::for_live_hive(provider, &live);
        manager
            .mutate_with_live_apply(
                &mut live,
                HiveLogOp::CreateChild {
                    parent: &canonical_parent,
                    name,
                    class_name: Some("policy attribute"),
                    descriptor,
                },
                |hive| {
                    let mut transaction = hive.begin_transaction();
                    transaction
                        .try_create_child(
                            parent,
                            name.into(),
                            Some("policy attribute".into()),
                            descriptor.to_vec(),
                        )
                        .unwrap();
                    transaction.commit();
                    true
                },
            )
            .unwrap();
        provider = manager.into_provider();
    }
    for (path, data) in [
        ("\\Policy\\PolAcDmN", &b"account domain"[..]),
        ("\\Policy\\PolAcDmS", &b"domain SID"[..]),
    ] {
        let key = live.open_key(path).unwrap();
        let mut manager = HiveManager::for_live_hive(provider, &live);
        manager
            .mutate_with_live_apply(
                &mut live,
                HiveLogOp::SetValue {
                    path,
                    name: "",
                    value_type: RegistryValueType::Binary,
                    data,
                },
                |hive| hive.set_value(key, "", RegistryValueType::Binary, data.to_vec()),
            )
            .unwrap();
        provider = manager.into_provider();
    }
    provider.crash();
    let journal = provider.read_log().unwrap();
    let mut restored = Hive::new(HiveKind::Security);
    assert_eq!(
        try_replay_log(&mut restored, &journal, 0),
        Ok(live.sequence)
    );
    for path in ["\\Policy", "\\Policy\\PolAcDmN", "\\Policy\\PolAcDmS"] {
        let key = restored.open_key(path).unwrap();
        assert_eq!(restored.key_kind(key), Some(KeyKind::Ordinary));
        assert_eq!(restored.key_security_descriptor(key), Some(&descriptor[..]));
        assert_eq!(restored.key_class(key), Some("policy attribute"));
    }
    for (path, data) in [
        ("\\Policy\\PolAcDmN", &b"account domain"[..]),
        ("\\Policy\\PolAcDmS", &b"domain SID"[..]),
    ] {
        let key = restored.open_key(path).unwrap();
        assert_eq!(
            restored.query_value(key, ""),
            Some((RegistryValueType::Binary, data))
        );
    }
}

#[test]
fn child_journal_accepts_empty_and_explicit_hive_root_parents() {
    for parent in ["", "\\"] {
        let mut restored = Hive::new(HiveKind::Security);
        assert_eq!(restored.open_key(parent), Some(restored.root()));
        let record = encode_log_record(
            &HiveLogOp::CreateChild {
                parent,
                name: "Policy",
                class_name: None,
                descriptor: b"assigned policy security",
            },
            1,
        );
        assert_eq!(
            try_replay_log(&mut restored, &record, 0),
            Ok(1),
            "parent {parent:?}"
        );
        let policy = restored.open_key("\\Policy").unwrap();
        assert_eq!(restored.key_kind(policy), Some(KeyKind::Ordinary));
        assert_eq!(
            restored.key_security_descriptor(policy),
            Some(&b"assigned policy security"[..])
        );
    }
}

#[test]
fn decoder_rejects_odd_utf16_and_unpaired_surrogates_without_replacement_names() {
    for prefix in [&[1, 0, 0, 0, 65][..], &[2, 0, 0, 0, 0, 0xd8][..]] {
        assert!(matches!(
            decode(prefix),
            Err(HiveLogReplayError::InvalidPayload)
        ));
    }
}

#[test]
fn child_record_composes_with_a_completed_parent_record() {
    let mut records = encode_log_record(&HiveLogOp::CreateKey { path: "Parent" }, 9);
    records.extend_from_slice(&record());
    let mut h = Hive::new(HiveKind::System);
    assert_eq!(try_replay_log(&mut h, &records, 0), Ok(10));
    assert!(h
        .key_security_descriptor(h.open_key("Parent\\Child").unwrap())
        .is_some());
}

#[test]
fn failed_child_preserves_prior_records_and_prevents_later_application() {
    let mut records = encode_log_record(&HiveLogOp::CreateKey { path: "Prior" }, 9);
    records.extend_from_slice(&record());
    records.extend_from_slice(&encode_log_record(
        &HiveLogOp::CreateKey { path: "Later" },
        11,
    ));
    for strict in [false, true] {
        let mut h = Hive::new(HiveKind::System);
        if strict {
            assert_eq!(
                try_replay_log(&mut h, &records, 0),
                Err(HiveLogReplayError::CreateChild(
                    CreateChildError::ParentNotFound
                ))
            );
        } else {
            assert_eq!(replay_log(&mut h, &records, 0), 9);
        }
        assert!(h.open_key("Prior").is_some());
        assert!(h.open_key("Parent").is_none());
        assert!(h.open_key("Later").is_none());
    }
}

#[test]
fn torn_second_child_preserves_the_complete_first_child_with_its_security() {
    let first = record();
    let second = encode_log_record(
        &HiveLogOp::CreateChild {
            parent: "Parent",
            name: "Second",
            class_name: None,
            descriptor: b"second security",
        },
        11,
    );
    let mut expected = hive();
    try_replay_log(&mut expected, &first, 0).unwrap();
    let image = encode_image(&expected);
    for end in 0..second.len() {
        let mut records = first.clone();
        records.extend_from_slice(&second[..end]);
        let mut h = hive();
        assert_eq!(try_replay_log(&mut h, &records, 0), Ok(10));
        assert_eq!(encode_image(&h), image, "second prefix {end}");
    }
}
