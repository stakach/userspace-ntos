use super::*;
use crate::{
    encode_image, encode_log_record, replay_log, try_encode_log_record, try_replay_log,
    CreateChildError, HiveKind, HiveLogOp,
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
        ("\\Parent", "Child", &b"sd"[..]),
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
