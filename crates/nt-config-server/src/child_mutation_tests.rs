use super::*;
use alloc::vec;

fn text(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn data(class: &[u8], descriptor: &[u8]) -> Vec<u8> {
    let mut result = nt_config_abi::hive_create_child_metadata::header(
        class.len() as u32,
        descriptor.len() as u32,
    )
    .to_vec();
    result.extend_from_slice(class);
    result.extend_from_slice(descriptor);
    result
}

fn record(flags: u16, value_type: u32, name: &[u8], data: &[u8]) -> Vec<u8> {
    let path = text(r"\Registry\Machine\System\ControlSet001\Services");
    let header = CmHiveMutationRecord {
        kind: hive_mutation_kind::CREATE_CHILD,
        flags,
        value_type,
        path_len_bytes: path.len() as u32,
        name_len_bytes: name.len() as u32,
        data_len_bytes: data.len() as u32,
        _reserved: 0,
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(&path);
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(data);
    bytes
}

#[test]
fn child_wire_preserves_large_descriptor_and_class_presence() {
    let descriptor = vec![0x42; 9000];
    for (flags, class) in [
        (0, None),
        (hive_mutation_flags::CLASS_PRESENT, Some("")),
        (hive_mutation_flags::CLASS_PRESENT, Some("class")),
    ] {
        let data = data(&text(class.unwrap_or("")), &descriptor);
        let decoded = decode_mutation_journal(&record(flags, 0, &text("Child"), &data)).unwrap();
        assert_eq!(
            decoded,
            vec![HiveMutation::CreateChild {
                parent: r"\Registry\Machine\System\ControlSet001\Services".into(),
                name: "Child".into(),
                class_name: class.map(String::from),
                descriptor: descriptor.clone(),
            }]
        );
    }
}

#[test]
fn child_wire_rejects_unknown_flags_types_names_and_invalid_utf16() {
    let data = data(&[], b"sd");
    for (flags, ty, name) in [
        (2, 0, text("Child")),
        (0, 1, text("Child")),
        (0, 0, text("")),
        (0, 0, text("a\\b")),
        (0, 0, text("a\0b")),
        (0, 0, vec![0, 0xd8]),
        (0, 0, vec![1]),
    ] {
        assert!(decode_mutation_journal(&record(flags, ty, &name, &data)).is_none());
    }
}

#[test]
fn child_wire_rejects_bad_metadata_and_every_truncated_record() {
    for (flags, data) in [
        (0, data(&[], &[])),
        (0, data(&text("class"), b"sd")),
        (1, data(&[0, 0xd8], b"sd")),
        (1, data(&text("a\0b"), b"sd")),
        (
            1,
            data(&text(&"c".repeat(CM_MAX_HIVE_VALUE_NAME_UNITS + 1)), b"sd"),
        ),
    ] {
        assert!(decode_mutation_journal(&record(flags, 0, &text("Child"), &data)).is_none());
    }
    let complete = record(1, 0, &text("Child"), &data(&text("class"), b"assigned"));
    for end in 0..complete.len() {
        assert!(decode_mutation_journal(&complete[..end]).is_none());
    }
    let mut extra = complete.clone();
    extra.push(0);
    assert!(decode_mutation_journal(&extra).is_none());
    assert!(decode_mutation_journal(&complete).is_some());
}
