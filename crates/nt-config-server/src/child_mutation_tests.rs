use super::*;
use crate::{
    config_manager_from_system_hive, CmServer, MountedSystemHive, PreparedSystemHiveMutation,
};
use alloc::vec;
use nt_hive_core::{Hive, HiveKind};

fn volatile_server() -> CmServer {
    let mut server = CmServer::new_for_incarnation(core::num::NonZeroU32::MIN);
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key(r"ControlSet001\Services");
    let current_control_set = hive.current_control_set().unwrap();
    let hardware_profile =
        nt_hive_core::HardwareProfileAlias::capture(&hive, &current_control_set).unwrap();
    server.cm = config_manager_from_system_hive(&hive, &current_control_set);
    server.system_hive = Some(MountedSystemHive {
        hive,
        identity: server.identities.take().unwrap(),
        generation: 1,
        current_control_set,
        hardware_profile,
    });
    server
}

#[test]
fn volatile_child_leases_and_absolute_aliases_share_one_namespace() {
    let mut server = volatile_server();
    let parent_path = r"\Registry\Machine\System\CurrentControlSet\Services";
    let mounted = server.system_hive.as_ref().unwrap();
    let physical = mounted.resolve_physical_path(parent_path).unwrap();
    let parent = mounted
        .hive
        .open_key(&mounted.resolve_relative_path(parent_path).unwrap())
        .unwrap();
    let token = server.system_key_leases.open(parent, physical).unwrap();
    let child = |name: &str| HiveMutation::CreateChild {
        authority: crate::mutation::ChildParentAuthority::Lease(token),
        parent: String::new(),
        name: name.into(),
        class_name: None,
        descriptor: vec![1],
        volatile: true,
    };
    let mut mutations = vec![child("Transient")];
    server
        .system_hive
        .as_ref()
        .unwrap()
        .resolve_mutation_paths(&server.system_key_leases, &mut mutations)
        .unwrap();
    assert!(server
        .prepare_system_hive_mutations(&mutations)
        .unwrap()
        .is_empty());
    server.commit_system_hive_mutations(&mutations, 2).unwrap();
    let mounted = server.system_hive.as_ref().unwrap();
    let by_alias = mounted
        .hive
        .open_key(
            &mounted
                .resolve_relative_path(&alloc::format!("{}\\Transient", parent_path))
                .unwrap(),
        )
        .unwrap();
    let by_physical = mounted
        .hive
        .open_key(r"ControlSet001\Services\Transient")
        .unwrap();
    let by_parent = mounted
        .hive
        .open_subkey(
            server.system_key_leases.get(token).unwrap().key,
            "Transient",
        )
        .unwrap();
    assert_eq!(by_alias, by_physical);
    assert_eq!(by_alias, by_parent);
    assert!(mounted.hive.is_volatile(by_alias));
    let selector = vec![
        HiveMutation::CreateKey {
            path: r"\Registry\Machine\System\ControlSet002\Services".into(),
        },
        HiveMutation::SetValue {
            path: r"\Registry\Machine\System\Select".into(),
            name: "Current".into(),
            value_type: 4,
            data: 2u32.to_le_bytes().to_vec(),
        },
    ];
    server.prepare_system_hive_mutations(&selector).unwrap();
    server.commit_system_hive_mutations(&selector, 3).unwrap();
    let mut later = vec![child("Anchored")];
    server
        .system_hive
        .as_ref()
        .unwrap()
        .resolve_mutation_paths(&server.system_key_leases, &mut later)
        .unwrap();
    assert!(server
        .prepare_system_hive_mutations(&later)
        .unwrap()
        .is_empty());
    server.commit_system_hive_mutations(&later, 4).unwrap();
    let mounted = server.system_hive.as_ref().unwrap();
    assert!(mounted
        .hive
        .open_key(r"ControlSet001\Services\Anchored")
        .is_some());
    assert!(mounted
        .hive
        .open_key(r"ControlSet002\Services\Anchored")
        .is_none());
    assert!(mounted
        .hive
        .open_key(
            &mounted
                .resolve_relative_path(&alloc::format!("{}\\Anchored", parent_path))
                .unwrap()
        )
        .is_none());
    let disk = nt_hive_core::decode_image(&nt_hive_core::encode_image(&mounted.hive)).unwrap();
    assert!(disk.open_key(r"ControlSet001\Services\Transient").is_none());
    assert!(disk.open_key(r"ControlSet001\Services\Anchored").is_none());
    assert!(disk.open_key(r"ControlSet002\Services").is_some());
}

#[test]
fn volatile_only_and_mixed_preparations_keep_durable_sequence_and_replay_exact() {
    let mut server = volatile_server();
    let before = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
    let original_sequence = server.system_hive.as_ref().unwrap().hive.sequence;
    let parent = r"\Registry\Machine\System\ControlSet001\Services";
    let child = |name: &str, volatile| HiveMutation::CreateChild {
        authority: crate::mutation::ChildParentAuthority::Path,
        parent: parent.into(),
        name: name.into(),
        class_name: None,
        descriptor: vec![1],
        volatile,
    };
    let volatile = vec![
        child("Transient", true),
        HiveMutation::SetValue {
            path: alloc::format!("{}\\Transient", parent),
            name: "Value".into(),
            value_type: 3,
            data: vec![1, 2, 3],
        },
    ];
    let journal = server.prepare_system_hive_mutations(&volatile).unwrap();
    assert!(journal.is_empty());
    assert_eq!(
        nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive),
        before
    );
    let token = server.identities.take().unwrap();
    server.prepared_system_mutation = Some(PreparedSystemHiveMutation {
        token,
        expected_generation: 1,
        next_generation: 2,
        semantic_journal_len: 100,
        mutations: volatile,
        durable_journal: journal,
    });
    assert_eq!(
        server
            .publish_prepared_system_mutation(token, 1, 100)
            .unwrap()
            .0,
        2
    );
    assert_eq!(
        server.system_hive.as_ref().unwrap().hive.sequence,
        original_sequence
    );
    let key = server
        .system_hive
        .as_ref()
        .unwrap()
        .hive
        .open_key(r"ControlSet001\Services\Transient")
        .unwrap();
    assert!(server.system_hive.as_ref().unwrap().hive.is_volatile(key));
    let invalid = HiveMutation::CreateChild {
        authority: crate::mutation::ChildParentAuthority::Path,
        parent: alloc::format!("{}\\Transient", parent),
        name: "StableChild".into(),
        class_name: None,
        descriptor: vec![1],
        volatile: false,
    };
    assert_eq!(
        server
            .prepare_system_hive_mutations(&[invalid])
            .unwrap_err(),
        0xc000_0181u32 as i32
    );
    let mixed = vec![
        HiveMutation::SetKeyClass {
            path: alloc::format!("{}\\Transient", parent),
            class_name: Some("live".into()),
        },
        child("Durable", false),
        HiveMutation::DeleteValue {
            path: alloc::format!("{}\\Transient", parent),
            name: "Value".into(),
        },
        HiveMutation::DeleteKey {
            path: alloc::format!("{}\\Transient", parent),
        },
    ];
    let journal = server.prepare_system_hive_mutations(&mixed).unwrap();
    assert!(!journal.is_empty());
    let mut replay = nt_hive_core::decode_image(&before).unwrap();
    assert_eq!(
        nt_hive_core::try_replay_log(&mut replay, &journal, original_sequence).unwrap(),
        original_sequence + 1
    );
    assert!(replay.open_key(r"ControlSet001\Services\Durable").is_some());
    assert!(replay
        .open_key(r"ControlSet001\Services\Transient")
        .is_none());
    server.commit_system_hive_mutations(&mixed, 3).unwrap();
    let live = &server.system_hive.as_ref().unwrap().hive;
    assert_eq!(live.sequence, original_sequence + 1);
    assert!(live.open_key(r"ControlSet001\Services\Transient").is_none());
    assert!(live.open_key(r"ControlSet001\Services\Durable").is_some());
}

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
                volatile: false,
                authority: crate::mutation::ChildParentAuthority::Path,
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
        (4, 0, text("Child")),
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
