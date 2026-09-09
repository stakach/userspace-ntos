use super::*;
use super::test_support::*;
use crate::SystemHiveMutation;
use alloc::vec::Vec;

#[test]
fn lost_commit_and_ack_replies_preserve_exact_publication_and_durable_replay() {
    let mut client = client(1);
    let device = r"\Registry\Machine\System\CurrentControlSet\Enum\ROOT\DEVICE\0000";
    let service: Vec<u8> = "Driver\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let prepared = client
        .prepare_system_hive_mutation(
            1,
            &[
                SystemHiveMutation::CreateChild {
                    parent: PARENT,
                    name: "Child",
                    class_name: Some("class"),
                    descriptor: b"security",
                },
                SystemHiveMutation::CreateKey { path: device },
                SystemHiveMutation::SetValue {
                    path: device,
                    name: "Service",
                    value_type: 1,
                    data: &service,
                },
                SystemHiveMutation::PublishDeviceAction {
                    kind: crate::DeviceActionKind::Arrival,
                    instance_id: r"ROOT\DEVICE\0000",
                },
            ],
        )
        .unwrap();
    let durable = prepared.durable_journal.clone();
    client.backend.corrupt = Some((operation::COMMIT, 0));
    assert_eq!(
        client.commit_system_hive_mutation_retained(&prepared),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(client
        .query_system_hive_key(&alloc::format!("{PARENT}\\Child"))
        .is_ok());
    assert_eq!(prepared.durable_journal, durable);
    assert_eq!(client.import_system_hive(&image()), Err(BUSY));
    let receipt = client
        .commit_system_hive_mutation_retained(&prepared)
        .unwrap();
    assert!(receipt.outcome().has_pending_device_action);
    while let Some(event) = client.next_device_action().unwrap() {
        client.acknowledge_device_action(&event).unwrap();
    }
    assert_eq!(
        client.commit_system_hive_mutation_retained(&prepared),
        Ok(receipt)
    );
    assert_eq!(client.prepare_system_hive_checkpoint(2).unwrap_err(), BUSY);
    client.backend.corrupt = Some((operation::ACKNOWLEDGE, 0));
    assert!(client
        .acknowledge_system_hive_mutation_commit(receipt)
        .is_err());
    let next = prepare(&mut client, 2, "Next");
    let next_receipt = client.commit_system_hive_mutation_retained(&next).unwrap();
    assert!(!next_receipt.outcome().has_pending_device_action);
    let proof = client
        .acknowledge_system_hive_mutation_commit(receipt)
        .unwrap();
    assert_eq!(proof.receipt(), receipt);
    assert_eq!(
        proof.disposition(),
        SystemHiveMutationAcknowledgementDisposition::AlreadyAcknowledged
    );
    assert_eq!(client.import_system_hive(&image()), Err(BUSY));
    assert_eq!(
        client.commit_system_hive_mutation_retained(&next),
        Ok(next_receipt)
    );
    let _ = client
        .acknowledge_system_hive_mutation_commit(next_receipt)
        .unwrap();
    client.import_system_hive(&image()).unwrap();
    assert_eq!(
        client
            .acknowledge_system_hive_mutation_commit(receipt)
            .unwrap()
            .disposition(),
        SystemHiveMutationAcknowledgementDisposition::AlreadyAcknowledged
    );
    assert!(client
        .commit_system_hive_mutation_retained(&prepared)
        .is_err());
}

#[test]
fn malformed_commit_success_retries_without_reapplying_child_creation() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    for corruption in 0..=14 {
        client.backend.corrupt = Some((operation::COMMIT, corruption));
        assert_eq!(
            client.commit_system_hive_mutation_retained(&prepared),
            Err(STATUS_INVALID_PARAMETER),
            "{corruption}"
        );
    }
    let receipt = client
        .commit_system_hive_mutation_retained(&prepared)
        .unwrap();
    assert_eq!(receipt.outcome().generation, 2);
    let _ = client
        .acknowledge_system_hive_mutation_commit(receipt)
        .unwrap();
}

#[test]
fn malformed_ack_success_never_constructs_acknowledgement_proof() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    let receipt = client
        .commit_system_hive_mutation_retained(&prepared)
        .unwrap();
    for corruption in 0..=16 {
        client.backend.corrupt = Some((operation::ACKNOWLEDGE, corruption));
        assert_eq!(
            client.acknowledge_system_hive_mutation_commit(receipt),
            Err(STATUS_INVALID_PARAMETER),
            "{corruption}"
        );
    }
    assert_eq!(
        client
            .acknowledge_system_hive_mutation_commit(receipt)
            .unwrap()
            .disposition(),
        SystemHiveMutationAcknowledgementDisposition::AlreadyAcknowledged
    );
}

#[test]
fn foreign_incarnation_cannot_commit_or_acknowledge_local_preparation() {
    let mut first = client(1);
    let mut second = client(2);
    let a = prepare(&mut first, 1, "Child");
    let b = prepare(&mut second, 1, "Child");
    assert_ne!(a.lease_token, b.lease_token);
    assert_eq!(
        second.commit_system_hive_mutation_retained(&a),
        Err(STATUS_INVALID_PARAMETER)
    );
    let receipt = first.commit_system_hive_mutation_retained(&a).unwrap();
    let local = second.commit_system_hive_mutation_retained(&b).unwrap();
    assert_eq!(
        second.acknowledge_system_hive_mutation_commit(receipt),
        Err(INVALID_HANDLE)
    );
    assert_eq!(second.commit_system_hive_mutation_retained(&b), Ok(local));
    let _ = second
        .acknowledge_system_hive_mutation_commit(local)
        .unwrap();
    let _ = first
        .acknowledge_system_hive_mutation_commit(receipt)
        .unwrap();
}

#[test]
fn invalid_prepared_identity_is_rejected_without_transport() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    // Malformed wire identities are crate-private fixtures, not cloneable public preparations.
    let mut invalid = core::array::from_fn::<_, 4, _>(|_| PreparedSystemHiveMutation {
        expected_generation: prepared.expected_generation,
        next_generation: prepared.next_generation,
        lease_token: prepared.lease_token,
        semantic_journal_len: prepared.semantic_journal_len,
        durable_journal: Vec::new(),
    });
    invalid[0].lease_token = 0;
    invalid[1].expected_generation = 0;
    invalid[2].next_generation = 8;
    invalid[3].semantic_journal_len = 0;
    let before = client.backend.calls;
    for prepared in invalid {
        assert_eq!(
            client.commit_system_hive_mutation_retained(&prepared),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    assert_eq!(client.backend.calls, before);
}
