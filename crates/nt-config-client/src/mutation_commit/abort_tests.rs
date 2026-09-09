use super::test_support::*;
use super::*;

#[test]
fn malformed_abort_and_ack_replay_exact_cleanup_without_publishing() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    for corruption in (0..=14).chain(core::iter::once(18)) {
        client.backend.corrupt = Some((operation::ABORT, corruption));
        assert_eq!(
            client.abort_prepared_system_hive_mutation_retained(&prepared),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    let receipt = client
        .abort_prepared_system_hive_mutation_retained(&prepared)
        .unwrap();
    assert!(client
        .query_system_hive_key(&alloc::format!("{PARENT}\\Child"))
        .is_err());
    assert_eq!(client.import_system_hive(&image()), Err(BUSY));
    assert!(client
        .commit_system_hive_mutation_retained(&prepared)
        .is_err());
    for corruption in 0..=16 {
        client.backend.corrupt = Some((operation::ACKNOWLEDGE, corruption));
        assert_eq!(
            client.acknowledge_system_hive_mutation_abort(receipt),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    let next = prepare(&mut client, 1, "Next");
    let committed = client.commit_system_hive_mutation_retained(&next).unwrap();
    assert_eq!(committed.outcome().generation, 2);
    let ack = client
        .acknowledge_system_hive_mutation_abort(receipt)
        .unwrap();
    assert_eq!(ack.receipt(), receipt);
    assert_eq!(
        ack.disposition(),
        SystemHiveMutationAcknowledgementDisposition::AlreadyAcknowledged
    );
    assert_eq!(client.import_system_hive(&image()), Err(BUSY));
    assert_eq!(
        client.commit_system_hive_mutation_retained(&next),
        Ok(committed)
    );
    let _ = client
        .acknowledge_system_hive_mutation_commit(committed)
        .unwrap();
    client.import_system_hive(&image()).unwrap();
    assert!(client
        .abort_prepared_system_hive_mutation_retained(&prepared)
        .is_err());
}

#[test]
fn abort_cannot_release_a_committed_or_foreign_preparation() {
    let mut first = client(1);
    let mut second = client(2);
    let prepared = prepare(&mut first, 1, "Child");
    let local = prepare(&mut second, 1, "Local");
    assert!(second
        .abort_prepared_system_hive_mutation_retained(&prepared)
        .is_err());
    let aborted = second
        .abort_prepared_system_hive_mutation_retained(&local)
        .unwrap();
    assert!(first
        .acknowledge_system_hive_mutation_abort(aborted)
        .is_err());
    first.backend.corrupt = Some((operation::COMMIT, 19));
    assert_eq!(
        first.commit_system_hive_mutation_retained(&prepared),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(first
        .abort_prepared_system_hive_mutation_retained(&prepared)
        .is_err());
    let committed = first
        .commit_system_hive_mutation_retained(&prepared)
        .unwrap();
    assert_eq!(committed.outcome().generation, 2);
    let _ = first
        .acknowledge_system_hive_mutation_commit(committed)
        .unwrap();
    let _ = second
        .acknowledge_system_hive_mutation_abort(aborted)
        .unwrap();
}
