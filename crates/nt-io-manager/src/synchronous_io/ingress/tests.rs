use super::*;

const KEY: FileIoWaitKey = FileIoWaitKey::LocalOverlay(0);
const ERROR: u32 = 0xc000_0005;

fn ready(table: &mut SynchronousFileWaitTable) -> usize {
    let mut waiter = SynchronousFileWaiter::waiting(
        FileIoWaitRoute::LocalOverlay { file_object: 0 },
        4,
        3,
        191,
        2,
        20,
        120,
        FileIoMode::SynchronousAlertable,
        true,
        0,
        0x1000,
        0x2000,
        0x202,
    );
    waiter.reply_cap = 50;
    let slot = table.park(waiter).unwrap();
    table.promote_exact(slot, KEY, 20).unwrap();
    let id = table.retry_identity(slot, KEY, 20).unwrap();
    let mut retry = table.begin_retry(id).unwrap();
    table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(table.finish_retry(id, Ok(())).unwrap());
    slot
}

fn claim(table: &mut SynchronousFileWaitTable) -> SynchronousFileIngress {
    table.begin_ingress(2, 20, 120, 191).unwrap().unwrap()
}

#[test]
fn claim_retains_route_and_blocks_duplicate_or_legacy_extraction() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = ready(&mut table);
    for (pi, badge, ssn) in [(3, 120, 191), (2, 121, 191), (2, 120, 192)] {
        assert_eq!(
            table.begin_ingress(pi, 20, badge, ssn).unwrap_err(),
            SynchronousFileIngressError::MetadataMismatch
        );
    }
    let ingress = claim(&mut table);
    assert_eq!(ingress.waiter().key(), KEY);
    assert_eq!(ingress.waiter().reply_cap, 0);
    assert!(ingress.matches_handle(4));
    assert!(!ingress.matches_handle(8));
    assert!(!ingress.matches_handle(0x1_0000_0004));
    assert_eq!(table.len(), 1);
    assert!(table.has_ingress_for_thread(20));
    assert!(table.has_ingress_for_pi(2));
    assert!(!table.has_ingress_for_pi(3));
    assert_eq!(
        table.begin_ingress(2, 20, 120, 191).unwrap_err(),
        SynchronousFileIngressError::InvalidPhase
    );
    assert!(table.take_exact(slot, KEY, 20).is_none());
    assert!(table.adopt_promoted_fixture(2, 20, 120, 191).is_none());
    assert!(table.has_runtime_dependency_for_thread(20));
    drop(ingress);
    assert!(!table.reset());
    assert!(table.has_ingress_for_thread(20));
}

#[test]
fn rejection_starts_same_row_cancellation_without_reply_effects() {
    let mut table = SynchronousFileWaitTable::new();
    ready(&mut table);
    let mut ingress = claim(&mut table);
    let id = table.reject_ingress(&mut ingress, ERROR).unwrap();
    assert_eq!(id, ingress.identity());
    let view = table.cancellation(id).unwrap();
    assert_eq!(view.waiter.reply_cap, 0);
    assert_eq!(
        view.phase,
        SynchronousFileCancelPhase::Ready {
            effect: SynchronousFileCancelEffect::Policy,
            last_error: Some(ERROR)
        }
    );
    assert!(!table.has_ingress_for_thread(20));
    assert!(table.has_cancellation_for_thread(20));
    assert!(table.begin_adoption(&mut ingress).is_err());
    assert!(table.reject_ingress(&mut ingress, ERROR).is_err());
}

#[test]
fn checked_adoption_receipt_transfers_exactly_once_and_rejects_stale_slot() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = ready(&mut table);
    let mut ingress = claim(&mut table);
    let mut attempt = table.begin_adoption(&mut ingress).unwrap();
    let mut other = SynchronousFileWaitTable::new();
    ready(&mut other);
    assert_eq!(
        other.record_adoption(&mut attempt, Ok(())).unwrap_err(),
        SynchronousFileIngressError::WrongIdentity
    );
    let owner = table
        .record_adoption(&mut attempt, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(owner.waiter().key(), KEY);
    assert!(!owner.cancellation_requested());
    assert!(table.is_empty());
    assert_eq!(ready(&mut table), slot);
    assert_eq!(
        table.record_adoption(&mut attempt, Ok(())).unwrap_err(),
        SynchronousFileIngressError::WrongIdentity
    );
    assert!(table.request_cancellation(ingress.identity()).is_err());
    assert_eq!(table.len(), 1);
}

#[test]
fn failed_adoption_retains_cancellation_and_never_retries_effect() {
    let mut table = SynchronousFileWaitTable::new();
    ready(&mut table);
    let mut ingress = claim(&mut table);
    let mut attempt = table.begin_adoption(&mut ingress).unwrap();
    table.request_cancellation(ingress.identity()).unwrap();
    assert_eq!(
        table.cancellation(ingress.identity()).unwrap().phase,
        SynchronousFileCancelPhase::DeferredRetry
    );
    assert!(table.begin_cancellation(ingress.identity()).is_err());
    assert!(table
        .record_adoption(&mut attempt, Err(ERROR))
        .unwrap()
        .is_none());
    assert!(table.begin_adoption(&mut ingress).is_err());
    assert!(table.record_adoption(&mut attempt, Ok(())).is_err());
    assert!(table.begin_cancellation(ingress.identity()).is_ok());
}

#[test]
fn cancellation_before_adoption_prevents_entry_but_during_adoption_transfers_intent() {
    let mut table = SynchronousFileWaitTable::new();
    ready(&mut table);
    let mut ingress = claim(&mut table);
    table.request_cancellation(ingress.identity()).unwrap();
    assert_eq!(
        table.begin_adoption(&mut ingress).unwrap_err(),
        SynchronousFileIngressError::CancellationRequested
    );
    let mut other = SynchronousFileWaitTable::new();
    ready(&mut other);
    let mut ingress = claim(&mut other);
    let mut attempt = other.begin_adoption(&mut ingress).unwrap();
    other.request_cancellation(ingress.identity()).unwrap();
    let owner = other
        .record_adoption(&mut attempt, Ok(()))
        .unwrap()
        .unwrap();
    assert!(owner.cancellation_requested());
    assert!(other.is_empty());
}

#[test]
fn dropped_adoption_remains_invoking_and_blocks_teardown() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = ready(&mut table);
    let mut ingress = claim(&mut table);
    let attempt = table.begin_adoption(&mut ingress).unwrap();
    drop(attempt);
    assert!(table.has_runtime_dependency_for_thread(20));
    table.request_cancellation(ingress.identity()).unwrap();
    assert!(table.has_runtime_dependency_for_thread(20));
    assert_eq!(
        table.cancellation(ingress.identity()).unwrap().phase,
        SynchronousFileCancelPhase::DeferredRetry
    );
    assert!(table.begin_cancellation(ingress.identity()).is_err());
    assert!(table.take_exact(slot, KEY, 20).is_none());
    assert!(!table.reset());
    assert_eq!(table.cancellation_ownership(KEY).promoted, 1);
}
