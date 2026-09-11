use super::*;

const APC: UserApc = UserApc {
    routine: 0x1000,
    normal_context: 2,
    system_argument1: 3,
    system_argument2: 4,
};

fn fixture() -> (ProcessManager, ProcessId, ThreadId) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("apc.exe", None, None);
    pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let tid = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    (pm, pid, tid)
}

#[test]
fn identical_entries_are_exclusive_and_committed_exactly_once() {
    let (mut pm, _, tid) = fixture();
    pm.queue_kernel_user_apc(tid, APC).unwrap();
    pm.queue_kernel_user_apc(tid, APC).unwrap();
    let mut first = pm.claim_user_apc(tid).unwrap().unwrap();
    assert_eq!(first.apc(), APC);
    assert_eq!(first.lifetime().thread_id(), tid);
    assert_eq!(pm.peek_user_apc(tid), None);
    assert_eq!(pm.take_user_apc(tid), None);
    assert!(pm.claim_user_apc(tid).is_err());
    assert!(pm.has_user_apc(tid));
    assert!(pm.validate_user_apc_claim(&first));
    assert_eq!(pm.commit_user_apc_claim(&mut first), Ok(APC));
    assert!(pm.commit_user_apc_claim(&mut first).is_err());
    let mut second = pm.claim_user_apc(tid).unwrap().unwrap();
    assert_ne!(first.entry, second.entry);
    assert_eq!(pm.release_user_apc_claim(&mut first), Ok(()));
    assert!(pm.validate_user_apc_claim(&second));
    assert_eq!(pm.commit_user_apc_claim(&mut second), Ok(APC));
    assert!(!pm.has_user_apc(tid));
}

#[test]
fn definite_release_allows_reclaim_but_never_revives_the_old_token() {
    let (mut pm, _, tid) = fixture();
    pm.queue_kernel_user_apc(tid, APC).unwrap();
    let mut first = pm.claim_user_apc(tid).unwrap().unwrap();
    pm.release_user_apc_claim(&mut first).unwrap();
    let mut second = pm.claim_user_apc(tid).unwrap().unwrap();
    assert_eq!(first.entry, second.entry);
    pm.release_user_apc_claim(&mut first).unwrap();
    assert!(pm.commit_user_apc_claim(&mut first).is_err());
    assert!(pm.validate_user_apc_claim(&second));
    assert_eq!(pm.peek_user_apc(tid), None);
    pm.commit_user_apc_claim(&mut second).unwrap();
}

#[test]
fn timer_removal_cannot_steal_claimed_front_or_requeue_its_source() {
    let (mut pm, _, tid) = fixture();
    let source = KernelUserApcSource::Timer(1);
    pm.queue_kernel_user_apc_once(tid, source, APC).unwrap();
    let mut claim = pm.claim_user_apc(tid).unwrap().unwrap();
    assert!(!pm.remove_kernel_user_apc(tid, source));
    assert_eq!(pm.queue_kernel_user_apc_once(tid, source, APC), Ok(false));
    pm.queue_kernel_user_apc_once(tid, KernelUserApcSource::Timer(2), APC)
        .unwrap();
    assert!(pm.remove_kernel_user_apc(tid, KernelUserApcSource::Timer(2)));
    assert!(pm.validate_user_apc_claim(&claim));
    pm.commit_user_apc_claim(&mut claim).unwrap();
    assert_eq!(pm.queue_kernel_user_apc_once(tid, source, APC), Ok(true));
}

#[test]
fn clearing_then_requeueing_identical_payload_cannot_aba_a_claim() {
    let (mut pm, _, tid) = fixture();
    pm.queue_kernel_user_apc(tid, APC).unwrap();
    let mut old = pm.claim_user_apc(tid).unwrap().unwrap();
    assert!(pm.clear_user_apcs(tid));
    pm.queue_kernel_user_apc(tid, APC).unwrap();
    let mut current = pm.claim_user_apc(tid).unwrap().unwrap();
    assert!(!pm.validate_user_apc_claim(&old));
    assert!(pm.commit_user_apc_claim(&mut old).is_err());
    pm.release_user_apc_claim(&mut old).unwrap();
    assert!(pm.validate_user_apc_claim(&current));
    pm.commit_user_apc_claim(&mut current).unwrap();
}

#[test]
fn cross_manager_claims_do_not_consume_or_release_an_identical_queue() {
    let (mut first, _, tid) = fixture();
    let (mut second, _, peer) = fixture();
    assert_eq!(tid, peer);
    first.queue_kernel_user_apc(tid, APC).unwrap();
    second.queue_kernel_user_apc(peer, APC).unwrap();
    let mut claim = first.claim_user_apc(tid).unwrap().unwrap();
    let mut other = second.claim_user_apc(peer).unwrap().unwrap();
    assert!(second.commit_user_apc_claim(&mut claim).is_err());
    assert!(second.release_user_apc_claim(&mut claim).is_err());
    assert!(first.validate_user_apc_claim(&claim));
    assert!(second.validate_user_apc_claim(&other));
    first.commit_user_apc_claim(&mut claim).unwrap();
    second.commit_user_apc_claim(&mut other).unwrap();
}

#[test]
fn thread_reactivation_invalidates_old_claim_without_touching_new_lifetime() {
    let (mut pm, _, tid) = fixture();
    pm.queue_kernel_user_apc(tid, APC).unwrap();
    let mut old = pm.claim_user_apc(tid).unwrap().unwrap();
    pm.terminate_thread(tid, 0).unwrap();
    assert!(!pm.validate_user_apc_claim(&old));
    let activation = pm
        .prepare_thread_activation(tid, 0x4000, 0, false, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(activation).unwrap();
    pm.queue_kernel_user_apc(tid, APC).unwrap();
    let mut current = pm.claim_user_apc(tid).unwrap().unwrap();
    assert_ne!(old.lifetime(), current.lifetime());
    pm.release_user_apc_claim(&mut old).unwrap();
    assert!(pm.validate_user_apc_claim(&current));
    pm.commit_user_apc_claim(&mut current).unwrap();
}

#[test]
fn dropped_claim_does_not_authorize_a_second_delivery() {
    let (mut pm, _, tid) = fixture();
    pm.queue_kernel_user_apc(tid, APC).unwrap();
    let claim = pm.claim_user_apc(tid).unwrap().unwrap();
    drop(claim);
    assert!(pm.claim_user_apc(tid).is_err());
    assert_eq!(pm.peek_user_apc(tid), None);
    assert_eq!(pm.take_user_apc(tid), None);
    assert!(pm.clear_user_apcs(tid));
    assert!(pm.claim_user_apc(tid).unwrap().is_none());
}
