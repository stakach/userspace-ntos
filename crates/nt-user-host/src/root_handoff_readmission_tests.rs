use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_component_suspension::{
    ComponentIngress, ComponentSuspensionLanes, IngressReceiveDisposition, IngressReceiver,
    IngressReplyObservation, IngressReplyPool, ReplyBindingObservation,
};

fn spare_free(_: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}

fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}

fn binding() -> ThreadBinding<u8> {
    ThreadBinding {
        pi: 7,
        process: ProcessIdentity { pid: 304, generation: ProcessGeneration::Hosted(2) },
        tid: 312,
        badge: 614,
        role: 0,
        tcb: 10,
        reservations: None,
    }
}

/// One retained external Call held by its own receiver, as CALLS holds it natively.
struct Held {
    _receiver: IngressReceiver<u64>,
    call: ExternalIngress<u64>,
}

impl Held {
    fn new(reply: u64) -> Self {
        let lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
        let mut receiver = IngressReceiver::new(20, reply, 1).unwrap();
        let mut pool = IngressReplyPool::new(20, 1).unwrap();
        pool.insert(ComponentIngress::new(20, reply + 1).unwrap(), &receiver, &lanes, spare_free)
            .ok().unwrap();
        receiver.begin_receive(&lanes).unwrap();
        receiver.capture(191).ok().unwrap();
        receiver.resolve(IngressReceiveDisposition::Call).ok().unwrap();
        let call = pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound).unwrap();
        Self { _receiver: receiver, call }
    }

    fn key(&self) -> HandoffKey<u8> {
        HandoffKey::new(binding(), self.call.admission_key()).unwrap()
    }
}

const UNTOUCHED: HeldRowState = HeldRowState {
    delivered: false, settled: false, dependent: false, sealed: false,
};
const NOT_ENTERED: RootPoolObservation = RootPoolObservation::NotEntered { reply_recorded: false };
const ENTERED_CLEAN: RootPoolObservation =
    RootPoolObservation::Entered { reply_recorded: false, selector_unchanged: true };

#[test]
fn key_requires_exact_caller_and_issued_admission() {
    let held = Held::new(127);
    assert!(HandoffKey::new(binding(), held.call.admission_key()).is_some());
    let mut other_tcb = binding();
    other_tcb.tcb = 11;
    assert!(HandoffKey::new(other_tcb, held.call.admission_key()).is_none(),
        "the admission key's executor must be the bound caller TCB");
    let mut retired = binding();
    retired.process = ProcessIdentity::empty();
    assert!(HandoffKey::new(retired, held.call.admission_key()).is_none());
}

#[test]
fn gate_excludes_unrelated_work_until_exact_receipt() {
    let held = Held::new(127);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    assert!(gate.admits_unrelated_work());
    let refused = gate.refuse(held.key(), HandoffRefusal::RetiredBinding).unwrap();
    assert!(!gate.admits_unrelated_work(), "a refusal excludes before any proof exists");
    assert_eq!(gate.excluded(), Some((held.key(), HandoffRefusal::RetiredBinding)));
    let (seal, receipt) = refused.seal(binding(), &held.call, UNTOUCHED, NOT_ENTERED).unwrap();
    assert_eq!(seal.key(), held.key());
    assert!(!gate.admits_unrelated_work(), "a seal alone does not re-admit");
    assert_eq!(gate.readmit(receipt).unwrap(), HandoffResolution::Quarantined);
    assert!(gate.admits_unrelated_work());
}

#[test]
fn readmission_refused_without_proof_keeps_original_exclusion() {
    let first = Held::new(127);
    let second = Held::new(137);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let _token = gate.refuse(first.key(), HandoffRefusal::ReplyUnbound).unwrap();
    assert_eq!(gate.refuse(second.key(), HandoffRefusal::RetiredBinding).unwrap_err(),
        ReadmissionError::Excluding);
    assert_eq!(gate.excluded(), Some((first.key(), HandoffRefusal::ReplyUnbound)),
        "a later refusal cannot replace the excluded Call");
    assert!(!gate.admits_unrelated_work());
}

#[test]
fn import_uncertain_requires_reconciled_pool_and_reports_reconciled() {
    let held = Held::new(127);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let refused = gate.refuse(held.key(), HandoffRefusal::ImportUncertain).unwrap();
    let (error, refused) = refused.seal(binding(), &held.call, UNTOUCHED,
        RootPoolObservation::Entered { reply_recorded: true, selector_unchanged: true }).unwrap_err();
    assert_eq!(error, ReadmissionError::ReplyInRootPool);
    let (error, refused) = refused.seal(binding(), &held.call, UNTOUCHED,
        RootPoolObservation::Entered { reply_recorded: false, selector_unchanged: false }).unwrap_err();
    assert_eq!(error, ReadmissionError::SelectorChanged);
    let (error, refused) = refused.seal(binding(), &held.call, UNTOUCHED, NOT_ENTERED).unwrap_err();
    assert_eq!(error, ReadmissionError::ObservationMismatch,
        "an entered import cannot be proven by a not-entered observation");
    let (_seal, receipt) = refused.seal(binding(), &held.call, UNTOUCHED, ENTERED_CLEAN).unwrap();
    assert_eq!(receipt.resolution(), HandoffResolution::Reconciled);
    assert_eq!(gate.readmit(receipt).unwrap(), HandoffResolution::Reconciled);
}

#[test]
fn pre_import_refusal_cannot_claim_an_entered_importer() {
    let held = Held::new(127);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let refused = gate.refuse(held.key(), HandoffRefusal::RetiredBinding).unwrap();
    let (error, refused) = refused.seal(binding(), &held.call, UNTOUCHED, ENTERED_CLEAN).unwrap_err();
    assert_eq!(error, ReadmissionError::ObservationMismatch);
    let (error, _refused) = refused.seal(binding(), &held.call, UNTOUCHED,
        RootPoolObservation::NotEntered { reply_recorded: true }).unwrap_err();
    assert_eq!(error, ReadmissionError::ReplyInRootPool,
        "a numeric Reply already recorded in the root pool may belong to another dispatch");
}

#[test]
fn seal_refuses_mismatched_call_and_stale_execution() {
    let held = Held::new(127);
    let other = Held::new(137);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let refused = gate.refuse(held.key(), HandoffRefusal::ImportNoEffect).unwrap();
    let (error, refused) = refused.seal(binding(), &other.call, UNTOUCHED, ENTERED_CLEAN).unwrap_err();
    assert_eq!(error, ReadmissionError::KeyMismatch, "a different Call cannot prove this refusal");
    let mut later = binding();
    later.process.generation = ProcessGeneration::Hosted(3);
    let (error, refused) = refused.seal(later, &held.call, UNTOUCHED, ENTERED_CLEAN).unwrap_err();
    assert_eq!(error, ReadmissionError::StaleExecution);
    let mut other_thread = binding();
    other_thread.tid = 313;
    let (error, refused) = refused.seal(other_thread, &held.call, UNTOUCHED, ENTERED_CLEAN)
        .unwrap_err();
    assert_eq!(error, ReadmissionError::KeyMismatch);
    assert!(!gate.admits_unrelated_work());
    let (_seal, receipt) = refused.seal(binding(), &held.call, UNTOUCHED, ENTERED_CLEAN).unwrap();
    assert_eq!(gate.readmit(receipt).unwrap(), HandoffResolution::Quarantined);
}

#[test]
fn seal_refuses_delivered_settled_dependent_or_already_sealed_rows() {
    let held = Held::new(127);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let mut refused = gate.refuse(held.key(), HandoffRefusal::ReplyUnbound).unwrap();
    for (row, expected) in [
        (HeldRowState { delivered: true, ..UNTOUCHED }, ReadmissionError::Delivered),
        (HeldRowState { settled: true, ..UNTOUCHED }, ReadmissionError::Settled),
        (HeldRowState { dependent: true, ..UNTOUCHED }, ReadmissionError::Dependent),
        (HeldRowState { sealed: true, ..UNTOUCHED }, ReadmissionError::AlreadySealed),
    ] {
        let (error, returned) = refused.seal(binding(), &held.call, row, NOT_ENTERED).unwrap_err();
        assert_eq!(error, expected);
        refused = returned;
    }
    assert!(!gate.admits_unrelated_work());
}

#[test]
fn seal_refuses_a_call_that_entered_a_reply_effect() {
    let mut held = Held::new(127);
    let key = held.key();
    held.call.reply_owned(bound, |_| IngressReplyObservation::Indeterminate).unwrap();
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let refused = gate.refuse(key, HandoffRefusal::ReplyUnbound).unwrap();
    let (error, _refused) = refused.seal(binding(), &held.call, UNTOUCHED, NOT_ENTERED).unwrap_err();
    assert_eq!(error, ReadmissionError::CallEntered,
        "an uncertain Reply send is not a no-effect handoff refusal");
}

#[test]
fn gate_refuses_receipt_from_foreign_or_earlier_refusal() {
    let held = Held::new(127);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let mut foreign = HandoffAdmissionGate::<u8>::new();
    let refused = gate.refuse(held.key(), HandoffRefusal::RetiredBinding).unwrap();
    let foreign_refused = foreign.refuse(held.key(), HandoffRefusal::RetiredBinding).unwrap();
    let (_seal, foreign_receipt) =
        foreign_refused.seal(binding(), &held.call, UNTOUCHED, NOT_ENTERED).unwrap();
    let (error, foreign_receipt) = gate.readmit(foreign_receipt).unwrap_err();
    assert_eq!(error, ReadmissionError::StaleRefusal,
        "an identical key from another refusal epoch is not proof for this exclusion");
    assert!(!gate.admits_unrelated_work());
    assert_eq!(foreign.readmit(foreign_receipt).unwrap(), HandoffResolution::Quarantined);

    let (seal, receipt) = refused.seal(binding(), &held.call, UNTOUCHED, NOT_ENTERED).unwrap();
    assert_eq!(gate.readmit(receipt).unwrap(), HandoffResolution::Quarantined);
    // A later refusal of the same Call issues a new epoch; an earlier proof cannot satisfy it.
    let again = gate.refuse(held.key(), HandoffRefusal::RetiredBinding).unwrap();
    assert_ne!(seal.epoch(), again.epoch);
    let (error, _) = gate.readmit(HandoffReadmission {
        epoch: seal.epoch(), key: held.key(), refusal: HandoffRefusal::RetiredBinding,
        resolution: HandoffResolution::Quarantined,
    }).unwrap_err();
    assert_eq!(error, ReadmissionError::StaleRefusal);
    assert!(!gate.admits_unrelated_work());
}

#[test]
fn gate_refuses_receipt_for_a_different_call_or_reason() {
    let first = Held::new(127);
    let second = Held::new(137);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let refused = gate.refuse(first.key(), HandoffRefusal::ImportNoEffect).unwrap();
    let epoch = refused.epoch;
    let (error, _) = gate.readmit(HandoffReadmission {
        epoch, key: second.key(), refusal: HandoffRefusal::ImportNoEffect,
        resolution: HandoffResolution::Quarantined,
    }).unwrap_err();
    assert_eq!(error, ReadmissionError::KeyMismatch);
    let (error, _) = gate.readmit(HandoffReadmission {
        epoch, key: first.key(), refusal: HandoffRefusal::RetiredBinding,
        resolution: HandoffResolution::Quarantined,
    }).unwrap_err();
    assert_eq!(error, ReadmissionError::KeyMismatch);
    assert!(!gate.admits_unrelated_work());
    let (_seal, receipt) = refused.seal(binding(), &first.call, UNTOUCHED, ENTERED_CLEAN).unwrap();
    assert_eq!(gate.readmit(receipt).unwrap(), HandoffResolution::Quarantined);
}

#[test]
fn readmit_without_exclusion_is_refused() {
    let held = Held::new(127);
    let mut gate = HandoffAdmissionGate::<u8>::new();
    let mut other = HandoffAdmissionGate::<u8>::new();
    let refused = other.refuse(held.key(), HandoffRefusal::RetiredBinding).unwrap();
    let (_seal, receipt) = refused.seal(binding(), &held.call, UNTOUCHED, NOT_ENTERED).unwrap();
    assert_eq!(gate.readmit(receipt).unwrap_err().0, ReadmissionError::NotExcluding);
    assert!(gate.admits_unrelated_work());
}

#[test]
fn a_live_caller_refused_without_pool_effect_fails_its_service_like_nt() {
    // NT fails a system service that cannot get its resources; it does not leave the caller
    // blocked until thread rundown. Only a proven no-effect import has a caller to answer.
    for (refusal, pool, status) in [
        (HandoffRefusal::ImportNoEffect, ENTERED_CLEAN, Some(STATUS_INSUFFICIENT_RESOURCES)),
        (HandoffRefusal::ImportUncertain, ENTERED_CLEAN, Some(STATUS_INSUFFICIENT_RESOURCES)),
        (HandoffRefusal::RetiredBinding, NOT_ENTERED, None),
        (HandoffRefusal::ReplyUnbound, NOT_ENTERED, None),
    ] {
        let held = Held::new(40);
        let mut gate = HandoffAdmissionGate::new();
        let refused = gate.refuse(held.key(), refusal).unwrap();
        let (seal, receipt) = refused.seal(binding(), &held.call, UNTOUCHED, pool).ok().unwrap();
        assert_eq!(seal.failure_status(), status, "{refusal:?}");
        assert_eq!(seal.refusal(), refusal);
        assert!(gate.readmit(receipt).is_ok());
    }
}
