//! Retained CM mutation ownership for boot stages without a native caller Reply.
//!
//! The boot caller waits at its stage boundary while this owner redrives the same CM token,
//! storage effect, and terminal receipt. A transport error never authorizes a second mutation.

use crate::*;
use nt_config_client::{
    CmMutationBeginAttempt, CmMutationBeginAttempts, CmMutationBeginOperation,
    CmMutationPreparationOperation, CmMutationPreparationPhase, PreparedSystemHiveMutation,
    SystemHiveMutation, SystemHiveMutationAbortReceipt, SystemHiveMutationCommitReceipt,
    SystemHiveMutationPreparation,
};

use crate::registry_mutation_work::MutationPersistence;

static mut BEGIN_ATTEMPTS: CmMutationBeginAttempts = CmMutationBeginAttempts::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootRegistryStage {
    AcpiRoot,
    TimeZone,
    Locale,
    Network,
    Print,
}

static mut BOOT_WORK: Option<BootSystemMutationWork<BootRegistryStage>> = None;
static mut BOOT_STAGE: Option<BootRegistryStage> = None;

enum Phase<C> {
    Begin(CmMutationBeginAttempt<C>),
    Prepare(SystemHiveMutationPreparation<C>),
    Admit,
    Durable,
    Commit,
    Acknowledge,
    Release,
    Abort,
    AcknowledgeAbort(SystemHiveMutationAbortReceipt),
    ReleaseRollback,
    Complete,
}

/// The continuation is moved from BEGIN to PREPARE and then into this work item. It is never
/// borrowed from a boot stack frame while component IPC or storage can have an uncertain effect.
#[must_use = "redrive until exact CM acknowledgement and storage release"]
pub(crate) struct BootSystemMutationWork<C> {
    phase: Option<Phase<C>>,
    continuation: Option<C>,
    prepared: Option<PreparedSystemHiveMutation>,
    persistence: MutationPersistence,
    receipt: Option<SystemHiveMutationCommitReceipt>,
    outcome: Option<DurableSystemHiveMutationOutcome>,
    status: i32,
    commit_entered: bool,
}

pub(crate) enum BootMutationProgress<C> {
    Pending,
    Blocked,
    Complete(C, Result<DurableSystemHiveMutationOutcome, i32>),
}

impl<C> BootSystemMutationWork<C> {
    /// Admission returns the complete caller unchanged if no CM request has been reserved.
    pub(crate) unsafe fn reserve(
        expected_generation: u64,
        mutations: &[SystemHiveMutation<'_>],
        continuation: C,
    ) -> Result<Self, (i32, C)> {
        let Some(mount) = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT else {
            return Err((CONFIG_STATUS_DEVICE_NOT_READY, continuation));
        };
        let attempt = (&mut *core::ptr::addr_of_mut!(BEGIN_ATTEMPTS))
            .reserve(mount, expected_generation, mutations, continuation)?;
        Ok(Self {
            phase: Some(Phase::Begin(attempt)),
            continuation: None,
            prepared: None,
            persistence: MutationPersistence::new(),
            receipt: None,
            outcome: None,
            status: 0,
            commit_entered: false,
        })
    }

    /// One bounded step. Errors retain the exact phase, token, receipt and storage owner; the
    /// parent must retry this same work item and may not replay its registry decisions.
    pub(crate) unsafe fn advance(&mut self) -> BootMutationProgress<C> {
        let Some(phase) = self.phase.as_mut() else {
            unreachable!("boot mutation phase absent outside a transition")
        };
        match phase {
            Phase::Begin(attempt) => {
                let bank = &mut *core::ptr::addr_of_mut!(BEGIN_ATTEMPTS);
                if attempt.is_acknowledged() {
                    if attempt.outcome_status() == Some(0) {
                        match bank.take_upload(attempt) {
                            Ok(upload) => self.phase = Some(Phase::Prepare(upload.into_preparation())),
                            Err(_) => return BootMutationProgress::Blocked,
                        }
                    } else {
                        match bank.take_failure(attempt) {
                            Ok((status, continuation)) => {
                                self.status = status;
                                self.continuation = Some(continuation);
                                self.phase = Some(Phase::Complete);
                            }
                            Err(_) => return BootMutationProgress::Blocked,
                        }
                    }
                } else {
                    let operation = if attempt.server_nonce().is_none() {
                        CmMutationBeginOperation::Query
                    } else if attempt.outcome_status().is_none() {
                        CmMutationBeginOperation::Begin
                    } else {
                        CmMutationBeginOperation::Acknowledge
                    };
                    let Ok(mut exchange) = bank.begin_exchange(attempt, operation) else {
                        return BootMutationProgress::Blocked;
                    };
                    let response = cm_mutation_transport::begin(&exchange);
                    if bank.complete_exchange(attempt, &mut exchange, response).is_err() {
                        return BootMutationProgress::Blocked;
                    }
                }
            }
            Phase::Prepare(preparation) => {
                use CmMutationPreparationPhase as P;
                match preparation.phase() {
                    P::Prepared => match preparation.take_prepared() {
                        Ok((prepared, continuation)) => {
                            self.prepared = Some(prepared);
                            self.continuation = Some(continuation);
                            self.phase = Some(Phase::Admit);
                        }
                        Err(_) => return BootMutationProgress::Blocked,
                    },
                    P::Cancelled => match preparation.take_cancelled() {
                        Ok(continuation) => {
                            assert_ne!(self.status, 0,
                                "confirmed CM cancellation cannot complete as success");
                            self.continuation = Some(continuation);
                            self.phase = Some(Phase::Complete);
                        }
                        Err(_) => return BootMutationProgress::Blocked,
                    },
                    P::Allocating if self.status == 0 => {
                        if let Err(status) = preparation.allocate_journal() {
                            self.status = status;
                        }
                    }
                    _ => {
                        let operation = match preparation.phase() {
                            P::AcknowledgingCancellation => CmMutationPreparationOperation::AcknowledgeCancellation,
                            _ if self.status != 0 => CmMutationPreparationOperation::Cancel,
                            P::Appending => CmMutationPreparationOperation::Append,
                            P::Preparing => CmMutationPreparationOperation::Prepare,
                            P::Pulling => CmMutationPreparationOperation::Pull,
                            _ => return BootMutationProgress::Blocked,
                        };
                        let Ok(mut exchange) = preparation.begin_exchange(operation) else {
                            return BootMutationProgress::Blocked;
                        };
                        let response = cm_mutation_transport::prepare(&exchange);
                        if let Err(status) = preparation.complete_exchange(&mut exchange, response) {
                            if self.status == 0 { self.status = status; }
                            return BootMutationProgress::Blocked;
                        }
                    }
                }
            }
            Phase::Admit => {
                let prepared = self.prepared.as_ref().expect("prepared CM mutation");
                if let Err(status) = cm_mutation_transport::validate_storage(prepared) {
                    self.status = status;
                    self.phase = Some(Phase::Abort);
                    return BootMutationProgress::Pending;
                }
                let journal = prepared.durable_journal();
                if journal.is_empty() {
                    self.phase = Some(Phase::Commit);
                } else {
                    let mut bytes = Vec::new();
                    if bytes.try_reserve_exact(journal.len()).is_err() {
                        self.status = 0xC000_009Au32 as i32;
                        self.phase = Some(Phase::Abort);
                        return BootMutationProgress::Pending;
                    }
                    bytes.extend_from_slice(journal);
                    match self.persistence.admit(bytes) {
                        Ok(()) => self.phase = Some(Phase::Durable),
                        Err(status) => {
                            self.status = status as i32;
                            self.phase = Some(Phase::Abort);
                        }
                    }
                }
            }
            Phase::Durable => {
                if self.persistence.make_durable().is_ok() {
                    self.phase = Some(Phase::Commit);
                } else {
                    return BootMutationProgress::Blocked;
                }
            }
            Phase::Commit => {
                if !self.commit_entered {
                    if self.persistence.begin_publication().is_err() {
                        return BootMutationProgress::Blocked;
                    }
                    // Record entry before IPC: a lost COMMIT reply may already have published CM.
                    self.commit_entered = true;
                }
                let prepared = self.prepared.as_ref().expect("retained CM preparation");
                let Ok(receipt) = cm_mutation_transport::commit(prepared) else {
                    return BootMutationProgress::Blocked;
                };
                let published = receipt.outcome();
                LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.fetch_max(published.generation, Ordering::AcqRel);
                let wake_device_action = published.has_pending_device_action
                    && !CONFIG_DEVICE_ACTION_PENDING.swap(true, Ordering::AcqRel);
                if wake_device_action {
                    config_manager_request_device_action_wake();
                }
                self.outcome = Some(DurableSystemHiveMutationOutcome {
                    generation: published.generation,
                    wake_device_action,
                    journaled: self.persistence.has_journal(),
                });
                self.receipt = Some(receipt);
                self.phase = Some(Phase::Acknowledge);
            }
            Phase::Acknowledge => {
                let receipt = self.receipt.expect("retained CM COMMIT receipt");
                if cm_mutation_transport::acknowledge(receipt).is_ok() {
                    self.phase = Some(Phase::Release);
                } else {
                    return BootMutationProgress::Blocked;
                }
            }
            Phase::Release => {
                if self.persistence.release_after_publication().is_ok() {
                    self.phase = Some(Phase::Complete);
                } else {
                    return BootMutationProgress::Blocked;
                }
            }
            Phase::Abort => {
                assert!(!self.commit_entered, "published CM work cannot abort");
                let prepared = self.prepared.as_ref().expect("precommit CM preparation");
                if let Ok(receipt) = cm_mutation_transport::abort(prepared) {
                    self.phase = Some(Phase::AcknowledgeAbort(receipt));
                } else {
                    return BootMutationProgress::Blocked;
                }
            }
            Phase::AcknowledgeAbort(receipt) => {
                if cm_mutation_transport::acknowledge_abort(*receipt).is_ok() {
                    self.phase = Some(Phase::ReleaseRollback);
                } else {
                    return BootMutationProgress::Blocked;
                }
            }
            Phase::ReleaseRollback => {
                if !self.persistence.has_journal()
                    || self.persistence.release_rolled_back().is_ok()
                {
                    self.phase = Some(Phase::Complete);
                } else {
                    return BootMutationProgress::Blocked;
                }
            }
            Phase::Complete => {
                let continuation = self.continuation.take().expect("retained boot continuation");
                let outcome = self.outcome.take().ok_or(self.status);
                self.phase = None;
                return BootMutationProgress::Complete(continuation, outcome);
            }
        }
        BootMutationProgress::Pending
    }
}

/// Install before any CM transport. A failed bootstrap pump leaves this exact work item in the
/// static slot; only its original stage may reenter and redrive it.
pub(crate) unsafe fn publish_boot_system_mutation(
    stage: BootRegistryStage,
    expected_generation: u64,
    mutations: &[SystemHiveMutation<'_>],
) -> Result<DurableSystemHiveMutationOutcome, u32> {
    let work_slot = core::ptr::addr_of_mut!(BOOT_WORK);
    let stage_slot = core::ptr::addr_of_mut!(BOOT_STAGE);
    if (*work_slot).is_none() {
        let work = BootSystemMutationWork::reserve(expected_generation, mutations, stage)
            .map_err(|(status, _stage)| status as u32)?;
        *stage_slot = Some(stage);
        *work_slot = Some(work);
    } else if *stage_slot != Some(stage) {
        return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32);
    }

    let mut completion = None;
    crate::bootstrap_receive::drive(stage, || {
        let work = (*work_slot).as_mut().expect("retained boot CM mutation");
        match work.advance() {
            BootMutationProgress::Pending | BootMutationProgress::Blocked => Ok(None),
            BootMutationProgress::Complete(completed_stage, outcome) => {
                assert_eq!(completed_stage, stage, "wrong boot CM continuation");
                *work_slot = None;
                *stage_slot = None;
                completion = Some(outcome);
                Ok(Some(true))
            }
        }
    })?;
    completion.expect("acknowledged boot CM mutation").map_err(|status| status as u32)
}

/// Drain an already-retained provider mutation while the bootstrap Ps store is still owned.
/// No setup decision may be made until the journal and every provider owner are terminal.
pub(crate) unsafe fn drain_boot_registry_before_handler_constructor() -> Result<(), u32> {
    crate::bootstrap_receive::drive((), || {
        let quiescent = crate::registry_mutation_work::pending_count() == 0
            && !crate::registry_mutation_work::redrive_active()
            && !crate::writable_fs::registry_journal::owns_volume();
        Ok(quiescent.then_some(true))
    })?;
    Ok(())
}

/// Setup runs while `ExecNtHandler::initialize_in` owns `&mut handler`. Every step here is a
/// synchronous CM or storage effect; autonomous bootstrap dispatch would alias that borrow.
/// A refused or uncertain effect leaves BOOT_WORK installed and stops constructor progress.
pub(crate) unsafe fn publish_setup_system_mutation(
    stage: BootRegistryStage,
    expected_generation: u64,
    mutations: &[SystemHiveMutation<'_>],
) -> Result<DurableSystemHiveMutationOutcome, u32> {
    assert!(stage != BootRegistryStage::AcpiRoot, "ACPI uses the bootstrap scheduler");
    assert_eq!(crate::registry_mutation_work::pending_count(), 0,
        "provider CM owner appeared during handler construction");
    assert!(!crate::registry_mutation_work::redrive_active(),
        "provider CM owner is executing during handler construction");
    assert!(!crate::writable_fs::registry_journal::owns_volume(),
        "registry journal was not released before setup");

    let work_slot = core::ptr::addr_of_mut!(BOOT_WORK);
    let stage_slot = core::ptr::addr_of_mut!(BOOT_STAGE);
    if (*work_slot).is_none() {
        let work = BootSystemMutationWork::reserve(expected_generation, mutations, stage)
            .map_err(|(status, _stage)| status as u32)?;
        *stage_slot = Some(stage);
        *work_slot = Some(work);
    } else if *stage_slot != Some(stage) {
        return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32);
    }
    loop {
        let work = (*work_slot).as_mut().expect("retained setup CM mutation");
        match work.advance() {
            BootMutationProgress::Pending => {}
            BootMutationProgress::Blocked => {
                return Err(nt_status::NtStatus::DEVICE_NOT_READY.raw() as u32);
            }
            BootMutationProgress::Complete(completed_stage, outcome) => {
                assert_eq!(completed_stage, stage, "wrong setup CM continuation");
                *work_slot = None;
                *stage_slot = None;
                return outcome.map_err(|status| status as u32);
            }
        }
    }
}

pub(crate) unsafe fn boot_system_mutation_pending(stage: BootRegistryStage) -> bool {
    let work = &*core::ptr::addr_of!(BOOT_WORK);
    let active_stage = &*core::ptr::addr_of!(BOOT_STAGE);
    work.is_some() && *active_stage == Some(stage)
}
