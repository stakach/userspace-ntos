//! Exact owner of one constructed child main thread through VSpace and runtime publication.

use crate::{img_spawn, thread_sched_context, ExecNtHandler, SMSS_PEB_VA};
use crate::exec_handler::ChildVspacePublicationObservation;
use nt_process;
use nt_user_host::main_spawn_publication::{
    MainSpawnPublication, PublicationAttempt, PublicationEffect, PublicationPhase,
};
use nt_user_host::thread_physical_placement::PlacementIdentity;

type Owner = MainSpawnPublication<img_spawn::SecImageSpawn, img_spawn::HostedProcessVspaceCaps>;

pub(crate) struct ChildMainPublication {
    owner: Owner,
    identity: PlacementIdentity,
    vspace_attempt: Option<PublicationAttempt>,
    fatal_status: Option<u32>,
}

impl ChildMainPublication {
    /// Return the original physical inventory on an invalid constructor identity.
    pub(crate) fn new(
        mut spawn: img_spawn::SecImageSpawn,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
    ) -> Result<Self, img_spawn::SecImageSpawn> {
        let identity = PlacementIdentity {
            process, tid, tcb: spawn.main_tcb,
            sched_context: spawn.main_mechanism.sched_context,
        };
        let valid = matches!(spawn.lifetime,
            nt_memory_manager::MemoryLifetime::Process(owner) if owner == process)
            && process.is_valid()
            && tid != 0
            && spawn.main_runtime.process_id == u64::from(process.pid)
            && spawn.main_runtime.thread_id == tid
            && identity.tcb > 1
            && identity.sched_context > 1
            && spawn.main_mechanism.is_live()
            && spawn.pml4 > 1
            && spawn.vspace_caps.as_ref().is_some_and(|caps|
                caps.pml4 == spawn.pml4
                    && matches!(process.generation,
                        nt_types::ProcessGeneration::Hosted(generation)
                            if generation == caps.generation))
            && spawn.placement.as_ref().is_some_and(|placement|
                placement.may_retire()
                    && placement.current_core(identity)
                        == Ok(thread_sched_context::GUEST_SCHED_CONTROL_CORE));
        if !valid { return Err(spawn); }
        let Some(vspace) = spawn.vspace_caps.take() else { return Err(spawn); };
        let owner = match Owner::new(identity, spawn, vspace) {
            Ok(owner) => owner,
            Err((_, mut spawn, vspace)) => {
                spawn.vspace_caps = Some(vspace);
                return Err(spawn);
            }
        };
        Ok(Self { owner, identity, vspace_attempt: None, fatal_status: None })
    }

    pub(crate) fn runtime_published(&self) -> bool {
        self.owner.phase() == PublicationPhase::RuntimePublished
    }

    pub(crate) fn identity(&self) -> PlacementIdentity { self.identity }

    pub(crate) fn fatal_status(&self) -> Option<u32> { self.fatal_status }

    /// A VSpace error is uncertain until the exact journal and commit owner can classify it.
    pub(crate) fn advance(&mut self, pi: usize, handler: &mut ExecNtHandler) -> Result<bool, u32> {
        if let Some(status) = self.fatal_status { return Err(status); }
        if handler.capture_thread_process_identity(pi, self.identity.tid)
            != Some(self.identity.process)
            || handler.pm_main_tid_for_pi(pi).map(u64::from) != Some(self.identity.tid)
        {
            self.fatal_status = Some(nt_process::STATUS_INVALID_HANDLE);
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        for _ in 0..5 {
            match self.owner.phase() {
                PublicationPhase::Constructed => {
                    if let Err(refusal) = handler.preflight_main_thread_spawn(
                        pi, self.owner.mechanism()
                            .expect("constructed owner retains its mechanism"),
                    ) {
                        if refusal.is_permanent() { self.fatal_status = Some(refusal.status()); }
                        return Err(refusal.status());
                    }
                    let attempt = self.owner.begin_vspace(self.identity)
                        .map_err(|_| nt_process::STATUS_INVALID_PARAMETER)?;
                    let caps = *self.owner.vspace()
                        .expect("constructed owner retains its VSpace inventory");
                    match handler.publish_hosted_process_vspace(pi, caps) {
                        Ok(()) => {
                            let _ = self.owner.settle_vspace(attempt, PublicationEffect::Applied)
                                .expect("current VSpace attempt transfers once");
                        }
                        Err(status) => {
                            self.owner.settle_vspace(attempt, PublicationEffect::Uncertain)
                                .expect("entered VSpace effect retains its inventory");
                            self.vspace_attempt = Some(attempt);
                            return Err(status);
                        }
                    }
                }
                PublicationPhase::VspaceUncertain => {
                    let caps = *self.owner.vspace()
                        .expect("uncertain VSpace retains its inventory");
                    let effect = match handler.reconcile_child_vspace_publication(
                        pi, self.identity.process, caps,
                    ) {
                        ChildVspacePublicationObservation::Applied => PublicationEffect::Applied,
                        ChildVspacePublicationObservation::NoEffect => PublicationEffect::NoEffect,
                        ChildVspacePublicationObservation::Busy =>
                            return Err(nt_process::STATUS_DEVICE_BUSY),
                        ChildVspacePublicationObservation::Conflict => {
                            self.fatal_status = Some(nt_process::STATUS_INVALID_PARAMETER);
                            return Err(nt_process::STATUS_INVALID_PARAMETER);
                        }
                    };
                    self.owner.reconcile_vspace(
                        self.vspace_attempt.take().expect("entered VSpace attempt retained"), effect,
                    ).expect("exact journal observation settles one attempt");
                }
                PublicationPhase::VspacePublished => {
                    if !handler.pm.set_peb_base(self.identity.process.pid, SMSS_PEB_VA) {
                        self.fatal_status = Some(nt_process::STATUS_INVALID_HANDLE);
                        return Err(nt_process::STATUS_INVALID_HANDLE);
                    }
                    self.owner.record_peb(self.identity)
                        .expect("exact VSpace owner records its PEB");
                }
                PublicationPhase::PebPublished => {
                    let attempt = self.owner.begin_runtime(self.identity)
                        .map_err(|_| nt_process::STATUS_INVALID_PARAMETER)?;
                    let result = handler.register_main_thread_spawn(
                        pi, self.owner.mechanism_mut()
                            .expect("runtime attempt retains its mechanism"),
                    );
                    let transferred = self.owner.mechanism()
                        .is_some_and(|spawn| spawn.placement.is_none());
                    let effect = if transferred { PublicationEffect::Applied }
                        else { PublicationEffect::NoEffect };
                    let _ = self.owner.settle_runtime(attempt, effect)
                        .expect("current runtime attempt settles once");
                    return result.map(|()| true).map_err(|refusal| {
                        if !transferred && refusal.is_permanent() {
                            self.fatal_status = Some(refusal.status());
                        }
                        refusal.status()
                    });
                }
                PublicationPhase::RuntimePublished => return Ok(true),
                PublicationPhase::VspacePending
                | PublicationPhase::RuntimePending
                | PublicationPhase::RuntimeUncertain => return Err(nt_process::STATUS_DEVICE_BUSY),
            }
        }
        Err(nt_process::STATUS_DEVICE_BUSY)
    }
}
