use super::*;
use nt_user_host::thread_slot::{RuntimeConstruction, RuntimeIdentity, RuntimeTcbProjection, ThreadRuntimeSlot};

type RuntimeSlot = ThreadRuntimeSlot<HostedThreadRuntimeOwner>;

#[path = "thread_memory_retirement.rs"]
mod memory_retirement;

/// Durable memory/progress ownership is distinct from copied routing/diagnostic metadata.
/// Mechanism inventory stays alongside this payload in the pending row's sealed retirement actor.
#[derive(Debug)]
pub(crate) struct HostedThreadRuntimeOwner {
    runtime: HostedThreadRuntime,
    pub(crate) suspension: crate::thread_suspend::HostedThreadSuspend,
    memory_coverage: nt_user_host::thread_construction::MemoryConstructionCoverage<TP_WORKER_STACK_FRAME_COUNT>,
    registered_memory: Option<nt_user_host::thread_construction::RegisteredThreadMemory>,
    registry_preparation: nt_user_host::thread_reconciliation::ThreadRegistryReconciliation<TP_WORKER_STACK_FRAME_COUNT>,
    alias_preparation: core::cell::OnceCell<win32k_glue::ThreadAliasCleanup>,
    prefetch_preparation: core::cell::OnceCell<client_prefetch::ThreadPrefetchCleanup>,
    provider_preparation: core::cell::OnceCell<win32k_glue::ThreadProviderAliasCleanup>,
    memory_retirement: core::cell::OnceCell<memory_retirement::MemoryRetirement>,
    retirement_error: core::cell::Cell<Option<u32>>,
}

impl HostedThreadRuntimeOwner {
    fn new(runtime: HostedThreadRuntime) -> Self {
        Self {
            runtime,
            suspension: crate::thread_suspend::HostedThreadSuspend::new(),
            memory_coverage: nt_user_host::thread_construction::MemoryConstructionCoverage::empty(),
            registered_memory: None,
            registry_preparation: nt_user_host::thread_reconciliation::ThreadRegistryReconciliation::empty(),
            alias_preparation: core::cell::OnceCell::new(),
            prefetch_preparation: core::cell::OnceCell::new(),
            provider_preparation: core::cell::OnceCell::new(),
            memory_retirement: core::cell::OnceCell::new(),
            retirement_error: core::cell::Cell::new(None),
        }
    }

    fn construction_is_empty(&self) -> bool {
        self.suspension.is_empty() && self.memory_coverage.is_empty()
            && !self.registry_preparation.is_prepared() && self.alias_preparation.get().is_none()
            && self.prefetch_preparation.get().is_none()
            && self.provider_preparation.get().is_none()
            && self.memory_retirement.get().is_none()
    }

    fn into_legacy_runtime(self) -> HostedThreadRuntime {
        assert!(
            self.construction_is_empty(),
            "construction ownership cannot escape through a copied runtime"
        );
        self.runtime
    }
}

impl core::ops::Deref for HostedThreadRuntimeOwner {
    type Target = HostedThreadRuntime;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

/// Copyable metadata only; construction slots belong to the pending row's sealed retirement actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostedThreadRuntime {
    pub(crate) pi: usize,
    pub(crate) process: nt_user_host::process_identity::ProcessIdentity,
    pub(crate) tid: u64,
    pub(crate) tcb: u64,
    pub(crate) badge: u64,
    pub(crate) role: HostedThreadRole,
    pub(crate) mechanism: HostedThreadMechanismCaps,
    pub(crate) teb_alias: u64,
    pub(crate) resources: HostedThreadResources,
    pub(crate) user_stack_allocation_base: u64,
    pub(crate) user_stack_base: u64,
    /// Broker port handle that delivered the server thread's current LPC message.
    pub(crate) lpc_server_port: u64,
    pub(crate) lpc_client_process: u32,
    pub(crate) publication: nt_user_host::thread_publication::ThreadPublicationSlot,
    pub(crate) reservations: Option<nt_user_host::thread_binding::ThreadRuntimeReservations>,
}

pub(crate) struct PreparedHostedThreadRuntime {
    pub(crate) index: usize,
    pub(crate) ticket: nt_user_host::thread_publication::PreparedThreadPublication<
        nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    >,
}

impl HostedThreadRuntime {
    pub(crate) const fn is_live(self) -> bool {
        self.tid != 0
    }

    pub(crate) fn binding(&self) -> nt_user_host::thread_binding::ThreadBinding<HostedThreadRole> {
        nt_user_host::thread_binding::ThreadBinding {
            pi: self.pi,
            process: self.process,
            tid: self.tid,
            tcb: self.tcb,
            badge: self.badge,
            role: self.role,
            reservations: self.reservations,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostedThreadQuiesceRecord {
    pub(crate) badge: u64,
    pub(crate) tid: u64,
    pub(crate) state: Option<nt_process::ThreadState>,
}

impl HostedThreadQuiesceRecord {
    pub(crate) const fn empty() -> Self {
        Self {
            badge: 0,
            tid: 0,
            state: None,
        }
    }
}

pub(crate) struct HostedThreadRuntimeTable {
    pub(crate) entries: Vec<RuntimeSlot>,
    pub(crate) allocation_failures: u64,
    pub(crate) store_failures: u64,
}

impl HostedThreadRuntimeTable {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            allocation_failures: 0,
            store_failures: 0,
        }
    }

    pub(crate) fn reset(&mut self, initial_reserve: usize) {
        assert!(self.entries.iter().all(|entry| {
            !entry.is_protected()
                && entry.owner().is_none_or(|owner| owner.construction_is_empty())
        }));
        self.entries.clear();
        if self.entries.capacity() < initial_reserve
            && self.entries.try_reserve(initial_reserve).is_err()
        {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
        }
    }

    pub(crate) fn register(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        tcb: u64,
        badge: u64,
        role: HostedThreadRole,
    ) -> Option<HostedThreadRuntime> {
        if tcb <= 1 {
            return None;
        }
        self.store(pi, process, tid, tcb, badge, role, None)
    }

    pub(crate) fn register_main(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        tcb: u64,
        badge: u64,
        mechanism: HostedThreadMechanismCaps,
    ) -> Option<HostedThreadRuntime> {
        if tcb <= 1 || !mechanism.is_live() {
            return None;
        }
        let previous = self
            .get_by_tid(tid)
            .map(|entry| entry.mechanism)
            .unwrap_or(HostedThreadMechanismCaps::empty());
        if !nt_user_host::thread_binding::admits_mechanism_publication(
            [previous.raw_cnode, previous.cnode, previous.sched_context],
            [
                mechanism.raw_cnode,
                mechanism.cnode,
                mechanism.sched_context,
            ],
        ) {
            return None;
        }
        let runtime = self.store(pi, process, tid, tcb, badge, HostedThreadRole::Main, None)?;
        let entry = self
            .entries
            .iter_mut()
            .filter_map(RuntimeSlot::ordinary_mut)
            .find(|entry| entry.is_live() && entry.tid == tid)?;
        entry.runtime.mechanism = mechanism;
        Some(HostedThreadRuntime {
            mechanism,
            ..runtime
        })
    }

    pub(crate) fn prepare_spawn(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        badge: u64,
        role: HostedThreadRole,
        reservations: nt_user_host::thread_binding::ThreadRuntimeReservations,
    ) -> Result<PreparedHostedThreadRuntime, u32> {
        use nt_user_host::thread_binding::{
            admit_thread_binding, ThreadBinding, ThreadBindingAdmission,
        };
        let key = ThreadBinding {
            pi,
            process,
            tid,
            badge,
            role,
            tcb: 1,
            reservations: Some(reservations),
        };
        let admission = admit_thread_binding(
            key,
            self.entries
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.owner().map(|entry| (index, entry.binding()))),
        )
        .map_err(|_| nt_process::STATUS_INVALID_PARAMETER)?;
        let ThreadBindingAdmission::Replay { index } = admission else {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        };
        let entry = self.entries[index]
            .ordinary_mut()
            .ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
        if !entry.construction_is_empty()
            || entry.mechanism.is_live()
            || entry.resources.is_live()
            || entry.teb_alias != 0
        {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        let ticket = entry
            .runtime
            .publication
            .prepare(key)
            .map_err(|error| match error {
                nt_user_host::thread_publication::PublicationError::Exhausted => {
                    nt_process::STATUS_INSUFFICIENT_RESOURCES
                }
                _ => nt_process::STATUS_INVALID_PARAMETER,
            })?;
        Ok(PreparedHostedThreadRuntime { index, ticket })
    }

    pub(crate) fn cancel_spawn(&mut self, prepared: PreparedHostedThreadRuntime) {
        let entry = self.entries[prepared.index]
            .publishing_mut(&prepared.ticket)
            .expect("construction ticket retains its runtime slot");
        let key = entry.binding();
        assert!(
            entry.construction_is_empty(),
            "cancellation cannot discard construction slots"
        );
        entry
            .runtime
            .publication
            .finish(prepared.ticket, &key)
            .expect("cancel must retain its exclusive runtime reservation");
    }

    pub(crate) fn construction_binding(
        &self, pi: usize, tid: u64, pid: u64,
    ) -> Option<nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>> {
        let slot = self.entries.iter().find(|slot| {
            slot.owner().is_some_and(|owner| owner.tid == tid)
        })?;
        if slot.is_pending() { return None; }
        let owner = slot.owner()?;
        (owner.pi == pi && u64::from(owner.process.pid) == pid && owner.tcb == 1
            && owner.reservations.is_some() && owner.publication.is_busy()
            && owner.construction_is_empty() && !owner.resources.is_live())
            .then(|| owner.binding())
    }

    pub(crate) fn retain_failed_spawn(
        &mut self, prepared: PreparedHostedThreadRuntime, partial: RetainedHostedThreadConstruction,
    ) -> nt_user_host::thread_rollback::ThreadRollbackId {
        let slot = self.entries.get_mut(prepared.index)
            .expect("constructor retains its pre-reserved runtime row");
        match slot.retain_failed_construction(prepared.ticket, partial) {
            Ok(id) => id,
            Err((_error, _ticket, _partial)) => {
                panic!("constructor lost its exclusive runtime publication ticket");
            }
        }
    }

    /// Prepare immutable coverage after exact pending admission, then claim external aliases only
    /// after all ownership checks pass. No mutable runtime projection or registry transfer escapes.
    pub(crate) unsafe fn reconcile_failed_spawn(
        &self, id: nt_user_host::thread_rollback::ThreadRollbackId,
    ) -> Result<(), ThreadReconciliationError> {
        if !self.entries.iter().filter_map(RuntimeSlot::pending)
            .any(|pending| pending.id() == id && pending.construction_retirement().is_some())
        {
            return Err(ThreadReconciliationError::OwnerChanged);
        }
        self.reconcile_pending_memory(id)
    }

    /// Retain the exact published mechanism bundle before preparing any registered memory cleanup.
    /// This only transfers ownership metadata; it neither stops execution nor invokes a backend.
    /// Caller must have completed retained GUI obligations and validated PM/process/reservation
    /// identity before this handoff closes lifecycle dispatch admission. No component reentry.
    pub(crate) unsafe fn reconcile_registered_runtime(
        &mut self, id: nt_user_host::thread_rollback::ThreadRollbackId,
    ) -> Result<(), ThreadReconciliationError> {
        let slot = self.entries.iter_mut()
            .find(|slot| slot.pending().is_some_and(|pending| pending.id() == id))
            .ok_or(ThreadReconciliationError::OwnerChanged)?;
        let pending = slot.pending().ok_or(ThreadReconciliationError::OwnerChanged)?;
        let owner = pending.runtime();
        if pending.construction_retirement().is_some()
            || !owner.registered_memory.as_ref().is_some_and(|registered| registered.matches(&owner.resources))
        {
            return Err(ThreadReconciliationError::OwnerChanged);
        }
        slot.handoff_registered_mechanisms(id)
            .map_err(|_| ThreadReconciliationError::OwnerChanged)?;
        self.reconcile_pending_memory(id)
    }

    unsafe fn reconcile_pending_memory(
        &self, id: nt_user_host::thread_rollback::ThreadRollbackId,
    ) -> Result<(), ThreadReconciliationError> {
        let _durable = allocator::enter_durable();
        if !temporary_frame_alias::backing_release_available()
            || !service_sec_image::section_scratch_is_quiescent()
        {
            return Err(ThreadReconciliationError::Aliases(nt_address_space::STATUS_INSUFFICIENT_RESOURCES));
        }
        let pending = self.entries.iter().filter_map(RuntimeSlot::pending)
            .find(|pending| pending.id() == id)
            .ok_or(ThreadReconciliationError::OwnerChanged)?;
        let owner = pending.runtime();
        let construction_retirement = pending.construction_retirement();
        let retirement = construction_retirement.or_else(|| pending.registered_mechanism_retirement())
            .ok_or(ThreadReconciliationError::OwnerChanged)?;
        let mechanisms = retirement.inventory();
        let registry = &*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY);
        let snapshot = if construction_retirement.is_some() {
            owner.registry_preparation.reconcile(
                id, &owner.resources, &owner.memory_coverage, retirement, registry,
            )
        } else {
            let registered = owner.registered_memory.as_ref()
                .filter(|registered| registered.matches(&owner.resources))
                .ok_or(ThreadReconciliationError::OwnerChanged)?;
            let mut pages = [0u64; TP_WORKER_STACK_FRAME_COUNT + 2];
            let mut len = 0;
            for page in registered.pages() {
                *pages.get_mut(len).ok_or(ThreadReconciliationError::OwnershipConflict)? = page;
                len += 1;
            }
            owner.registry_preparation.reconcile_registered(id, &owner.resources, &pages[..len], registry)
        }.map_err(ThreadReconciliationError::Registry)?;
        for cap in mechanisms.entries().filter_map(|(_, state)| state.slot()) {
            if (construction_retirement.is_some() && owner.memory_coverage.empty_slot() == Some(cap))
                || snapshot.rollback_resources().iter().any(|resource| resource.cap == cap)
                || registry.records().iter().any(|record|
                    [record.frame, record.alias_cap, record.source_cap].contains(&cap))
            {
                return Err(ThreadReconciliationError::OwnershipConflict);
            }
        }
        let aliases = match owner.alias_preparation.get() {
            Some(aliases) => aliases,
            None => {
                let layout = owner.resources.layout().ok_or(ThreadReconciliationError::OwnerChanged)?;
                let aliases = win32k_glue::ThreadAliasCleanup::prepare(id, layout)
                    .map_err(ThreadReconciliationError::Aliases)?;
                assert!(owner.alias_preparation.set(aliases).is_ok());
                owner.alias_preparation.get().expect("retained alias preparation")
            }
        };
        let prefetch = match owner.prefetch_preparation.get() {
            Some(prefetch) => prefetch,
            None => {
                let layout = owner.resources.layout().ok_or(ThreadReconciliationError::OwnerChanged)?;
                let prefetch = client_prefetch::ThreadPrefetchCleanup::prepare(id, layout)
                    .map_err(ThreadReconciliationError::Aliases)?;
                assert!(owner.prefetch_preparation.set(prefetch).is_ok());
                owner.prefetch_preparation.get().expect("retained prefetch preparation")
            }
        };
        let provider = match owner.provider_preparation.get() {
            Some(provider) => provider,
            None => {
                let layout = owner.resources.layout().ok_or(ThreadReconciliationError::OwnerChanged)?;
                let provider = win32k_glue::ThreadProviderAliasCleanup::prepare(id, layout)
                    .map_err(ThreadReconciliationError::Aliases)?;
                assert!(owner.provider_preparation.set(provider).is_ok());
                owner.provider_preparation.get().expect("retained provider alias preparation")
            }
        };
        aliases.revalidate(id).map_err(ThreadReconciliationError::Aliases)?;
        prefetch.revalidate(id).map_err(ThreadReconciliationError::Aliases)?;
        provider.revalidate(id).map_err(ThreadReconciliationError::Aliases)?;
        for cap in snapshot.rollback_resources().iter().map(|resource| resource.cap)
            .chain(mechanisms.entries().filter_map(|(_, state)| state.slot()))
            .chain(retirement.pending_memory_slot())
        {
            if client_prefetch::owns_cap(cap) || win32k_glue::attachment_owns_cap(cap)
                || win32k_glue::provider_alias_owns_root_cap(cap)
                || temporary_frame_alias::owns_root_cap(cap)
                || frame_acquisition::owns_root_cap(cap)
                || crate::ps_object_backing::owns_root_cap(cap)
            {
                return Err(ThreadReconciliationError::OwnershipConflict);
            }
        }
        if aliases.capabilities().any(|cap| client_prefetch::owns_cap(cap))
            || prefetch.capabilities().any(|cap| win32k_glue::attachment_owns_cap(cap))
            || aliases.capabilities().chain(prefetch.capabilities()).any(|cap|
                win32k_glue::provider_alias_owns_root_cap(cap) || temporary_frame_alias::owns_root_cap(cap)
                    || frame_acquisition::owns_root_cap(cap))
            || provider.root_capabilities().any(|cap|
                client_prefetch::owns_cap(cap) || win32k_glue::attachment_owns_cap(cap)
                    || temporary_frame_alias::owns_root_cap(cap))
            || provider.root_capabilities().any(frame_acquisition::owns_root_cap)
            || aliases.capabilities()
                .chain(prefetch.capabilities())
                .chain(provider.root_capabilities())
                .any(crate::ps_object_backing::owns_root_cap)
        {
            return Err(ThreadReconciliationError::OwnershipConflict);
        }
        for cap in aliases.capabilities().chain(prefetch.capabilities()).chain(provider.root_capabilities()) {
            if registry.records().iter().any(|record|
                    [record.frame, record.alias_cap, record.source_cap].contains(&cap))
            {
                return Err(ThreadReconciliationError::OwnershipConflict);
            }
        }
        // All journals and every cross-owner check precede the first pin. No backend call,
        // allocation or reentry occurs between these disjoint, prevalidated claim commits.
        aliases.claim(id).map_err(ThreadReconciliationError::Aliases)?;
        prefetch.claim(id).map_err(ThreadReconciliationError::Aliases)?;
        provider.claim(id).map_err(ThreadReconciliationError::Aliases)
    }

    /// Validate the original reservation and completed owner before PM activation or first run.
    pub(crate) fn validate_spawn(
        &mut self, prepared: &PreparedHostedThreadRuntime, spawn: &HostedThreadSpawn,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(prepared.index)
            .and_then(|slot| slot.publishing_mut(&prepared.ticket)) else { return false; };
        let key = entry.binding();
        entry.construction_is_empty() && !entry.resources.is_live() && !entry.mechanism.is_live()
            && entry.tcb == 1 && entry.teb_alias == 0 && key == spawn.binding()
            && key == *prepared.ticket.owner() && spawn.resources().client_pi == key.pi
            && spawn.tcb() > 1 && spawn.mechanism().is_live() && spawn.resources().is_live()
            && spawn.registered_memory().is_ok()
    }

    pub(crate) fn commit_spawn(
        &mut self,
        prepared: PreparedHostedThreadRuntime,
        spawn: &HostedThreadSpawn,
    ) {
        assert!(self.validate_spawn(&prepared, spawn), "prevalidated constructor publication remains current");
        let entry = self.entries[prepared.index]
            .publishing_mut(&prepared.ticket)
            .expect("construction ticket retains its runtime slot");
        let key = entry.binding();
        assert!(
            entry.construction_is_empty(),
            "publication cannot overwrite construction slots"
        );
        assert!(spawn.tcb() > 1 && spawn.mechanism().is_live() && spawn.resources().is_live());
        assert_eq!(spawn.resources().client_pi, key.pi);
        let registered = spawn.registered_memory().expect("validated complete constructor registration");
        entry
            .runtime
            .publication
            .finish(prepared.ticket, &key)
            .expect("construction must retain its exclusive runtime reservation");
        entry.runtime.tcb = spawn.tcb();
        entry.runtime.mechanism = spawn.mechanism();
        entry.runtime.teb_alias = spawn.teb_alias();
        entry.runtime.resources = spawn.resources();
        entry.registered_memory = Some(registered);
    }

    pub(crate) fn reserve(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        badge: u64,
        role: HostedThreadRole,
        reservations: nt_user_host::thread_binding::ThreadRuntimeReservations,
    ) -> Option<HostedThreadRuntime> {
        self.store(pi, process, tid, 1, badge, role, Some(reservations))
    }

    pub(crate) fn store(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        tcb: u64,
        badge: u64,
        role: HostedThreadRole,
        reservations: Option<nt_user_host::thread_binding::ThreadRuntimeReservations>,
    ) -> Option<HostedThreadRuntime> {
        use nt_user_host::thread_binding::{
            admit_thread_binding, ThreadBinding, ThreadBindingAdmission,
        };
        let admission = admit_thread_binding(
            ThreadBinding {
                pi,
                process,
                tid,
                tcb,
                badge,
                role,
                reservations,
            },
            self.entries
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.owner().map(|entry| (index, entry.binding()))),
        )
        .ok()?;
        match admission {
            ThreadBindingAdmission::Replay { index } => {
                return self.entries[index]
                    .ordinary_mut()
                    .filter(|entry| entry.construction_is_empty())
                    .map(|entry| entry.runtime);
            }
            ThreadBindingAdmission::Promote { index } => {
                let existing = self.entries[index].ordinary_mut()?;
                if !existing.construction_is_empty()
                    || existing.mechanism.is_live()
                    || existing.resources.is_live()
                    || existing.teb_alias != 0
                {
                    return None;
                }
                existing.runtime.tcb = tcb;
                return Some(existing.runtime);
            }
            ThreadBindingAdmission::Insert => {}
        }
        let runtime = HostedThreadRuntime {
            pi,
            process,
            tid,
            tcb,
            badge,
            role,
            mechanism: HostedThreadMechanismCaps::empty(),
            teb_alias: 0,
            resources: HostedThreadResources::empty(),
            user_stack_allocation_base: 0,
            user_stack_base: 0,
            lpc_server_port: 0,
            lpc_client_process: 0,
            publication: nt_user_host::thread_publication::ThreadPublicationSlot::empty(),
            reservations,
        };
        if let Some(empty) = self.entries.iter_mut().find(|entry| entry.is_empty()) {
            empty
                .insert(HostedThreadRuntimeOwner::new(runtime))
                .expect("admitted runtime fills a vacant row");
            return Some(runtime);
        }
        if self.entries.len() == self.entries.capacity() && self.entries.try_reserve(1).is_err() {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            self.store_failures = self.store_failures.saturating_add(1);
            return None;
        }
        let mut slot = RuntimeSlot::empty();
        slot.insert(HostedThreadRuntimeOwner::new(runtime))
            .expect("admitted runtime fills a new row");
        self.entries.push(slot);
        Some(runtime)
    }

    pub(crate) fn stats(&self) -> (usize, usize, usize, u64, u64) {
        (
            self.entries
                .iter()
                .filter(|entry| !entry.is_empty())
                .count(),
            self.entries.len(),
            self.entries.capacity(),
            self.allocation_failures,
            self.store_failures,
        )
    }

    pub(crate) fn get_by_tid(&self, tid: u64) -> Option<HostedThreadRuntime> {
        (tid != 0).then_some(())?;
        self.entries
            .iter()
            .filter_map(RuntimeSlot::owner)
            .map(|entry| entry.runtime)
            .find(|entry| entry.is_live() && entry.tid == tid)
    }

    pub(crate) fn unbuilt_reservation_by_tid(&self, tid: u64) -> Option<HostedThreadRuntime> {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::releasable)
            .filter(|entry| entry.construction_is_empty())
            .map(|entry| entry.runtime)
            .find(|entry| {
                entry.is_live()
                    && entry.tid == tid
                    && entry.publication.can_release_unbuilt(
                        entry.tcb,
                        entry.mechanism.is_live() || entry.resources.is_live() || entry.teb_alias != 0,
                    )
            })
    }

    pub(crate) fn executable_by_tid(&self, tid: u64) -> Option<HostedThreadRuntime> {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::executable)
            .map(|entry| entry.runtime)
            .find(|entry| entry.tid == tid)
    }

    pub(crate) fn executable_by_badge(&self, badge: u64) -> Option<HostedThreadRuntime> {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::executable)
            .map(|entry| entry.runtime)
            .find(|entry| entry.badge == badge)
    }

    pub(crate) fn executable_by_role(
        &self,
        pi: usize,
        role: HostedThreadRole,
    ) -> Option<HostedThreadRuntime> {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::executable)
            .map(|entry| entry.runtime)
            .find(|entry| entry.pi == pi && entry.role == role)
    }

    pub(crate) fn executable_by_index(&self, index: usize) -> Option<HostedThreadRuntime> {
        self.entries.get(index)?.executable().map(|entry| entry.runtime)
    }

    pub(crate) fn pending_for_tid(&self, tid: u64) -> bool {
        self.entries
            .iter()
            .any(|slot| slot.is_pending() && slot.owner().is_some_and(|entry| entry.tid == tid))
    }

    pub(crate) fn pending_for_badge(&self, badge: u64) -> bool {
        self.entries
            .iter()
            .any(|slot| slot.is_pending() && slot.owner().is_some_and(|entry| entry.badge == badge))
    }

    pub(crate) fn record_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn set_user_stack(
        &mut self,
        tid: u64,
        allocation_base: u64,
        stack_base: u64,
    ) -> Option<HostedThreadRuntime> {
        if tid == 0 || allocation_base == 0 || stack_base <= allocation_base {
            return None;
        }
        let entry = self
            .entries
            .iter_mut()
            .filter_map(RuntimeSlot::ordinary_mut)
            .find(|entry| entry.is_live() && entry.tid == tid)?;
        entry.runtime.user_stack_allocation_base = allocation_base;
        entry.runtime.user_stack_base = stack_base;
        Some(entry.runtime)
    }

    pub(crate) fn tcb_by_tid(&self, tid: u64) -> Option<u64> {
        self.executable_by_tid(tid)
            .map(|entry| entry.tcb)
            .filter(|&tcb| tcb > 1)
    }

    pub(crate) fn tcb_for_main_pi(&self, pi: usize) -> Option<u64> {
        self.executable_by_role(pi, HostedThreadRole::Main)
            .map(|entry| entry.tcb)
            .filter(|&tcb| tcb > 1)
    }

    pub(crate) fn has_process(&self, pi: usize) -> bool {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::owner)
            .any(|entry| entry.pi == pi)
    }

    pub(crate) fn holds_pool_slot(&self, pi: usize, slot: usize) -> bool {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::owner)
            .any(|entry| entry.binding().holds_pool_slot(pi, slot))
    }

    pub(crate) fn holds_window_slot(&self, pi: usize, slot: usize) -> bool {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::owner)
            .any(|entry| entry.binding().holds_window_slot(pi, slot))
    }

    pub(crate) fn get_by_role(
        &self,
        pi: usize,
        role: HostedThreadRole,
    ) -> Option<HostedThreadRuntime> {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::owner)
            .map(|entry| entry.runtime)
            .find(|entry| entry.is_live() && entry.pi == pi && entry.role == role)
    }

    pub(crate) fn get_by_badge(&self, badge: u64) -> Option<HostedThreadRuntime> {
        self.entries
            .iter()
            .filter_map(RuntimeSlot::owner)
            .map(|entry| entry.runtime)
            .find(|entry| entry.is_live() && entry.badge == badge)
    }

    pub(crate) fn set_lpc_server_context(&mut self, badge: u64, port: u64, process: u32) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .filter_map(RuntimeSlot::ordinary_mut)
            .find(|entry| entry.is_live() && entry.badge == badge)
        else {
            return false;
        };
        entry.runtime.lpc_server_port = port;
        entry.runtime.lpc_client_process = process;
        true
    }

    pub(crate) fn tcb_for_role(&self, pi: usize, role: HostedThreadRole) -> Option<u64> {
        self.executable_by_role(pi, role)
            .map(|entry| entry.tcb)
            .filter(|&tcb| tcb > 1)
    }

    pub(crate) fn release_tid(&mut self, tid: u64) -> Option<HostedThreadRuntime> {
        (tid != 0).then_some(())?;
        let slot = self.entries
            .iter_mut()
            .find(|slot| slot.owner().is_some_and(|entry| entry.tid == tid))?;
        if !slot.owner()?.construction_is_empty() {
            return None;
        }
        slot.release_published()
            .map(HostedThreadRuntimeOwner::into_legacy_runtime)
    }
}

static mut HOSTED_THREAD_RUNTIME_WORK: HostedThreadRuntimeTable = HostedThreadRuntimeTable::new();

/// Read-only shortcut geometry from an executable runtime's actual fixed-stack inventory.
/// Missing, pending, unmirrored and caller-stack runtimes expose no fixed mirror range. As with
/// the memory exclusion queries, no allocation, IPC or callbacks may occur during this borrow.
pub(crate) fn hosted_thread_fixed_stack_geometry(pi: usize, badge: u64) -> (u64, u64) {
    let table = unsafe { &*core::ptr::addr_of!(HOSTED_THREAD_RUNTIME_WORK) };
    let Some(runtime) = table.executable_by_badge(badge)
        .filter(|runtime| runtime.pi == pi && runtime.resources.client_pi == pi)
    else {
        return (0, 0);
    };
    let resources = &runtime.resources;
    let Some(layout) = resources.layout() else {
        return (0, 0);
    };
    let frames = resources.stack_frames();
    if frames == 0 || resources.has_unlocated_capabilities()
        || (0..frames as usize).any(|index| {
            resources.stack_owner[index] <= 1 || resources.stack_target[index] <= 1
                || resources.stack_mirror[index] <= 1
        })
    {
        return (0, 0);
    }
    (layout.stack().base, frames)
}

/// Deny-only query for ordinary memory paths, including copies already borrowing ExecNtHandler.
/// No allocation, IPC or callbacks may occur during this short table borrow. Cleanup backends
/// holding a mutable slot must use retained capabilities directly, never recurse through here.
pub(crate) fn hosted_thread_memory_access(pi: u64, base: u64, size: u64) -> Result<(), u32> {
    hosted_thread_memory_retirement_access(pi, base, size)?;
    if !unsafe { (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).memory_available(pi, base, size) } {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    if !unsafe { (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).memory_available(pi, base, size) } {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// Retained VM cleanup uses exact registry rows, but must still respect pending thread owners
/// and live scratch aliases. Ordinary reads, mappings and writes use the stricter entry above.
pub(crate) fn hosted_thread_memory_retirement_access(pi: u64, base: u64, size: u64) -> Result<(), u32> {
    use nt_user_host::thread_memory_access::{check_pending_thread_memory, PendingThreadMemory};
    if !crate::temporary_frame_alias::memory_available(pi, base, size) {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    let pi = usize::try_from(pi).map_err(|_| nt_address_space::STATUS_ACCESS_VIOLATION)?;
    let table = unsafe { &*core::ptr::addr_of!(HOSTED_THREAD_RUNTIME_WORK) };
    check_pending_thread_memory(
        pi,
        base,
        size,
        table.entries.iter().filter_map(|slot| {
            let owner = slot.pending()?;
            let runtime = owner.runtime();
            Some(PendingThreadMemory {
                owner: owner.id(),
                memory: &runtime.resources,
                user_stack_allocation_base: runtime.user_stack_allocation_base,
                user_stack_base: runtime.user_stack_base,
            })
        }),
    )
    .map_err(|_| nt_address_space::STATUS_ACCESS_VIOLATION)
}

/// Live transport mappings have their own target/mirror journals. A residency row cannot revoke
/// their canonical backing; the thread owner must retire or transfer those journals first.
pub(crate) fn hosted_thread_retains_page_backing(pi: u64, page: u64) -> bool {
    let table = unsafe { &*core::ptr::addr_of!(HOSTED_THREAD_RUNTIME_WORK) };
    table.entries.iter().filter_map(RuntimeSlot::owner).any(|owner| {
        owner.pi as u64 == pi && owner.resources.retains_page_backing(page)
    })
}

/// Exclusive pointer to the serialized executive's hosted TID -> seL4 TCB table.
///
/// The table is deliberately not stored inline in `ExecNtHandler`; that handler is constructed on the
/// root task stack during the early SEC_IMAGE self-tests. The record store grows in the executive
/// heap and reuses released records.
pub(crate) struct HostedThreadRuntimes {
    pub(crate) table: *mut HostedThreadRuntimeTable,
}

impl HostedThreadRuntimes {
    pub(crate) fn admit_ingress(
        &self,
        badge: u64,
        current_process: Option<nt_user_host::process_identity::ProcessIdentity>,
    ) -> Result<HostedThreadRuntime, nt_user_host::thread_slot::ThreadIngressError> {
        use nt_user_host::thread_slot::ThreadIngressError;
        let table = unsafe { &*self.table };
        let slot = table.entries.iter()
            .find(|slot| slot.owner().is_some_and(|runtime| runtime.badge == badge))
            .ok_or(ThreadIngressError::UnknownBadge)?;
        slot.admit_ingress(badge, current_process).map(|entry| entry.runtime)
    }

    pub(crate) fn executable_by_tid(&self, tid: u64) -> Option<HostedThreadRuntime> {
        unsafe { (&*self.table).executable_by_tid(tid) }
    }

    pub(crate) fn executable_by_badge(&self, badge: u64) -> Option<HostedThreadRuntime> {
        unsafe { (&*self.table).executable_by_badge(badge) }
    }

    pub(crate) fn executable_by_role(
        &self,
        pi: usize,
        role: HostedThreadRole,
    ) -> Option<HostedThreadRuntime> {
        unsafe { (&*self.table).executable_by_role(pi, role) }
    }

    pub(crate) fn executable_by_index(&self, index: usize) -> Option<HostedThreadRuntime> {
        unsafe { (&*self.table).executable_by_index(index) }
    }

    pub(crate) fn pending_for_tid(&self, tid: u64) -> bool {
        unsafe { (&*self.table).pending_for_tid(tid) }
    }

    pub(crate) fn pending_for_badge(&self, badge: u64) -> bool {
        unsafe { (&*self.table).pending_for_badge(badge) }
    }

    pub(crate) fn reset() -> Self {
        let table = core::ptr::addr_of_mut!(HOSTED_THREAD_RUNTIME_WORK);
        // SAFETY: service_sec_image is serialized. A previous handler has been
        // dropped before a new one is constructed, so no other table reference exists.
        unsafe { (&mut *table).reset(HOSTED_THREAD_RUNTIME_INITIAL_RESERVE) };
        Self { table }
    }

    pub(crate) fn register(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        tcb: u64,
        badge: u64,
        role: HostedThreadRole,
    ) -> Option<HostedThreadRuntime> {
        // SAFETY: this wrapper is the sole owner while its handler is live.
        unsafe { (&mut *self.table).register(pi, process, tid, tcb, badge, role) }
    }

    pub(crate) fn register_main(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        tcb: u64,
        badge: u64,
        mechanism: HostedThreadMechanismCaps,
    ) -> Option<HostedThreadRuntime> {
        unsafe { (&mut *self.table).register_main(pi, process, tid, tcb, badge, mechanism) }
    }

    pub(crate) fn prepare_spawn(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        badge: u64,
        role: HostedThreadRole,
        reservations: nt_user_host::thread_binding::ThreadRuntimeReservations,
    ) -> Result<PreparedHostedThreadRuntime, u32> {
        unsafe { (&mut *self.table).prepare_spawn(pi, process, tid, badge, role, reservations) }
    }

    pub(crate) fn cancel_spawn(&mut self, prepared: PreparedHostedThreadRuntime) {
        unsafe { (&mut *self.table).cancel_spawn(prepared) }
    }

    pub(crate) fn construction_binding(
        &self, pi: usize, tid: u64, pid: u64,
    ) -> Option<nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>> {
        unsafe { (&*self.table).construction_binding(pi, tid, pid) }
    }

    pub(crate) fn retain_failed_spawn(
        &mut self, prepared: PreparedHostedThreadRuntime, partial: RetainedHostedThreadConstruction,
    ) -> nt_user_host::thread_rollback::ThreadRollbackId {
        unsafe { (&mut *self.table).retain_failed_spawn(prepared, partial) }
    }

    pub(crate) unsafe fn reconcile_failed_spawn(
        &self, id: nt_user_host::thread_rollback::ThreadRollbackId,
    ) -> Result<(), ThreadReconciliationError> {
        (&*self.table).reconcile_failed_spawn(id)
    }

    pub(crate) unsafe fn reconcile_registered_runtime(
        &mut self, id: nt_user_host::thread_rollback::ThreadRollbackId,
    ) -> Result<(), ThreadReconciliationError> {
        (&mut *self.table).reconcile_registered_runtime(id)
    }

    pub(crate) fn validate_spawn(
        &mut self, prepared: &PreparedHostedThreadRuntime, spawn: &HostedThreadSpawn,
    ) -> bool {
        unsafe { (&mut *self.table).validate_spawn(prepared, spawn) }
    }

    pub(crate) fn slot_count(&self) -> usize {
        unsafe { (&*self.table).entries.len() }
    }

    pub(crate) fn pending_construction_at(&self, index: usize) -> Option<(
        nt_user_host::thread_rollback::ThreadRollbackId, HostedThreadRuntime,
    )> {
        let pending = unsafe { (&*self.table).entries.get(index)?.pending()? };
        pending.construction_retirement()?;
        Some((pending.id(), pending.runtime().runtime))
    }

    /// # Safety
    /// Caller has validated current PM/process identity and held pool/window reservations.
    /// Direct kernel operations only. Completed bookkeeping is returned for immediate, allocation-
    /// free reservation release. Failed construction never committed an MM/job charge.
    pub(crate) unsafe fn advance_failed_construction(
        &mut self, index: usize, id: nt_user_host::thread_rollback::ThreadRollbackId,
    ) -> Result<HostedThreadRuntime, u32> {
        let _durable = allocator::enter_durable();
        let table = &mut *self.table;
        let result = (|| {
            if table.entries.get(index).and_then(RuntimeSlot::pending)
                .is_none_or(|pending| pending.id() != id)
            { return Err(nt_address_space::STATUS_INVALID_PARAMETER); }
            // Original cap numbers are only pre-handoff provenance. Once a registry transfer
            // exists, retries validate the exact retained owners, never recycled numeric slots.
            if table.entries[index].pending().unwrap().runtime().memory_retirement.get().is_none() {
                table.reconcile_failed_spawn(id).map_err(|error| error.status())?;
            }
            let slot = table.entries.get_mut(index).ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
            if slot.pending().is_none_or(|pending| pending.id() != id) {
                return Err(nt_address_space::STATUS_INVALID_PARAMETER);
            }
            if !slot.pending().and_then(|pending| pending.construction_retirement())
                .is_some_and(|owner| owner.is_complete())
            {
                crate::thread_construction_retirement::advance(slot, id)?;
            }
            memory_retirement::prepare(slot, id)?;
            memory_retirement::advance(slot, id)?;
            let owner = slot.take_retired_payload(id).ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
            Ok(owner.runtime)
        })();
        if let Some(pending) = table.entries.get(index).and_then(RuntimeSlot::pending)
            .filter(|pending| pending.id() == id)
        {
            let current = result.as_ref().err().copied();
            if pending.runtime().retirement_error.replace(current) != current {
                if let Some(status) = current {
                    print_str(b"[thread-retirement] retained tid=");
                    print_u64(id.identity().tid);
                    print_str(b" status=0x");
                    print_hex(status);
                    print_str(b"\n");
                }
            }
        }
        result
    }

    pub(crate) fn commit_spawn(
        &mut self,
        prepared: PreparedHostedThreadRuntime,
        spawn: &HostedThreadSpawn,
    ) {
        unsafe { (&mut *self.table).commit_spawn(prepared, spawn) }
    }

    pub(crate) fn reserve(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        tid: u64,
        badge: u64,
        role: HostedThreadRole,
        reservations: nt_user_host::thread_binding::ThreadRuntimeReservations,
    ) -> Option<HostedThreadRuntime> {
        // SAFETY: this wrapper is the sole owner while its handler is live.
        unsafe { (&mut *self.table).reserve(pi, process, tid, badge, role, reservations) }
    }

    pub(crate) fn set_lpc_server_context(&mut self, badge: u64, port: u64, process: u32) -> bool {
        // SAFETY: this wrapper is the sole owner while its handler is live.
        unsafe { (&mut *self.table).set_lpc_server_context(badge, port, process) }
    }

    pub(crate) fn get_by_tid(&self, tid: u64) -> Option<HostedThreadRuntime> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).get_by_tid(tid) }
    }

    pub(crate) fn unbuilt_reservation_by_tid(&self, tid: u64) -> Option<HostedThreadRuntime> {
        unsafe { (&*self.table).unbuilt_reservation_by_tid(tid) }
    }

    pub(crate) fn record_count(&self) -> usize {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).record_count() }
    }

    pub(crate) fn set_user_stack(
        &mut self,
        tid: u64,
        allocation_base: u64,
        stack_base: u64,
    ) -> Option<HostedThreadRuntime> {
        // SAFETY: this wrapper is the sole owner while its handler is live.
        unsafe { (&mut *self.table).set_user_stack(tid, allocation_base, stack_base) }
    }

    pub(crate) fn tcb_by_tid(&self, tid: u64) -> Option<u64> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).tcb_by_tid(tid) }
    }

    pub(crate) fn get_by_role(
        &self,
        pi: usize,
        role: HostedThreadRole,
    ) -> Option<HostedThreadRuntime> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).get_by_role(pi, role) }
    }

    pub(crate) fn get_by_badge(&self, badge: u64) -> Option<HostedThreadRuntime> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).get_by_badge(badge) }
    }

    pub(crate) fn tcb_for_main_pi(&self, pi: usize) -> Option<u64> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).tcb_for_main_pi(pi) }
    }

    pub(crate) fn has_process(&self, pi: usize) -> bool {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).has_process(pi) }
    }

    pub(crate) fn holds_pool_slot(&self, pi: usize, slot: usize) -> bool {
        unsafe { (&*self.table).holds_pool_slot(pi, slot) }
    }

    pub(crate) fn holds_window_slot(&self, pi: usize, slot: usize) -> bool {
        unsafe { (&*self.table).holds_window_slot(pi, slot) }
    }

    pub(crate) fn tcb_for_role(&self, pi: usize, role: HostedThreadRole) -> Option<u64> {
        // SAFETY: shared access is bounded by the borrow of this sole-owner wrapper.
        unsafe { (&*self.table).tcb_for_role(pi, role) }
    }

    pub(crate) fn release_tid(&mut self, tid: u64) -> Option<HostedThreadRuntime> {
        // SAFETY: this wrapper is the sole owner while its handler is live.
        unsafe { (&mut *self.table).release_tid(tid) }
    }
}

pub(crate) fn hosted_thread_runtime_table_stats() -> (usize, usize, usize, u64, u64) {
    unsafe { (&*core::ptr::addr_of!(HOSTED_THREAD_RUNTIME_WORK)).stats() }
}

impl RuntimeIdentity for HostedThreadRuntimeOwner {
    type Role = HostedThreadRole;

    fn binding(&self) -> nt_user_host::thread_binding::ThreadBinding<Self::Role> {
        self.runtime.binding()
    }

    fn publication(&self) -> &nt_user_host::thread_publication::ThreadPublicationSlot {
        &self.runtime.publication
    }

    fn control_busy(&self) -> bool {
        self.suspension.is_pending()
    }
}

impl nt_user_host::thread_memory_retirement_access::RuntimeThreadMemory<TP_WORKER_STACK_FRAME_COUNT>
    for HostedThreadRuntimeOwner
{
    fn thread_memory(&self) -> &HostedThreadResources {
        &self.runtime.resources
    }

    fn user_stack_bounds(&self) -> (u64, u64) {
        (self.runtime.user_stack_allocation_base, self.runtime.user_stack_base)
    }
}

pub(crate) fn check_user_stack_retirement_access(
    permit: &nt_user_host::thread_memory_retirement_access::UserStackRetirementPermit<'_>,
    current: nt_user_host::process_identity::ProcessIdentity,
    pi: usize,
    page: u64,
) -> Result<(), u32> {
    if !temporary_frame_alias::memory_available(pi as u64, page, 4096) {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    let table = unsafe { &*core::ptr::addr_of!(HOSTED_THREAD_RUNTIME_WORK) };
    permit.check(pi, current, page, 4096, table.entries.iter().filter_map(|slot| {
        let owner = slot.pending()?;
        let runtime = owner.runtime();
        Some(nt_user_host::thread_memory_access::PendingThreadMemory {
            owner: owner.id(),
            memory: &runtime.resources,
            user_stack_allocation_base: runtime.user_stack_allocation_base,
            user_stack_base: runtime.user_stack_base,
        })
    })).map_err(|_| nt_address_space::STATUS_ACCESS_VIOLATION)
}

impl RuntimeTcbProjection for HostedThreadRuntimeOwner {
    fn clear_retired_tcb_projection(&mut self, expected_cap: u64) -> Result<(), u32> {
        if expected_cap <= 1 || (self.runtime.tcb != expected_cap && self.runtime.tcb != 1) {
            return Err(nt_address_space::STATUS_INVALID_PARAMETER);
        }
        self.runtime.tcb = 1;
        Ok(())
    }
}

impl nt_user_host::thread_slot::RuntimeMechanismHandoff for HostedThreadRuntimeOwner {
    fn registered_mechanism_slots(&self) -> Result<[u64; 4], u32> {
        if self.runtime.tcb <= 1 || !self.runtime.mechanism.is_live() {
            return Err(nt_address_space::STATUS_INVALID_PARAMETER);
        }
        Ok([
            self.runtime.mechanism.raw_cnode,
            self.runtime.mechanism.cnode,
            self.runtime.tcb,
            self.runtime.mechanism.sched_context,
        ])
    }

    fn clear_registered_mechanism_projections(
        &mut self, id: nt_user_host::thread_rollback::ThreadRollbackId, expected: [u64; 4],
    ) -> Result<(), u32> {
        // The enclosing pending owner validates the opaque attempt and reservation tuple before
        // this callback. Recheck every locally held identity and source slot before the first clear.
        let identity = id.identity();
        if self.runtime.pi != identity.pi || self.runtime.process.pid != identity.pid
            || self.runtime.process.generation != identity.process_generation
            || self.runtime.tid != identity.tid || self.runtime.publication.is_busy()
            || self.registered_mechanism_slots()? != expected
        {
            return Err(nt_address_space::STATUS_INVALID_PARAMETER);
        }
        self.runtime.mechanism = HostedThreadMechanismCaps::empty();
        Ok(())
    }
}

impl RuntimeConstruction for HostedThreadRuntimeOwner {
    type Partial = RetainedHostedThreadConstruction;

    fn construction_binding(partial: &Self::Partial) -> nt_user_host::thread_binding::ThreadBinding<Self::Role> {
        partial.binding
    }

    fn construction_tcb(partial: &Self::Partial) -> Option<u64> {
        partial.construction.live_tcb()
    }

    fn validate_construction(partial: &Self::Partial) -> Result<(), nt_user_host::thread_rollback::ThreadRollbackError> {
        partial.memory_progress.validate_failed_slot(&partial.construction, &partial.resources)
    }

    fn publication_mut(&mut self) -> &mut nt_user_host::thread_publication::ThreadPublicationSlot {
        &mut self.runtime.publication
    }

    fn retain_partial(&mut self, partial: Self::Partial) -> (nt_user_host::thread_construction::ThreadConstructionInventory, Option<nt_user_host::thread_construction::FailedMemorySlot>) {
        assert!(self.construction_is_empty() && !self.runtime.resources.is_live());
        self.runtime.tcb = partial.construction.live_tcb().unwrap_or(1);
        self.runtime.resources = partial.resources;
        self.runtime.teb_alias = partial.teb_alias;
        let (coverage, memory_slot) = partial.memory_progress.into_retained();
        self.memory_coverage = coverage;
        (partial.construction, memory_slot)
    }
}
