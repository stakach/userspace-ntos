use super::*;
use nt_user_host::thread_slot::{RuntimeIdentity, ThreadRuntimeSlot};

type RuntimeSlot = ThreadRuntimeSlot<HostedThreadRuntimeOwner>;

/// Durable row ownership is distinct from copied routing/diagnostic metadata. Construction
/// inventory must move with this owner and may never be cloned by an ordinary table lookup.
#[derive(Debug)]
pub(crate) struct HostedThreadRuntimeOwner {
    runtime: HostedThreadRuntime,
    construction: nt_user_host::thread_construction::ThreadConstructionInventory,
}

impl HostedThreadRuntimeOwner {
    fn new(runtime: HostedThreadRuntime) -> Self {
        Self {
            runtime,
            construction: nt_user_host::thread_construction::ThreadConstructionInventory::empty(),
        }
    }

    fn into_legacy_runtime(self) -> HostedThreadRuntime {
        assert!(
            self.construction.is_empty(),
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

/// Copyable metadata only; pending construction slots belong to HostedThreadRuntimeOwner.
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
                && entry.owner().is_none_or(|owner| owner.construction.is_empty())
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
        if !entry.construction.is_empty()
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
            entry.construction.is_empty(),
            "cancellation cannot discard construction slots"
        );
        entry
            .runtime
            .publication
            .finish(prepared.ticket, &key)
            .expect("cancel must retain its exclusive runtime reservation");
    }

    pub(crate) fn commit_spawn(
        &mut self,
        prepared: PreparedHostedThreadRuntime,
        spawn: &HostedThreadSpawn,
    ) {
        let entry = self.entries[prepared.index]
            .publishing_mut(&prepared.ticket)
            .expect("construction ticket retains its runtime slot");
        let key = entry.binding();
        assert!(
            entry.construction.is_empty(),
            "publication cannot overwrite construction slots"
        );
        assert!(spawn.tcb() > 1 && spawn.mechanism().is_live() && spawn.resources().is_live());
        assert_eq!(spawn.resources().client_pi, key.pi);
        entry
            .runtime
            .publication
            .finish(prepared.ticket, &key)
            .expect("construction must retain its exclusive runtime reservation");
        entry.runtime.tcb = spawn.tcb();
        entry.runtime.mechanism = spawn.mechanism();
        entry.runtime.teb_alias = spawn.teb_alias();
        entry.runtime.resources = spawn.resources();
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
                    .filter(|entry| entry.construction.is_empty())
                    .map(|entry| entry.runtime);
            }
            ThreadBindingAdmission::Promote { index } => {
                let existing = self.entries[index].ordinary_mut()?;
                if !existing.construction.is_empty()
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
            .filter(|entry| entry.construction.is_empty())
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
        if !slot.owner()?.construction.is_empty() {
            return None;
        }
        slot.release_published()
            .map(HostedThreadRuntimeOwner::into_legacy_runtime)
    }
}

static mut HOSTED_THREAD_RUNTIME_WORK: HostedThreadRuntimeTable = HostedThreadRuntimeTable::new();

/// Deny-only query for ordinary memory paths, including copies already borrowing ExecNtHandler.
/// No allocation, IPC or callbacks may occur during this short table borrow. Cleanup backends
/// holding a mutable slot must use retained capabilities directly, never recurse through here.
pub(crate) fn hosted_thread_memory_access(pi: u64, base: u64, size: u64) -> Result<(), u32> {
    use nt_user_host::thread_memory_access::{check_pending_thread_memory, PendingThreadMemory};
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
}
