//! When a retired namespace slot may be handed out again.
//!
//! Handles to symbolic links, semaphores, mutants and timers encode the entry's index, and
//! the dispatcher stores, the user timer table, queued timer APCs and the Event registry are
//! keyed by it. None of those carries the entry identity, so they cannot tell a later occupant
//! of the index from the object they were created for. The slot is therefore reused only when
//! all of them have stopped naming it.

use crate::*;

impl ExecNtHandler {
    /// References to namespace slot `index` held outside the table.
    fn namespace_slot_references(&self, index: usize) -> usize {
        let key = index as u64;
        let handles: usize = [
            SYMBOLIC_LINK_HANDLE_TAG,
            SEMAPHORE_HANDLE_TAG,
            MUTANT_HANDLE_TAG,
            TIMER_HANDLE_TAG,
        ]
        .into_iter()
        .map(|tag| {
            self.pm
                .handle_object_reference_count(nt_process::HandleObject::Opaque(tag | key))
        })
        .sum();
        let wait_records = self
            .obj_ns
            .get(index)
            .map_or(0, |entry| entry.wait_references as usize);
        handles
            + wait_records
            + usize::from(self.events.contains(key))
            + usize::from(self.semaphores.contains(key))
            + usize::from(self.mutants.contains(key))
            + usize::from(self.user_timers.contains(key))
            + usize::from(
                self.pm
                    .has_kernel_user_apc_source(nt_process::KernelUserApcSource::Timer(key)),
            )
            + usize::from(self.event_objects.id_for_native(key).is_some())
    }

    /// Delete the object at `index` after its backing has been removed. The slot is queued for
    /// reuse only if nothing outside the table still names the index; otherwise the entry is
    /// deleted in place and keeps its slot.
    pub(crate) fn retire_namespace_slot(&mut self, index: usize) -> bool {
        let outstanding = self.namespace_slot_references(index);
        self.obj_ns.retire(index, outstanding)
    }
}

impl ExecNtHandler {
    /// The identity of the namespace entry behind a dispatcher wait object, or 0 when the
    /// object is not a live namespace entry (processes, threads, files, internal Events). A
    /// caller that resolves a handle and parks later compares this across the gap: the index
    /// alone cannot tell the resolved object from a later occupant of its slot.
    pub(crate) fn wait_object_namespace_identity(&self, object: WaitObject) -> u64 {
        if object.kind() != WaitObject::KIND_DISPATCHER {
            return 0;
        }
        usize::try_from(object.id())
            .ok()
            .and_then(|index| self.obj_ns.get(index))
            .filter(|entry| entry.is_live())
            .map_or(0, |entry| entry.identity)
    }
}
