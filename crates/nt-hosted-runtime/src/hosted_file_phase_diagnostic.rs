//! Temporary bounded timing evidence for hosted File I/O. Identities are diagnostic keys only.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilePhaseIdentity {
    pub pid: u32,
    pub process_generation: u64,
    pub file_id: u64,
    /// Canonical IrpId packs its generation in the high bits.
    pub irp_id: u64,
}

#[derive(Clone, Copy)]
pub struct LocalFilePhaseMarks {
    pub entered: u64,
    pub captured: u64,
    pub acquired: u64,
    pub dispatched: u64,
    pub terminal: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalFilePhaseDurations {
    pub capture: u64,
    pub acquire: u64,
    pub dispatch: u64,
    pub tail: u64,
    pub total: u64,
}

#[derive(Clone, Copy)]
pub struct NpfsDispatchMarks {
    pub entered: u64,
    pub handler_entered: u64,
    pub handler_returned: u64,
    pub terminal: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NpfsDispatchDurations {
    pub pre_handler: u64,
    pub handler: u64,
    pub post_handler: u64,
    pub total: u64,
}

/// Timing only; retirement authority remains with the exact allocation owner.
#[derive(Clone, Copy)]
pub struct NpfsPoolRetireMarks {
    pub entered: u64,
    pub ownership_checked: u64,
    pub retirement_returned: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NpfsPoolRetireDurations {
    pub ownership_check: u64,
    pub retirement_service: u64,
    pub total: u64,
}

/// Temporary callback timing ledger. The canonical IRP id labels the active callback; the raw
/// completion target is checked separately because a write may complete an older queued read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NpfsMajor { Read, Write }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NpfsCallbackIdentity {
    pub canonical_irp_id: u64,
    pub major: NpfsMajor,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NpfsCallbackCounts {
    pub read_calls: u64,
    pub read_ticks: u64,
    pub read_completion_calls: u64,
    pub read_completion_ticks: u64,
    pub read_pool_retire_calls: u64,
    pub read_pool_retire_ticks: u64,
    pub read_quota_alloc_calls: u64,
    pub read_quota_alloc_ticks: u64,
    pub write_calls: u64,
    pub write_ticks: u64,
    pub write_completion_calls: u64,
    pub write_completion_ticks: u64,
    pub write_pool_retire_calls: u64,
    pub write_pool_retire_ticks: u64,
    pub write_quota_alloc_calls: u64,
    pub write_quota_alloc_ticks: u64,
    pub owner_mismatches: u64,
}

pub struct NpfsCallbackDiagnostic {
    active: Option<(NpfsCallbackIdentity, u64)>,
    counts: NpfsCallbackCounts,
}

impl NpfsCallbackDiagnostic {
    pub const fn new() -> Self {
        Self { active: None, counts: NpfsCallbackCounts {
            read_calls: 0, read_ticks: 0, read_completion_calls: 0,
            read_completion_ticks: 0, read_pool_retire_calls: 0, read_pool_retire_ticks: 0,
            read_quota_alloc_calls: 0, read_quota_alloc_ticks: 0,
            write_calls: 0, write_ticks: 0, write_completion_calls: 0,
            write_completion_ticks: 0, write_pool_retire_calls: 0,
            write_pool_retire_ticks: 0, write_quota_alloc_calls: 0,
            write_quota_alloc_ticks: 0, owner_mismatches: 0,
        } }
    }

    pub fn enter(&mut self, identity: NpfsCallbackIdentity, now: u64) -> bool {
        if identity.canonical_irp_id == 0 || self.active.is_some() {
            self.counts.owner_mismatches = self.counts.owner_mismatches.saturating_add(1);
            return false;
        }
        self.active = Some((identity, now));
        true
    }

    pub fn nested_completion(&mut self, active: NpfsCallbackIdentity, target_raw_irp: u64,
        ticks: u64) -> bool {
        if target_raw_irp == 0 || !self.active.is_some_and(|(identity, _)| identity == active) {
            self.counts.owner_mismatches = self.counts.owner_mismatches.saturating_add(1);
            return false;
        }
        let (calls, total) = match active.major {
            NpfsMajor::Read => (&mut self.counts.read_completion_calls,
                &mut self.counts.read_completion_ticks),
            NpfsMajor::Write => (&mut self.counts.write_completion_calls,
                &mut self.counts.write_completion_ticks),
        };
        *calls = calls.saturating_add(1);
        *total = total.saturating_add(ticks);
        true
    }

    pub fn nested_pool_retirement(&mut self, active: NpfsCallbackIdentity, allocation: u64,
        ticks: u64) -> bool {
        if allocation == 0 || !self.active.is_some_and(|(identity, _)| identity == active) {
            self.counts.owner_mismatches = self.counts.owner_mismatches.saturating_add(1);
            return false;
        }
        let (calls, total) = match active.major {
            NpfsMajor::Read => (&mut self.counts.read_pool_retire_calls,
                &mut self.counts.read_pool_retire_ticks),
            NpfsMajor::Write => (&mut self.counts.write_pool_retire_calls,
                &mut self.counts.write_pool_retire_ticks),
        };
        *calls = calls.saturating_add(1);
        *total = total.saturating_add(ticks);
        true
    }

    pub fn nested_quota_allocation(&mut self, active: NpfsCallbackIdentity, size: u64,
        ticks: u64) -> bool {
        if size == 0 || !self.active.is_some_and(|(identity, _)| identity == active) {
            self.counts.owner_mismatches = self.counts.owner_mismatches.saturating_add(1);
            return false;
        }
        let (calls, total) = match active.major {
            NpfsMajor::Read => (&mut self.counts.read_quota_alloc_calls,
                &mut self.counts.read_quota_alloc_ticks),
            NpfsMajor::Write => (&mut self.counts.write_quota_alloc_calls,
                &mut self.counts.write_quota_alloc_ticks),
        };
        *calls = calls.saturating_add(1);
        *total = total.saturating_add(ticks);
        true
    }

    pub fn returned(&mut self, identity: NpfsCallbackIdentity, now: u64) -> bool {
        let Some((active, started)) = self.active else {
            self.counts.owner_mismatches = self.counts.owner_mismatches.saturating_add(1);
            return false;
        };
        if active != identity || now < started {
            self.counts.owner_mismatches = self.counts.owner_mismatches.saturating_add(1);
            return false;
        }
        self.active = None;
        let (calls, ticks) = match identity.major {
            NpfsMajor::Read => (&mut self.counts.read_calls, &mut self.counts.read_ticks),
            NpfsMajor::Write => (&mut self.counts.write_calls, &mut self.counts.write_ticks),
        };
        *calls = calls.saturating_add(1);
        *ticks = ticks.saturating_add(now - started);
        true
    }

    pub fn counts(&self) -> NpfsCallbackCounts { self.counts }
}

impl Default for NpfsCallbackDiagnostic {
    fn default() -> Self { Self::new() }
}

impl NpfsDispatchMarks {
    pub fn durations(self) -> Option<NpfsDispatchDurations> {
        if self.entered > self.handler_entered || self.handler_entered > self.handler_returned
            || self.handler_returned > self.terminal { return None; }
        Some(NpfsDispatchDurations {
            pre_handler: self.handler_entered - self.entered,
            handler: self.handler_returned - self.handler_entered,
            post_handler: self.terminal - self.handler_returned,
            total: self.terminal - self.entered,
        })
    }
}

impl NpfsPoolRetireMarks {
    pub fn durations(self) -> Option<NpfsPoolRetireDurations> {
        if self.entered > self.ownership_checked
            || self.ownership_checked > self.retirement_returned { return None; }
        Some(NpfsPoolRetireDurations {
            ownership_check: self.ownership_checked - self.entered,
            retirement_service: self.retirement_returned - self.ownership_checked,
            total: self.retirement_returned - self.entered,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilePhaseCounts {
    pub calls: u64,
    pub capture_ticks: u64,
    pub acquire_ticks: u64,
    pub dispatch_ticks: u64,
    pub tail_ticks: u64,
    pub invalid_phase_order: u64,
    pub pump_calls: u64,
    pub pump_ticks: u64,
    pub handler_calls: u64,
    pub handler_ticks: u64,
    pub npfs_calls: u64,
    pub npfs_pre_ticks: u64,
    pub npfs_handler_ticks: u64,
    pub npfs_post_ticks: u64,
    pub pending_completed: u64,
    pub pending_untracked: u64,
    pub pending_rejected: u64,
    pub pending_ticks: u64,
    pub pending_published: u64,
    pub pending_publication_rejected: u64,
    pub pending_unpublished: u64,
    pub pending_wait_ticks: u64,
    pub pending_delivery_ticks: u64,
    pub pending_overflow: u64,
    pub pending_terminal_recorded: u64,
    pub pending_terminal_rejected: u64,
    pub pending_terminal_success: u64,
    pub pending_terminal_informational: u64,
    pub pending_terminal_warning: u64,
    pub pending_terminal_error: u64,
    pub pending_terminal_copy_eligible_bytes: u64,
    pub pending_terminal_no_copy: u64,
    pub pending_terminal_zero_bytes: u64,
    pub pending_completed_with_terminal: u64,
    pub pending_completed_without_terminal: u64,
}

#[derive(Clone, Copy)]
struct PendingReadMark {
    identity: FilePhaseIdentity,
    started: u64,
    published: Option<u64>,
    terminal: Option<(u32, u64)>,
}

pub struct HostedFilePhaseDiagnostic<const N: usize> {
    pending: [Option<PendingReadMark>; N],
    counts: FilePhaseCounts,
}

impl<const N: usize> HostedFilePhaseDiagnostic<N> {
    pub const fn new() -> Self {
        Self { pending: [None; N], counts: FilePhaseCounts {
            calls: 0, capture_ticks: 0, acquire_ticks: 0, dispatch_ticks: 0,
            tail_ticks: 0, invalid_phase_order: 0, pump_calls: 0, pump_ticks: 0,
            handler_calls: 0, handler_ticks: 0, npfs_calls: 0, npfs_pre_ticks: 0,
            npfs_handler_ticks: 0, npfs_post_ticks: 0, pending_completed: 0,
            pending_untracked: 0, pending_rejected: 0, pending_ticks: 0,
            pending_published: 0, pending_publication_rejected: 0, pending_unpublished: 0,
            pending_wait_ticks: 0, pending_delivery_ticks: 0,
            pending_overflow: 0, pending_terminal_recorded: 0, pending_terminal_rejected: 0,
            pending_terminal_success: 0, pending_terminal_informational: 0,
            pending_terminal_warning: 0, pending_terminal_error: 0,
            pending_terminal_copy_eligible_bytes: 0, pending_terminal_no_copy: 0,
            pending_terminal_zero_bytes: 0,
            pending_completed_with_terminal: 0, pending_completed_without_terminal: 0,
        } }
    }

    pub fn record_call(&mut self, _identity: FilePhaseIdentity, marks: LocalFilePhaseMarks)
        -> Option<LocalFilePhaseDurations> {
        if !(marks.entered <= marks.captured && marks.captured <= marks.acquired
            && marks.acquired <= marks.dispatched && marks.dispatched <= marks.terminal)
        {
            self.counts.invalid_phase_order = self.counts.invalid_phase_order.saturating_add(1);
            return None;
        }
        let durations = LocalFilePhaseDurations {
            capture: marks.captured - marks.entered,
            acquire: marks.acquired - marks.captured,
            dispatch: marks.dispatched - marks.acquired,
            tail: marks.terminal - marks.dispatched,
            total: marks.terminal - marks.entered,
        };
        self.counts.calls = self.counts.calls.saturating_add(1);
        self.counts.capture_ticks = self.counts.capture_ticks.saturating_add(durations.capture);
        self.counts.acquire_ticks = self.counts.acquire_ticks.saturating_add(durations.acquire);
        self.counts.dispatch_ticks = self.counts.dispatch_ticks.saturating_add(durations.dispatch);
        self.counts.tail_ticks = self.counts.tail_ticks.saturating_add(durations.tail);
        Some(durations)
    }

    pub fn record_component_pump(&mut self, ticks: u64) {
        self.counts.pump_calls = self.counts.pump_calls.saturating_add(1);
        self.counts.pump_ticks = self.counts.pump_ticks.saturating_add(ticks);
    }

    pub fn record_npfs_handler(&mut self, ticks: u64) {
        self.counts.handler_calls = self.counts.handler_calls.saturating_add(1);
        self.counts.handler_ticks = self.counts.handler_ticks.saturating_add(ticks);
    }

    pub fn record_npfs_dispatch(&mut self, marks: NpfsDispatchMarks)
        -> Option<NpfsDispatchDurations> {
        let Some(durations) = marks.durations() else {
            self.counts.invalid_phase_order = self.counts.invalid_phase_order.saturating_add(1);
            return None;
        };
        self.counts.npfs_calls = self.counts.npfs_calls.saturating_add(1);
        self.counts.npfs_pre_ticks = self.counts.npfs_pre_ticks.saturating_add(durations.pre_handler);
        self.counts.npfs_handler_ticks = self.counts.npfs_handler_ticks.saturating_add(durations.handler);
        self.counts.npfs_post_ticks = self.counts.npfs_post_ticks.saturating_add(durations.post_handler);
        Some(durations)
    }

    pub fn begin_pending_read(&mut self, identity: FilePhaseIdentity, now: u64) -> bool {
        if identity.irp_id == 0 || self.pending.iter().flatten().any(|mark| mark.identity == identity) {
            self.counts.pending_untracked = self.counts.pending_untracked.saturating_add(1);
            return false;
        }
        let Some(slot) = self.pending.iter_mut().find(|slot| slot.is_none()) else {
            self.counts.pending_untracked = self.counts.pending_untracked.saturating_add(1);
            self.counts.pending_overflow = self.counts.pending_overflow.saturating_add(1);
            return false;
        };
        *slot = Some(PendingReadMark { identity, started: now, published: None, terminal: None });
        true
    }

    pub fn pending_is_tracked(&self, identity: FilePhaseIdentity) -> bool {
        self.pending.iter().flatten().any(|mark| mark.identity == identity)
    }

    pub fn pending_publication_recorded(&self, identity: FilePhaseIdentity) -> bool {
        self.pending.iter().flatten().any(|mark| mark.identity == identity && mark.published.is_some())
    }

    pub fn mark_pending_publication(&mut self, identity: FilePhaseIdentity, now: u64) -> bool {
        let Some(mark) = self.pending.iter_mut().flatten().find(|mark| mark.identity == identity) else {
            self.counts.pending_publication_rejected = self.counts.pending_publication_rejected.saturating_add(1);
            return false;
        };
        if mark.published.is_some() || now < mark.started {
            self.counts.pending_publication_rejected = self.counts.pending_publication_rejected.saturating_add(1);
            return false;
        }
        mark.published = Some(now);
        self.counts.pending_published = self.counts.pending_published.saturating_add(1);
        true
    }

    pub fn pending_terminal_recorded(&self, identity: FilePhaseIdentity) -> bool {
        self.pending.iter().flatten().any(|mark| mark.identity == identity && mark.terminal.is_some())
    }

    pub fn record_pending_terminal(&mut self, identity: FilePhaseIdentity, now: u64,
        status: u32, information: u64) -> bool {
        let Some(mark) = self.pending.iter_mut().flatten().find(|mark| mark.identity == identity) else {
            self.counts.pending_terminal_rejected = self.counts.pending_terminal_rejected.saturating_add(1);
            return false;
        };
        if mark.terminal.is_some() || now < mark.started
            || mark.published.is_some_and(|published| now < published) {
            self.counts.pending_terminal_rejected = self.counts.pending_terminal_rejected.saturating_add(1);
            return false;
        }
        mark.terminal = Some((status, information));
        self.counts.pending_terminal_recorded = self.counts.pending_terminal_recorded.saturating_add(1);
        true
    }

    pub fn complete_pending_read(&mut self, identity: FilePhaseIdentity, now: u64) -> Option<u64> {
        let Some(slot) = self.pending.iter_mut().find(|slot| slot.is_some_and(|mark| mark.identity == identity)) else {
            self.counts.pending_rejected = self.counts.pending_rejected.saturating_add(1);
            return None;
        };
        let mark = slot.as_ref()?;
        let ticks = now.checked_sub(mark.started)?;
        if let Some(published) = mark.published { now.checked_sub(published)?; }
        let mark = slot.take()?;
        self.counts.pending_completed = self.counts.pending_completed.saturating_add(1);
        self.counts.pending_ticks = self.counts.pending_ticks.saturating_add(ticks);
        if let Some(published) = mark.published {
            self.counts.pending_wait_ticks = self.counts.pending_wait_ticks.saturating_add(published - mark.started);
            self.counts.pending_delivery_ticks = self.counts.pending_delivery_ticks.saturating_add(now - published);
        } else {
            self.counts.pending_unpublished = self.counts.pending_unpublished.saturating_add(1);
        }
        if let Some((status, information)) = mark.terminal {
            self.counts.pending_completed_with_terminal = self.counts.pending_completed_with_terminal.saturating_add(1);
            match status >> 30 {
                0 => self.counts.pending_terminal_success = self.counts.pending_terminal_success.saturating_add(1),
                1 => self.counts.pending_terminal_informational = self.counts.pending_terminal_informational.saturating_add(1),
                2 => self.counts.pending_terminal_warning = self.counts.pending_terminal_warning.saturating_add(1),
                _ => self.counts.pending_terminal_error = self.counts.pending_terminal_error.saturating_add(1),
            }
            if nt_io_completion::file_io_status_copies_output(status) {
                self.counts.pending_terminal_copy_eligible_bytes = self.counts.pending_terminal_copy_eligible_bytes.saturating_add(information);
                if information == 0 {
                    self.counts.pending_terminal_zero_bytes = self.counts.pending_terminal_zero_bytes.saturating_add(1);
                }
            } else {
                self.counts.pending_terminal_no_copy = self.counts.pending_terminal_no_copy.saturating_add(1);
            }
        } else {
            self.counts.pending_completed_without_terminal = self.counts.pending_completed_without_terminal.saturating_add(1);
        }
        Some(ticks)
    }

    pub fn counts(&self) -> FilePhaseCounts { self.counts }
}

impl<const N: usize> Default for HostedFilePhaseDiagnostic<N> {
    fn default() -> Self { Self::new() }
}
