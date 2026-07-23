//! Pure state models for ReactOS RTL timer queues and registered waits.
//!
//! Adapters serialize access to these models and perform the returned wake, signal, wait, close,
//! and reclaim actions only after releasing their model lock. User callbacks must likewise run
//! without that lock so callback re-entry can update or delete timers safely.

#![no_std]

use nt_rtl_work_item::WorkItemFlags;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// How a delete caller wants completion reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionMode {
    /// A null completion event. ReactOS returns `STATUS_PENDING`, even when already idle.
    Async,
    /// Signal the caller's event when destruction finishes.
    Event(u64),
    /// The adapter owns this internal event and waits when `wait_event` is returned.
    Synchronous(u64),
}

impl CompletionMode {
    const fn event(self) -> Option<u64> {
        match self {
            Self::Async => None,
            Self::Event(event) | Self::Synchronous(event) => Some(event),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompletionPlan {
    pub signal_event: Option<u64>,
    pub close_handle: Option<u64>,
    pub wake_scheduler: bool,
    pub reclaim: bool,
    pub queue_exited: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletePlan {
    pub status: u32,
    pub signal_event: Option<u64>,
    pub wait_event: Option<u64>,
    pub wake_scheduler: bool,
    pub reclaim: bool,
}

impl DeletePlan {
    const fn timer(mode: CompletionMode, idle: bool, wake_scheduler: bool) -> Self {
        let status = match mode {
            CompletionMode::Async => STATUS_PENDING,
            CompletionMode::Event(_) if idle => STATUS_SUCCESS,
            CompletionMode::Event(_) => STATUS_PENDING,
            CompletionMode::Synchronous(_) => STATUS_SUCCESS,
        };
        Self {
            status,
            signal_event: if idle { mode.event() } else { None },
            wait_event: match mode {
                CompletionMode::Synchronous(event) if !idle => Some(event),
                _ => None,
            },
            wake_scheduler,
            reclaim: idle,
        }
    }

    const fn queue(mode: CompletionMode) -> Self {
        Self {
            status: match mode {
                CompletionMode::Synchronous(_) => STATUS_SUCCESS,
                CompletionMode::Async | CompletionMode::Event(_) => STATUS_PENDING,
            },
            signal_event: None,
            wait_event: match mode {
                CompletionMode::Synchronous(event) => Some(event),
                CompletionMode::Async | CompletionMode::Event(_) => None,
            },
            wake_scheduler: true,
            reclaim: false,
        }
    }
}

pub mod timer {
    use super::*;

    const MAX_TIMER_CALLBACKS: usize = 8;
    const TIMER_WORK_FLAGS: u32 = WorkItemFlags::EXECUTE_IN_IO_THREAD.bits()
        | WorkItemFlags::EXECUTE_LONG_FUNCTION.bits()
        | WorkItemFlags::EXECUTE_IN_PERSISTENT_THREAD.bits()
        | WorkItemFlags::TRANSFER_IMPERSONATION.bits();

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct TimerKey {
        index: u16,
        generation: u32,
    }

    impl TimerKey {
        pub const fn from_parts(index: u16, generation: u32) -> Option<Self> {
            if generation == 0 {
                None
            } else {
                Some(Self { index, generation })
            }
        }

        pub const fn index(self) -> usize {
            self.index as usize
        }

        pub const fn generation(self) -> u32 {
            self.generation
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct TimerSpec {
        pub callback: u64,
        pub context: u64,
        pub due_ms: u32,
        pub period_ms: u32,
        pub flags: WorkItemFlags,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum QueuePhase {
        Running,
        Deleting,
        AwaitingWorkerExit,
        Exited,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TimerPhase {
        Free,
        Armed,
        Dormant,
        Destroying,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TimerSlot {
        generation: u32,
        phase: TimerPhase,
        callback: u64,
        context: u64,
        deadline_ms: u64,
        sequence: u64,
        period_ms: u32,
        flags: WorkItemFlags,
        callbacks_in_flight: u32,
        active_callbacks: [u64; MAX_TIMER_CALLBACKS],
        completion_event: u64,
    }

    impl TimerSlot {
        const EMPTY: Self = Self {
            generation: 0,
            phase: TimerPhase::Free,
            callback: 0,
            context: 0,
            deadline_ms: 0,
            sequence: 0,
            period_ms: 0,
            flags: WorkItemFlags::EXECUTE_DEFAULT,
            callbacks_in_flight: 0,
            active_callbacks: [0; MAX_TIMER_CALLBACKS],
            completion_event: 0,
        };
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct WakeScheduler(pub bool);

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CallbackTicket {
        key: TimerKey,
        firing_id: u64,
    }

    impl CallbackTicket {
        pub const fn key(&self) -> TimerKey {
            self.key
        }

        pub const fn firing_id(&self) -> u64 {
            self.firing_id
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum DispatchKind {
        Inline,
        QueueWork(WorkItemFlags),
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Dispatch {
        pub callback: u64,
        pub context: u64,
        pub timer_fired: bool,
        pub kind: DispatchKind,
        pub ticket: CallbackTicket,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ExpireResult {
        Idle,
        NotDue,
        CallbackCapacity,
        InlineBusy,
        Dispatch(Dispatch),
    }

    pub struct TimerQueue<const N: usize> {
        slots: [TimerSlot; N],
        phase: QueuePhase,
        next_sequence: u64,
        next_callback_id: u64,
        inline_callback_id: u64,
        queue_completion_event: u64,
    }

    impl<const N: usize> Default for TimerQueue<N> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<const N: usize> TimerQueue<N> {
        pub const fn new() -> Self {
            Self {
                slots: [TimerSlot::EMPTY; N],
                phase: QueuePhase::Running,
                next_sequence: 0,
                next_callback_id: 1,
                inline_callback_id: 0,
                queue_completion_event: 0,
            }
        }

        pub const fn phase(&self) -> QueuePhase {
            self.phase
        }

        pub fn len(&self) -> usize {
            self.slots
                .iter()
                .filter(|slot| slot.phase != TimerPhase::Free)
                .count()
        }

        pub fn callbacks_in_flight(&self, key: TimerKey) -> Option<u32> {
            self.slot(key).map(|slot| slot.callbacks_in_flight)
        }

        pub fn total_callbacks_in_flight(&self) -> u32 {
            self.slots.iter().map(|slot| slot.callbacks_in_flight).sum()
        }

        pub fn create_timer(
            &mut self,
            now_ms: u64,
            spec: TimerSpec,
        ) -> Result<(TimerKey, WakeScheduler), u32> {
            if self.phase != QueuePhase::Running {
                return Err(STATUS_INVALID_HANDLE);
            }
            if spec.callback == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let old_head = self.head_identity();
            let index = self
                .slots
                .iter()
                .position(|slot| slot.phase == TimerPhase::Free)
                .ok_or(STATUS_NO_MEMORY)?;
            let index = u16::try_from(index).map_err(|_| STATUS_NO_MEMORY)?;
            let generation = self.slots[index as usize].generation.wrapping_add(1).max(1);
            let sequence = self.take_sequence();
            self.slots[index as usize] = TimerSlot {
                generation,
                phase: TimerPhase::Armed,
                callback: spec.callback,
                context: spec.context,
                deadline_ms: now_ms.saturating_add(spec.due_ms as u64),
                sequence,
                period_ms: spec.period_ms,
                flags: spec.flags,
                callbacks_in_flight: 0,
                active_callbacks: [0; MAX_TIMER_CALLBACKS],
                completion_event: 0,
            };
            let key = TimerKey { index, generation };
            Ok((key, WakeScheduler(self.head_identity() != old_head)))
        }

        pub fn update_timer(
            &mut self,
            key: TimerKey,
            now_ms: u64,
            due_ms: u32,
            period_ms: u32,
        ) -> Result<WakeScheduler, u32> {
            let phase = self.slot(key).ok_or(STATUS_INVALID_HANDLE)?.phase;
            if matches!(phase, TimerPhase::Dormant | TimerPhase::Destroying) {
                return Ok(WakeScheduler(false));
            }
            let old_head = self.head_identity();
            let sequence = self.take_sequence();
            let slot = self.slot_mut(key).expect("validated timer key");
            slot.phase = TimerPhase::Armed;
            slot.deadline_ms = now_ms.saturating_add(due_ms as u64);
            slot.period_ms = period_ms;
            slot.sequence = sequence;
            Ok(WakeScheduler(self.head_identity() != old_head))
        }

        pub fn next_timeout(&self, now_ms: u64) -> Option<u32> {
            let (_, deadline, _) = self.head_identity()?;
            Some(deadline.saturating_sub(now_ms).min(u32::MAX as u64) as u32)
        }

        /// Timeout for the next timer that currently has callback capacity. A scheduler uses this
        /// after [`ExpireResult::CallbackCapacity`] while also waiting on its wake event, so another
        /// timer can still expire before an outstanding callback returns.
        pub fn next_dispatch_timeout(&self, now_ms: u64) -> Option<u32> {
            if self.inline_callback_id != 0 {
                return None;
            }
            self.dispatchable_head_identity()
                .map(|(_, deadline, _)| deadline.saturating_sub(now_ms).min(u32::MAX as u64) as u32)
        }

        pub fn expire_one(&mut self, now_ms: u64) -> ExpireResult {
            if self.inline_callback_id != 0 {
                return ExpireResult::InlineBusy;
            }
            let Some((_, first_deadline, _)) = self.head_identity() else {
                return ExpireResult::Idle;
            };
            let Some((index, deadline, _)) = self.dispatchable_head_identity() else {
                return if first_deadline <= now_ms {
                    ExpireResult::CallbackCapacity
                } else {
                    ExpireResult::NotDue
                };
            };
            if deadline > now_ms {
                if first_deadline <= now_ms {
                    return ExpireResult::CallbackCapacity;
                }
                return ExpireResult::NotDue;
            }
            let callback_index = self.slots[index]
                .active_callbacks
                .iter()
                .position(|id| *id == 0)
                .expect("dispatchable timer has callback capacity");
            let firing_id = self.take_callback_id();
            let sequence = self.take_sequence();
            let (callback, context, generation, kind) = {
                let slot = &mut self.slots[index];
                slot.active_callbacks[callback_index] = firing_id;
                slot.callbacks_in_flight = slot.callbacks_in_flight.saturating_add(1);
                if slot.period_ms == 0 {
                    slot.phase = TimerPhase::Dormant;
                } else {
                    let cadence = deadline.saturating_add(slot.period_ms as u64);
                    slot.deadline_ms = if cadence < now_ms {
                        now_ms.saturating_add(slot.period_ms as u64)
                    } else {
                        cadence
                    };
                    slot.sequence = sequence;
                }
                let flags = WorkItemFlags::from_bits_retain(slot.flags.bits() & TIMER_WORK_FLAGS);
                let kind = if slot.flags.contains(WorkItemFlags::EXECUTE_IN_TIMER_THREAD) {
                    DispatchKind::Inline
                } else {
                    DispatchKind::QueueWork(flags)
                };
                (slot.callback, slot.context, slot.generation, kind)
            };
            if kind == DispatchKind::Inline {
                self.inline_callback_id = firing_id;
            }
            ExpireResult::Dispatch(Dispatch {
                callback,
                context,
                timer_fired: true,
                kind,
                ticket: CallbackTicket {
                    key: TimerKey {
                        index: index as u16,
                        generation,
                    },
                    firing_id,
                },
            })
        }

        pub fn dispatch_failed(&mut self, ticket: CallbackTicket) -> Result<CompletionPlan, u32> {
            self.callback_finished(ticket)
        }

        pub fn callback_finished(&mut self, ticket: CallbackTicket) -> Result<CompletionPlan, u32> {
            let slot = self.slot(ticket.key).ok_or(STATUS_INVALID_HANDLE)?;
            let callback_index = slot
                .active_callbacks
                .iter()
                .position(|id| *id == ticket.firing_id)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            if ticket.firing_id == 0 || slot.callbacks_in_flight == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let capacity_was_full = !slot.active_callbacks.contains(&0);
            let inline_finished = self.inline_callback_id == ticket.firing_id;
            if inline_finished {
                self.inline_callback_id = 0;
            }
            let slot = self
                .slot_mut(ticket.key)
                .expect("validated callback ticket");
            slot.active_callbacks[callback_index] = 0;
            slot.callbacks_in_flight -= 1;
            let mut plan = CompletionPlan::default();
            if capacity_was_full || inline_finished {
                plan.wake_scheduler = true;
            }
            if slot.phase == TimerPhase::Destroying && slot.callbacks_in_flight == 0 {
                plan.signal_event = (slot.completion_event != 0).then_some(slot.completion_event);
                plan.reclaim = true;
                slot.phase = TimerPhase::Free;
                slot.completion_event = 0;
            }
            self.finish_queue_drain(&mut plan);
            Ok(plan)
        }

        pub fn delete_timer(
            &mut self,
            key: TimerKey,
            mode: CompletionMode,
        ) -> Result<DeletePlan, u32> {
            let old_head = self.head_identity();
            let slot = self.slot_mut(key).ok_or(STATUS_INVALID_HANDLE)?;
            if slot.phase == TimerPhase::Destroying {
                return Err(STATUS_INVALID_HANDLE);
            }
            slot.phase = TimerPhase::Destroying;
            slot.completion_event = mode.event().unwrap_or(0);
            let idle = slot.callbacks_in_flight == 0;
            if idle {
                slot.phase = TimerPhase::Free;
                slot.completion_event = 0;
            }
            let wake_scheduler = self.head_identity() != old_head;
            Ok(DeletePlan::timer(mode, idle, wake_scheduler))
        }

        pub fn delete_queue(&mut self, mode: CompletionMode) -> Result<DeletePlan, u32> {
            if self.phase != QueuePhase::Running {
                return Err(STATUS_INVALID_HANDLE);
            }
            self.phase = QueuePhase::Deleting;
            self.queue_completion_event = mode.event().unwrap_or(0);
            for slot in &mut self.slots {
                if slot.phase == TimerPhase::Free {
                    continue;
                }
                if slot.callbacks_in_flight == 0 {
                    slot.phase = TimerPhase::Free;
                } else {
                    slot.phase = TimerPhase::Destroying;
                }
            }
            let idle = self.slots.iter().all(|slot| slot.phase == TimerPhase::Free);
            if idle {
                self.phase = QueuePhase::AwaitingWorkerExit;
            }
            Ok(DeletePlan::queue(mode))
        }

        pub fn worker_exited(&mut self) -> Result<CompletionPlan, u32> {
            if self.phase != QueuePhase::AwaitingWorkerExit {
                return Err(STATUS_INVALID_PARAMETER);
            }
            self.phase = QueuePhase::Exited;
            let signal_event =
                (self.queue_completion_event != 0).then_some(self.queue_completion_event);
            self.queue_completion_event = 0;
            Ok(CompletionPlan {
                signal_event,
                reclaim: true,
                queue_exited: true,
                ..CompletionPlan::default()
            })
        }

        fn slot(&self, key: TimerKey) -> Option<&TimerSlot> {
            let slot = self.slots.get(key.index())?;
            (slot.phase != TimerPhase::Free && slot.generation == key.generation).then_some(slot)
        }

        fn slot_mut(&mut self, key: TimerKey) -> Option<&mut TimerSlot> {
            let slot = self.slots.get_mut(key.index())?;
            (slot.phase != TimerPhase::Free && slot.generation == key.generation).then_some(slot)
        }

        fn head_identity(&self) -> Option<(usize, u64, u64)> {
            self.slots
                .iter()
                .enumerate()
                .filter(|(_, slot)| slot.phase == TimerPhase::Armed)
                .map(|(index, slot)| (index, slot.deadline_ms, slot.sequence))
                .min_by_key(|(_, deadline, sequence)| (*deadline, *sequence))
        }

        fn dispatchable_head_identity(&self) -> Option<(usize, u64, u64)> {
            self.slots
                .iter()
                .enumerate()
                .filter(|(_, slot)| {
                    slot.phase == TimerPhase::Armed && slot.active_callbacks.contains(&0)
                })
                .map(|(index, slot)| (index, slot.deadline_ms, slot.sequence))
                .min_by_key(|(_, deadline, sequence)| (*deadline, *sequence))
        }

        fn take_sequence(&mut self) -> u64 {
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.wrapping_add(1);
            sequence
        }

        fn take_callback_id(&mut self) -> u64 {
            loop {
                let id = self.next_callback_id.max(1);
                self.next_callback_id = id.wrapping_add(1).max(1);
                if !self
                    .slots
                    .iter()
                    .any(|slot| slot.active_callbacks.contains(&id))
                {
                    return id;
                }
            }
        }

        fn finish_queue_drain(&mut self, plan: &mut CompletionPlan) {
            if self.phase == QueuePhase::Deleting
                && self.slots.iter().all(|slot| slot.phase == TimerPhase::Free)
            {
                self.phase = QueuePhase::AwaitingWorkerExit;
                plan.wake_scheduler = true;
            }
        }
    }
}

pub mod registered_wait {
    use super::*;

    pub const STATUS_WAIT_0: u32 = 0;
    pub const STATUS_USER_APC: u32 = 0x0000_00C0;
    pub const STATUS_TIMEOUT: u32 = 0x0000_0102;

    const WAIT_WORK_FLAGS: u32 = WorkItemFlags::EXECUTE_IN_IO_THREAD.bits()
        | WorkItemFlags::EXECUTE_LONG_FUNCTION.bits()
        | WorkItemFlags::EXECUTE_IN_PERSISTENT_THREAD.bits()
        | WorkItemFlags::TRANSFER_IMPERSONATION.bits();

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum WaitState {
        Starting,
        Waiting,
        Callback,
        Exiting,
        WorkerExited,
        Reclaimable,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct WaitRequest {
        pub cancel_event: u64,
        pub object: u64,
        pub alertable: bool,
        pub timeout_ms: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum WaitOutcome {
        Cancel,
        Object,
        Timeout,
        UserApc,
        Failed(u32),
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct WaitSetEntry {
        pub token: u64,
        pub object: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum WaitSetOutcome {
        Wake,
        Cancel(u64),
        Object(u64),
        Timeout,
        UserApc,
        Failed(u32),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum WaitSetError {
        Capacity,
        OutputTooSmall,
    }

    /// Stable WaitAny layout for one scheduler wake event followed by registered objects.
    pub struct WaitSet<const N: usize> {
        entries: [WaitSetEntry; N],
        len: usize,
    }

    impl<const N: usize> WaitSet<N> {
        pub const fn new() -> Self {
            Self {
                entries: [WaitSetEntry {
                    token: 0,
                    object: 0,
                }; N],
                len: 0,
            }
        }

        pub const fn len(&self) -> usize {
            self.len
        }

        pub const fn handle_count(&self) -> usize {
            1 + self.len
        }

        pub fn push(&mut self, entry: WaitSetEntry) -> Result<(), WaitSetError> {
            if self.len == N {
                return Err(WaitSetError::Capacity);
            }
            self.entries[self.len] = entry;
            self.len += 1;
            Ok(())
        }

        pub fn write_handles(
            &self,
            wake_event: u64,
            output: &mut [u64],
        ) -> Result<usize, WaitSetError> {
            let count = self.handle_count();
            if output.len() < count {
                return Err(WaitSetError::OutputTooSmall);
            }
            output[0] = wake_event;
            for (index, entry) in self.entries[..self.len].iter().enumerate() {
                output[1 + index] = entry.object;
            }
            Ok(count)
        }

        pub const fn decode_status(&self, status: u32) -> WaitSetOutcome {
            if status == STATUS_TIMEOUT {
                return WaitSetOutcome::Timeout;
            }
            if status == STATUS_USER_APC {
                return WaitSetOutcome::UserApc;
            }
            let index = status.wrapping_sub(STATUS_WAIT_0) as usize;
            if index == 0 {
                return WaitSetOutcome::Wake;
            }
            let entry_index = index - 1;
            if entry_index < self.len {
                WaitSetOutcome::Object(self.entries[entry_index].token)
            } else {
                WaitSetOutcome::Failed(status)
            }
        }
    }

    impl<const N: usize> Default for WaitSet<N> {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct WaitDeadline {
        timeout_ms: u32,
        deadline_ms: u64,
    }

    impl WaitDeadline {
        pub const fn new(now_ms: u64, timeout_ms: u32) -> Self {
            Self {
                timeout_ms,
                deadline_ms: now_ms.saturating_add(timeout_ms as u64),
            }
        }

        pub const fn remaining(self, now_ms: u64) -> Option<u32> {
            if self.timeout_ms == u32::MAX {
                None
            } else {
                let remaining = self.deadline_ms.saturating_sub(now_ms);
                Some(if remaining > u32::MAX as u64 {
                    u32::MAX
                } else {
                    remaining as u32
                })
            }
        }

        pub fn rearm(&mut self, now_ms: u64) {
            self.deadline_ms = now_ms.saturating_add(self.timeout_ms as u64);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum WaitAction {
        Retry,
        Invoke {
            callback: u64,
            context: u64,
            timed_out: bool,
        },
        ExitWorker,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct DeregisterPlan {
        pub status: u32,
        pub set_cancel_event: Option<u64>,
        pub signal_event: Option<u64>,
        pub close_handle: Option<u64>,
        pub wait_event: Option<u64>,
        pub reclaim: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct StartFailurePlan {
        pub close_cancel_event: u64,
        pub reclaim: bool,
    }

    pub struct RegisteredWait {
        object: u64,
        cancel_event: u64,
        callback: u64,
        context: u64,
        timeout_ms: u32,
        flags: WorkItemFlags,
        state: WaitState,
        deregistered: bool,
        worker_exited: bool,
        completion_event: u64,
    }

    impl RegisteredWait {
        pub fn new(
            object: u64,
            cancel_event: u64,
            callback: u64,
            context: u64,
            timeout_ms: u32,
            flags: WorkItemFlags,
        ) -> Result<Self, u32> {
            if object == 0 || cancel_event == 0 || callback == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            Ok(Self {
                object,
                cancel_event,
                callback,
                context,
                timeout_ms,
                flags,
                state: WaitState::Starting,
                deregistered: false,
                worker_exited: false,
                completion_event: 0,
            })
        }

        pub const fn state(&self) -> WaitState {
            self.state
        }

        pub const fn queue_flags(&self) -> WorkItemFlags {
            WorkItemFlags::from_bits_retain(self.flags.bits() & WAIT_WORK_FLAGS)
        }

        pub fn worker_started(&mut self) -> Result<(), u32> {
            if self.state != WaitState::Starting {
                return Err(STATUS_INVALID_PARAMETER);
            }
            self.state = WaitState::Waiting;
            Ok(())
        }

        pub const fn wait_request(&self) -> Option<WaitRequest> {
            if !matches!(self.state, WaitState::Waiting) {
                return None;
            }
            Some(WaitRequest {
                cancel_event: self.cancel_event,
                object: self.object,
                alertable: self.flags.contains(WorkItemFlags::EXECUTE_IN_IO_THREAD),
                timeout_ms: self.timeout_ms,
            })
        }

        pub fn observe_wait(&mut self, outcome: WaitOutcome) -> Result<WaitAction, u32> {
            if self.state != WaitState::Waiting {
                return Err(STATUS_INVALID_PARAMETER);
            }
            match outcome {
                WaitOutcome::UserApc => Ok(WaitAction::Retry),
                WaitOutcome::Cancel | WaitOutcome::Failed(_) => {
                    self.state = WaitState::Exiting;
                    Ok(WaitAction::ExitWorker)
                }
                WaitOutcome::Object | WaitOutcome::Timeout => {
                    self.state = WaitState::Callback;
                    Ok(WaitAction::Invoke {
                        callback: self.callback,
                        context: self.context,
                        timed_out: matches!(outcome, WaitOutcome::Timeout),
                    })
                }
            }
        }

        pub fn callback_finished(&mut self) -> Result<WaitAction, u32> {
            if self.state != WaitState::Callback {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if self.deregistered || self.flags.contains(WorkItemFlags::EXECUTE_ONLY_ONCE) {
                self.state = WaitState::Exiting;
                Ok(WaitAction::ExitWorker)
            } else {
                self.state = WaitState::Waiting;
                Ok(WaitAction::Retry)
            }
        }

        pub fn deregister(&mut self, mode: CompletionMode) -> Result<DeregisterPlan, u32> {
            if self.deregistered || self.state == WaitState::Reclaimable {
                return Err(STATUS_INVALID_HANDLE);
            }
            let callback_in_progress = self.state == WaitState::Callback;
            self.deregistered = true;
            self.completion_event = mode.event().unwrap_or(0);
            if self.worker_exited {
                self.state = WaitState::Reclaimable;
            }
            let status = if callback_in_progress && !matches!(mode, CompletionMode::Synchronous(_))
            {
                STATUS_PENDING
            } else {
                STATUS_SUCCESS
            };
            Ok(DeregisterPlan {
                status,
                set_cancel_event: (!self.worker_exited).then_some(self.cancel_event),
                signal_event: self
                    .worker_exited
                    .then_some(self.completion_event)
                    .filter(|e| *e != 0),
                close_handle: self.worker_exited.then_some(self.cancel_event),
                wait_event: match mode {
                    CompletionMode::Synchronous(event) if !self.worker_exited => Some(event),
                    CompletionMode::Async
                    | CompletionMode::Event(_)
                    | CompletionMode::Synchronous(_) => None,
                },
                reclaim: self.worker_exited,
            })
        }

        pub fn worker_exited(&mut self) -> Result<CompletionPlan, u32> {
            if self.worker_exited {
                return Err(STATUS_INVALID_PARAMETER);
            }
            self.worker_exited = true;
            self.state = WaitState::WorkerExited;
            if !self.deregistered {
                return Ok(CompletionPlan::default());
            }
            self.state = WaitState::Reclaimable;
            Ok(CompletionPlan {
                signal_event: (self.completion_event != 0).then_some(self.completion_event),
                close_handle: Some(self.cancel_event),
                reclaim: true,
                queue_exited: false,
                ..CompletionPlan::default()
            })
        }

        pub fn start_failed(mut self) -> StartFailurePlan {
            self.state = WaitState::Reclaimable;
            StartFailurePlan {
                close_cancel_event: self.cancel_event,
                reclaim: true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{registered_wait::*, timer::*, *};

    fn spec(due_ms: u32, period_ms: u32, flags: WorkItemFlags) -> TimerSpec {
        TimerSpec {
            callback: 0x1000,
            context: 0x2000,
            due_ms,
            period_ms,
            flags,
        }
    }

    fn expire<const N: usize>(queue: &mut TimerQueue<N>, now_ms: u64) -> Dispatch {
        match queue.expire_one(now_ms) {
            ExpireResult::Dispatch(dispatch) => dispatch,
            other => panic!("expected dispatch, got {other:?}"),
        }
    }

    #[test]
    fn timers_are_stable_at_equal_deadlines_and_wake_for_new_head() {
        let mut queue = TimerQueue::<3>::new();
        let (first, wake) = queue
            .create_timer(100, spec(20, 0, WorkItemFlags::default()))
            .unwrap();
        assert_eq!(wake, WakeScheduler(true));
        let (second, wake) = queue
            .create_timer(100, spec(20, 0, WorkItemFlags::default()))
            .unwrap();
        assert_eq!(wake, WakeScheduler(false));
        assert_eq!(queue.next_timeout(119), Some(1));
        assert_eq!(expire(&mut queue, 120).ticket.key(), first);
        assert_eq!(expire(&mut queue, 120).ticket.key(), second);
    }

    #[test]
    fn periodic_timer_preserves_cadence_and_clamps_missed_periods() {
        let mut queue = TimerQueue::<1>::new();
        let (key, _) = queue
            .create_timer(100, spec(10, 20, WorkItemFlags::default()))
            .unwrap();
        let first = expire(&mut queue, 110);
        assert_eq!(queue.next_timeout(110), Some(20));
        queue.callback_finished(first.ticket).unwrap();
        let on_cadence = expire(&mut queue, 130);
        assert_eq!(queue.next_timeout(130), Some(20));
        queue.callback_finished(on_cadence.ticket).unwrap();
        let second = expire(&mut queue, 150);
        assert_eq!(second.ticket.key(), key);
        assert_eq!(queue.next_timeout(150), Some(20));
    }

    #[test]
    fn timer_dispatch_masks_flags_and_inline_mode_wins() {
        let mut queue = TimerQueue::<2>::new();
        let flags = WorkItemFlags::EXECUTE_IN_TIMER_THREAD
            .with(WorkItemFlags::EXECUTE_LONG_FUNCTION)
            .with(WorkItemFlags::EXECUTE_ONLY_ONCE);
        queue.create_timer(0, spec(0, 0, flags)).unwrap();
        let inline = expire(&mut queue, 0);
        assert_eq!(inline.kind, DispatchKind::Inline);
        assert_eq!(queue.expire_one(0), ExpireResult::InlineBusy);
        queue.callback_finished(inline.ticket).unwrap();

        let flags = WorkItemFlags::EXECUTE_IN_IO_THREAD
            .with(WorkItemFlags::TRANSFER_IMPERSONATION)
            .with(WorkItemFlags::EXECUTE_ONLY_ONCE);
        queue.create_timer(0, spec(0, 0, flags)).unwrap();
        assert_eq!(
            expire(&mut queue, 0).kind,
            DispatchKind::QueueWork(
                WorkItemFlags::EXECUTE_IN_IO_THREAD.with(WorkItemFlags::TRANSFER_IMPERSONATION)
            )
        );
    }

    #[test]
    fn one_shot_remains_dormant_until_deleted() {
        let mut queue = TimerQueue::<1>::new();
        let (key, _) = queue
            .create_timer(0, spec(0, 0, WorkItemFlags::default()))
            .unwrap();
        let dispatch = expire(&mut queue, 0);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.next_timeout(0), None);
        queue.callback_finished(dispatch.ticket).unwrap();
        assert_eq!(
            queue
                .delete_timer(key, CompletionMode::Async)
                .unwrap()
                .status,
            STATUS_PENDING
        );
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn timer_delete_waits_for_callback_and_signals_once() {
        let mut queue = TimerQueue::<1>::new();
        let (key, _) = queue
            .create_timer(0, spec(0, 0, WorkItemFlags::default()))
            .unwrap();
        let dispatch = expire(&mut queue, 0);
        let duplicate = dispatch.ticket.clone();
        let delete = queue
            .delete_timer(key, CompletionMode::Event(0x44))
            .unwrap();
        assert_eq!(delete.status, STATUS_PENDING);
        assert!(!delete.reclaim);
        let completion = queue.callback_finished(dispatch.ticket).unwrap();
        assert_eq!(completion.signal_event, Some(0x44));
        assert!(completion.reclaim);
        assert_eq!(
            queue.callback_finished(duplicate),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn overlapping_timer_callbacks_have_distinct_completion_tickets() {
        let mut queue = TimerQueue::<1>::new();
        let (key, _) = queue
            .create_timer(0, spec(0, 1, WorkItemFlags::default()))
            .unwrap();
        let first = expire(&mut queue, 0);
        let duplicate = first.ticket.clone();
        let second = expire(&mut queue, 1);
        assert_ne!(first.ticket.firing_id(), second.ticket.firing_id());
        assert_eq!(queue.callbacks_in_flight(key), Some(2));
        assert_eq!(queue.total_callbacks_in_flight(), 2);
        queue.callback_finished(first.ticket).unwrap();
        assert_eq!(queue.callbacks_in_flight(key), Some(1));
        assert_eq!(
            queue.callback_finished(duplicate),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(queue.callbacks_in_flight(key), Some(1));
        queue.dispatch_failed(second.ticket).unwrap();
        assert_eq!(queue.callbacks_in_flight(key), Some(0));
    }

    #[test]
    fn callback_capacity_backpressures_and_wakes_scheduler() {
        let mut queue = TimerQueue::<2>::new();
        let (primary, _) = queue
            .create_timer(0, spec(0, 1, WorkItemFlags::default()))
            .unwrap();
        let (secondary, _) = queue
            .create_timer(0, spec(20, 0, WorkItemFlags::default()))
            .unwrap();
        let mut tickets: [Option<CallbackTicket>; 8] = core::array::from_fn(|_| None);
        for (now, ticket) in tickets.iter_mut().enumerate() {
            let dispatch = expire(&mut queue, now as u64);
            assert!(dispatch.timer_fired);
            *ticket = Some(dispatch.ticket);
        }
        assert_eq!(queue.expire_one(8), ExpireResult::CallbackCapacity);
        assert_eq!(queue.next_dispatch_timeout(8), Some(12));
        let completion = queue.callback_finished(tickets[0].take().unwrap()).unwrap();
        assert!(completion.wake_scheduler);
        let resumed = expire(&mut queue, 8);
        assert_eq!(resumed.ticket.key(), primary);
        assert!(resumed.timer_fired);
        let other = expire(&mut queue, 20);
        assert_eq!(other.ticket.key(), secondary);
    }

    #[test]
    fn queue_delete_waits_for_callbacks_and_worker_exit() {
        let mut queue = TimerQueue::<2>::new();
        queue
            .create_timer(0, spec(100, 0, WorkItemFlags::default()))
            .unwrap();
        queue
            .create_timer(0, spec(0, 0, WorkItemFlags::default()))
            .unwrap();
        let dispatch = expire(&mut queue, 0);
        let delete = queue
            .delete_queue(CompletionMode::Synchronous(0x55))
            .unwrap();
        assert_eq!(delete.wait_event, Some(0x55));
        assert_eq!(queue.phase(), QueuePhase::Deleting);
        let completion = queue.callback_finished(dispatch.ticket).unwrap();
        assert_eq!(completion.signal_event, None);
        assert!(completion.wake_scheduler);
        assert!(!completion.queue_exited);
        assert_eq!(queue.phase(), QueuePhase::AwaitingWorkerExit);
        let completion = queue.worker_exited().unwrap();
        assert_eq!(completion.signal_event, Some(0x55));
        assert!(completion.reclaim);
        assert!(completion.queue_exited);
        assert_eq!(queue.phase(), QueuePhase::Exited);
    }

    #[test]
    fn empty_queue_delete_modes_wait_for_worker_exit() {
        for mode in [
            CompletionMode::Async,
            CompletionMode::Event(0x55),
            CompletionMode::Synchronous(0x66),
        ] {
            let mut queue = TimerQueue::<1>::new();
            let delete = queue.delete_queue(mode).unwrap();
            let expected_status = match mode {
                CompletionMode::Synchronous(_) => STATUS_SUCCESS,
                CompletionMode::Async | CompletionMode::Event(_) => STATUS_PENDING,
            };
            assert_eq!(delete.status, expected_status);
            assert!(delete.wake_scheduler);
            assert!(!delete.reclaim);
            assert_eq!(queue.phase(), QueuePhase::AwaitingWorkerExit);
            let completion = queue.worker_exited().unwrap();
            assert_eq!(completion.signal_event, mode.event());
            assert!(completion.reclaim);
        }
    }

    #[test]
    fn queue_delete_preserves_pending_timer_completion() {
        let mut queue = TimerQueue::<1>::new();
        let (key, _) = queue
            .create_timer(0, spec(0, 0, WorkItemFlags::default()))
            .unwrap();
        let dispatch = expire(&mut queue, 0);
        queue
            .delete_timer(key, CompletionMode::Event(0x44))
            .unwrap();
        queue.delete_queue(CompletionMode::Event(0x55)).unwrap();
        let timer_completion = queue.callback_finished(dispatch.ticket).unwrap();
        assert_eq!(timer_completion.signal_event, Some(0x44));
        assert!(timer_completion.wake_scheduler);
        assert_eq!(queue.phase(), QueuePhase::AwaitingWorkerExit);
        let queue_completion = queue.worker_exited().unwrap();
        assert_eq!(queue_completion.signal_event, Some(0x55));
    }

    #[test]
    fn dormant_and_destroying_timer_updates_are_successful_noops() {
        let mut queue = TimerQueue::<2>::new();
        let (dormant, _) = queue
            .create_timer(0, spec(0, 0, WorkItemFlags::default()))
            .unwrap();
        let dispatch = expire(&mut queue, 0);
        assert_eq!(
            queue.update_timer(dormant, 10, 20, 30),
            Ok(WakeScheduler(false))
        );
        queue.callback_finished(dispatch.ticket).unwrap();

        let (destroying, _) = queue
            .create_timer(0, spec(0, 0, WorkItemFlags::default()))
            .unwrap();
        let dispatch = expire(&mut queue, 0);
        queue
            .delete_timer(destroying, CompletionMode::Async)
            .unwrap();
        assert_eq!(
            queue.update_timer(destroying, 10, 20, 30),
            Ok(WakeScheduler(false))
        );
        queue.callback_finished(dispatch.ticket).unwrap();
    }

    #[test]
    fn stale_timer_generation_is_rejected() {
        let mut queue = TimerQueue::<1>::new();
        let (old, _) = queue
            .create_timer(0, spec(1, 0, WorkItemFlags::default()))
            .unwrap();
        queue.delete_timer(old, CompletionMode::Async).unwrap();
        let (new, _) = queue
            .create_timer(0, spec(1, 0, WorkItemFlags::default()))
            .unwrap();
        assert_ne!(old.generation(), new.generation());
        assert_eq!(queue.update_timer(old, 0, 1, 0), Err(STATUS_INVALID_HANDLE));
        assert_eq!(TimerKey::from_parts(0, 0), None);
        assert_eq!(
            TimerKey::from_parts(new.index() as u16, new.generation()),
            Some(new)
        );
    }

    fn wait(flags: WorkItemFlags) -> RegisteredWait {
        RegisteredWait::new(0x10, 0x20, 0x30, 0x40, 50, flags).unwrap()
    }

    #[test]
    fn registered_wait_distinguishes_object_timeout_and_apc() {
        let mut object = wait(WorkItemFlags::default());
        object.worker_started().unwrap();
        assert_eq!(
            object.observe_wait(WaitOutcome::UserApc),
            Ok(WaitAction::Retry)
        );
        assert_eq!(
            object.observe_wait(WaitOutcome::Object),
            Ok(WaitAction::Invoke {
                callback: 0x30,
                context: 0x40,
                timed_out: false
            })
        );
        assert_eq!(object.callback_finished(), Ok(WaitAction::Retry));
        assert_eq!(
            object.observe_wait(WaitOutcome::Timeout),
            Ok(WaitAction::Invoke {
                callback: 0x30,
                context: 0x40,
                timed_out: true
            })
        );
    }

    #[test]
    fn only_once_wait_exits_after_callback() {
        let mut wait = wait(WorkItemFlags::EXECUTE_ONLY_ONCE);
        wait.worker_started().unwrap();
        wait.observe_wait(WaitOutcome::Object).unwrap();
        assert_eq!(wait.callback_finished(), Ok(WaitAction::ExitWorker));
        assert_eq!(wait.state(), WaitState::Exiting);
        assert_eq!(wait.worker_exited().unwrap(), CompletionPlan::default());
        let delete = wait.deregister(CompletionMode::Event(0x77)).unwrap();
        assert_eq!(delete.status, STATUS_SUCCESS);
        assert_eq!(delete.signal_event, Some(0x77));
        assert!(delete.reclaim);
    }

    #[test]
    fn deregister_during_callback_uses_two_party_handshake() {
        let mut wait = wait(WorkItemFlags::default());
        wait.worker_started().unwrap();
        wait.observe_wait(WaitOutcome::Object).unwrap();
        let delete = wait.deregister(CompletionMode::Synchronous(0x88)).unwrap();
        assert_eq!(delete.set_cancel_event, Some(0x20));
        assert_eq!(delete.wait_event, Some(0x88));
        assert_eq!(wait.callback_finished(), Ok(WaitAction::ExitWorker));
        let completion = wait.worker_exited().unwrap();
        assert_eq!(completion.signal_event, Some(0x88));
        assert_eq!(completion.close_handle, Some(0x20));
        assert!(completion.reclaim);
    }

    #[test]
    fn cancel_while_waiting_exits_without_callback() {
        let mut wait = wait(WorkItemFlags::default());
        wait.worker_started().unwrap();
        let delete = wait.deregister(CompletionMode::Async).unwrap();
        assert_eq!(delete.status, STATUS_SUCCESS);
        assert_eq!(
            wait.observe_wait(WaitOutcome::Cancel),
            Ok(WaitAction::ExitWorker)
        );
        assert!(wait.worker_exited().unwrap().reclaim);
    }

    #[test]
    fn wait_queue_flags_drop_only_once_and_wait_thread_bits() {
        let flags = WorkItemFlags::EXECUTE_IN_IO_THREAD
            .with(WorkItemFlags::EXECUTE_LONG_FUNCTION)
            .with(WorkItemFlags::EXECUTE_ONLY_ONCE)
            .with(WorkItemFlags::EXECUTE_IN_WAIT_THREAD)
            .with(WorkItemFlags::EXECUTE_IN_PERSISTENT_THREAD)
            .with(WorkItemFlags::EXECUTE_IN_PERSISTENT_IO_THREAD);
        assert_eq!(
            wait(flags).queue_flags(),
            WorkItemFlags::EXECUTE_IN_IO_THREAD
                .with(WorkItemFlags::EXECUTE_LONG_FUNCTION)
                .with(WorkItemFlags::EXECUTE_IN_PERSISTENT_THREAD)
        );
    }

    #[test]
    fn registered_wait_alertability_follows_io_thread_flag() {
        let mut ordinary = wait(WorkItemFlags::default());
        ordinary.worker_started().unwrap();
        assert!(!ordinary.wait_request().unwrap().alertable);

        let mut io = wait(WorkItemFlags::EXECUTE_IN_IO_THREAD);
        io.worker_started().unwrap();
        assert!(io.wait_request().unwrap().alertable);
    }

    #[test]
    fn multiplexed_wait_set_preserves_object_tokens_and_bounds_output() {
        let mut set = WaitSet::<2>::new();
        set.push(WaitSetEntry {
            token: 0x101,
            object: 0x20,
        })
        .unwrap();
        set.push(WaitSetEntry {
            token: 0x202,
            object: 0x30,
        })
        .unwrap();
        assert_eq!(
            set.push(WaitSetEntry {
                token: 0x303,
                object: 0x40,
            }),
            Err(WaitSetError::Capacity)
        );

        let mut handles = [0u64; 3];
        assert_eq!(set.write_handles(0x10, &mut handles), Ok(3));
        assert_eq!(handles, [0x10, 0x20, 0x30]);
        assert_eq!(set.decode_status(STATUS_WAIT_0), WaitSetOutcome::Wake);
        assert_eq!(
            set.decode_status(STATUS_WAIT_0 + 1),
            WaitSetOutcome::Object(0x101)
        );
        assert_eq!(
            set.decode_status(STATUS_WAIT_0 + 2),
            WaitSetOutcome::Object(0x202)
        );
        assert_eq!(
            set.decode_status(STATUS_WAIT_0 + 3),
            WaitSetOutcome::Failed(3)
        );
        assert_eq!(
            WaitSet::<1>::new().write_handles(0x10, &mut []),
            Err(WaitSetError::OutputTooSmall)
        );
    }

    #[test]
    fn multiplexed_wait_set_decodes_timeout_apc_and_failure() {
        let set = WaitSet::<1>::new();
        assert_eq!(set.decode_status(STATUS_TIMEOUT), WaitSetOutcome::Timeout);
        assert_eq!(set.decode_status(STATUS_USER_APC), WaitSetOutcome::UserApc);
        assert_eq!(
            set.decode_status(STATUS_INVALID_PARAMETER),
            WaitSetOutcome::Failed(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn registered_wait_deadline_rearms_relative_timeout_and_keeps_infinite() {
        let mut finite = WaitDeadline::new(100, 25);
        assert_eq!(finite.remaining(100), Some(25));
        assert_eq!(finite.remaining(130), Some(0));
        finite.rearm(200);
        assert_eq!(finite.remaining(210), Some(15));

        let mut infinite = WaitDeadline::new(100, u32::MAX);
        assert_eq!(infinite.remaining(100), None);
        infinite.rearm(u64::MAX - 10);
        assert_eq!(infinite.remaining(u64::MAX), None);
    }

    #[test]
    fn deregister_status_depends_on_callback_in_progress() {
        for mode in [
            CompletionMode::Async,
            CompletionMode::Event(0x70),
            CompletionMode::Synchronous(0x71),
        ] {
            let mut waiting = wait(WorkItemFlags::default());
            waiting.worker_started().unwrap();
            let plan = waiting.deregister(mode).unwrap();
            assert_eq!(plan.status, STATUS_SUCCESS);
            assert_eq!(
                plan.wait_event,
                match mode {
                    CompletionMode::Synchronous(event) => Some(event),
                    CompletionMode::Async | CompletionMode::Event(_) => None,
                }
            );

            let mut callback = wait(WorkItemFlags::default());
            callback.worker_started().unwrap();
            callback.observe_wait(WaitOutcome::Object).unwrap();
            let plan = callback.deregister(mode).unwrap();
            assert_eq!(
                plan.status,
                match mode {
                    CompletionMode::Synchronous(_) => STATUS_SUCCESS,
                    CompletionMode::Async | CompletionMode::Event(_) => STATUS_PENDING,
                }
            );
        }
    }

    #[test]
    fn deregister_after_worker_exit_signals_and_reclaims_immediately() {
        let mut wait = wait(WorkItemFlags::EXECUTE_ONLY_ONCE);
        wait.worker_started().unwrap();
        wait.observe_wait(WaitOutcome::Object).unwrap();
        wait.callback_finished().unwrap();
        wait.worker_exited().unwrap();
        let plan = wait.deregister(CompletionMode::Event(0x77)).unwrap();
        assert_eq!(plan.status, STATUS_SUCCESS);
        assert_eq!(plan.signal_event, Some(0x77));
        assert_eq!(plan.close_handle, Some(0x20));
        assert!(plan.reclaim);
    }

    #[test]
    fn wait_start_failure_closes_private_cancel_event() {
        let plan = wait(WorkItemFlags::default()).start_failed();
        assert_eq!(plan.close_cancel_event, 0x20);
        assert!(plan.reclaim);
    }
}
