//! Pure state model for the ReactOS `RtlQueueWorkItem` packet and worker-start protocol.

#![no_std]

use core::sync::atomic::{AtomicU32, Ordering};

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub const STATUS_NO_TOKEN: u32 = 0xC000_007C;
pub const STATUS_CANT_OPEN_ANONYMOUS: u32 = 0xC000_00A6;

/// ReactOS's literal relative polling interval. Despite its source comment saying 100 ms, this is
/// one millisecond in NT's 100-nanosecond interval units.
pub const WORKER_START_POLL_INTERVAL_100NS: i64 = -10_000;

#[inline]
pub const fn nt_success(status: u32) -> bool {
    status as i32 >= 0
}

/// The private x64 `RTLP_WORKITEM` copied by the worker before it frees the heap allocation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkItemPacket {
    pub callback: u64,
    pub context: u64,
    pub flags: u32,
    pub _padding: u32,
    pub token_handle: u64,
}

const _: [(); 0x20] = [(); core::mem::size_of::<WorkItemPacket>()];

impl WorkItemPacket {
    pub const fn new(callback: u64, context: u64, flags: WorkItemFlags, token_handle: u64) -> Self {
        Self {
            callback,
            context,
            flags: flags.bits(),
            _padding: 0,
            token_handle,
        }
    }

    pub const fn work_flags(self) -> WorkItemFlags {
        WorkItemFlags::from_bits_retain(self.flags)
    }

    pub const fn queue_class(self) -> QueueClass {
        self.work_flags().queue_class()
    }
}

/// Windows work-item flags. Unknown bits are retained and passed through unchanged.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkItemFlags(u32);

impl WorkItemFlags {
    pub const EXECUTE_DEFAULT: Self = Self(0);
    pub const EXECUTE_IN_IO_THREAD: Self = Self(0x0000_0001);
    pub const EXECUTE_IN_UI_THREAD: Self = Self(0x0000_0002);
    pub const EXECUTE_IN_WAIT_THREAD: Self = Self(0x0000_0004);
    pub const EXECUTE_ONLY_ONCE: Self = Self(0x0000_0008);
    pub const EXECUTE_LONG_FUNCTION: Self = Self(0x0000_0010);
    pub const EXECUTE_IN_TIMER_THREAD: Self = Self(0x0000_0020);
    pub const EXECUTE_IN_PERSISTENT_IO_THREAD: Self = Self(0x0000_0040);
    pub const EXECUTE_IN_PERSISTENT_THREAD: Self = Self(0x0000_0080);
    pub const TRANSFER_IMPERSONATION: Self = Self(0x0000_0100);

    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn is_long(self) -> bool {
        self.contains(Self::EXECUTE_LONG_FUNCTION)
    }

    pub const fn transfers_impersonation(self) -> bool {
        self.contains(Self::TRANSFER_IMPERSONATION)
    }

    /// ReactOS routes IO, UI, and persistent-IO requests through the IO/APC worker family.
    pub const fn queue_class(self) -> QueueClass {
        let io_mask = Self(
            Self::EXECUTE_IN_IO_THREAD.0
                | Self::EXECUTE_IN_UI_THREAD.0
                | Self::EXECUTE_IN_PERSISTENT_IO_THREAD.0,
        );
        if self.intersects(io_mask) {
            if self.contains(Self::EXECUTE_IN_PERSISTENT_IO_THREAD) {
                QueueClass::PersistentIoApc
            } else {
                QueueClass::IoApc
            }
        } else if self.contains(Self::EXECUTE_IN_PERSISTENT_THREAD) {
            QueueClass::PersistentNormalApc
        } else {
            QueueClass::NormalCompletion
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueClass {
    NormalCompletion,
    PersistentNormalApc,
    IoApc,
    PersistentIoApc,
}

impl QueueClass {
    pub const fn counter_lane(self) -> CounterLane {
        match self {
            Self::NormalCompletion | Self::PersistentNormalApc => CounterLane::Normal,
            Self::IoApc | Self::PersistentIoApc => CounterLane::Io,
        }
    }

    pub const fn is_io(self) -> bool {
        matches!(self.counter_lane(), CounterLane::Io)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenCapture {
    NotRequested,
    Absent,
    Captured(u64),
    Failed(u32),
}

impl TokenCapture {
    pub const fn token_handle(self) -> u64 {
        match self {
            Self::Captured(handle) => handle,
            _ => 0,
        }
    }

    pub const fn status(self) -> u32 {
        match self {
            Self::Failed(status) => status,
            _ => STATUS_SUCCESS,
        }
    }
}

/// Interpret the result of ReactOS's optional `NtOpenThreadToken` capture.
pub const fn normalize_token_capture(
    flags: WorkItemFlags,
    status: u32,
    token_handle: u64,
) -> TokenCapture {
    if !flags.transfers_impersonation() {
        return TokenCapture::NotRequested;
    }
    if status == STATUS_NO_TOKEN || status == STATUS_CANT_OPEN_ANONYMOUS {
        return TokenCapture::Absent;
    }
    if !nt_success(status) {
        return TokenCapture::Failed(status);
    }
    if token_handle == 0 {
        TokenCapture::Absent
    } else {
        TokenCapture::Captured(token_handle)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketOwner {
    Submitter,
    Queue,
    Worker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupAction {
    CloseToken(u64),
    FreePacket(u64),
}

#[derive(Debug, Eq, PartialEq)]
pub struct CleanupPlan {
    actions: [CleanupAction; 2],
    len: usize,
}

impl CleanupPlan {
    fn submission_failure(packet_va: u64, token_handle: u64) -> Self {
        if token_handle == 0 {
            Self {
                actions: [
                    CleanupAction::FreePacket(packet_va),
                    CleanupAction::FreePacket(0),
                ],
                len: 1,
            }
        } else {
            Self {
                actions: [
                    CleanupAction::CloseToken(token_handle),
                    CleanupAction::FreePacket(packet_va),
                ],
                len: 2,
            }
        }
    }

    pub fn actions(&self) -> &[CleanupAction] {
        &self.actions[..self.len]
    }
}

/// Submitter-owned heap packet. Only a successful queue operation transfers this ownership.
#[derive(Debug, Eq, PartialEq)]
pub struct Submission {
    packet_va: u64,
    packet: WorkItemPacket,
    accounting: RequestTicket,
}

impl Submission {
    pub const fn owner(&self) -> PacketOwner {
        PacketOwner::Submitter
    }

    pub const fn packet(&self) -> WorkItemPacket {
        self.packet
    }

    /// Commits a successful queue operation and transfers packet and accounting ownership.
    pub fn commit_queue_success(self) -> QueuedPacket {
        QueuedPacket {
            packet_va: self.packet_va,
            packet: self.packet,
            accounting: self.accounting.commit(),
        }
    }

    /// Rolls back accounting before returning the queue-failure resource cleanup plan.
    pub fn queue_failed(
        mut self,
        counters: &mut PoolCounters,
    ) -> Result<CleanupPlan, TransitionError> {
        counters.rollback(&mut self.accounting)?;
        Ok(CleanupPlan::submission_failure(
            self.packet_va,
            self.packet.token_handle,
        ))
    }
}

/// Queue-owned packet after a successful completion/APC enqueue operation.
#[derive(Debug, Eq, PartialEq)]
pub struct QueuedPacket {
    packet_va: u64,
    packet: WorkItemPacket,
    accounting: AccountingTransfer,
}

impl QueuedPacket {
    pub const fn owner(&self) -> PacketOwner {
        PacketOwner::Queue
    }

    pub const fn dequeue(self) -> WorkerPacket {
        WorkerPacket {
            packet_va: self.packet_va,
            packet: self.packet,
            accounting: self.accounting,
        }
    }
}

/// Worker-owned packet after successful dequeue/APC delivery.
#[derive(Debug, Eq, PartialEq)]
pub struct WorkerPacket {
    packet_va: u64,
    packet: WorkItemPacket,
    accounting: AccountingTransfer,
}

impl WorkerPacket {
    /// Reconstructs worker ownership at the trusted dequeue transport boundary.
    ///
    /// The queue and worker may be separated by a syscall or IPC transport, so the
    /// producer-side [`QueuedPacket`] value itself cannot be moved to the worker. The caller
    /// must only use this constructor after the queue has successfully removed the packet and
    /// transferred its allocation to the current worker. Calling it for a packet that remains
    /// queued or has already been claimed would duplicate ownership authority.
    pub const fn from_dequeue(packet_va: u64, packet: WorkItemPacket) -> Self {
        Self {
            packet_va,
            packet,
            accounting: AccountingTransfer::from_dequeue(),
        }
    }

    pub const fn owner(&self) -> PacketOwner {
        PacketOwner::Worker
    }

    /// Copies the packet values into the execution state. The first action remains `FreePacket`.
    pub const fn begin_execution(self) -> Execution {
        Execution {
            packet_va: self.packet_va,
            packet: self.packet,
            accounting: self.accounting,
            phase: ExecutionPhase::ReleaseHeap,
            impersonated: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackOutcome {
    Returned,
    Exception(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterLane {
    Normal,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionAction {
    FreePacket(u64),
    SetThreadImpersonation(u64),
    CloseToken(u64),
    Invoke { callback: u64, context: u64 },
    RevertToSelf,
    ClearIoWorkerLong,
    CompleteAccounting { lane: CounterLane, long: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionResult {
    Done,
    Status(u32),
    Callback(CallbackOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPhase {
    ReleaseHeap,
    SetToken,
    CloseToken,
    Invoke,
    Revert,
    ClearIoWorkerLong,
    CompleteAccounting,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    UnexpectedResult,
    CounterOverflow,
    CounterUnderflow,
    TicketConsumed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Execution {
    packet_va: u64,
    packet: WorkItemPacket,
    accounting: AccountingTransfer,
    phase: ExecutionPhase,
    impersonated: bool,
}

impl Execution {
    pub const fn phase(&self) -> ExecutionPhase {
        self.phase
    }

    pub const fn next_action(&self) -> Option<ExecutionAction> {
        let flags = self.packet.work_flags();
        match self.phase {
            ExecutionPhase::ReleaseHeap => Some(ExecutionAction::FreePacket(self.packet_va)),
            ExecutionPhase::SetToken => Some(ExecutionAction::SetThreadImpersonation(
                self.packet.token_handle,
            )),
            ExecutionPhase::CloseToken => {
                Some(ExecutionAction::CloseToken(self.packet.token_handle))
            }
            ExecutionPhase::Invoke => Some(ExecutionAction::Invoke {
                callback: self.packet.callback,
                context: self.packet.context,
            }),
            ExecutionPhase::Revert => Some(ExecutionAction::RevertToSelf),
            ExecutionPhase::ClearIoWorkerLong => Some(ExecutionAction::ClearIoWorkerLong),
            ExecutionPhase::CompleteAccounting => Some(ExecutionAction::CompleteAccounting {
                lane: self.packet.queue_class().counter_lane(),
                long: flags.is_long(),
            }),
            ExecutionPhase::Complete => None,
        }
    }

    pub fn advance(&mut self, result: ActionResult) -> Result<(), TransitionError> {
        let flags = self.packet.work_flags();
        self.phase = match (self.phase, result) {
            (ExecutionPhase::ReleaseHeap, ActionResult::Done) => {
                if self.packet.token_handle != 0 {
                    ExecutionPhase::SetToken
                } else {
                    ExecutionPhase::Invoke
                }
            }
            (ExecutionPhase::SetToken, ActionResult::Status(status)) => {
                self.impersonated = nt_success(status);
                ExecutionPhase::CloseToken
            }
            (ExecutionPhase::CloseToken, ActionResult::Done) => ExecutionPhase::Invoke,
            (ExecutionPhase::Invoke, ActionResult::Callback(_)) => {
                if self.impersonated {
                    ExecutionPhase::Revert
                } else if self.packet.queue_class().is_io() && flags.is_long() {
                    ExecutionPhase::ClearIoWorkerLong
                } else {
                    ExecutionPhase::CompleteAccounting
                }
            }
            (ExecutionPhase::Revert, ActionResult::Status(_)) => {
                if self.packet.queue_class().is_io() && flags.is_long() {
                    ExecutionPhase::ClearIoWorkerLong
                } else {
                    ExecutionPhase::CompleteAccounting
                }
            }
            (ExecutionPhase::ClearIoWorkerLong, ActionResult::Done) => {
                ExecutionPhase::CompleteAccounting
            }
            _ => return Err(TransitionError::UnexpectedResult),
        };
        Ok(())
    }

    /// Completes accounting from the effective packet transported to this worker.
    pub fn complete_accounting(
        &mut self,
        counters: &mut PoolCounters,
    ) -> Result<(), TransitionError> {
        if self.phase != ExecutionPhase::CompleteAccounting {
            return Err(TransitionError::UnexpectedResult);
        }
        counters.complete(self.packet, &mut self.accounting)?;
        self.phase = ExecutionPhase::Complete;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PoolCounters {
    normal_requests: u32,
    normal_long_requests: u32,
    io_requests: u32,
    io_long_requests: u32,
}

impl PoolCounters {
    pub const fn requests(&self, lane: CounterLane) -> u32 {
        match lane {
            CounterLane::Normal => self.normal_requests,
            CounterLane::Io => self.io_requests,
        }
    }

    pub const fn long_requests(&self, lane: CounterLane) -> u32 {
        match lane {
            CounterLane::Normal => self.normal_long_requests,
            CounterLane::Io => self.io_long_requests,
        }
    }

    /// Reserves counters and couples that reservation to the effective packet being queued.
    pub fn reserve(
        &mut self,
        packet_va: u64,
        packet: WorkItemPacket,
    ) -> Result<Submission, TransitionError> {
        let lane = packet.queue_class().counter_lane();
        let long = packet.work_flags().is_long();
        let next_requests = self
            .requests(lane)
            .checked_add(1)
            .ok_or(TransitionError::CounterOverflow)?;
        let next_long = if long {
            self.long_requests(lane)
                .checked_add(1)
                .ok_or(TransitionError::CounterOverflow)?
        } else {
            self.long_requests(lane)
        };
        match lane {
            CounterLane::Normal => {
                self.normal_requests = next_requests;
                self.normal_long_requests = next_long;
            }
            CounterLane::Io => {
                self.io_requests = next_requests;
                self.io_long_requests = next_long;
            }
        }
        Ok(Submission {
            packet_va,
            packet,
            accounting: RequestTicket {
                lane,
                long,
                active: true,
            },
        })
    }

    fn rollback(&mut self, ticket: &mut RequestTicket) -> Result<(), TransitionError> {
        self.consume(ticket)
    }

    fn complete(
        &mut self,
        packet: WorkItemPacket,
        transfer: &mut AccountingTransfer,
    ) -> Result<(), TransitionError> {
        self.consume_fields(
            packet.queue_class().counter_lane(),
            packet.work_flags().is_long(),
            &mut transfer.active,
        )
    }

    fn consume(&mut self, ticket: &mut RequestTicket) -> Result<(), TransitionError> {
        self.consume_fields(ticket.lane, ticket.long, &mut ticket.active)
    }

    fn consume_fields(
        &mut self,
        lane: CounterLane,
        long: bool,
        active: &mut bool,
    ) -> Result<(), TransitionError> {
        if !*active {
            return Err(TransitionError::TicketConsumed);
        }
        if self.requests(lane) == 0 || (long && self.long_requests(lane) == 0) {
            return Err(TransitionError::CounterUnderflow);
        }
        match lane {
            CounterLane::Normal => {
                self.normal_requests -= 1;
                if long {
                    self.normal_long_requests -= 1;
                }
            }
            CounterLane::Io => {
                self.io_requests -= 1;
                if long {
                    self.io_long_requests -= 1;
                }
            }
        }
        *active = false;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RequestTicket {
    lane: CounterLane,
    long: bool,
    active: bool,
}

impl RequestTicket {
    fn commit(self) -> AccountingTransfer {
        AccountingTransfer {
            active: self.active,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct AccountingTransfer {
    active: bool,
}

impl AccountingTransfer {
    const fn from_dequeue() -> Self {
        Self { active: true }
    }
}

/// A single-use stack latch borrowed by a newly created worker until it acknowledges initialization.
#[repr(transparent)]
pub struct WorkerStartLatch {
    initialized: AtomicU32,
}

impl WorkerStartLatch {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicU32::new(0),
        }
    }

    /// Returns the opaque worker parameter passed through the native thread-start hook.
    ///
    /// The latch must remain alive until the creator observes acknowledgement with Acquire
    /// ordering. This is normally a pointer to a latch stored in the creator's stack frame.
    pub fn as_parameter(&self) -> *mut core::ffi::c_void {
        (self as *const Self).cast_mut().cast()
    }

    /// Acknowledges a latch received as the raw native worker parameter.
    ///
    /// # Safety
    ///
    /// `parameter` must be non-null, properly aligned, and point to a live [`WorkerStartLatch`]
    /// whose creator will retain it until this acknowledgement is visible.
    pub unsafe fn acknowledge_parameter(parameter: *mut core::ffi::c_void) -> bool {
        // SAFETY: The caller guarantees that the opaque parameter identifies a live latch.
        let latch = unsafe { &*parameter.cast::<Self>() };
        latch.acknowledge()
    }

    /// Signal that the worker will never read its borrowed start parameter again.
    /// Returns `true` only for the first acknowledgement.
    pub fn acknowledge(&self) -> bool {
        self.initialized.swap(1, Ordering::Release) == 0
    }

    pub fn is_acknowledged(&self) -> bool {
        self.initialized.load(Ordering::Acquire) != 0
    }
}

impl Default for WorkerStartLatch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerStartPhase {
    Fresh,
    Created,
    WaitingForAck,
    DelayPending,
    Closing,
    Returning,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerStartAction {
    CallStartHook {
        worker_routine: u64,
        parameter: *mut core::ffi::c_void,
    },
    ResumeThread(u64),
    PollLatch,
    Delay(i64),
    CloseThread(u64),
    Return(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerStartEvent {
    StartReturned { status: u32, thread_handle: u64 },
    ResumeIssued,
    PollObserved(bool),
    DelayCompleted,
    ThreadClosed,
    ReturnDelivered,
}

#[derive(Debug, Eq, PartialEq)]
pub struct WorkerStart {
    phase: WorkerStartPhase,
    worker_routine: u64,
    latch_parameter: *mut core::ffi::c_void,
    thread_handle: u64,
    return_status: u32,
}

impl WorkerStart {
    /// Models the creator-side bootstrap protocol only. Worker identity setup, top-level SEH,
    /// callback execution, and target syscall consumption remain responsibilities of the target
    /// worker routine and its native adapters.
    pub const fn new(worker_routine: u64, latch_parameter: *mut core::ffi::c_void) -> Self {
        Self {
            phase: WorkerStartPhase::Fresh,
            worker_routine,
            latch_parameter,
            thread_handle: 0,
            return_status: STATUS_SUCCESS,
        }
    }

    pub const fn phase(&self) -> WorkerStartPhase {
        self.phase
    }

    pub const fn next_action(&self) -> Option<WorkerStartAction> {
        match self.phase {
            WorkerStartPhase::Fresh => Some(WorkerStartAction::CallStartHook {
                worker_routine: self.worker_routine,
                parameter: self.latch_parameter,
            }),
            WorkerStartPhase::Created => Some(WorkerStartAction::ResumeThread(self.thread_handle)),
            WorkerStartPhase::WaitingForAck => Some(WorkerStartAction::PollLatch),
            WorkerStartPhase::DelayPending => {
                Some(WorkerStartAction::Delay(WORKER_START_POLL_INTERVAL_100NS))
            }
            WorkerStartPhase::Closing => Some(WorkerStartAction::CloseThread(self.thread_handle)),
            WorkerStartPhase::Returning => Some(WorkerStartAction::Return(self.return_status)),
            WorkerStartPhase::Complete => None,
        }
    }

    pub fn advance(&mut self, event: WorkerStartEvent) -> Result<(), TransitionError> {
        match (self.phase, event) {
            (
                WorkerStartPhase::Fresh,
                WorkerStartEvent::StartReturned {
                    status,
                    thread_handle,
                },
            ) => {
                self.return_status = status;
                if nt_success(status) {
                    if thread_handle == 0 {
                        self.return_status = STATUS_UNSUCCESSFUL;
                        self.phase = WorkerStartPhase::Returning;
                    } else {
                        self.thread_handle = thread_handle;
                        self.phase = WorkerStartPhase::Created;
                    }
                } else {
                    self.phase = WorkerStartPhase::Returning;
                }
            }
            (WorkerStartPhase::Created, WorkerStartEvent::ResumeIssued) => {
                self.phase = WorkerStartPhase::WaitingForAck;
            }
            (WorkerStartPhase::WaitingForAck, WorkerStartEvent::PollObserved(false)) => {
                self.phase = WorkerStartPhase::DelayPending;
            }
            (WorkerStartPhase::WaitingForAck, WorkerStartEvent::PollObserved(true)) => {
                self.phase = WorkerStartPhase::Closing;
            }
            (WorkerStartPhase::DelayPending, WorkerStartEvent::DelayCompleted) => {
                self.phase = WorkerStartPhase::WaitingForAck;
            }
            (WorkerStartPhase::Closing, WorkerStartEvent::ThreadClosed) => {
                self.phase = WorkerStartPhase::Returning;
            }
            (WorkerStartPhase::Returning, WorkerStartEvent::ReturnDelivered) => {
                self.phase = WorkerStartPhase::Complete;
            }
            _ => return Err(TransitionError::UnexpectedResult),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::{offset_of, size_of};
    use std::{sync::Arc, thread, vec, vec::Vec};

    #[test]
    fn packet_layout_matches_reactos_x64() {
        assert_eq!(size_of::<WorkItemPacket>(), 0x20);
        assert_eq!(offset_of!(WorkItemPacket, callback), 0x00);
        assert_eq!(offset_of!(WorkItemPacket, context), 0x08);
        assert_eq!(offset_of!(WorkItemPacket, flags), 0x10);
        assert_eq!(offset_of!(WorkItemPacket, token_handle), 0x18);
    }

    #[test]
    fn flags_classify_all_worker_families_and_retain_unknown_bits() {
        assert_eq!(
            WorkItemFlags::EXECUTE_DEFAULT.queue_class(),
            QueueClass::NormalCompletion
        );
        assert_eq!(
            WorkItemFlags::EXECUTE_IN_WAIT_THREAD.queue_class(),
            QueueClass::NormalCompletion
        );
        assert_eq!(
            WorkItemFlags::EXECUTE_ONLY_ONCE.queue_class(),
            QueueClass::NormalCompletion
        );
        assert_eq!(
            WorkItemFlags::EXECUTE_IN_TIMER_THREAD.queue_class(),
            QueueClass::NormalCompletion
        );
        assert_eq!(
            WorkItemFlags::EXECUTE_IN_PERSISTENT_THREAD.queue_class(),
            QueueClass::PersistentNormalApc
        );
        assert_eq!(
            WorkItemFlags::EXECUTE_IN_IO_THREAD.queue_class(),
            QueueClass::IoApc
        );
        assert_eq!(
            WorkItemFlags::EXECUTE_IN_UI_THREAD.queue_class(),
            QueueClass::IoApc
        );
        assert_eq!(
            WorkItemFlags::EXECUTE_IN_PERSISTENT_IO_THREAD.queue_class(),
            QueueClass::PersistentIoApc
        );
        let flags =
            WorkItemFlags::from_bits_retain(0x8000_0000).with(WorkItemFlags::EXECUTE_LONG_FUNCTION);
        assert_eq!(flags.bits(), 0x8000_0010);
        assert!(flags.is_long());
        assert!(!flags
            .without(WorkItemFlags::EXECUTE_LONG_FUNCTION)
            .is_long());
    }

    #[test]
    fn token_capture_normalizes_absence_but_preserves_hard_failure() {
        let transfer = WorkItemFlags::TRANSFER_IMPERSONATION;
        assert_eq!(
            normalize_token_capture(WorkItemFlags::EXECUTE_DEFAULT, 0xdead_beef, 9),
            TokenCapture::NotRequested
        );
        assert_eq!(
            normalize_token_capture(transfer, STATUS_SUCCESS, 9),
            TokenCapture::Captured(9)
        );
        assert_eq!(
            normalize_token_capture(transfer, STATUS_NO_TOKEN, 0),
            TokenCapture::Absent
        );
        assert_eq!(
            normalize_token_capture(transfer, STATUS_CANT_OPEN_ANONYMOUS, 0),
            TokenCapture::Absent
        );
        assert_eq!(
            normalize_token_capture(transfer, 0xC000_0022, 0),
            TokenCapture::Failed(0xC000_0022)
        );
    }

    #[test]
    fn queue_failure_closes_token_before_free_and_success_transfers_ownership() {
        let packet = WorkItemPacket::new(1, 2, WorkItemFlags::EXECUTE_DEFAULT, 0x44);
        let mut counters = PoolCounters::default();
        let failed = counters
            .reserve(0x1000, packet)
            .unwrap()
            .queue_failed(&mut counters)
            .unwrap();
        assert_eq!(
            failed.actions(),
            &[
                CleanupAction::CloseToken(0x44),
                CleanupAction::FreePacket(0x1000)
            ]
        );

        let no_token = counters
            .reserve(
                0x2000,
                WorkItemPacket::new(1, 2, WorkItemFlags::EXECUTE_DEFAULT, 0),
            )
            .unwrap()
            .queue_failed(&mut counters)
            .unwrap();
        assert_eq!(no_token.actions(), &[CleanupAction::FreePacket(0x2000)]);
        assert_eq!(counters, PoolCounters::default());

        let queued = counters
            .reserve(0x3000, packet)
            .unwrap()
            .commit_queue_success();
        assert_eq!(queued.owner(), PacketOwner::Queue);
        assert_eq!(queued.dequeue().owner(), PacketOwner::Worker);
    }

    #[test]
    fn worker_packet_reconstructs_ownership_at_dequeue_transport_boundary() {
        let packet = WorkItemPacket::new(0x20, 0x30, WorkItemFlags::EXECUTE_DEFAULT, 0);
        let worker = WorkerPacket::from_dequeue(0x4000, packet);

        assert_eq!(worker.owner(), PacketOwner::Worker);
        assert_eq!(
            worker.begin_execution().next_action(),
            Some(ExecutionAction::FreePacket(0x4000))
        );
    }

    fn drive_execution(
        mut execution: Execution,
        token_status: u32,
        counters: &mut PoolCounters,
    ) -> Vec<ExecutionAction> {
        let mut trace = Vec::new();
        while let Some(action) = execution.next_action() {
            trace.push(action);
            if matches!(action, ExecutionAction::CompleteAccounting { .. }) {
                execution.complete_accounting(counters).unwrap();
                continue;
            }
            let result = match action {
                ExecutionAction::SetThreadImpersonation(_) | ExecutionAction::RevertToSelf => {
                    ActionResult::Status(token_status)
                }
                ExecutionAction::Invoke { .. } => ActionResult::Callback(CallbackOutcome::Returned),
                _ => ActionResult::Done,
            };
            execution.advance(result).unwrap();
        }
        trace
    }

    #[test]
    fn execution_frees_before_token_close_callback_revert_and_accounting() {
        let flags =
            WorkItemFlags::EXECUTE_LONG_FUNCTION.with(WorkItemFlags::TRANSFER_IMPERSONATION);
        let mut counters = PoolCounters::default();
        let execution = counters
            .reserve(0x1000, WorkItemPacket::new(0x20, 0x30, flags, 0x40))
            .unwrap()
            .commit_queue_success()
            .dequeue()
            .begin_execution();
        assert_eq!(
            drive_execution(execution, STATUS_SUCCESS, &mut counters),
            vec![
                ExecutionAction::FreePacket(0x1000),
                ExecutionAction::SetThreadImpersonation(0x40),
                ExecutionAction::CloseToken(0x40),
                ExecutionAction::Invoke {
                    callback: 0x20,
                    context: 0x30
                },
                ExecutionAction::RevertToSelf,
                ExecutionAction::CompleteAccounting {
                    lane: CounterLane::Normal,
                    long: true
                },
            ]
        );
    }

    #[test]
    fn failed_impersonation_still_closes_token_and_skips_revert() {
        let mut counters = PoolCounters::default();
        let execution = counters
            .reserve(
                0x1000,
                WorkItemPacket::new(0x20, 0x30, WorkItemFlags::TRANSFER_IMPERSONATION, 0x40),
            )
            .unwrap()
            .commit_queue_success()
            .dequeue()
            .begin_execution();
        assert_eq!(
            drive_execution(execution, 0xC000_0022, &mut counters),
            vec![
                ExecutionAction::FreePacket(0x1000),
                ExecutionAction::SetThreadImpersonation(0x40),
                ExecutionAction::CloseToken(0x40),
                ExecutionAction::Invoke {
                    callback: 0x20,
                    context: 0x30
                },
                ExecutionAction::CompleteAccounting {
                    lane: CounterLane::Normal,
                    long: false
                },
            ]
        );
    }

    #[test]
    fn execution_rejects_callback_completion_before_heap_release() {
        let mut counters = PoolCounters::default();
        let mut execution = counters
            .reserve(
                0x1000,
                WorkItemPacket::new(0x20, 0x30, WorkItemFlags::EXECUTE_DEFAULT, 0),
            )
            .unwrap()
            .commit_queue_success()
            .dequeue()
            .begin_execution();
        assert_eq!(
            execution.advance(ActionResult::Callback(CallbackOutcome::Returned)),
            Err(TransitionError::UnexpectedResult)
        );
        assert_eq!(execution.phase(), ExecutionPhase::ReleaseHeap);
    }

    #[test]
    fn callback_exception_still_reverts_and_io_long_clears_worker_flag() {
        let flags = WorkItemFlags::EXECUTE_IN_IO_THREAD
            .with(WorkItemFlags::EXECUTE_LONG_FUNCTION)
            .with(WorkItemFlags::TRANSFER_IMPERSONATION);
        let mut counters = PoolCounters::default();
        let mut execution = counters
            .reserve(7, WorkItemPacket::new(1, 2, flags, 3))
            .unwrap()
            .commit_queue_success()
            .dequeue()
            .begin_execution();
        execution.advance(ActionResult::Done).unwrap();
        execution
            .advance(ActionResult::Status(STATUS_SUCCESS))
            .unwrap();
        execution.advance(ActionResult::Done).unwrap();
        execution
            .advance(ActionResult::Callback(CallbackOutcome::Exception(
                0xC000_0005,
            )))
            .unwrap();
        assert_eq!(execution.next_action(), Some(ExecutionAction::RevertToSelf));
        execution
            .advance(ActionResult::Status(0xC000_0001))
            .unwrap();
        assert_eq!(
            execution.next_action(),
            Some(ExecutionAction::ClearIoWorkerLong)
        );
        execution.advance(ActionResult::Done).unwrap();
        assert_eq!(
            execution.next_action(),
            Some(ExecutionAction::CompleteAccounting {
                lane: CounterLane::Io,
                long: true
            })
        );
    }

    #[test]
    fn clearing_effective_long_flag_removes_io_long_cleanup_and_accounting() {
        let requested =
            WorkItemFlags::EXECUTE_IN_IO_THREAD.with(WorkItemFlags::EXECUTE_LONG_FUNCTION);
        let effective = requested.without(WorkItemFlags::EXECUTE_LONG_FUNCTION);
        let mut counters = PoolCounters::default();
        let execution = counters
            .reserve(7, WorkItemPacket::new(1, 2, effective, 0))
            .unwrap()
            .commit_queue_success()
            .dequeue()
            .begin_execution();
        assert_eq!(
            drive_execution(execution, STATUS_SUCCESS, &mut counters),
            vec![
                ExecutionAction::FreePacket(7),
                ExecutionAction::Invoke {
                    callback: 1,
                    context: 2
                },
                ExecutionAction::CompleteAccounting {
                    lane: CounterLane::Io,
                    long: false
                },
            ]
        );
    }

    #[test]
    fn accounting_is_coupled_to_the_effective_packet_and_queue_outcome() {
        let mut counters = PoolCounters::default();
        let normal_long = WorkItemPacket::new(1, 2, WorkItemFlags::EXECUTE_LONG_FUNCTION, 0);
        let failed = counters.reserve(0x1000, normal_long).unwrap();
        assert_eq!(counters.requests(CounterLane::Normal), 1);
        assert_eq!(counters.long_requests(CounterLane::Normal), 1);
        failed.queue_failed(&mut counters).unwrap();
        assert_eq!(counters, PoolCounters::default());

        let effective_io_long = WorkItemPacket::new(
            3,
            4,
            WorkItemFlags::EXECUTE_IN_IO_THREAD.with(WorkItemFlags::EXECUTE_LONG_FUNCTION),
            0,
        );
        let execution = counters
            .reserve(0x2000, effective_io_long)
            .unwrap()
            .commit_queue_success()
            .dequeue()
            .begin_execution();
        assert_eq!(counters.requests(CounterLane::Normal), 0);
        assert_eq!(counters.requests(CounterLane::Io), 1);
        assert_eq!(counters.long_requests(CounterLane::Io), 1);
        drive_execution(execution, STATUS_SUCCESS, &mut counters);
        assert_eq!(counters, PoolCounters::default());
    }

    #[test]
    fn latch_is_release_acquire_and_acknowledges_once() {
        let latch = Arc::new(WorkerStartLatch::new());
        let worker = Arc::clone(&latch);
        let join = thread::spawn(move || {
            let parameter = worker.as_parameter() as usize;
            // SAFETY: The Arc keeps the latch live across both raw acknowledgements.
            unsafe {
                assert!(WorkerStartLatch::acknowledge_parameter(
                    parameter as *mut core::ffi::c_void,
                ));
                assert!(!WorkerStartLatch::acknowledge_parameter(
                    parameter as *mut core::ffi::c_void,
                ));
            }
        });
        join.join().unwrap();
        assert!(latch.is_acknowledged());
    }

    #[test]
    fn worker_start_waits_for_ack_then_closes_before_returning() {
        let latch = WorkerStartLatch::new();
        let parameter = latch.as_parameter();
        let mut start = WorkerStart::new(0x1234, parameter);
        assert_eq!(
            start.next_action(),
            Some(WorkerStartAction::CallStartHook {
                worker_routine: 0x1234,
                parameter,
            })
        );
        start
            .advance(WorkerStartEvent::StartReturned {
                status: STATUS_SUCCESS,
                thread_handle: 0x55,
            })
            .unwrap();
        assert_eq!(
            start.next_action(),
            Some(WorkerStartAction::ResumeThread(0x55))
        );
        start.advance(WorkerStartEvent::ResumeIssued).unwrap();
        start
            .advance(WorkerStartEvent::PollObserved(false))
            .unwrap();
        assert_eq!(
            start.next_action(),
            Some(WorkerStartAction::Delay(WORKER_START_POLL_INTERVAL_100NS))
        );
        start.advance(WorkerStartEvent::DelayCompleted).unwrap();
        start.advance(WorkerStartEvent::PollObserved(true)).unwrap();
        assert_eq!(
            start.next_action(),
            Some(WorkerStartAction::CloseThread(0x55))
        );
        start.advance(WorkerStartEvent::ThreadClosed).unwrap();
        assert_eq!(
            start.next_action(),
            Some(WorkerStartAction::Return(STATUS_SUCCESS))
        );
        start.advance(WorkerStartEvent::ReturnDelivered).unwrap();
        assert_eq!(start.next_action(), None);
    }

    #[test]
    fn worker_start_failure_returns_without_resume_or_close() {
        let latch = WorkerStartLatch::new();
        let mut start = WorkerStart::new(0x1234, latch.as_parameter());
        start
            .advance(WorkerStartEvent::StartReturned {
                status: 0xC000_009A,
                thread_handle: 0,
            })
            .unwrap();
        assert_eq!(
            start.next_action(),
            Some(WorkerStartAction::Return(0xC000_009A))
        );
        assert_eq!(
            start.advance(WorkerStartEvent::ThreadClosed),
            Err(TransitionError::UnexpectedResult)
        );
    }

    #[test]
    fn successful_start_hook_must_return_a_thread_handle() {
        let latch = WorkerStartLatch::new();
        let mut start = WorkerStart::new(0x1234, latch.as_parameter());
        start
            .advance(WorkerStartEvent::StartReturned {
                status: STATUS_SUCCESS,
                thread_handle: 0,
            })
            .unwrap();
        assert_eq!(
            start.next_action(),
            Some(WorkerStartAction::Return(STATUS_UNSUCCESSFUL))
        );
    }

    #[test]
    fn fake_executor_records_complete_no_token_trace() {
        let mut counters = PoolCounters::default();
        let packet = WorkItemPacket::new(0xaaaa, 0xbbbb, WorkItemFlags::EXECUTE_DEFAULT, 0);
        let mut execution = counters
            .reserve(0xcccc, packet)
            .unwrap()
            .commit_queue_success()
            .dequeue()
            .begin_execution();
        let mut trace = Vec::new();
        while let Some(action) = execution.next_action() {
            trace.push(action);
            if matches!(action, ExecutionAction::CompleteAccounting { .. }) {
                execution.complete_accounting(&mut counters).unwrap();
                continue;
            }
            let result = match action {
                ExecutionAction::Invoke { .. } => ActionResult::Callback(CallbackOutcome::Returned),
                _ => ActionResult::Done,
            };
            execution.advance(result).unwrap();
        }
        assert_eq!(
            trace,
            vec![
                ExecutionAction::FreePacket(0xcccc),
                ExecutionAction::Invoke {
                    callback: 0xaaaa,
                    context: 0xbbbb
                },
                ExecutionAction::CompleteAccounting {
                    lane: CounterLane::Normal,
                    long: false
                },
            ]
        );
        assert_eq!(counters, PoolCounters::default());
    }
}
