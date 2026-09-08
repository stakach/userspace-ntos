//! Per-runtime native application continuation ownership, separate from copied routing metadata.
//!
//! Register values are execution data, not authority or NT validation. The caller validates NT
//! context policy and the mechanism independently. As with ThreadLifetime, all PM arguments must
//! refer to the issuing ProcessManager; equal numeric IDs from another PM are not interchangeable.
//! The native runtime must retain this non-clone owner across IPC and refuse runtime retirement
//! while it is nonempty. No method exposes mutable frames or takes ownership out before IPC.
//! Termination cancellation requires a separate mechanism acknowledgement and is not supplied
//! here; termination never authorizes dropping a retained or ambiguous invocation.

use crate::thread_binding::ThreadBinding;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_process::{ProcessManager, ThreadLifetime, ThreadState};
use nt_syscall_abi::native_context::{
    exact_native_context_argc, validate_native_context_request, NativeCallContinuation,
    NATIVE_CONTEXT_MAX_ARGS,
};
use nt_user_callback::CallbackCorrelation;

const REGISTER_MASK: u64 = (1 << 18) - 1;
const MAX_DEPTH: usize = nt_user_callback::MAX_ACTIVE_CALLBACK_DEPTH + 1;
static LAST_OWNER: AtomicU64 = AtomicU64::new(0);

fn issue_owner(counter: &AtomicU64) -> Result<u64, NativeCallError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            last.checked_add(1)
        })
        .map(|last| last + 1)
        .map_err(|_| NativeCallError::Exhausted)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCallError {
    BindingChanged,
    LifetimeChanged,
    Terminated,
    Suspended,
    WrongCall,
    WrongAttempt,
    InvalidPhase,
    InvalidMask,
    CallbackChanged,
    DepthLimit,
    Allocation,
    Exhausted,
    StatusChanged,
    InvalidArguments,
    InvalidEnvelope,
    ServiceChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCallPhase {
    Active,
    Waiting,
    CallbackSuspended(CallbackCorrelation),
    RetryReady,
    AwaitingRetry,
    Ready(u32),
    InFlight(NativeCallOperation),
    Accepted(u32),
    Indeterminate(NativeCallOperation, u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCallOperation {
    Edit,
    Retry,
    Complete,
    Callback,
}

/// Mechanism evidence, not classification by status sign alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCallOutcome {
    Acknowledged,
    NotEntered(u32),
    RejectedNoEffects(u32),
    Indeterminate(u32),
}

/// Copied invocation data is not permission to execute it. Only the exact retained invocation
/// ticket can record an outcome; the adapter must revalidate its runtime and mechanism first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCallWork {
    Edit {
        values: [u64; 18],
        mask: u64,
    },
    Retry {
        original: NativeCallContinuation,
        arguments: NativeCallArguments,
    },
    Complete {
        registers: [u64; 18],
        status: u32,
        edited: bool,
    },
    Callback(CallbackCorrelation),
}

/// Immutable bounded argument snapshot, including arguments beyond the register transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCallArguments {
    words: [u64; NATIVE_CONTEXT_MAX_ARGS as usize],
    count: u8,
}

impl NativeCallArguments {
    fn capture(ssn: u32, arguments: &[u64]) -> Result<Self, NativeCallError> {
        let count = exact_native_context_argc(u64::from(ssn))
            .map_err(|_| NativeCallError::InvalidArguments)?;
        if arguments.len() != usize::from(count) {
            return Err(NativeCallError::InvalidArguments);
        }
        let mut words = [0; NATIVE_CONTEXT_MAX_ARGS as usize];
        words[..arguments.len()].copy_from_slice(arguments);
        Ok(Self { words, count })
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.words[..usize::from(self.count)]
    }
}

impl NativeCallWork {
    fn operation(self) -> NativeCallOperation {
        match self {
            Self::Edit { .. } => NativeCallOperation::Edit,
            Self::Retry { .. } => NativeCallOperation::Retry,
            Self::Complete { .. } => NativeCallOperation::Complete,
            Self::Callback(_) => NativeCallOperation::Callback,
        }
    }
}

/// Non-clone invocation ticket. Dropping it leaves the owner InFlight, never implicitly retryable.
///
/// ```compile_fail
/// use nt_user_host::native_call_owner::NativeCallInvocation;
/// fn duplicate(ticket: NativeCallInvocation) {
///     let _second_authority = ticket.clone();
/// }
/// ```
#[derive(Debug)]
pub struct NativeCallInvocation {
    owner: u64,
    call: u64,
    attempt: u64,
    work: NativeCallWork,
    consumed: bool,
}

impl NativeCallInvocation {
    pub const fn call_epoch(&self) -> u64 {
        self.call
    }
    pub const fn work(&self) -> &NativeCallWork {
        &self.work
    }
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    attempt: u64,
    previous: NativeCallPhase,
    work: NativeCallWork,
}

#[derive(Debug)]
struct Frame {
    epoch: u64,
    original: NativeCallContinuation,
    arguments: NativeCallArguments,
    logical: [u64; 18],
    edited: u64,
    phase: NativeCallPhase,
    pending: Option<Pending>,
    last_failure: Option<NativeCallOutcome>,
}

/// One durable owner for one exact runtime activation, including nested user callback calls.
///
/// ```compile_fail
/// use nt_user_host::native_call_owner::NativeCallOwner;
/// fn duplicate(owner: NativeCallOwner<()>) {
///     let _second_owner = owner.clone();
/// }
/// ```
#[derive(Debug)]
pub struct NativeCallOwner<R> {
    binding: ThreadBinding<R>,
    lifetime: ThreadLifetime,
    owner: u64,
    last_call: u64,
    last_attempt: u64,
    frames: Vec<Frame>,
}

impl<R: Copy + Eq> NativeCallOwner<R> {
    pub fn new(
        binding: ThreadBinding<R>,
        lifetime: ThreadLifetime,
        pm: &ProcessManager,
    ) -> Result<Self, NativeCallError> {
        if !binding.process.is_valid()
            || binding.tcb <= 1
            || binding.process.pid != lifetime.process_id()
            || binding.tid != u64::from(lifetime.thread_id())
        {
            return Err(NativeCallError::BindingChanged);
        }
        if !pm.validate_thread_lifetime(lifetime) {
            return Err(NativeCallError::LifetimeChanged);
        }
        let owner = issue_owner(&LAST_OWNER)?;
        Ok(Self {
            binding,
            lifetime,
            owner,
            last_call: 0,
            last_attempt: 0,
            frames: Vec::new(),
        })
    }

    fn validate(
        &self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
    ) -> Result<(), NativeCallError> {
        if binding != self.binding {
            return Err(NativeCallError::BindingChanged);
        }
        if !pm.validate_thread_lifetime(self.lifetime) {
            return Err(NativeCallError::LifetimeChanged);
        }
        Ok(())
    }

    fn live(&self, binding: ThreadBinding<R>, pm: &ProcessManager) -> Result<(), NativeCallError> {
        self.validate(binding, pm)?;
        if pm.thread(self.lifetime.thread_id()).unwrap().state == ThreadState::Terminated {
            return Err(NativeCallError::Terminated);
        }
        if pm.thread(self.lifetime.thread_id()).unwrap().state == ThreadState::Initialized {
            return Err(NativeCallError::InvalidPhase);
        }
        Ok(())
    }

    fn executable(
        &self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
    ) -> Result<(), NativeCallError> {
        self.live(binding, pm)?;
        let thread = pm.thread(self.lifetime.thread_id()).unwrap();
        if thread.suspend_count != 0 || thread.state == ThreadState::Suspended {
            return Err(NativeCallError::Suspended);
        }
        Ok(())
    }

    fn top(&self, epoch: u64) -> Result<&Frame, NativeCallError> {
        self.frames
            .last()
            .filter(|frame| frame.epoch == epoch)
            .ok_or(NativeCallError::WrongCall)
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
    pub fn depth(&self) -> usize {
        self.frames.len()
    }
    /// A correlation value only, not an invocation authority.
    pub fn current_epoch(&self) -> Option<u64> {
        self.frames.last().map(|frame| frame.epoch)
    }
    pub fn phase(&self, epoch: u64) -> Result<NativeCallPhase, NativeCallError> {
        Ok(self.top(epoch)?.phase)
    }
    pub fn last_failure(&self, epoch: u64) -> Result<Option<NativeCallOutcome>, NativeCallError> {
        Ok(self.top(epoch)?.last_failure)
    }
    /// Read-only retained proposal, including after an ambiguous operation. This is execution
    /// data for diagnosis/reconciliation, never permission to replay the original operation.
    pub fn pending_work(&self, epoch: u64) -> Result<Option<&NativeCallWork>, NativeCallError> {
        Ok(self
            .top(epoch)?
            .pending
            .as_ref()
            .map(|pending| &pending.work))
    }

    /// Snapshot all eighteen application words, including originally unselected volatile GPRs.
    pub fn logical_registers(
        &self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
    ) -> Result<[u64; 18], NativeCallError> {
        self.live(binding, pm)?;
        let frame = self.top(epoch)?;
        if !matches!(
            frame.phase,
            NativeCallPhase::Active
                | NativeCallPhase::Waiting
                | NativeCallPhase::Ready(_)
                | NativeCallPhase::RetryReady
        ) {
            return Err(NativeCallError::InvalidPhase);
        }
        Ok(frame.logical)
    }

    /// Admit a new call, or a nested call under the exact currently suspended callback.
    /// Allocation happens here before service execution, never after acceptance of an effect.
    pub fn admit(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        original: NativeCallContinuation,
        arguments: &[u64],
        callback: Option<CallbackCorrelation>,
    ) -> Result<u64, NativeCallError> {
        self.live(binding, pm)?;
        let arguments = NativeCallArguments::capture(original.service_number(), arguments)?;
        match (self.frames.last().map(|frame| frame.phase), callback) {
            (None, None) => {}
            (Some(NativeCallPhase::CallbackSuspended(expected)), Some(actual))
                if actual == expected => {}
            _ => return Err(NativeCallError::InvalidPhase),
        }
        if self.frames.len() >= MAX_DEPTH {
            return Err(NativeCallError::DepthLimit);
        }
        let epoch = self
            .last_call
            .checked_add(1)
            .ok_or(NativeCallError::Exhausted)?;
        self.frames
            .try_reserve(1)
            .map_err(|_| NativeCallError::Allocation)?;
        self.frames.push(Frame {
            epoch,
            logical: *original.registers(),
            original,
            arguments,
            edited: 0,
            phase: NativeCallPhase::Active,
            pending: None,
            last_failure: None,
        });
        self.last_call = epoch;
        Ok(epoch)
    }

    pub fn mark_waiting(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
    ) -> Result<(), NativeCallError> {
        self.live(binding, pm)?;
        if !matches!(
            self.top(epoch)?.phase,
            NativeCallPhase::Active | NativeCallPhase::Waiting
        ) {
            return Err(NativeCallError::InvalidPhase);
        }
        self.frames.last_mut().unwrap().phase = NativeCallPhase::Waiting;
        Ok(())
    }

    /// The actual wait/service owner supplies terminal success OR error. Ready does not wake a
    /// suspended thread and must remain retained until completion and local retirement succeed.
    pub fn ready(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
        status: u32,
    ) -> Result<(), NativeCallError> {
        self.live(binding, pm)?;
        match self.top(epoch)?.phase {
            NativeCallPhase::Active | NativeCallPhase::Waiting => {}
            NativeCallPhase::Ready(old) if old == status => return Ok(()),
            NativeCallPhase::Ready(_) => return Err(NativeCallError::StatusChanged),
            _ => return Err(NativeCallError::InvalidPhase),
        }
        self.frames.last_mut().unwrap().phase = NativeCallPhase::Ready(status);
        Ok(())
    }

    pub fn retry_ready(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
    ) -> Result<(), NativeCallError> {
        self.live(binding, pm)?;
        if !matches!(
            self.top(epoch)?.phase,
            NativeCallPhase::Waiting | NativeCallPhase::RetryReady
        ) {
            return Err(NativeCallError::InvalidPhase);
        }
        self.frames.last_mut().unwrap().phase = NativeCallPhase::RetryReady;
        Ok(())
    }

    fn begin(
        &mut self,
        epoch: u64,
        work: NativeCallWork,
    ) -> Result<NativeCallInvocation, NativeCallError> {
        let previous = self.top(epoch)?.phase;
        let attempt = self
            .last_attempt
            .checked_add(1)
            .ok_or(NativeCallError::Exhausted)?;
        let pending = Pending {
            attempt,
            previous,
            work,
        };
        let frame = self.frames.last_mut().unwrap();
        frame.pending = Some(pending);
        frame.phase = NativeCallPhase::InFlight(work.operation());
        self.last_attempt = attempt;
        Ok(NativeCallInvocation {
            owner: self.owner,
            call: epoch,
            attempt,
            work,
            consumed: false,
        })
    }

    /// Values have already passed NT context policy. This only checks the public GPR mask and
    /// commits the logical overlay AFTER the corresponding mechanism acknowledgement.
    pub fn begin_edit(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
        values: [u64; 18],
        mask: u64,
    ) -> Result<NativeCallInvocation, NativeCallError> {
        self.live(binding, pm)?;
        if mask & !REGISTER_MASK != 0 {
            return Err(NativeCallError::InvalidMask);
        }
        if !matches!(
            self.top(epoch)?.phase,
            NativeCallPhase::Active | NativeCallPhase::Waiting | NativeCallPhase::Ready(_)
        ) {
            return Err(NativeCallError::InvalidPhase);
        }
        self.begin(epoch, NativeCallWork::Edit { values, mask })
    }

    pub fn begin_retry(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
    ) -> Result<NativeCallInvocation, NativeCallError> {
        self.executable(binding, pm)?;
        let frame = self.top(epoch)?;
        if frame.phase != NativeCallPhase::RetryReady {
            return Err(NativeCallError::InvalidPhase);
        }
        self.begin(
            epoch,
            NativeCallWork::Retry {
                original: frame.original,
                arguments: frame.arguments,
            },
        )
    }

    /// Retry ingress uses retained capture and arguments, never a second user-memory read.
    /// The adapter authenticates the incoming thread and supplies its exact retained call epoch.
    pub fn admit_retry(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
        message_info: u64,
        ssn: u64,
    ) -> Result<(), NativeCallError> {
        self.live(binding, pm)?;
        let frame = self.top(epoch)?;
        if frame.phase != NativeCallPhase::AwaitingRetry {
            return Err(NativeCallError::InvalidPhase);
        }
        validate_native_context_request(message_info, ssn)
            .map_err(|_| NativeCallError::InvalidEnvelope)?;
        if ssn != u64::from(frame.original.service_number()) {
            return Err(NativeCallError::ServiceChanged);
        }
        self.frames.last_mut().unwrap().phase = NativeCallPhase::Active;
        Ok(())
    }

    /// Service dispatch after first admission or retry always uses this immutable argument set.
    pub fn arguments(
        &self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
    ) -> Result<&[u64], NativeCallError> {
        self.live(binding, pm)?;
        let frame = self.top(epoch)?;
        if frame.phase != NativeCallPhase::Active {
            return Err(NativeCallError::InvalidPhase);
        }
        Ok(frame.arguments.as_slice())
    }

    pub fn begin_completion(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
    ) -> Result<NativeCallInvocation, NativeCallError> {
        self.executable(binding, pm)?;
        let frame = self.top(epoch)?;
        let NativeCallPhase::Ready(status) = frame.phase else {
            return Err(NativeCallError::InvalidPhase);
        };
        let mut registers = frame.logical;
        registers[3] = u64::from(status);
        self.begin(
            epoch,
            NativeCallWork::Complete {
                registers,
                status,
                edited: frame.edited != 0,
            },
        )
    }

    pub fn begin_callback(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
        correlation: CallbackCorrelation,
    ) -> Result<NativeCallInvocation, NativeCallError> {
        self.executable(binding, pm)?;
        if self.top(epoch)?.phase != NativeCallPhase::Active {
            return Err(NativeCallError::InvalidPhase);
        }
        if usize::try_from(correlation.client_pi).ok() != Some(binding.pi)
            || correlation.client_tid != binding.tid
            || correlation.client_badge != binding.badge
            || self
                .frames
                .iter()
                .any(|frame| frame.phase == NativeCallPhase::CallbackSuspended(correlation))
        {
            return Err(NativeCallError::CallbackChanged);
        }
        if self.frames.len() >= MAX_DEPTH {
            return Err(NativeCallError::DepthLimit);
        }
        // A successful redirect must not be followed by an allocation failure admitting its call.
        self.last_call
            .checked_add(1)
            .ok_or(NativeCallError::Exhausted)?;
        self.frames
            .try_reserve(1)
            .map_err(|_| NativeCallError::Allocation)?;
        self.begin(epoch, NativeCallWork::Callback(correlation))
    }

    pub fn resume_callback(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
        correlation: CallbackCorrelation,
    ) -> Result<(), NativeCallError> {
        self.live(binding, pm)?;
        if self.top(epoch)?.phase != NativeCallPhase::CallbackSuspended(correlation) {
            return Err(NativeCallError::CallbackChanged);
        }
        self.frames.last_mut().unwrap().phase = NativeCallPhase::Active;
        Ok(())
    }

    /// Record only the exact outstanding ticket. Every rejection leaves owner and ticket intact.
    /// Successful mechanism completion remains Accepted until explicit local retirement.
    pub fn record(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        ticket: &mut NativeCallInvocation,
        outcome: NativeCallOutcome,
    ) -> Result<(), NativeCallError> {
        self.validate(binding, pm)?;
        if ticket.owner != self.owner || ticket.consumed {
            return Err(NativeCallError::WrongAttempt);
        }
        let frame = self.top(ticket.call)?;
        let pending = frame.pending.ok_or(NativeCallError::WrongAttempt)?;
        if pending.attempt != ticket.attempt
            || pending.work != ticket.work
            || frame.phase != NativeCallPhase::InFlight(ticket.work.operation())
        {
            return Err(NativeCallError::WrongAttempt);
        }
        let frame = self.frames.last_mut().unwrap();
        frame.phase = match outcome {
            NativeCallOutcome::Acknowledged => match pending.work {
                NativeCallWork::Edit { values, mask } => {
                    for (index, value) in values.into_iter().enumerate() {
                        if mask & (1 << index) != 0 {
                            frame.logical[index] = value;
                        }
                    }
                    frame.edited |= mask;
                    pending.previous
                }
                NativeCallWork::Retry { .. } => NativeCallPhase::AwaitingRetry,
                NativeCallWork::Complete { status, .. } => NativeCallPhase::Accepted(status),
                NativeCallWork::Callback(correlation) => {
                    NativeCallPhase::CallbackSuspended(correlation)
                }
            },
            NativeCallOutcome::NotEntered(_) | NativeCallOutcome::RejectedNoEffects(_) => {
                pending.previous
            }
            NativeCallOutcome::Indeterminate(status) => {
                NativeCallPhase::Indeterminate(ticket.work.operation(), status)
            }
        };
        frame.last_failure = (outcome != NativeCallOutcome::Acknowledged).then_some(outcome);
        if !matches!(outcome, NativeCallOutcome::Indeterminate(_)) {
            frame.pending = None;
        }
        ticket.consumed = true;
        Ok(())
    }

    /// Call only after the exact native reply-cap/local completion bookkeeping was retired.
    /// No IPC occurs here; failure before this acknowledgement leaves Accepted non-replayable.
    pub fn acknowledge_retirement(
        &mut self,
        binding: ThreadBinding<R>,
        pm: &ProcessManager,
        epoch: u64,
    ) -> Result<(), NativeCallError> {
        self.validate(binding, pm)?;
        if !matches!(self.top(epoch)?.phase, NativeCallPhase::Accepted(_)) {
            return Err(NativeCallError::InvalidPhase);
        }
        self.frames.pop();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
