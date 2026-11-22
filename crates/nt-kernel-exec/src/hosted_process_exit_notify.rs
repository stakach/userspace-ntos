//! Admission and argument projection for hosted `PsSetCreateProcessNotifyRoutineEx` callbacks.
//!
//! The driver host supplies a *live* loaded-image record to these functions. A callback address
//! is executable only when it lies within that exact image generation. Process Manager retains the
//! corresponding provider registration and EPROCESS until the host acknowledges its exit ticket.

/// Projection-only identity; the process-policy owner converts this into its registration type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedProcessNotifyOwner {
    pub image_base: u64,
    pub image_generation: u64,
}

/// Read-only view of a Process Manager ticket. The native adapter retains the original ticket
/// separately and acknowledges it only after the callback returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedProcessExitDelivery {
    pub owner: HostedProcessNotifyOwner,
    pub callback: u64,
    pub process_id: u32,
    pub process_object: u64,
}

/// One loaded provider image, captured from the host's exact publication record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedImageIdentity {
    pub run_base: u64,
    pub image_len: u64,
    pub publication_generation: u64,
}

impl HostedImageIdentity {
    /// Admit only a function pointer inside the published image. Checked arithmetic makes a
    /// wrapped image end invalid instead of accidentally authorizing an unrelated low address.
    pub fn owner_for_callback(self, callback: u64) -> Option<HostedProcessNotifyOwner> {
        let end = self.run_base.checked_add(self.image_len)?;
        if self.run_base == 0
            || self.image_len == 0
            || self.publication_generation == 0
            || callback < self.run_base
            || callback >= end
        {
            return None;
        }
        Some(HostedProcessNotifyOwner {
            image_base: self.run_base,
            image_generation: self.publication_generation,
        })
    }
}

/// The three Win64 callback arguments for `PCREATE_PROCESS_NOTIFY_ROUTINE_EX` on process exit.
/// The host invokes the target at PASSIVE_LEVEL in its owning provider domain. A null CreateInfo
/// is the documented exit signal; the EPROCESS is retained until invocation completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessExitCall {
    pub callback: u64,
    pub process_object: u64,
    pub process_id: u32,
    pub create_info: u64,
}

impl ProcessExitCall {
    pub fn for_delivery(
        delivery: HostedProcessExitDelivery,
        live_image: HostedImageIdentity,
    ) -> Option<Self> {
        if delivery.process_object == 0
            || live_image.owner_for_callback(delivery.callback)? != delivery.owner
        {
            return None;
        }
        Some(Self {
            callback: delivery.callback,
            process_object: delivery.process_object,
            process_id: delivery.process_id,
            create_info: 0,
        })
    }
}

/// Exact physical transport for the provider domain that owns the image. All fields must still
/// match at callback delivery; a numeric endpoint or image address alone is insufficient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedProcessNotifyTransport {
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub endpoint: u64,
    pub vspace: u64,
    pub shared: u64,
}

impl HostedProcessNotifyTransport {
    pub const fn is_valid(self) -> bool {
        self.domain_id != 0
            && self.domain_cookie != 0
            && self.endpoint != 0
            && self.vspace != 0
            && self.shared != 0
    }
}

/// Image and transport captured together when `PsSetCreateProcessNotifyRoutineEx` registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedProcessNotifyBinding {
    pub image: HostedImageIdentity,
    pub transport: HostedProcessNotifyTransport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessNotifyRegisterError<E> {
    InvalidBinding,
    Registration(E),
}

impl HostedProcessNotifyBinding {
    /// The caller's closure commits the owner to Process Manager. It is never called for an
    /// address outside the exact loaded image or for an incomplete physical transport.
    pub fn register<E>(
        self,
        callback: u64,
        register: impl FnOnce(HostedProcessNotifyOwner, u64) -> Result<(), E>,
    ) -> Result<(), ProcessNotifyRegisterError<E>> {
        if !self.transport.is_valid() {
            return Err(ProcessNotifyRegisterError::InvalidBinding);
        }
        let owner = self.image.owner_for_callback(callback)
            .ok_or(ProcessNotifyRegisterError::InvalidBinding)?;
        register(owner, callback).map_err(ProcessNotifyRegisterError::Registration)
    }

    /// The native host must resolve `live_binding` from its current provider registry, not from
    /// caller input. A stale domain cookie, image generation, or VA range refuses invocation.
    pub fn plan_exit(
        self,
        delivery: HostedProcessExitDelivery,
        live_binding: HostedProcessNotifyBinding,
    ) -> Option<ProcessExitDispatchPlan> {
        if self != live_binding || !self.transport.is_valid() {
            return None;
        }
        let call = ProcessExitCall::for_delivery(delivery, self.image)?;
        Some(ProcessExitDispatchPlan { call, transport: self.transport })
    }
}

/// Consuming this plan attempts one provider call. A failed/uncertain transport result leaves the
/// Process Manager ticket in flight, so the host may diagnose or retire it only by explicit policy.
#[derive(Debug, PartialEq, Eq)]
pub struct ProcessExitDispatchPlan {
    call: ProcessExitCall,
    transport: HostedProcessNotifyTransport,
}

/// How one provider call ended for its transport: returned, or still running in the provider
/// with `P` the host's continuation for it (#420).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackInvocation<P> {
    Returned,
    Running(P),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessExitDispatchResult<E, P = ()> {
    Completed,
    /// The callback is still running. Its ticket stays in flight; only
    /// [`RunningProcessExit::resume`] continues it, and no acknowledgement is made before it
    /// returns.
    CallbackRunning(RunningProcessExit<P>),
    CallbackUncertain(E),
    AcknowledgementPending(E),
}

/// A provider callback that has not returned yet, and owes its acknowledgement once it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "a running exit callback is owed its resume"]
pub struct RunningProcessExit<P> {
    running: P,
}

impl<P> RunningProcessExit<P> {
    /// Continue the callback once. The acknowledgement runs only on its true return.
    pub fn resume<E>(
        self,
        resume: impl FnOnce(P) -> Result<CallbackInvocation<P>, E>,
        acknowledge: impl FnOnce() -> Result<(), E>,
    ) -> ProcessExitDispatchResult<E, P> {
        settle(resume(self.running), acknowledge)
    }
}

fn settle<E, P>(
    invoked: Result<CallbackInvocation<P>, E>,
    acknowledge: impl FnOnce() -> Result<(), E>,
) -> ProcessExitDispatchResult<E, P> {
    match invoked {
        Err(error) => ProcessExitDispatchResult::CallbackUncertain(error),
        Ok(CallbackInvocation::Running(running)) =>
            ProcessExitDispatchResult::CallbackRunning(RunningProcessExit { running }),
        Ok(CallbackInvocation::Returned) => match acknowledge() {
            Ok(()) => ProcessExitDispatchResult::Completed,
            Err(error) => ProcessExitDispatchResult::AcknowledgementPending(error),
        },
    }
}

impl ProcessExitDispatchPlan {
    pub fn execute<E, P>(
        self,
        invoke: impl FnOnce(ProcessExitCall, HostedProcessNotifyTransport)
            -> Result<CallbackInvocation<P>, E>,
        acknowledge: impl FnOnce() -> Result<(), E>,
    ) -> ProcessExitDispatchResult<E, P> {
        settle(invoke(self.call, self.transport), acknowledge)
    }
}

/// What the host of a [`ProcessExitRow`] provides: Process Manager's tickets and the provider
/// transport.
pub trait ProcessExitHost<T, P> {
    type Error;
    /// Whether a callback may be entered in this turn. A refusal claims no ticket.
    fn may_enter(&mut self) -> bool;
    /// Claim the next ticket, once.
    fn claim(&mut self) -> Option<T>;
    /// Attempt the claimed ticket's one provider call.
    fn dispatch(&mut self, ticket: &T) -> ProcessExitDispatchResult<Self::Error, P>;
    /// Continue the ticket's running call once.
    fn resume(&mut self, ticket: &T, running: RunningProcessExit<P>)
        -> ProcessExitDispatchResult<Self::Error, P>;
    /// Acknowledge a completed ticket to Process Manager.
    fn complete(&mut self, ticket: T) -> Result<(), Self::Error>;
}

/// How one drain turn stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessExitDrain<E> {
    /// No ticket was waiting, or none may be entered in this turn.
    Idle,
    /// A callback is still running; no other ticket was claimed.
    Running,
    /// The ticket stays in flight: its callback was uncertain or its acknowledgement failed.
    Retained(E),
}

/// The host's one exit-callback row (#420). A callback that has not returned keeps its ticket
/// here; every drain resumes it before claiming any other ticket, and acknowledges it exactly
/// once, on its true return.
pub struct ProcessExitRow<T, P> {
    running: Option<(T, RunningProcessExit<P>)>,
}

impl<T, P> Default for ProcessExitRow<T, P> {
    fn default() -> Self { Self::new() }
}

impl<T, P> ProcessExitRow<T, P> {
    pub const fn new() -> Self { Self { running: None } }

    pub fn is_running(&self) -> bool { self.running.is_some() }

    pub fn drain<H: ProcessExitHost<T, P>>(&mut self, host: &mut H) -> ProcessExitDrain<H::Error> {
        if let Some((ticket, running)) = self.running.take() {
            if !host.may_enter() {
                self.running = Some((ticket, running));
                return ProcessExitDrain::Running;
            }
            let resumed = host.resume(&ticket, running);
            if let Some(stop) = self.settle(host, ticket, resumed) { return stop; }
        }
        loop {
            if !host.may_enter() { return ProcessExitDrain::Idle; }
            let Some(ticket) = host.claim() else { return ProcessExitDrain::Idle };
            let dispatched = host.dispatch(&ticket);
            if let Some(stop) = self.settle(host, ticket, dispatched) { return stop; }
        }
    }

    fn settle<H: ProcessExitHost<T, P>>(
        &mut self, host: &mut H, ticket: T, result: ProcessExitDispatchResult<H::Error, P>,
    ) -> Option<ProcessExitDrain<H::Error>> {
        match result {
            ProcessExitDispatchResult::Completed =>
                host.complete(ticket).err().map(ProcessExitDrain::Retained),
            ProcessExitDispatchResult::CallbackRunning(running) => {
                self.running = Some((ticket, running));
                Some(ProcessExitDrain::Running)
            }
            ProcessExitDispatchResult::CallbackUncertain(error)
            | ProcessExitDispatchResult::AcknowledgementPending(error) =>
                Some(ProcessExitDrain::Retained(error)),
        }
    }
}
