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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessExitDispatchResult<E> {
    Completed,
    CallbackUncertain(E),
    AcknowledgementPending(E),
}

impl ProcessExitDispatchPlan {
    pub fn execute<E>(
        self,
        invoke: impl FnOnce(ProcessExitCall, HostedProcessNotifyTransport) -> Result<(), E>,
        acknowledge: impl FnOnce() -> Result<(), E>,
    ) -> ProcessExitDispatchResult<E> {
        if let Err(error) = invoke(self.call, self.transport) {
            return ProcessExitDispatchResult::CallbackUncertain(error);
        }
        match acknowledge() {
            Ok(()) => ProcessExitDispatchResult::Completed,
            Err(error) => ProcessExitDispatchResult::AcknowledgementPending(error),
        }
    }
}
