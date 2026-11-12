//! Owned kernel-job destinations carried by canonical provider activations.

use super::*;
use nt_user_host::provider_kernel_pump::{
    KernelProviderPumpAttempt, KernelProviderPumpDisposition, KernelProviderPumpFacts,
    KernelProviderPumpProgress, PumpProgressError,
};
use nt_user_host::provider_kernel_wait::{KernelProviderWaitRecipient, KernelProviderWaitState};

pub(super) enum KernelJobDestination {
    DriverEntry,
    Executive(alloc::sync::Arc<AtomicU64>),
}

pub(super) struct KernelJobRecipient {
    // Physical layout template only; Reply is resolved from the live dispatch at each entry.
    channel: spawn_hosts::PumpChannel,
    wait: KernelProviderWaitState,
    observation: Option<spawn_hosts::PumpResult>,
    refusal: KernelCaptureRefusalSlot,
    destination: KernelJobDestination,
    ps_retirement: Option<(u32, nt_user_host::provider_ps_retirement::PsRetirementTarget)>,
}

/// Inline storage belongs to this activation before any native Call. A refused labelled Call
/// remains here with its non-copyable attempt and both pre-entry and observed Reply snapshots.
#[allow(dead_code)] // Retained for exact-owner diagnostics; never replayed.
enum KernelCaptureRefusalSlot {
    Available,
    Reserved {
        caller: KernelProviderCaller,
        entry_reply: u64,
    },
    Observed {
        caller: KernelProviderCaller,
        entry_reply: u64,
    },
    Retained {
        caller: KernelProviderCaller,
        attempt: KernelProviderPumpAttempt,
        channel: spawn_hosts::PumpChannel,
        pump: Option<spawn_hosts::PumpResult>,
        entry_reply: u64,
        status: u32,
        resume: Option<KernelResumeAuthority>,
    },
}

/// The selected wait's authority survives a pre-Call adapter refusal and a later uncertain
/// physical observation. A scheduler receive has the capture but no new selection ticket.
pub(super) struct KernelResumeAuthority {
    pub capture: nt_user_host::provider_kernel_activation::KernelProviderWaitCapture,
    pub selection: Option<nt_component_suspension::SuspensionResume<ComponentSuspensionCompletion>>,
}

impl KernelProviderWaitRecipient for KernelJobRecipient {
    fn kernel_wait_state(&mut self) -> &mut KernelProviderWaitState {
        &mut self.wait
    }
}

fn pump_error(error: PumpProgressError) -> u32 {
    match error {
        PumpProgressError::IdentityExhausted => nt_process::STATUS_INSUFFICIENT_RESOURCES,
        _ => nt_process::STATUS_INVALID_PARAMETER,
    }
}

impl KernelJobRecipient {
    pub(super) fn new(mut channel: spawn_hosts::PumpChannel) -> Result<Self, u32> {
        let wait = KernelProviderWaitState::new(channel.reply_cap).map_err(pump_error)?;
        channel.reply_cap = 0;
        Ok(Self {
            wait,
            channel,
            observation: None,
            refusal: KernelCaptureRefusalSlot::Available,
            destination: KernelJobDestination::DriverEntry,
            ps_retirement: None,
        })
    }

    pub(super) fn executive(
        channel: spawn_hosts::PumpChannel,
        result: alloc::sync::Arc<AtomicU64>,
    ) -> Result<Self, u32> {
        let mut recipient = Self::new(channel)?;
        recipient.destination = KernelJobDestination::Executive(result);
        Ok(recipient)
    }

    pub(super) fn is_driver_entry(&self) -> bool {
        matches!(self.destination, KernelJobDestination::DriverEntry)
    }

    pub(super) fn retain_ps_retirement(
        &mut self,
        pi: u32,
        target: nt_user_host::provider_ps_retirement::PsRetirementTarget,
    ) {
        self.ps_retirement = Some((pi, target));
    }

    pub(super) fn release_ps_retirement(&mut self, pm: &mut nt_process::ProcessManager) -> Result<(), u32> {
        if let Some((_, target)) = self.ps_retirement.as_mut() {
            target.release(pm)?;
        }
        self.ps_retirement = None;
        Ok(())
    }

    pub(super) fn ps_retirement(&self) -> Option<(u32, &nt_user_host::provider_ps_retirement::PsRetirementTarget)> {
        self.ps_retirement.as_ref().map(|(pi, target)| (*pi, target))
    }

    pub(super) fn return_status_offset(&self) -> u64 {
        if self.is_driver_entry() { win32k_subsystem::SH_DE_STATUS }
        else { win32k_subsystem::SH_REQ_STATUS }
    }

    pub(super) fn matches(&self, channel: &spawn_hosts::PumpChannel) -> bool {
        self.channel.tcb == channel.tcb
            && self.channel.fault_ep == channel.fault_ep
            && self.channel.pml4 == channel.pml4
            && self.channel.shared_va == channel.shared_va
            && self.channel.dispatch_label == channel.dispatch_label
            && self.channel.client_pi == channel.client_pi
            && self.channel.client_generation == channel.client_generation
            && self.channel.caps.client_attach == channel.caps.client_attach
    }

    pub(super) fn completion_label(&self) -> u64 {
        self.channel.dispatch_label
    }

    pub(super) unsafe fn begin_initial(
        &mut self,
        caller: KernelProviderCaller,
    ) -> Result<(spawn_hosts::PumpChannel, KernelProviderPumpAttempt), u32> {
        let channel = self.execution_channel(caller)?;
        self.reserve_capture_refusal(caller, &channel)?;
        let attempt = match self.wait.begin_initial() {
            Ok(attempt) => attempt,
            Err(error) => {
                self.refusal = KernelCaptureRefusalSlot::Available;
                return Err(pump_error(error));
            }
        };
        Ok((channel, attempt))
    }

    /// Reserve the existing inline row before an entered pump can observe an untrusted Call.
    pub(super) fn reserve_capture_refusal(
        &mut self,
        caller: KernelProviderCaller,
        channel: &spawn_hosts::PumpChannel,
    ) -> Result<(), u32> {
        if !matches!(&self.refusal, KernelCaptureRefusalSlot::Available)
            || channel.kernel_caller != Some(caller)
            || channel.reply_cap == 0
            || !self.matches(channel)
        {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        self.refusal = KernelCaptureRefusalSlot::Reserved {
            caller,
            entry_reply: channel.reply_cap,
        };
        Ok(())
    }

    /// Scheduler work may adopt an authenticated interim Call before the receive half starts.
    /// Rebind this pre-entry reservation to the newly resolved canonical Reply, preserving the
    /// original activation and physical channel identity.
    pub(super) fn rebind_reserved_reply(
        &mut self,
        caller: KernelProviderCaller,
        channel: &spawn_hosts::PumpChannel,
    ) -> Result<(), u32> {
        let matches_channel = self.matches(channel);
        let KernelCaptureRefusalSlot::Reserved { caller: reserved, entry_reply } =
            &mut self.refusal
        else { return Err(nt_process::STATUS_INVALID_HANDLE); };
        if *reserved != caller || channel.kernel_caller != Some(caller)
            || channel.reply_cap == 0 || !matches_channel
        {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        *entry_reply = channel.reply_cap;
        Ok(())
    }

    /// Move the complete returned pump into its pre-reserved row before any physical route or
    /// activation revalidation. The caller's progress remains Invoking, forbidding another entry.
    pub(super) fn retain_capture_refusal(
        &mut self,
        caller: KernelProviderCaller,
        attempt: KernelProviderPumpAttempt,
        channel: spawn_hosts::PumpChannel,
        pump: spawn_hosts::PumpResult,
        resume: Option<KernelResumeAuthority>,
    ) -> u32 {
        let refusal = pump.provider_wait_capture_refusal
            .expect("kernel refusal retention requires the labelled Call observation");
        let status = match refusal.reason {
            spawn_hosts::ProviderWaitCaptureRefusalReason::BadBadge =>
                nt_process::STATUS_INVALID_PARAMETER,
            spawn_hosts::ProviderWaitCaptureRefusalReason::MissingLanePage =>
                nt_process::STATUS_INVALID_HANDLE,
        };
        let status = if refusal.tcb == channel.tcb
            && refusal.fault_ep == channel.fault_ep
            && refusal.reply_cap == pump.reply_cap
            && pump.reply_cap != 0
        { status } else { nt_process::STATUS_INVALID_HANDLE };
        self.retain_uncertain_pump(caller, attempt, channel, Some(pump), resume, status)
    }

    /// A pre-Call error retains the selected attempt/continuation without inventing a return.
    /// A post-Call error moves the full pump into this row. If observe() already stored that
    /// pump, take its canonical recipient slot rather than copying a second authority.
    pub(super) fn retain_uncertain_pump(
        &mut self,
        caller: KernelProviderCaller,
        attempt: KernelProviderPumpAttempt,
        channel: spawn_hosts::PumpChannel,
        pump: Option<spawn_hosts::PumpResult>,
        resume: Option<KernelResumeAuthority>,
        status: u32,
    ) -> u32 {
        let (entry_reply, observed, identity_ok) = match &self.refusal {
            KernelCaptureRefusalSlot::Available =>
                (channel.reply_cap, false, false),
            KernelCaptureRefusalSlot::Reserved { caller: reserved, entry_reply } =>
                (*entry_reply, false, *reserved == caller),
            KernelCaptureRefusalSlot::Observed { caller: reserved, entry_reply } =>
                (*entry_reply, true, *reserved == caller),
            _ => panic!("kernel provider stop lost its pre-entry owner"),
        };
        let retained_pump = if observed {
            Some(self.observation.take().expect("observed kernel pump lost its result"))
        } else {
            pump
        };
        let identity_ok = identity_ok && channel.kernel_caller == Some(caller)
            && channel.reply_cap == entry_reply;
        self.refusal = KernelCaptureRefusalSlot::Retained {
            caller, attempt, channel, pump: retained_pump, entry_reply,
            status, resume,
        };
        if identity_ok { status } else { nt_process::STATUS_INVALID_HANDLE }
    }

    /// Release only after the result and any provider request are safely observed.
    pub(super) fn finish_observation(&mut self, caller: KernelProviderCaller) -> Result<(), u32> {
        if !matches!(&self.refusal,
            KernelCaptureRefusalSlot::Observed { caller: observed, .. } if *observed == caller)
        {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        self.refusal = KernelCaptureRefusalSlot::Available;
        Ok(())
    }

    pub(super) unsafe fn execution_channel(
        &self,
        caller: KernelProviderCaller,
    ) -> Result<spawn_hosts::PumpChannel, u32> {
        let binding = kernel_provider_current_binding(caller)?;
        if binding.executor_id != self.channel.tcb
            || binding.receive_endpoint != self.channel.fault_ep
        {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let mut channel = self.channel;
        channel.reply_cap = binding.reply_object;
        channel.kernel_caller = Some(caller);
        channel.caps.kernel_irq_yield = true;
        Ok(channel)
    }

    pub(super) unsafe fn begin_receive_after_yield(
        &mut self,
        caller: KernelProviderCaller,
    ) -> Result<
        (
            spawn_hosts::PumpChannel,
            KernelProviderPumpAttempt,
            spawn_hosts::PumpResult,
        ),
        u32,
    > {
        let previous = self
            .observation
            .ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
        let channel = self.execution_channel(caller)?;
        self.reserve_capture_refusal(caller, &channel)?;
        let attempt = match self.wait.begin_receive_after_yield() {
            Ok(attempt) => attempt,
            Err(error) => {
                self.refusal = KernelCaptureRefusalSlot::Available;
                return Err(pump_error(error));
            }
        };
        Ok((channel, attempt, previous))
    }

    pub(super) fn observe(
        &mut self,
        attempt: &mut KernelProviderPumpAttempt,
        pump: spawn_hosts::PumpResult,
        facts: KernelProviderPumpFacts,
        returned_status: Option<u32>,
        current_reply: u64,
    ) -> Result<(), u32> {
        if !matches!(&self.refusal, KernelCaptureRefusalSlot::Reserved { .. }) {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let disposition = self
            .wait
            .observe_current(attempt, facts, returned_status, current_reply)
            .map_err(pump_error)?;
        self.observation = Some(pump);
        let (caller, entry_reply) = match &self.refusal {
            KernelCaptureRefusalSlot::Reserved { caller, entry_reply } => (*caller, *entry_reply),
            _ => unreachable!("checked pre-entry reservation changed during observation"),
        };
        // Keep the reservation until provider request capture also succeeds. An error from
        // that later step moves this canonical observation into the uncertainty row.
        self.refusal = KernelCaptureRefusalSlot::Observed { caller, entry_reply };
        if disposition == KernelProviderPumpDisposition::Invalid {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    pub(super) fn observed_return(&self) -> Option<u32> {
        match self.wait.progress().disposition() {
            Some(KernelProviderPumpDisposition::Returned(status)) => Some(status),
            _ => None,
        }
    }

    pub(super) fn progress(&self) -> &KernelProviderPumpProgress {
        self.wait.progress()
    }

    pub(super) fn stopped_outcome(
        &self,
    ) -> Result<nt_user_host::provider_kernel_wait::KernelProviderStoppedOutcome, u32> {
        self.wait.stopped_outcome()
    }

    pub(super) fn observation(&self) -> Option<spawn_hosts::PumpResult> {
        self.observation
    }

    pub(super) fn deliver_terminal_return(
        &mut self,
        terminal: nt_component_suspension::TerminalIdentity,
        status: u32,
    ) -> Result<(), u32> {
        self.wait.deliver_terminal_return(terminal, status)
    }

    pub(super) fn delivered_terminal_return(
        &self,
        terminal: nt_component_suspension::TerminalIdentity,
        status: u32,
    ) -> bool {
        self.wait.delivered_terminal_return(terminal, status)
    }

    pub(super) fn retain_provider_wait(
        &mut self,
        request: nt_provider_wait::ProviderWaitRequest,
        capture: Result<nt_user_host::provider_kernel_activation::KernelProviderWaitCapture, u32>,
    ) -> Result<(), u32> {
        self.wait.retain_provider_wait(request, capture)
    }

    pub(super) unsafe fn can_initialize(&self, caller: KernelProviderCaller) -> bool {
        let owner = caller.owner();
        let lane = caller.dispatch().lane();
        let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
        let Ok(binding) = lanes.binding(lane) else {
            return false;
        };
        current_win32k_provider_domain().is_some_and(|provider| {
            provider.domain == owner.provider_domain
                && provider.generation == owner.provider_generation
        }) && binding.executor_id == caller.executor_id()
            && binding.receive_endpoint == caller.receive_endpoint()
            && binding.executor_id == self.channel.tcb
            && binding.receive_endpoint == self.channel.fault_ep
            && win32k_glue::win32k_physical_lane_for_channel(
                binding.executor_id, binding.receive_endpoint, binding.reply_object,
            ) == Some(lane)
            && component_execution_lane_is_idle(lane)
            && lanes.active_dispatch_identity(lane) == Ok(None)
    }
}

/// Non-copyable ownership delivered only by successful canonical completion acknowledgment.
pub(crate) struct KernelJobCompletion {
    status: i32,
    recipient: KernelJobRecipient,
}

pub(super) enum KernelJobInitialization {
    Complete(bool),
    Pending(KernelJobCompletion, win32k_glue::Win32kBootstrapPending),
    Failed(KernelJobCompletion),
}

impl KernelJobCompletion {
    pub(super) fn new(status: u32, recipient: KernelJobRecipient) -> Self {
        Self {
            status: status as i32,
            recipient,
        }
    }

    /// Readiness is the initiating bootstrap consumer's work, not a generic Reply effect.
    pub(crate) unsafe fn initialize(mut self) -> KernelJobInitialization {
        let recipient = &mut self.recipient;
        let executive_result = match &recipient.destination {
            KernelJobDestination::Executive(result) => Some(result.clone()),
            KernelJobDestination::DriverEntry => None,
        };
        if let Some(result) = executive_result {
            if recipient.ps_retirement.is_some() {
                // The completion ACK transferred this exact recipient; target Ps references
                // cannot be released on a mere provider return or reply observation.
                if crate::service_sec_image::with_provider_process_manager(|pm| {
                    recipient.release_ps_retirement(pm)
                }).is_err() {
                    crate::park();
                }
            }
            // This destination receives the retained result only after the activation ACK
            // transferred the recipient and released its canonical requestor references.
            result.store((1u64 << 32) | u64::from(self.status as u32), Ordering::Release);
            return KernelJobInitialization::Complete(true);
        }
        if self.status < 0 {
            return KernelJobInitialization::Complete(false);
        }
        let channel = recipient.channel;
        WIN32K_FAULT_EP.store(channel.fault_ep, Ordering::Relaxed);
        WIN32K_HOST_PML4.store(channel.pml4, Ordering::Relaxed);
        match win32k_glue::initialize_win32k_bootstrap_lane(channel.pml4) {
            win32k_glue::Win32kBootstrapStartup::Ready => {}
            win32k_glue::Win32kBootstrapStartup::Pending(ticket) => {
                return KernelJobInitialization::Pending(self, ticket);
            }
            win32k_glue::Win32kBootstrapStartup::Failed => {
                return KernelJobInitialization::Failed(self);
            }
        }
        report_win32k_bootstrap_display();
        KernelJobInitialization::Complete(true)
    }

    pub(crate) unsafe fn resume(
        self,
        pending: win32k_glue::Win32kBootstrapPending,
    ) -> KernelJobInitialization {
        match win32k_glue::resume_win32k_bootstrap_lane(pending) {
            win32k_glue::Win32kBootstrapStartup::Ready => {
                report_win32k_bootstrap_display();
                KernelJobInitialization::Complete(true)
            }
            win32k_glue::Win32kBootstrapStartup::Pending(ticket) => {
                KernelJobInitialization::Pending(self, ticket)
            }
            win32k_glue::Win32kBootstrapStartup::Failed => KernelJobInitialization::Failed(self),
        }
    }
}

unsafe fn report_win32k_bootstrap_display() {
        // HARDWARE\\DEVICEMAP\\VIDEO is still published by the real started videoprt miniport.
        if let Some(display_spec) = system_hive_display_driver_spec() {
            let view = display_spec.win32k_spec();
            print_str(b"[win32k-svc] display service=");
            print_str(display_spec.service_name());
            print_str(b" driver=");
            print_str(view.display_driver_leaf);
            print_str(b" description=");
            print_str(view.device_description);
            print_str(b" mode=");
            print_u64(view.mode.width as u64);
            print_str(b"x");
            print_u64(view.mode.height as u64);
            print_str(b" stride=");
            print_u64(view.mode.stride as u64);
            print_str(b" size=0x");
            print_hex(view.framebuffer_size as u32);
            print_str(b"\n");
        } else {
            print_str(b"[win32k-svc] no loadable display Device0 in SYSTEM hive and ReactOS FS\n");
        }
}
