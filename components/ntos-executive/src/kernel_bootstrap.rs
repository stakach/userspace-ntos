//! Owned DriverEntry destination carried by the canonical kernel activation.

use super::*;
use nt_user_host::provider_kernel_pump::{
    KernelProviderPumpAttempt, KernelProviderPumpDisposition, KernelProviderPumpFacts,
    KernelProviderPumpProgress, PumpProgressError,
};
use nt_user_host::provider_kernel_wait::{KernelProviderWaitRecipient, KernelProviderWaitState};

pub(super) struct DriverEntryRecipient {
    // Physical layout template only; Reply is resolved from the live dispatch at each entry.
    channel: spawn_hosts::PumpChannel,
    wait: KernelProviderWaitState,
    observation: Option<spawn_hosts::PumpResult>,
}

impl KernelProviderWaitRecipient for DriverEntryRecipient {
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

impl DriverEntryRecipient {
    pub(super) fn new(mut channel: spawn_hosts::PumpChannel) -> Result<Self, u32> {
        let wait = KernelProviderWaitState::new(channel.reply_cap).map_err(pump_error)?;
        channel.reply_cap = 0;
        Ok(Self {
            wait,
            channel,
            observation: None,
        })
    }

    pub(super) fn matches(&self, channel: &spawn_hosts::PumpChannel) -> bool {
        self.channel.tcb == channel.tcb
            && self.channel.fault_ep == channel.fault_ep
            && self.channel.pml4 == channel.pml4
            && self.channel.shared_va == channel.shared_va
            && self.channel.dispatch_label == channel.dispatch_label
    }

    pub(super) unsafe fn begin_initial(
        &mut self,
        caller: KernelProviderCaller,
    ) -> Result<(spawn_hosts::PumpChannel, KernelProviderPumpAttempt), u32> {
        let channel = self.execution_channel(caller)?;
        let attempt = self.wait.begin_initial().map_err(pump_error)?;
        Ok((channel, attempt))
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
        let attempt = self
            .wait
            .begin_receive_after_yield()
            .map_err(pump_error)?;
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
        let disposition = self
            .wait
            .observe_current(attempt, facts, returned_status, current_reply)
            .map_err(pump_error)?;
        self.observation = Some(pump);
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
pub(crate) struct DriverEntryCompletion {
    status: i32,
    recipient: DriverEntryRecipient,
}

impl DriverEntryCompletion {
    pub(super) fn new(status: u32, recipient: DriverEntryRecipient) -> Self {
        Self {
            status: status as i32,
            recipient,
        }
    }

    /// Readiness is the initiating bootstrap consumer's work, not a generic Reply effect.
    pub(crate) unsafe fn initialize(self) -> bool {
        if self.status < 0 {
            return false;
        }
        let channel = self.recipient.channel;
        WIN32K_FAULT_EP.store(channel.fault_ep, Ordering::Relaxed);
        WIN32K_HOST_PML4.store(channel.pml4, Ordering::Relaxed);
        if !win32k_glue::initialize_win32k_physical_lane(channel.pml4) {
            panic!("win32k secondary execution lane failed its ready handshake");
        }
        register_win32k_gdi_loader(channel.pml4);
        load_win32k_static_import_drivers(channel.pml4);
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
        true
    }
}
