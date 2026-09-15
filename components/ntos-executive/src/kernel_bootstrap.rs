//! Owned DriverEntry destination carried by the canonical kernel activation.

use super::*;
use nt_user_host::provider_kernel_pump::{
    KernelProviderPumpAttempt, KernelProviderPumpDisposition, KernelProviderPumpFacts,
    KernelProviderPumpProgress, PumpProgressError,
};
use nt_user_host::provider_kernel_wait::{KernelProviderWaitRecipient, KernelProviderWaitState};

pub(super) struct DriverEntryRecipient {
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
    pub(super) fn new(channel: spawn_hosts::PumpChannel) -> Result<Self, u32> {
        Ok(Self {
            wait: KernelProviderWaitState::new(channel.reply_cap).map_err(pump_error)?,
            channel,
            observation: None,
        })
    }

    pub(super) fn matches(&self, channel: &spawn_hosts::PumpChannel) -> bool {
        channel_binding(&self.channel) == channel_binding(channel)
            && self.channel.pml4 == channel.pml4
            && self.channel.shared_va == channel.shared_va
            && self.channel.dispatch_label == channel.dispatch_label
    }

    pub(super) fn begin_initial(
        &mut self,
        caller: KernelProviderCaller,
    ) -> Result<(spawn_hosts::PumpChannel, KernelProviderPumpAttempt), u32> {
        let attempt = self.wait.begin_initial().map_err(pump_error)?;
        Ok((self.execution_channel(caller), attempt))
    }

    pub(super) fn execution_channel(&self, caller: KernelProviderCaller) -> spawn_hosts::PumpChannel {
        let mut channel = self.channel;
        channel.kernel_caller = Some(caller);
        channel.caps.kernel_irq_yield = true;
        channel
    }

    pub(super) fn begin_receive_after_yield(
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
        let attempt = self
            .wait
            .begin_receive_after_yield()
            .map_err(pump_error)?;
        Ok((self.execution_channel(caller), attempt, previous))
    }

    pub(super) fn observe(
        &mut self,
        attempt: &mut KernelProviderPumpAttempt,
        pump: spawn_hosts::PumpResult,
        facts: KernelProviderPumpFacts,
        returned_status: Option<u32>,
    ) -> Result<(), u32> {
        let disposition = self
            .wait
            .observe(attempt, facts, returned_status)
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

    pub(super) fn captured_wait(
        &self,
    ) -> Option<nt_user_host::provider_kernel_activation::KernelProviderWaitCapture> {
        self.wait.captured_wait()
    }

    pub(super) fn observation(&self) -> Option<spawn_hosts::PumpResult> {
        self.observation
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
        current_win32k_provider_domain().is_some_and(|provider| {
            provider.domain == owner.provider_domain
                && provider.generation == owner.provider_generation
        }) && win32k_glue::win32k_physical_lane_for_channel(
            self.channel.tcb,
            self.channel.fault_ep,
            self.channel.reply_cap,
        )
        .is_some_and(|lane| {
            owner.caller == nt_component_suspension::SuspensionCaller::Kernel { lane }
                && component_execution_lane_is_idle(lane)
                && (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).binding(lane)
                    == Ok(caller.binding())
        })
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
