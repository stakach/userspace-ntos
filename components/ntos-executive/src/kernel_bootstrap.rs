//! Owned DriverEntry destination carried by the canonical kernel activation.

use super::*;

pub(super) struct DriverEntryRecipient {
    channel: spawn_hosts::PumpChannel,
    observation: Option<DriverEntryObservation>,
}

struct DriverEntryObservation {
    pump: spawn_hosts::PumpResult,
    // Captured before any shared-bank reuse. Only the activation's receipt authorizes delivery.
    returned_status: Option<u32>,
}

impl DriverEntryRecipient {
    pub(super) const fn new(channel: spawn_hosts::PumpChannel) -> Self {
        Self {
            channel,
            observation: None,
        }
    }

    pub(super) fn matches(&self, channel: &spawn_hosts::PumpChannel) -> bool {
        channel_binding(&self.channel) == channel_binding(channel)
            && self.channel.pml4 == channel.pml4
            && self.channel.shared_va == channel.shared_va
            && self.channel.dispatch_label == channel.dispatch_label
    }

    pub(super) fn initial_channel(
        &self,
        caller: KernelProviderCaller,
    ) -> Result<spawn_hosts::PumpChannel, u32> {
        if self.observation.is_some() {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        let mut channel = self.channel;
        channel.kernel_caller = Some(caller);
        Ok(channel)
    }

    pub(super) fn observe(
        &mut self,
        pump: spawn_hosts::PumpResult,
        returned_status: Option<u32>,
    ) -> Result<(), u32> {
        if self.observation.is_some() {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        self.observation = Some(DriverEntryObservation {
            pump,
            returned_status,
        });
        Ok(())
    }

    pub(super) fn observed_return(&self) -> Option<u32> {
        self.observation.as_ref().and_then(|observed| {
            observed
                .pump
                .completed
                .then_some(observed.returned_status)
                .flatten()
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

    pub(crate) const fn status(&self) -> i32 {
        self.status
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
