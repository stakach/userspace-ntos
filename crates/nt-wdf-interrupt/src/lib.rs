//! # `nt-wdf-interrupt` — the WDFINTERRUPT object
//!
//! A WDF interrupt wraps a HAL interrupt line (spec: NT KMDF Hardware Extensions, §7).
//! `WdfInterruptCreate` records intent (the ISR/DPC callbacks); the framework connects the
//! underlying HAL interrupt after `EvtDevicePrepareHardware` succeeds (§7.4). A HAL
//! interrupt only reaches the driver's `EvtInterruptIsr` while the interrupt is **active**
//! (connected + enabled) — an out-of-D0 or disabled interrupt drops it (§14.3). Inside the
//! ISR the driver latches a framework DPC with `WdfInterruptQueueDpcForIsr` (once until it
//! runs); the dispatcher later invokes `EvtInterruptDpc`.
//!
//! This is the host-testable state machine: it returns the driver callback pointers for the
//! Driver Host to invoke in driver context — it never calls the driver itself. `no_std`.

#![no_std]

/// The callbacks + policy a driver supplies in `WDF_INTERRUPT_CONFIG` (spec §7.4), as
/// function pointers (0 = not supplied).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdfInterruptConfig {
    pub evt_isr: u64,
    pub evt_dpc: u64,
    pub evt_enable: u64,
    pub evt_disable: u64,
    pub automatic_serialization: bool,
}

/// A WDFINTERRUPT's runtime state.
#[derive(Copy, Clone, Debug)]
pub struct WdfInterrupt {
    config: WdfInterruptConfig,
    connected: bool,
    enabled: bool,
    dpc_queued: bool,
    interrupt_count: u64,
    dpc_count: u64,
}

impl WdfInterrupt {
    /// `WdfInterruptCreate` — record the config; not yet connected to the HAL (§7.4).
    pub fn new(config: WdfInterruptConfig) -> Self {
        Self {
            config,
            connected: false,
            enabled: false,
            dpc_queued: false,
            interrupt_count: 0,
            dpc_count: 0,
        }
    }

    /// The ISR callback (never null for a valid interrupt — `WdfInterruptCreate` requires it).
    pub fn evt_isr(&self) -> u64 {
        self.config.evt_isr
    }
    pub fn is_connected(&self) -> bool {
        self.connected
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    /// Active = connected to the HAL and enabled; only then do injected interrupts deliver.
    pub fn is_active(&self) -> bool {
        self.connected && self.enabled
    }
    pub fn interrupt_count(&self) -> u64 {
        self.interrupt_count
    }
    pub fn dpc_count(&self) -> u64 {
        self.dpc_count
    }

    /// The framework connects the HAL interrupt after PrepareHardware (§7.4). KMDF enables
    /// interrupts as part of D0 entry, so connecting also enables in v0.2.
    pub fn connect(&mut self) {
        self.connected = true;
        self.enabled = true;
    }

    /// `WdfInterruptEnable` — connect if needed, mark enabled, return `EvtInterruptEnable`
    /// (0 if none) for the Driver Host to invoke (§7.8).
    pub fn enable(&mut self) -> u64 {
        self.connected = true;
        self.enabled = true;
        self.config.evt_enable
    }

    /// `WdfInterruptDisable` — mark disabled, drop future injected interrupts, return
    /// `EvtInterruptDisable` (0 if none) (§7.8).
    pub fn disable(&mut self) -> u64 {
        self.enabled = false;
        self.config.evt_disable
    }

    /// A HAL interrupt fired (spec §7.5). If active, bump the count + return the ISR callback
    /// to invoke; otherwise `None` — the interrupt is dropped (disabled / out of D0, §14.3).
    pub fn on_hardware_interrupt(&mut self) -> Option<u64> {
        if self.is_active() {
            self.interrupt_count += 1;
            Some(self.config.evt_isr)
        } else {
            None
        }
    }

    /// `WdfInterruptQueueDpcForIsr` — latch a framework DPC. Returns `true` if newly queued,
    /// `false` if one is already pending (§7.5).
    pub fn queue_dpc_for_isr(&mut self) -> bool {
        if self.dpc_queued {
            false
        } else {
            self.dpc_queued = true;
            true
        }
    }

    /// DPC delivery (spec §7.6): if a DPC is latched, clear it, bump the count, and return
    /// `EvtInterruptDpc` (0 if none) for the dispatcher to invoke. `None` if nothing queued.
    pub fn take_dpc(&mut self) -> Option<u64> {
        if self.dpc_queued {
            self.dpc_queued = false;
            self.dpc_count += 1;
            Some(self.config.evt_dpc)
        } else {
            None
        }
    }

    pub fn dpc_pending(&self) -> bool {
        self.dpc_queued
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> WdfInterruptConfig {
        WdfInterruptConfig {
            evt_isr: 0x1500,
            evt_dpc: 0x1600,
            automatic_serialization: true,
            ..Default::default()
        }
    }

    #[test]
    fn inactive_until_connected_and_enabled() {
        let mut i = WdfInterrupt::new(cfg());
        assert!(!i.is_active());
        // Before connect, an injected interrupt is dropped.
        assert_eq!(i.on_hardware_interrupt(), None);
        i.connect();
        assert!(i.is_active());
        assert_eq!(i.on_hardware_interrupt(), Some(0x1500));
        assert_eq!(i.interrupt_count(), 1);
    }

    #[test]
    fn isr_queues_dpc_once_then_dpc_runs() {
        let mut i = WdfInterrupt::new(cfg());
        i.connect();
        i.on_hardware_interrupt().unwrap();
        // ISR latches a DPC — only once until it runs.
        assert!(i.queue_dpc_for_isr());
        assert!(!i.queue_dpc_for_isr());
        assert!(i.dpc_pending());
        // DPC delivery clears the latch + returns EvtInterruptDpc.
        assert_eq!(i.take_dpc(), Some(0x1600));
        assert_eq!(i.dpc_count(), 1);
        assert!(!i.dpc_pending());
        assert_eq!(i.take_dpc(), None);
        // A second interrupt can re-latch.
        i.on_hardware_interrupt().unwrap();
        assert!(i.queue_dpc_for_isr());
    }

    #[test]
    fn disable_drops_interrupts() {
        let mut i = WdfInterrupt::new(cfg());
        i.connect();
        i.disable();
        assert!(!i.is_active());
        assert_eq!(i.on_hardware_interrupt(), None); // dropped in D3 / disabled (§14.3)
        i.enable();
        assert_eq!(i.on_hardware_interrupt(), Some(0x1500));
    }

    #[test]
    fn enable_disable_return_optional_callbacks() {
        let mut i = WdfInterrupt::new(WdfInterruptConfig {
            evt_isr: 0x1500,
            evt_enable: 0xEE,
            evt_disable: 0xDD,
            ..Default::default()
        });
        assert_eq!(i.enable(), 0xEE);
        assert_eq!(i.disable(), 0xDD);
    }
}
