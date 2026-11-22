//! What the root's exclusive AddDevice turn does when it cannot continue its parked parent
//! (#420).
//!
//! NT fails a devnode whose AddDevice failed and keeps enumerating every other devnode:
//! ReactOS `PiCallDriverAddDevice` sets `CM_PROB_FAILED_ADD` on that devnode and returns the
//! failure, and `PiDevNodeStateMachine` skips devnodes with a problem. Only a broken root
//! invariant may end the service loop.

/// `CM_PROB_FAILED_ADD` (cfgmgr32.h): the devnode's AddDevice failed.
pub const CM_PROB_FAILED_ADD: u32 = 0x1F;
/// `DN_HAS_PROBLEM` (cfg.h): the devnode carries a problem code.
pub const DN_HAS_PROBLEM: u32 = 0x0000_0400;
/// `STATUS_UNSUCCESSFUL`: the status ReactOS reports for an AddDevice whose result the PnP
/// manager cannot obtain from the driver, alongside `CM_PROB_FAILED_ADD`.
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

/// Why the parked AddDevice turn stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootAddDeviceStop {
    /// The parent's selected child was quarantined, or the parent was refused with nothing
    /// left to retry: its AddDevice effect is uncertain.
    ParentRetained,
    /// The turn is owned by another parent than the one settling it.
    Settle,
    /// The parked parent's own timer or IRQ notification could not be acknowledged.
    Notification,
}

/// What the root does about a stopped AddDevice turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootAddDeviceStopAction {
    /// Fail the devnode with [`CM_PROB_FAILED_ADD`]. The uncertain parent keeps its Reply,
    /// banks and its driver's rows; the turn is released and the service loop continues.
    FailDevnode,
    /// A root invariant broke; the service loop cannot continue.
    Terminal,
}

pub const fn root_add_device_stop_action(stop: RootAddDeviceStop) -> RootAddDeviceStopAction {
    match stop {
        // The devnode's own AddDevice is uncertain: fence it, as NT fails the devnode.
        RootAddDeviceStop::ParentRetained => RootAddDeviceStopAction::FailDevnode,
        // Two parents claim one turn, or the root's own timer could not be acknowledged:
        // neither is about the devnode, and failing it would not repair the root.
        RootAddDeviceStop::Settle | RootAddDeviceStop::Notification => {
            RootAddDeviceStopAction::Terminal
        }
    }
}

/// The devnode failure recorded for an AddDevice whose effect is uncertain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailedAddDevice {
    pub status: u32,
    pub devnode_status: u32,
    pub problem: u32,
}

pub const UNCERTAIN_ADD_DEVICE: FailedAddDevice = FailedAddDevice {
    status: STATUS_UNSUCCESSFUL,
    devnode_status: DN_HAS_PROBLEM,
    problem: CM_PROB_FAILED_ADD,
};
