//! When the root retries a parked AddDevice's child that no lane could admit yet (#420).
//!
//! A child refused admission entered nothing (#427), so retrying it before a lane becomes
//! idle could only be refused again. The root therefore reruns it on the lane-idle epoch,
//! not on a timer: never while every lane that refused it is still busy, and always once one
//! goes idle.

/// What the root does for a parked parent whose child work is ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddDeviceChildAction {
    /// Run one child step.
    RunChild,
    /// The last step was refused admission at the current lane-idle epoch: run nothing, arm
    /// no retry, and wait for the next root event.
    AwaitLaneIdle,
}

/// The lane-idle epoch at which a parked AddDevice's last child step was refused admission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AddDeviceChildWait {
    refused_at: Option<u64>,
}

impl AddDeviceChildWait {
    pub const fn new() -> Self {
        Self { refused_at: None }
    }

    /// The action at lane-idle epoch `epoch`.
    pub fn action(&self, epoch: u64) -> AddDeviceChildAction {
        match self.refused_at {
            Some(refused_at) if refused_at == epoch => AddDeviceChildAction::AwaitLaneIdle,
            _ => AddDeviceChildAction::RunChild,
        }
    }

    /// A child step ran after sampling `epoch_before`; `refused` if no lane admitted it.
    pub fn observe(&mut self, refused: bool, epoch_before: u64) {
        self.refused_at = refused.then_some(epoch_before);
    }
}

/// Whether the parked turn arms its retry shot before receiving.
pub const fn arm_add_device_retry_shot(awaiting_lane_idle: bool) -> bool {
    !awaiting_lane_idle
}
