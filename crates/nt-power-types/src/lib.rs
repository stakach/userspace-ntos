//! # `nt-power-types` — NT power management types + IRP constants
//!
//! `POWER_STATE_TYPE`, `SYSTEM_POWER_STATE`, `DEVICE_POWER_STATE`, the `POWER_STATE`
//! union projection, and the `IRP_MJ_POWER` major/minor constants + the
//! `Parameters.Power` stack-location layout a WDM driver reads (spec: NT Power
//! Manager, Milestone 13, §6, §9.5). `no_std`, no allocation, explicit `repr`.

#![no_std]

/// `POWER_STATE_TYPE` (spec §6.1).
pub const POWER_STATE_TYPE_SYSTEM: u32 = 0;
pub const POWER_STATE_TYPE_DEVICE: u32 = 1;

/// `EXECUTION_STATE` flags accepted by NT5's `NtSetThreadExecutionState`.
pub const ES_SYSTEM_REQUIRED: u32 = 0x0000_0001;
pub const ES_DISPLAY_REQUIRED: u32 = 0x0000_0002;
pub const ES_USER_PRESENT: u32 = 0x0000_0004;
pub const ES_CONTINUOUS: u32 = 0x8000_0000;
pub const THREAD_EXECUTION_STATE_MASK: u32 = ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED;
pub const THREAD_EXECUTION_STATE_VALID_MASK: u32 = THREAD_EXECUTION_STATE_MASK | ES_CONTINUOUS;

/// `LATENCY_TIME`, the process-scoped wakeup-latency policy accepted by NT5.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum WakeupLatency {
    DontCare = 0,
    LowestLatency = 1,
}

impl WakeupLatency {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::DontCare,
            1 => Self::LowestLatency,
            _ => return None,
        })
    }
}

/// `SYSTEM_POWER_STATE` (spec §6.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SystemPowerState {
    Unspecified = 0,
    Working = 1, // S0
    Sleeping1 = 2,
    Sleeping2 = 3,
    Sleeping3 = 4, // S3
    Hibernate = 5, // S4
    Shutdown = 6,
    Maximum = 7,
}

/// `DEVICE_POWER_STATE` (spec §6.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DevicePowerState {
    Unspecified = 0,
    D0 = 1, // on / usable
    D1 = 2,
    D2 = 3,
    D3 = 4, // off / not usable
    Maximum = 5,
}

impl DevicePowerState {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Unspecified,
            1 => Self::D0,
            2 => Self::D1,
            3 => Self::D2,
            4 => Self::D3,
            5 => Self::Maximum,
            _ => return None,
        })
    }

    /// True for `D0` (device on / usable). Any other state gates I/O + interrupts.
    pub fn is_on(self) -> bool {
        self == Self::D0
    }
}

impl SystemPowerState {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Unspecified,
            1 => Self::Working,
            2 => Self::Sleeping1,
            3 => Self::Sleeping2,
            4 => Self::Sleeping3,
            5 => Self::Hibernate,
            6 => Self::Shutdown,
            7 => Self::Maximum,
            _ => return None,
        })
    }
}

// --- IRP_MJ_POWER + minor functions (WDK) ------------------------------------

/// `IRP_MJ_POWER`.
pub const IRP_MJ_POWER: u8 = 0x16;

pub const IRP_MN_WAIT_WAKE: u8 = 0x00;
pub const IRP_MN_POWER_SEQUENCE: u8 = 0x01;
pub const IRP_MN_SET_POWER: u8 = 0x02;
pub const IRP_MN_QUERY_POWER: u8 = 0x03;

/// Offset of `Parameters.Power.Type` within an `IO_STACK_LOCATION` (spec §9.5).
/// `Parameters`@8; the `Power` fields are `POINTER_ALIGNMENT` 8-byte slots (same as
/// `DeviceIoControl`): `SystemContext`@Parameters+0, `Type`@Parameters+8,
/// `State`@Parameters+16 → 16 / 24 within the stack location.
pub const PARAM_POWER_TYPE_OFFSET: u64 = 16;
/// Offset of `Parameters.Power.State`.
pub const PARAM_POWER_STATE_OFFSET: u64 = 24;

/// `STATUS_DEVICE_POWERED_OFF`.
pub const STATUS_DEVICE_POWERED_OFF: i32 = 0xC000_02DBu32 as i32;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn enum_values_match_wdk() {
        assert_eq!(size_of::<DevicePowerState>(), 4);
        assert_eq!(DevicePowerState::D0 as u32, 1);
        assert_eq!(DevicePowerState::D3 as u32, 4);
        assert_eq!(SystemPowerState::Working as u32, 1);
        assert_eq!(SystemPowerState::Shutdown as u32, 6);
    }

    #[test]
    fn irp_constants() {
        assert_eq!(IRP_MJ_POWER, 0x16);
        assert_eq!(IRP_MN_SET_POWER, 2);
        assert_eq!(IRP_MN_QUERY_POWER, 3);
    }

    #[test]
    fn execution_state_flags_match_nt5() {
        assert_eq!(ES_SYSTEM_REQUIRED, 1);
        assert_eq!(ES_DISPLAY_REQUIRED, 2);
        assert_eq!(ES_USER_PRESENT, 4);
        assert_eq!(ES_CONTINUOUS, 0x8000_0000);
        assert_eq!(THREAD_EXECUTION_STATE_VALID_MASK, 0x8000_0003);
    }

    #[test]
    fn wakeup_latency_values_match_nt5() {
        assert_eq!(WakeupLatency::DontCare as u32, 0);
        assert_eq!(WakeupLatency::LowestLatency as u32, 1);
        assert_eq!(WakeupLatency::from_u32(0), Some(WakeupLatency::DontCare));
        assert_eq!(
            WakeupLatency::from_u32(1),
            Some(WakeupLatency::LowestLatency)
        );
        assert_eq!(WakeupLatency::from_u32(2), None);
    }

    #[test]
    fn device_state_helpers() {
        assert!(DevicePowerState::D0.is_on());
        assert!(!DevicePowerState::D3.is_on());
        assert_eq!(DevicePowerState::from_u32(4), Some(DevicePowerState::D3));
        assert_eq!(DevicePowerState::from_u32(99), None);
    }
}
