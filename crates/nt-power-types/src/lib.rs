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

/// Offset of `Parameters.Power.Type` within an `IO_STACK_LOCATION` (Parameters@8;
/// `Power.SystemContext`@0, `Type`@4, `State`@8 → 8+4 / 8+8, spec §9.5).
pub const PARAM_POWER_TYPE_OFFSET: u64 = 12;
/// Offset of `Parameters.Power.State`.
pub const PARAM_POWER_STATE_OFFSET: u64 = 16;

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
    fn device_state_helpers() {
        assert!(DevicePowerState::D0.is_on());
        assert!(!DevicePowerState::D3.is_on());
        assert_eq!(DevicePowerState::from_u32(4), Some(DevicePowerState::D3));
        assert_eq!(DevicePowerState::from_u32(99), None);
    }
}
