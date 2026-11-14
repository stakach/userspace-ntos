//! `NtPowerInformation` levels answered from Power Manager state, with the NT 5.2 admission
//! rules (ReactOS `ntoskrnl/po/power.c`).

use crate::PowerManager;

pub const SYSTEM_POWER_CAPABILITIES_LEVEL: u32 = 4;
pub const SYSTEM_BATTERY_STATE_LEVEL: u32 = 5;

pub const SYSTEM_POWER_CAPABILITIES_SIZE: usize = 0x4c;
pub const SYSTEM_BATTERY_STATE_SIZE: usize = 0x20;

pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// A level this Power Manager answers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerInformationQuery {
    SystemPowerCapabilities,
    SystemBatteryState,
}

impl PowerInformationQuery {
    pub const fn output_length(self) -> usize {
        match self {
            Self::SystemPowerCapabilities => SYSTEM_POWER_CAPABILITIES_SIZE,
            Self::SystemBatteryState => SYSTEM_BATTERY_STATE_SIZE,
        }
    }
}

/// Admit one `NtPowerInformation` call after its buffers have been probed. Both served levels
/// are pure queries: an input buffer is `STATUS_INVALID_PARAMETER` and a short output buffer is
/// `STATUS_BUFFER_TOO_SMALL`. Every other level is `STATUS_NOT_IMPLEMENTED`.
pub const fn plan_power_information(
    level: u32,
    input_present: bool,
    output_length: usize,
) -> Result<PowerInformationQuery, u32> {
    let query = match level {
        SYSTEM_POWER_CAPABILITIES_LEVEL => PowerInformationQuery::SystemPowerCapabilities,
        SYSTEM_BATTERY_STATE_LEVEL => PowerInformationQuery::SystemBatteryState,
        _ => return Err(STATUS_NOT_IMPLEMENTED),
    };
    if input_present {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if output_length < query.output_length() {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    Ok(query)
}

/// The members of `SYSTEM_POWER_CAPABILITIES` a producer can assert. Nothing registers a sleep
/// state, a power or sleep button, a lid or a battery with this Power Manager, so every member
/// of the record it reports is absent until such a producer exists.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemPowerCapabilities {
    pub system_batteries_present: bool,
}

impl SystemPowerCapabilities {
    pub fn encode(self) -> [u8; SYSTEM_POWER_CAPABILITIES_SIZE] {
        let mut output = [0u8; SYSTEM_POWER_CAPABILITIES_SIZE];
        output[0x1e] = self.system_batteries_present as u8;
        output
    }
}

/// `SYSTEM_BATTERY_STATE`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SystemBatteryState {
    pub ac_on_line: bool,
    pub battery_present: bool,
}

impl SystemBatteryState {
    /// The state NT reports while no battery is present: on AC power, everything else zero.
    pub const NO_BATTERY: Self = Self { ac_on_line: true, battery_present: false };

    pub fn encode(self) -> [u8; SYSTEM_BATTERY_STATE_SIZE] {
        let mut output = [0u8; SYSTEM_BATTERY_STATE_SIZE];
        output[0] = self.ac_on_line as u8;
        output[1] = self.battery_present as u8;
        output
    }
}

impl PowerManager {
    pub fn system_power_capabilities(&self) -> SystemPowerCapabilities {
        SystemPowerCapabilities::default()
    }

    /// `None` when batteries are present: their state belongs to the battery driver, which this
    /// Power Manager cannot query.
    pub fn system_battery_state(&self) -> Option<SystemBatteryState> {
        (!self.system_power_capabilities().system_batteries_present)
            .then_some(SystemBatteryState::NO_BATTERY)
    }

    /// Encode one admitted level into `output` and return the record length, or `None` when the
    /// level's state belongs to a provider this manager cannot query.
    pub fn power_information(
        &self,
        query: PowerInformationQuery,
        output: &mut [u8; SYSTEM_POWER_CAPABILITIES_SIZE],
    ) -> Option<usize> {
        let length = query.output_length();
        match query {
            PowerInformationQuery::SystemPowerCapabilities => {
                *output = self.system_power_capabilities().encode();
            }
            PowerInformationQuery::SystemBatteryState => {
                output[..length].copy_from_slice(&self.system_battery_state()?.encode());
            }
        }
        Some(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_levels_reject_input_and_short_output() {
        assert_eq!(
            plan_power_information(4, false, 0x4c),
            Ok(PowerInformationQuery::SystemPowerCapabilities)
        );
        assert_eq!(
            plan_power_information(5, false, 0x40),
            Ok(PowerInformationQuery::SystemBatteryState)
        );
        assert_eq!(plan_power_information(4, false, 0x4b), Err(STATUS_BUFFER_TOO_SMALL));
        assert_eq!(plan_power_information(5, false, 0x1f), Err(STATUS_BUFFER_TOO_SMALL));
        // The input check precedes the length check.
        assert_eq!(plan_power_information(5, true, 0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(plan_power_information(4, true, 0x4c), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn other_levels_are_not_implemented_whatever_their_buffers() {
        for level in [0, 1, 2, 3, 6, 11, 12, 16, 83, u32::MAX] {
            assert_eq!(plan_power_information(level, false, 0x1000), Err(STATUS_NOT_IMPLEMENTED));
            assert_eq!(plan_power_information(level, true, 0), Err(STATUS_NOT_IMPLEMENTED));
        }
    }

    #[test]
    fn a_manager_without_battery_producers_reports_ac_power_and_no_capability() {
        let manager = PowerManager::new();
        let capabilities = manager.system_power_capabilities().encode();
        assert_eq!(capabilities.len(), 76);
        assert!(capabilities.iter().all(|byte| *byte == 0));
        let battery = manager.system_battery_state().unwrap().encode();
        assert_eq!(battery[0], 1);
        assert!(battery[1..].iter().all(|byte| *byte == 0));

        let mut output = [0xffu8; SYSTEM_POWER_CAPABILITIES_SIZE];
        assert_eq!(
            manager.power_information(PowerInformationQuery::SystemBatteryState, &mut output),
            Some(0x20)
        );
        assert_eq!(output[..0x20], battery);
        assert_eq!(
            manager.power_information(PowerInformationQuery::SystemPowerCapabilities, &mut output),
            Some(0x4c)
        );
        assert_eq!(output, capabilities);
    }

    #[test]
    fn batteries_present_occupies_its_native_offset() {
        let capabilities = SystemPowerCapabilities { system_batteries_present: true }.encode();
        assert_eq!(capabilities[0x1e], 1);
        assert_eq!(capabilities.iter().filter(|byte| **byte != 0).count(), 1);
    }
}
