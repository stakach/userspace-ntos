//! Pure `RTL_TIME_ZONE_INFORMATION` layout and effective-bias policy.

use crate::rtl_time::{cutover_time_to_system_time, TimeFields};

pub const RTL_TIME_ZONE_INFORMATION_SIZE: usize = 0xac;
pub const TIME_ZONE_ID_UNKNOWN: u32 = 0;
pub const TIME_ZONE_ID_STANDARD: u32 = 1;
pub const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
pub const TICKS_PER_MINUTE: i64 = 60 * 10_000_000;

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeZoneRegistryField {
    Bias,
    StandardName,
    StandardBias,
    StandardStart,
    DaylightName,
    DaylightBias,
    DaylightStart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeZoneError {
    InvalidCutover,
    TimeOutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveTimeZone {
    pub id: u32,
    pub bias_100ns: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeZoneInformation {
    pub bias: i32,
    pub standard_name: [u16; 32],
    pub standard_date: TimeFields,
    pub standard_bias: i32,
    pub daylight_name: [u16; 32],
    pub daylight_date: TimeFields,
    pub daylight_bias: i32,
}

impl TimeZoneInformation {
    pub fn decode_prefix(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < RTL_TIME_ZONE_INFORMATION_SIZE {
            return None;
        }
        Some(Self {
            bias: read_i32(bytes, 0x00),
            standard_name: read_name(bytes, 0x04),
            standard_date: read_time_fields(bytes, 0x44),
            standard_bias: read_i32(bytes, 0x54),
            daylight_name: read_name(bytes, 0x58),
            daylight_date: read_time_fields(bytes, 0x98),
            daylight_bias: read_i32(bytes, 0xa8),
        })
    }

    pub fn encode(self) -> [u8; RTL_TIME_ZONE_INFORMATION_SIZE] {
        let mut output = [0u8; RTL_TIME_ZONE_INFORMATION_SIZE];
        write_i32(&mut output, 0x00, self.bias);
        write_name(&mut output, 0x04, &self.standard_name);
        write_time_fields(&mut output, 0x44, self.standard_date);
        write_i32(&mut output, 0x54, self.standard_bias);
        write_name(&mut output, 0x58, &self.daylight_name);
        write_time_fields(&mut output, 0x98, self.daylight_date);
        write_i32(&mut output, 0xa8, self.daylight_bias);
        output
    }

    /// Apply one validated SYSTEM-hive value, retaining the prior field when malformed.
    pub fn apply_registry_value(
        &mut self,
        field: TimeZoneRegistryField,
        value_type: u32,
        data: &[u8],
    ) -> bool {
        match field {
            TimeZoneRegistryField::Bias => {
                let Some(value) = registry_i32(value_type, data) else {
                    return false;
                };
                self.bias = value;
            }
            TimeZoneRegistryField::StandardBias => {
                let Some(value) = registry_i32(value_type, data) else {
                    return false;
                };
                self.standard_bias = value;
            }
            TimeZoneRegistryField::DaylightBias => {
                let Some(value) = registry_i32(value_type, data) else {
                    return false;
                };
                self.daylight_bias = value;
            }
            TimeZoneRegistryField::StandardName => {
                let Some(value) = registry_name(value_type, data) else {
                    return false;
                };
                self.standard_name = value;
            }
            TimeZoneRegistryField::DaylightName => {
                let Some(value) = registry_name(value_type, data) else {
                    return false;
                };
                self.daylight_name = value;
            }
            TimeZoneRegistryField::StandardStart => {
                let Some(value) = registry_time_fields(value_type, data) else {
                    return false;
                };
                self.standard_date = value;
            }
            TimeZoneRegistryField::DaylightStart => {
                let Some(value) = registry_time_fields(value_type, data) else {
                    return false;
                };
                self.daylight_date = value;
            }
        }
        true
    }

    /// Resolve the active standard/daylight bias at one UTC NT timestamp.
    pub fn effective_at(self, system_time_100ns: i64) -> Result<EffectiveTimeZone, TimeZoneError> {
        let base_bias = i64::from(self.bias) * TICKS_PER_MINUTE;
        if self.standard_date.month == 0 || self.daylight_date.month == 0 {
            return Ok(EffectiveTimeZone {
                id: TIME_ZONE_ID_UNKNOWN,
                bias_100ns: base_bias,
            });
        }

        let local_standard_time = system_time_100ns
            .checked_sub(base_bias)
            .ok_or(TimeZoneError::TimeOutOfRange)?;
        if local_standard_time < 0 {
            return Err(TimeZoneError::TimeOutOfRange);
        }
        let standard_time =
            cutover_time_to_system_time(&self.standard_date, local_standard_time, true)
                .ok_or(TimeZoneError::InvalidCutover)?;
        let daylight_time =
            cutover_time_to_system_time(&self.daylight_date, local_standard_time, true)
                .ok_or(TimeZoneError::InvalidCutover)?;

        let daylight = if daylight_time < standard_time {
            local_standard_time >= daylight_time && local_standard_time < standard_time
        } else {
            !(local_standard_time >= standard_time && local_standard_time < daylight_time)
        };
        let (id, additional_bias) = if daylight {
            (TIME_ZONE_ID_DAYLIGHT, self.daylight_bias)
        } else {
            (TIME_ZONE_ID_STANDARD, self.standard_bias)
        };
        Ok(EffectiveTimeZone {
            id,
            bias_100ns: base_bias + i64::from(additional_bias) * TICKS_PER_MINUTE,
        })
    }
}

fn registry_i32(value_type: u32, data: &[u8]) -> Option<i32> {
    (value_type == REG_DWORD && data.len() == 4)
        .then(|| i32::from_le_bytes(data.try_into().unwrap()))
}

fn registry_name(value_type: u32, data: &[u8]) -> Option<[u16; 32]> {
    if !matches!(value_type, REG_SZ | REG_EXPAND_SZ)
        || data.len() < 2
        || data.len() > 64
        || data.len() & 1 != 0
        || data[data.len() - 2..] != [0, 0]
    {
        return None;
    }
    let mut output = [0u16; 32];
    for (slot, pair) in output.iter_mut().zip(data.chunks_exact(2)) {
        *slot = u16::from_le_bytes([pair[0], pair[1]]);
    }
    Some(output)
}

fn registry_time_fields(value_type: u32, data: &[u8]) -> Option<TimeFields> {
    (value_type == REG_BINARY && data.len() == 16).then(|| read_time_fields(data, 0))
}

fn read_i16(bytes: &[u8], offset: usize) -> i16 {
    i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_name(bytes: &[u8], offset: usize) -> [u16; 32] {
    let mut output = [0u16; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u16::from_le_bytes(
            bytes[offset + index * 2..offset + index * 2 + 2]
                .try_into()
                .unwrap(),
        );
    }
    output
}

fn read_time_fields(bytes: &[u8], offset: usize) -> TimeFields {
    TimeFields {
        year: read_i16(bytes, offset),
        month: read_i16(bytes, offset + 2),
        day: read_i16(bytes, offset + 4),
        hour: read_i16(bytes, offset + 6),
        minute: read_i16(bytes, offset + 8),
        second: read_i16(bytes, offset + 10),
        milliseconds: read_i16(bytes, offset + 12),
        weekday: read_i16(bytes, offset + 14),
    }
}

fn write_i16(bytes: &mut [u8], offset: usize, value: i16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_name(bytes: &mut [u8], offset: usize, name: &[u16; 32]) {
    for (index, value) in name.iter().copied().enumerate() {
        bytes[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_time_fields(bytes: &mut [u8], offset: usize, fields: TimeFields) {
    for (index, value) in [
        fields.year,
        fields.month,
        fields.day,
        fields.hour,
        fields.minute,
        fields.second,
        fields.milliseconds,
        fields.weekday,
    ]
    .into_iter()
    .enumerate()
    {
        write_i16(bytes, offset + index * 2, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtl_time::time_fields_to_time;
    use alloc::vec::Vec;

    fn utf16_name(value: &str) -> [u16; 32] {
        let mut output = [0u16; 32];
        for (slot, unit) in output.iter_mut().zip(value.encode_utf16()) {
            *slot = unit;
        }
        output
    }

    fn recurring(month: i16, week: i16, weekday: i16) -> TimeFields {
        TimeFields {
            month,
            day: week,
            hour: 2,
            weekday,
            ..Default::default()
        }
    }

    fn timestamp(year: i16, month: i16, day: i16) -> i64 {
        time_fields_to_time(&TimeFields {
            year,
            month,
            day,
            hour: 12,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn codec_uses_the_native_172_byte_layout() {
        let information = TimeZoneInformation {
            bias: -60,
            standard_name: utf16_name("Standard"),
            standard_date: recurring(11, 1, 0),
            standard_bias: 7,
            daylight_name: utf16_name("Daylight"),
            daylight_date: recurring(3, 2, 0),
            daylight_bias: -53,
        };
        let encoded = information.encode();
        assert_eq!(encoded.len(), 0xac);
        assert_eq!(i32::from_le_bytes(encoded[0..4].try_into().unwrap()), -60);
        assert_eq!(read_time_fields(&encoded, 0x44), information.standard_date);
        assert_eq!(
            i32::from_le_bytes(encoded[0x54..0x58].try_into().unwrap()),
            7
        );
        assert_eq!(read_time_fields(&encoded, 0x98), information.daylight_date);
        assert_eq!(
            i32::from_le_bytes(encoded[0xa8..0xac].try_into().unwrap()),
            -53
        );
        assert_eq!(
            TimeZoneInformation::decode_prefix(&encoded),
            Some(information)
        );
        let mut extended = [0u8; RTL_TIME_ZONE_INFORMATION_SIZE + 1];
        extended[..RTL_TIME_ZONE_INFORMATION_SIZE].copy_from_slice(&encoded);
        assert_eq!(
            TimeZoneInformation::decode_prefix(&extended),
            Some(information)
        );
        assert_eq!(TimeZoneInformation::decode_prefix(&encoded[..171]), None);
    }

    #[test]
    fn registry_values_are_type_and_length_checked() {
        let mut information = TimeZoneInformation::default();
        assert!(information.apply_registry_value(
            TimeZoneRegistryField::Bias,
            REG_DWORD,
            &300i32.to_le_bytes(),
        ));
        assert!(!information.apply_registry_value(
            TimeZoneRegistryField::StandardBias,
            REG_BINARY,
            &1i32.to_le_bytes(),
        ));
        assert_eq!(information.standard_bias, 0);

        let mut name = Vec::new();
        for unit in "Eastern Standard Time".encode_utf16().chain([0]) {
            name.extend_from_slice(&unit.to_le_bytes());
        }
        assert!(information.apply_registry_value(
            TimeZoneRegistryField::StandardName,
            REG_SZ,
            &name,
        ));
        assert_eq!(information.standard_name[0], 'E' as u16);
        let prior = information.standard_name;
        assert!(!information.apply_registry_value(
            TimeZoneRegistryField::StandardName,
            REG_SZ,
            &[b'X', 0],
        ));
        assert_eq!(information.standard_name, prior);
        assert!(!information.apply_registry_value(
            TimeZoneRegistryField::DaylightName,
            REG_SZ,
            &[b'X', 0],
        ));
    }

    #[test]
    fn no_cutovers_use_only_the_base_bias() {
        let information = TimeZoneInformation {
            bias: -90,
            standard_bias: 15,
            daylight_bias: -30,
            ..Default::default()
        };
        assert_eq!(
            information.effective_at(timestamp(2026, 7, 1)),
            Ok(EffectiveTimeZone {
                id: TIME_ZONE_ID_UNKNOWN,
                bias_100ns: -90 * TICKS_PER_MINUTE,
            })
        );
    }

    #[test]
    fn northern_and_southern_cutovers_select_the_active_bias() {
        let northern = TimeZoneInformation {
            bias: 300,
            standard_date: recurring(11, 1, 0),
            daylight_date: recurring(3, 2, 0),
            daylight_bias: -60,
            ..Default::default()
        };
        assert_eq!(
            northern.effective_at(timestamp(2026, 7, 1)).unwrap(),
            EffectiveTimeZone {
                id: TIME_ZONE_ID_DAYLIGHT,
                bias_100ns: 240 * TICKS_PER_MINUTE,
            }
        );
        assert_eq!(
            northern.effective_at(timestamp(2026, 1, 1)).unwrap().id,
            TIME_ZONE_ID_STANDARD,
        );

        let southern = TimeZoneInformation {
            bias: -600,
            standard_date: recurring(4, 1, 0),
            daylight_date: recurring(10, 1, 0),
            daylight_bias: -60,
            ..Default::default()
        };
        assert_eq!(
            southern.effective_at(timestamp(2026, 1, 1)).unwrap().id,
            TIME_ZONE_ID_DAYLIGHT,
        );
        assert_eq!(
            southern.effective_at(timestamp(2026, 7, 1)).unwrap().id,
            TIME_ZONE_ID_STANDARD,
        );
    }

    #[test]
    fn cutover_boundaries_change_bias_at_the_transition_tick() {
        let information = TimeZoneInformation {
            standard_date: recurring(11, 1, 0),
            standard_bias: 30,
            daylight_date: recurring(3, 2, 0),
            daylight_bias: -60,
            ..Default::default()
        };
        let reference = timestamp(2026, 1, 1);
        let daylight =
            cutover_time_to_system_time(&information.daylight_date, reference, true).unwrap();
        assert_eq!(
            information.effective_at(daylight - 1).unwrap().id,
            TIME_ZONE_ID_STANDARD,
        );
        assert_eq!(
            information.effective_at(daylight).unwrap(),
            EffectiveTimeZone {
                id: TIME_ZONE_ID_DAYLIGHT,
                bias_100ns: -60 * TICKS_PER_MINUTE,
            },
        );

        let standard =
            cutover_time_to_system_time(&information.standard_date, reference, true).unwrap();
        assert_eq!(
            information.effective_at(standard - 1).unwrap().id,
            TIME_ZONE_ID_DAYLIGHT,
        );
        assert_eq!(
            information.effective_at(standard).unwrap(),
            EffectiveTimeZone {
                id: TIME_ZONE_ID_STANDARD,
                bias_100ns: 30 * TICKS_PER_MINUTE,
            },
        );
    }

    #[test]
    fn malformed_cutovers_do_not_produce_a_bias() {
        let information = TimeZoneInformation {
            standard_date: recurring(13, 1, 0),
            daylight_date: recurring(3, 2, 0),
            ..Default::default()
        };
        assert_eq!(
            information.effective_at(timestamp(2026, 7, 1)),
            Err(TimeZoneError::InvalidCutover),
        );
        assert_eq!(
            TimeZoneInformation {
                bias: i32::MIN,
                standard_date: recurring(11, 1, 0),
                daylight_date: recurring(3, 2, 0),
                ..Default::default()
            }
            .effective_at(i64::MAX),
            Err(TimeZoneError::TimeOutOfRange),
        );
    }
}
