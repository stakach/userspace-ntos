//! Scalar PoSetPowerState transport. Decoding does not grant device authority.

use nt_power_types::{DevicePowerState, SystemPowerState, POWER_STATE_TYPE_DEVICE, POWER_STATE_TYPE_SYSTEM};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerReportError {
    InvalidDevice,
    InvalidType,
    InvalidState,
    Envelope,
    StatusUpperBits,
    ReservedWords,
    UnexpectedStatus,
    FailureValue,
}

const fn valid_state(power_type: u32, state: u64) -> bool {
    match power_type {
        POWER_STATE_TYPE_SYSTEM => state < SystemPowerState::Maximum as u64,
        POWER_STATE_TYPE_DEVICE => state < DevicePowerState::Maximum as u64,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerReportRequest {
    pub device: u64,
    pub power_type: u32,
    pub state: u32,
}

impl PowerReportRequest {
    pub const fn decode(device: u64, power_type: u64, state: u64) -> Result<Self, PowerReportError> {
        if device == 0 { return Err(PowerReportError::InvalidDevice); }
        if power_type != POWER_STATE_TYPE_SYSTEM as u64 && power_type != POWER_STATE_TYPE_DEVICE as u64 {
            return Err(PowerReportError::InvalidType);
        }
        if !valid_state(power_type as u32, state) { return Err(PowerReportError::InvalidState); }
        Ok(Self { device, power_type: power_type as u32, state: state as u32 })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerReportReply {
    Success(u32),
    Rejected(i32),
}

impl PowerReportReply {
    pub const fn decode(
        words: u64, status: u64, previous: u64, reserved: [u64; 2], power_type: u32,
    ) -> Result<Self, PowerReportError> {
        if words != 4 { return Err(PowerReportError::Envelope); }
        if power_type != POWER_STATE_TYPE_SYSTEM && power_type != POWER_STATE_TYPE_DEVICE {
            return Err(PowerReportError::InvalidType);
        }
        if status > u32::MAX as u64 { return Err(PowerReportError::StatusUpperBits); }
        if reserved[0] != 0 || reserved[1] != 0 { return Err(PowerReportError::ReservedWords); }
        if status != 0 {
            if status & 0x8000_0000 == 0 { return Err(PowerReportError::UnexpectedStatus); }
            if previous != 0 { return Err(PowerReportError::FailureValue); }
            return Ok(Self::Rejected(status as u32 as i32));
        }
        if !valid_state(power_type, previous) { return Err(PowerReportError::InvalidState); }
        Ok(Self::Success(previous as u32))
    }

    pub const fn into_result(self) -> Result<u32, i32> {
        match self { Self::Success(previous) => Ok(previous), Self::Rejected(status) => Err(status) }
    }
}
