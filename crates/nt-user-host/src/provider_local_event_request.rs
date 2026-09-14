//! Strict scalar decoding for kernel provider-local Event operations without wake effects.

use nt_kernel_exec::EventObjectId;

pub const PUBLISH: u64 = 13;
pub const RETIRE: u64 = 14;
pub const ACK_RETIREMENT: u64 = 15;
pub const RESET: u64 = 17;
pub const CLEAR: u64 = 18;
pub const READ: u64 = 20;

const INVALID_PARAMETER: u32 = 0xC000_000D;
const NOT_SUPPORTED: u32 = 0xC000_00BB;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalEventRequest {
    Publish {
        local: u64,
        event_type: u32,
        signaled: bool,
    },
    Retire {
        local: u64,
    },
    Ack {
        local: u64,
        id: EventObjectId,
    },
    Reset {
        local: u64,
    },
    Clear {
        local: u64,
    },
    Read {
        local: u64,
    },
}

impl LocalEventRequest {
    /// Decode only operations whose full contract is memory-local. SET/PULSE require wake
    /// arbitration; timers require deadline ownership; process handles require other authority.
    /// Refuse those operations rather than routing them through a fabricated hosted client.
    pub fn decode(op: u64, local: u64, arg2: u64, arg3: u64) -> Result<Self, u32> {
        if !matches!(op, PUBLISH | RETIRE | ACK_RETIREMENT | RESET | CLEAR | READ) {
            return Err(NOT_SUPPORTED);
        }
        if local == 0 {
            return Err(INVALID_PARAMETER);
        }
        match op {
            PUBLISH if arg2 <= 1 && arg3 <= 1 => Ok(Self::Publish {
                local,
                event_type: arg2 as u32,
                signaled: arg3 != 0,
            }),
            ACK_RETIREMENT => EventObjectId::from_wire_parts(arg2, arg3)
                .map(|id| Self::Ack { local, id })
                .ok_or(INVALID_PARAMETER),
            RETIRE | RESET | CLEAR | READ if arg2 == 0 && arg3 == 0 => Ok(match op {
                RETIRE => Self::Retire { local },
                RESET => Self::Reset { local },
                CLEAR => Self::Clear { local },
                _ => Self::Read { local },
            }),
            _ => Err(INVALID_PARAMETER),
        }
    }
}

#[cfg(test)]
#[path = "provider_local_event_request_tests.rs"]
mod tests;
