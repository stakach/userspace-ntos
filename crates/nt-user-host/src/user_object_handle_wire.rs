//! Four-word requests from the win32k provider to the root for process-owned USER handles.
//!
//! The provider names bodies and types; the root supplies the provider domain from the
//! authenticated channel and the caller from the retained dispatch, never from these words.

use crate::user_object_handles::{HandleDelta, MAX_DELTA};
use nt_process::user_object_handle::UserObjectTarget;
use nt_process::STATUS_INVALID_PARAMETER;
use nt_types::AccessMode;

pub const OP_PUBLISH: u64 = 1;
pub const OP_LOOKUP: u64 = 2;
pub const OP_CLOSE: u64 = 3;
pub const OP_FIND: u64 = 4;
pub const OP_DRAIN: u64 = 5;
pub const OP_ACKNOWLEDGE: u64 = 6;

/// OBJ_INHERIT | OBJ_KERNEL_HANDLE: the attributes a handle publication can carry.
pub const PUBLISH_ATTRIBUTES: u32 = 0x202;
/// OBJECT_HANDLE_INFORMATION.HandleAttributes: OBJ_PROTECT_CLOSE | OBJ_INHERIT.
const HANDLE_ATTRIBUTES: u32 = 0x3;
const ADDRESS_LIMIT: u64 = 1 << 56;

pub type Words = [u64; 4];

fn mode_bit(mode: AccessMode) -> u64 {
    u64::from(mode == AccessMode::UserMode)
}

fn mode(bit: u64) -> Result<AccessMode, u32> {
    match bit {
        0 => Ok(AccessMode::KernelMode),
        1 => Ok(AccessMode::UserMode),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

fn generation(value: u64) -> Result<u64, u32> {
    if value == 0 || value > u64::from(u32::MAX) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(value)
}

fn address(value: u64) -> Result<u64, u32> {
    if value == 0 || value >= ADDRESS_LIMIT {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(value)
}

pub fn op(words: Words) -> u64 {
    words[0] & 0xFF
}

/// Publish a handle the provider has already counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publish {
    pub mode: AccessMode,
    pub attributes: u32,
    pub body: u64,
    pub object_type: u64,
    pub generation: u64,
    pub granted_access: u32,
}

impl Publish {
    pub fn encode(self) -> Words {
        [
            OP_PUBLISH | mode_bit(self.mode) << 8 | u64::from(self.attributes) << 16,
            self.body,
            self.object_type,
            self.generation << 32 | u64::from(self.granted_access),
        ]
    }

    pub fn decode(words: Words) -> Result<Self, u32> {
        let attributes = (words[0] >> 16) as u32;
        if op(words) != OP_PUBLISH
            || words[0] >> 9 & 0x7F != 0
            || words[0] >> 48 != 0
            || attributes & !PUBLISH_ATTRIBUTES != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self {
            mode: mode(words[0] >> 8 & 1)?,
            attributes,
            body: address(words[1])?,
            object_type: address(words[2])?,
            generation: generation(words[3] >> 32)?,
            granted_access: words[3] as u32,
        })
    }
}

/// ObReferenceObjectByHandle for a USER handle. `expected_type == 0` accepts any USER type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub mode: AccessMode,
    pub handle: u64,
    pub desired_access: u32,
    pub expected_type: u64,
}

impl Lookup {
    pub fn encode(self) -> Words {
        [
            OP_LOOKUP | mode_bit(self.mode) << 8,
            self.handle,
            u64::from(self.desired_access),
            self.expected_type,
        ]
    }

    pub fn decode(words: Words) -> Result<Self, u32> {
        if op(words) != OP_LOOKUP || words[0] >> 9 != 0 || words[2] > u64::from(u32::MAX) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self {
            mode: mode(words[0] >> 8 & 1)?,
            handle: words[1],
            desired_access: words[2] as u32,
            expected_type: words[3],
        })
    }
}

/// A resolved USER handle: its exact target and handle information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub body: u64,
    pub object_type: u64,
    pub generation: u64,
    pub granted_access: u32,
    pub attributes: u32,
}

impl Resolved {
    /// The three reply words after the status.
    pub fn encode(self) -> [u64; 3] {
        [
            self.body,
            self.generation << 32 | u64::from(self.granted_access),
            self.object_type | u64::from(self.attributes) << 56,
        ]
    }

    pub fn decode(words: [u64; 3]) -> Result<Self, u32> {
        let attributes = (words[2] >> 56) as u32;
        if attributes & !HANDLE_ATTRIBUTES != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self {
            body: address(words[0])?,
            object_type: address(words[2] & (ADDRESS_LIMIT - 1))?,
            generation: generation(words[1] >> 32)?,
            granted_access: words[1] as u32,
            attributes,
        })
    }
}

/// ObCloseHandle / ZwClose of a USER handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Close {
    pub mode: AccessMode,
    pub handle: u64,
}

impl Close {
    pub fn encode(self) -> Words {
        [OP_CLOSE | mode_bit(self.mode) << 8, self.handle, 0, 0]
    }

    pub fn decode(words: Words) -> Result<Self, u32> {
        if op(words) != OP_CLOSE || words[0] >> 9 != 0 || words[2] != 0 || words[3] != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self { mode: mode(words[0] >> 8 & 1)?, handle: words[1] })
    }
}

/// ObFindHandleForObject: `process` is the target EPROCESS projection; zero body or type is a
/// wildcard and `information` is an exact input filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Find {
    pub process: u64,
    pub body: u64,
    pub object_type: u64,
    pub information: Option<(u32, u32)>,
}

impl Find {
    pub fn encode(self) -> Words {
        let information = match self.information {
            Some((attributes, granted)) => {
                1 << 8 | u64::from(attributes) << 16 | u64::from(granted) << 32
            }
            None => 0,
        };
        [OP_FIND | information, self.process, self.body, self.object_type]
    }

    pub fn decode(words: Words) -> Result<Self, u32> {
        let filtered = words[0] >> 8 & 1 != 0;
        let attributes = (words[0] >> 16) as u16 as u32;
        if op(words) != OP_FIND
            || words[0] >> 9 & 0x7F != 0
            || (!filtered && words[0] >> 16 != 0)
            || attributes & !HANDLE_ATTRIBUTES != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self {
            process: address(words[1])?,
            body: words[2],
            object_type: words[3],
            information: filtered.then_some((attributes, (words[0] >> 32) as u32)),
        })
    }
}

/// A count change the provider applies: carried by the drain reply and its acknowledgement.
pub fn encode_delta(delta: HandleDelta) -> [u64; 3] {
    let (target, count, released) = match delta {
        HandleDelta::Acquired { target, count } => (target, count, 0),
        HandleDelta::Released { target, count } => (target, count, 1),
    };
    [
        target.body,
        target.generation << 32 | released << 31 | u64::from(count),
        target.object_type,
    ]
}

/// Decode a change for `domain`; the domain is never carried on the wire.
pub fn decode_delta(domain: u64, words: [u64; 3]) -> Result<HandleDelta, u32> {
    let count = (words[1] & 0x7FFF_FFFF) as u32;
    if count == 0 || count > MAX_DELTA {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let target = UserObjectTarget {
        domain,
        object_type: address(words[2])?,
        body: address(words[0])?,
        generation: generation(words[1] >> 32)?,
    };
    Ok(if words[1] >> 31 & 1 == 0 {
        HandleDelta::Acquired { target, count }
    } else {
        HandleDelta::Released { target, count }
    })
}

#[cfg(test)]
mod tests;
