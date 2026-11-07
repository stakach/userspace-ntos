//! Kernel SRM logon-session existence, separate from token reference ownership.

use alloc::vec::Vec;

use crate::{Luid, TokenStore};

pub const STATUS_NO_SUCH_LOGON_SESSION: u32 = 0xC000_005F;
pub const STATUS_LOGON_SESSION_EXISTS: u32 = 0xC000_00EE;
pub const STATUS_BAD_LOGON_SESSION_STATE: u32 = 0xC000_0104;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

const ANONYMOUS_LOGON_ID: Luid = Luid { low: 0x3e6, high: 0 };
const SYSTEM_LOGON_ID: Luid = Luid { low: 0x3e7, high: 0 };

/// Sessions created by the Security Reference Monitor. The two built-in
/// sessions exist for the lifetime of the kernel and cannot be removed.
#[derive(Clone, Debug, Default)]
pub struct LogonSessionRegistry {
    created: Vec<Luid>,
}

impl LogonSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, id: Luid) -> bool {
        Self::is_builtin(id) || self.created.contains(&id)
    }

    pub fn create(&mut self, id: Luid) -> Result<(), u32> {
        if self.contains(id) {
            return Err(STATUS_LOGON_SESSION_EXISTS);
        }
        self.created
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.created.push(id);
        Ok(())
    }

    pub fn delete(&mut self, id: Luid, tokens: &TokenStore) -> Result<(), u32> {
        if Self::is_builtin(id) {
            return Err(STATUS_BAD_LOGON_SESSION_STATE);
        }
        let index = self.created.iter().position(|entry| *entry == id)
            .ok_or(STATUS_NO_SUCH_LOGON_SESSION)?;
        if tokens.logon_session_reference_count(id).unwrap_or(0) != 0 {
            return Err(STATUS_BAD_LOGON_SESSION_STATE);
        }
        self.created.swap_remove(index);
        Ok(())
    }

    fn is_builtin(id: Luid) -> bool {
        id == ANONYMOUS_LOGON_ID || id == SYSTEM_LOGON_ID
    }
}
