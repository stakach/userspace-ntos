//! Replay targets for the selected WAL suffix after boot has copied SYSTEM and SYSTEM.LOG.
//!
//! Persisted file identities, not paths or a new snapshot lookup, identify the two images
//! already handed to the Config Manager. The owner also preserves file-delta sequence order
//! across interleaved SYSTEM and other-hive records.

use crate::{
    FileDeltaReplayCursor, FileDeltaWalPayload, FileDeltaWalReplayError, FileSystem,
    HiveLogWalPayload, HiveLogWalReplay, HiveLogWalReplayError,
};

pub struct BootSystemPreRead {
    system_primary_id: Option<u64>,
    system_log_id: Option<u64>,
    file_delta_cursor: FileDeltaReplayCursor,
}

impl BootSystemPreRead {
    /// Capture identities from the unpublished snapshot before applying its anchored suffix.
    pub fn new(fs: &FileSystem, system_primary_path: &str, system_log_path: &str) -> Self {
        Self {
            system_primary_id: fs.existing_file_id(system_primary_path),
            system_log_id: fs.existing_file_id(system_log_path),
            file_delta_cursor: FileDeltaReplayCursor::new(),
        }
    }

    fn is_pre_read(&self, file_id: u64) -> bool {
        Some(file_id) == self.system_primary_id || Some(file_id) == self.system_log_id
    }

    pub fn replay_hive_log(
        &mut self,
        fs: &mut FileSystem,
        payload: HiveLogWalPayload<'_>,
    ) -> Result<HiveLogWalReplay, HiveLogWalReplayError> {
        if self.is_pre_read(payload.file_id) {
            return Err(HiveLogWalReplayError::ProtectedTarget);
        }
        fs.replay_hive_log_wal_payload(payload)
    }

    pub fn replay_file_delta(
        &mut self,
        fs: &mut FileSystem,
        payload: FileDeltaWalPayload<'_>,
    ) -> Result<(), FileDeltaWalReplayError> {
        if self.is_pre_read(payload.file_id()) {
            return Err(FileDeltaWalReplayError::ProtectedTarget);
        }
        fs.replay_file_delta_wal_payload(&mut self.file_delta_cursor, payload)
    }
}

#[cfg(test)]
#[path = "boot_system_pre_read_tests.rs"]
mod tests;
