//! Mutable hive value preparation and acknowledged journal publication.
use super::*;

impl ExecNtHandler {
    pub(super) fn journal_set_mutable_value(
        &mut self,
        key: ResolvedHiveKey,
        name: &str,
        value_type: nt_hive_core::RegistryValueType,
        data: &[u8],
    ) -> Result<(), u32> {
        let _durable = allocator::enter_durable();
        let relative = self
            .mutable_key_relative_path(key)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let path = self
            .mutable_hive_checkpoint_path_owned(key.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let receipt = {
            let hive = self
                .mutable_hives
                .hive_mut(key.hive)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let provider = crate::writable_fs::WritableHiveIoProvider::new(&path);
            let mut manager = nt_hive_core::HiveManager::for_live_hive(provider, hive);
            manager
                .try_set_value(hive, key.key, &relative, name, value_type, data)
                .map_err(Self::mutable_hive_set_value_status)?
        };
        if receipt.durable {
            self.note_mutable_hive_journal_record(key.hive);
        }
        Ok(())
    }

    fn mutable_hive_set_value_status(err: nt_hive_core::HiveSetValueError) -> u32 {
        use nt_hive_core::{HiveSetValueError, SetValueError};
        match err {
            HiveSetValueError::Prepare(SetValueError::KeyNotFound)
            | HiveSetValueError::PathMismatch => STATUS_INVALID_HANDLE,
            HiveSetValueError::Prepare(SetValueError::InsufficientResources)
            | HiveSetValueError::Encode(_)
            | HiveSetValueError::SequenceOverflow => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
            HiveSetValueError::Io(err) => Self::mutable_hive_journal_status(err),
            HiveSetValueError::Prepare(SetValueError::RetainedPublication)
            | HiveSetValueError::RetainedPublication
            | HiveSetValueError::SequenceMismatch => STATUS_UNSUCCESSFUL,
        }
    }
}
