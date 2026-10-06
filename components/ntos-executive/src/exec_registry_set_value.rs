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
        let relative = self
            .mutable_key_relative_path(key)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let path = self
            .mutable_hive_checkpoint_path_owned(key.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        {
            let hive = self
                .mutable_hives
                .hive_mut(key.hive)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let provider = crate::writable_fs::WritableHiveIoProvider::new(&path);
            let mut manager = nt_hive_core::HiveManager::for_live_hive(provider, hive);
            manager
                .mutate_with_live_apply(
                    hive,
                    nt_hive_core::HiveLogOp::SetValue {
                        path: &relative,
                        name,
                        value_type,
                        data,
                    },
                    |hive| hive.set_value(key.key, name, value_type, data.to_vec()),
                )
                .map_err(Self::mutable_hive_journal_status)?;
        }
        self.note_mutable_hive_journal_record(key.hive);
        Ok(())
    }

    pub(super) fn journal_set_mutable_value_from_existing_value(
        &mut self,
        key: ResolvedHiveKey,
        name: &str,
        value_type: nt_hive_core::RegistryValueType,
        source: nt_hive_core::ResolvedHiveValue,
    ) -> Result<(), u32> {
        let log_data = match self.mutable_hives.query_resolved_value(source) {
            Some((source_type, source_data)) if source_type == value_type => source_data.to_vec(),
            _ => return Err(STATUS_INVALID_HANDLE),
        };
        if key.hive != source.hive {
            return self.journal_set_mutable_value(key, name, value_type, &log_data);
        }
        let relative = self
            .mutable_key_relative_path(key)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let path = self
            .mutable_hive_checkpoint_path_owned(key.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let hive = self
            .mutable_hives
            .hive_mut(key.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let provider = crate::writable_fs::WritableHiveIoProvider::new(&path);
        let mut manager = nt_hive_core::HiveManager::for_live_hive(provider, hive);
        manager
            .mutate_with_live_apply(
                hive,
                nt_hive_core::HiveLogOp::SetValue {
                    path: &relative,
                    name,
                    value_type,
                    data: &log_data,
                },
                |hive| hive.set_value_from_existing_value(key.key, name, value_type, source.value),
            )
            .map_err(Self::mutable_hive_journal_status)?;
        self.note_mutable_hive_journal_record(key.hive);
        Ok(())
    }
}
