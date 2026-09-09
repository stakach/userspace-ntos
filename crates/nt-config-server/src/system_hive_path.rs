//! One mounted alias resolver for key acquisition, snapshots and durable mutation addressing.

use super::{
    system_hive_relative_path_into, HiveMutation, MountedSystemHive, String,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND,
    SYSTEM_HIVE_PATH,
};

impl MountedSystemHive {
    pub(super) fn resolve_relative_path(&self, path: &str) -> Result<String, i32> {
        let mut relative = String::new();
        let capacity = path
            .len()
            .checked_add(self.current_control_set.as_str().len())
            .and_then(|len| len.checked_add(10))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        relative
            .try_reserve_exact(capacity)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        if !system_hive_relative_path_into(path, &self.current_control_set, &mut relative) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.hardware_profile
            .resolve_relative_path(&mut relative)
            .map_err(|error| match error {
                nt_hive_core::HardwareProfileError::Capacity => STATUS_INSUFFICIENT_RESOURCES,
                _ => STATUS_OBJECT_NAME_NOT_FOUND,
            })?;
        Ok(relative)
    }

    pub(super) fn resolve_physical_path(&self, path: &str) -> Result<String, i32> {
        let mut relative = self.resolve_relative_path(path)?;
        relative
            .try_reserve(SYSTEM_HIVE_PATH.len() + 1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        if !relative.is_empty() {
            relative.insert(0, '\\');
        }
        relative.insert_str(0, SYSTEM_HIVE_PATH);
        Ok(relative)
    }

    /// Freeze alias addressing before validation, durable-log encoding and retained commit.
    /// No later selector edit can redirect a prepared mutation to another key. The decoded
    /// unpublished journal is discarded by PREPARE on error; this method changes no CM state.
    pub(super) fn resolve_mutation_paths(&self, mutations: &mut [HiveMutation]) -> Result<(), i32> {
        for mutation in mutations {
            let path = match mutation {
                HiveMutation::CreateKey { path }
                | HiveMutation::SetValue { path, .. }
                | HiveMutation::DeleteValue { path, .. }
                | HiveMutation::DeleteKey { path }
                | HiveMutation::SetKeyClass { path, .. }
                | HiveMutation::SetKeySecurity { path, .. } => path,
                HiveMutation::PublishDeviceAction { .. } => continue,
            };
            *path = self.resolve_physical_path(path)?;
        }
        Ok(())
    }
}
