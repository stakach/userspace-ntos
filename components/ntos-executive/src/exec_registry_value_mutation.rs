//! Exact-Key mutation shared by hosted syscalls and kernel provider requests.

use super::*;

impl ExecNtHandler {
    pub(crate) unsafe fn registry_target_set_value(
        &mut self,
        key: KeyRef,
        name: &str,
        value_type: u32,
        data: &[u8],
    ) -> u32 {
        let _durable = allocator::enter_durable();
        if let Some(path) = self.cm_runtime_key_target(key) {
            return crate::config_manager_runtime_key_operation(
                path.key,
                nt_config_abi::runtime_key_op::SET_VALUE,
                0,
                name,
                value_type,
                data,
            )
            .err()
            .map_or(0, |status| status as u32);
        }
        if let Some(target) = self.cm_system_key_target(key) {
            let Some(value_type) = nt_hive_core::RegistryValueType::from_u32(value_type) else {
                return STATUS_INVALID_PARAMETER;
            };
            let generation = crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
            let information = match crate::config_manager_query_leased_system_hive_key_information(
                target.lease,
            ) {
                Ok(information) if information.mount_generation == generation => information,
                Ok(_) => return 0xC000_022D,
                Err(status) => return status as u32,
            };
            return self
                .persist_and_publish_system_mutations(
                    generation,
                    &[OwnedSystemHiveMutation::SetValue {
                        path: information.path,
                        name: name.into(),
                        value_type,
                        data: data.to_vec(),
                    }],
                    SystemHiveMutationOrigin::Runtime,
                )
                .err()
                .unwrap_or(0);
        }
        if let Some(index) = overlay_key_idx(key) {
            return if self
                .overlay
                .set_value_from_slice(index, name.into(), value_type, data)
            {
                0
            } else {
                STATUS_INVALID_HANDLE
            };
        }
        if let Some(key) = self.mutable_key_handle(key) {
            let Some(value_type) = nt_hive_core::RegistryValueType::from_u32(value_type) else {
                return STATUS_INVALID_PARAMETER;
            };
            return self
                .journal_set_mutable_value(key, name, value_type, data)
                .err()
                .unwrap_or(0);
        }
        STATUS_ACCESS_DENIED
    }

    pub(crate) unsafe fn registry_target_delete_value(&mut self, key: KeyRef, name: &str) -> u32 {
        let _durable = allocator::enter_durable();
        if let Some(path) = self.cm_runtime_key_target(key) {
            return crate::config_manager_runtime_key_operation(
                path.key,
                nt_config_abi::runtime_key_op::DELETE_VALUE,
                0,
                name,
                0,
                &[],
            )
            .err()
            .map_or(0, |status| status as u32);
        }
        if let Some(target) = self.cm_system_key_target(key) {
            let generation = crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
            let information = match crate::config_manager_query_leased_system_hive_key_information(
                target.lease,
            ) {
                Ok(information) if information.mount_generation == generation => information,
                Ok(_) => return 0xC000_022D,
                Err(status) => return status as u32,
            };
            return self
                .persist_and_publish_system_mutations(
                    generation,
                    &[OwnedSystemHiveMutation::DeleteValue {
                        path: information.path,
                        name: name.into(),
                    }],
                    SystemHiveMutationOrigin::Runtime,
                )
                .err()
                .unwrap_or(0);
        }
        if let Some(index) = overlay_key_idx(key) {
            if self.overlay.path(index).is_none() {
                return STATUS_INVALID_HANDLE;
            }
            return if self.overlay.delete_value(index, name) {
                0
            } else {
                STATUS_OBJECT_NAME_NOT_FOUND
            };
        }
        if let Some(key) = self.mutable_key_handle(key) {
            return self
                .journal_delete_mutable_value(key, name)
                .err()
                .unwrap_or(0);
        }
        STATUS_ACCESS_DENIED
    }

    pub(super) unsafe fn nt_set_value_key_admitted(&mut self, args: &[u64]) -> u32 {
        let key = match self.resolve_registry_key(args[0], 2) {
            Ok(key) => key,
            Err(status) => return status,
        };
        let mut retained = if self.cm_system_key_target(key).is_some() {
            match crate::registry_mutation_work::retain_hosted_existing(self, key) {
                Ok(retained) => Some(retained),
                Err(status) => return status,
            }
        } else {
            None
        };
        let name = match self.read_registry_name_checked(args[1]) {
            Ok(name) => name,
            Err(status) => {
                if let Some(retained) = retained.take() { retained.abort(self); }
                return status;
            }
        };
        let mut data = match try_zeroed_transfer_buffer(nt_ulong_arg(args[5]) as usize) {
            Ok(data) => data,
            Err(status) => {
                if let Some(retained) = retained.take() { retained.abort(self); }
                return status;
            }
        };
        if !data.is_empty() {
            if let Err(status) = self.process_memory_read_status(self.pi, args[4], &mut data) {
                if let Some(retained) = retained.take() { retained.abort(self); }
                return status;
            }
        }
        if let Some(retained) = retained {
            if nt_hive_core::RegistryValueType::from_u32(nt_ulong_arg(args[3])).is_none() {
                retained.abort(self);
                return STATUS_INVALID_PARAMETER;
            }
            let generation = crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
            let information = match retained.information() {
                Ok(information) if information.mount_generation == generation => information,
                Ok(_) => { retained.abort(self); return 0xC000_022D; }
                Err(status) => { retained.abort(self); return status; }
            };
            return match crate::registry_mutation_work::submit_hosted_existing(
                self, retained, generation,
                nt_config_client::SystemHiveMutation::SetValue {
                    path: &information.path,
                    name: &name,
                    value_type: nt_ulong_arg(args[3]),
                    data: &data,
                },
            ) {
                Ok(()) => 0x103,
                Err(status) => status,
            };
        }
        self.registry_target_set_value(key, &name, nt_ulong_arg(args[3]), &data)
    }

    pub(super) unsafe fn nt_delete_value_key_admitted(&mut self, args: &[u64]) -> u32 {
        let key = match self.resolve_registry_key(args[0], 2) {
            Ok(key) => key,
            Err(status) => return status,
        };
        let retained = if self.cm_system_key_target(key).is_some() {
            match crate::registry_mutation_work::retain_hosted_existing(self, key) {
                Ok(retained) => Some(retained),
                Err(status) => return status,
            }
        } else {
            None
        };
        let name = match self.read_registry_name_checked(args[1]) {
            Ok(name) => name,
            Err(status) => {
                if let Some(retained) = retained { retained.abort(self); }
                return status;
            }
        };
        if let Some(retained) = retained {
            let generation = crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
            let information = match retained.information() {
                Ok(information) if information.mount_generation == generation => information,
                Ok(_) => { retained.abort(self); return 0xC000_022D; }
                Err(status) => { retained.abort(self); return status; }
            };
            return match crate::registry_mutation_work::submit_hosted_existing(
                self, retained, generation,
                nt_config_client::SystemHiveMutation::DeleteValue {
                    path: &information.path,
                    name: &name,
                },
            ) {
                Ok(()) => 0x103,
                Err(status) => status,
            };
        }
        self.registry_target_delete_value(key, &name)
    }
}
