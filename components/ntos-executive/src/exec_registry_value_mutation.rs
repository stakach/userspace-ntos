//! Exact-Key mutation shared by hosted syscalls and kernel provider requests.

use super::*;
use crate::mutable_hive_edit_route::{EditOwner, STATUS_DEVICE_NOT_READY};

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
            return match crate::config_manager_runtime_key_operation(
                path.key,
                nt_config_abi::runtime_key_op::SET_VALUE,
                0,
                name,
                value_type,
                data,
            ) {
                Ok(_) => {
                    self.registry_key_values_changed(&path.path);
                    0
                }
                Err(status) => status as u32,
            };
        }
        if self.cm_system_key_target(key).is_some() {
            unreachable!("SYSTEM value SET requires retained mutation work");
        }
        if let Some(index) = overlay_key_idx(key) {
            return if self
                .overlay
                .set_value_from_slice(index, name.into(), value_type, data)
            {
                self.registry_target_values_changed(key);
                0
            } else {
                STATUS_INVALID_HANDLE
            };
        }
        if let Some(key) = self.mutable_key_handle(key) {
            let Some(value_type) = nt_hive_core::RegistryValueType::from_u32(value_type) else {
                return STATUS_INVALID_PARAMETER;
            };
            return match self.journal_set_mutable_value(key, name, value_type, data) {
                Ok(()) => {
                    self.mutable_registry_key_values_changed(key);
                    0
                }
                Err(status) => status,
            };
        }
        STATUS_ACCESS_DENIED
    }

    pub(crate) unsafe fn registry_target_delete_value(&mut self, key: KeyRef, name: &str) -> u32 {
        let _durable = allocator::enter_durable();
        if let Some(path) = self.cm_runtime_key_target(key) {
            return match crate::config_manager_runtime_key_operation(
                path.key,
                nt_config_abi::runtime_key_op::DELETE_VALUE,
                0,
                name,
                0,
                &[],
            ) {
                Ok(_) => {
                    self.registry_key_values_changed(&path.path);
                    0
                }
                Err(status) => status as u32,
            };
        }
        if self.cm_system_key_target(key).is_some() {
            unreachable!("SYSTEM value DELETE requires retained mutation work");
        }
        if let Some(index) = overlay_key_idx(key) {
            if self.overlay.path(index).is_none() {
                return STATUS_INVALID_HANDLE;
            }
            return if self.overlay.delete_value(index, name) {
                self.registry_target_values_changed(key);
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

    /// Whether `key` is a symbolic link key held by the executive (a mutable hive or the overlay).
    fn registry_key_is_symbolic_link(&self, key: KeyRef) -> bool {
        if let Some(mutable) = self.mutable_key_handle(key) {
            return self.mutable_hives.hive(mutable.hive)
                .and_then(|hive| hive.key_kind(mutable.key))
                == Some(nt_hive_core::KeyKind::SymbolicLink);
        }
        overlay_key_idx(key).is_some_and(|index| self.overlay.is_symbolic_link(index as usize))
    }

    pub(super) unsafe fn nt_set_value_key_admitted(&mut self, args: &[u64]) -> u32 {
        let _capture_scope = allocator::enter_scope(b"registry.set-value-capture");
        let key = match self.resolve_registry_key(args[0], 2) {
            Ok(key) => key,
            Err(status) => return status,
        };
        let path = self.registry_target_path(key);
        if let Some(path) = path.as_deref() {
            registry_admission::trace_computer_name_registry(
                b"set-ingress", path, 0, self.pi, self.current_tid,
            );
        }
        let status = (|| {
        let mut retained = if self.cm_system_key_target(key).is_some() {
            let _scope = allocator::enter_scope(b"registry.set-value-retain-cm");
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
        let _mutation_scope = allocator::enter_scope(b"registry.set-value-mutation");
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
        // CmSetValueKey: a link key holds only its REG_LINK target (SYSTEM enforces this in CM).
        if self.registry_key_is_symbolic_link(key)
            && !(nt_ulong_arg(args[3]) == nt_hive_core::RegistryValueType::Link as u32
                && name.eq_ignore_ascii_case(nt_hive_core::SYMBOLIC_LINK_VALUE))
        {
            return nt_security::STATUS_ACCESS_DENIED;
        }
        if let Some(mutable) = self.mutable_key_handle(key) {
            match self.mutable_edit_owner() {
                EditOwner::NotReady => return STATUS_DEVICE_NOT_READY,
                EditOwner::NativeWal => {
                    let Some(value_type) = nt_hive_core::RegistryValueType::from_u32(nt_ulong_arg(args[3]))
                        else { return STATUS_INVALID_PARAMETER; };
                    return match crate::mutable_hive_mutation_work::submit_hosted_set_value(
                        self, key, mutable, name, value_type, data,
                    ) {
                        Ok(()) => 0x103,
                        Err(status) => status,
                    };
                }
                EditOwner::BootWal | EditOwner::LegacyJournal => {}
            }
        }
        self.registry_target_set_value(key, &name, nt_ulong_arg(args[3]), &data)
        })();
        if let Some(path) = path.as_deref() {
            registry_admission::trace_computer_name_registry(
                b"set-return", path, status, self.pi, self.current_tid,
            );
        }
        status
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
        if let Some(mutable) = self.mutable_key_handle(key) {
            match self.mutable_edit_owner() {
                EditOwner::NotReady => return STATUS_DEVICE_NOT_READY,
                EditOwner::NativeWal => {
                    return match crate::mutable_hive_mutation_work::submit_hosted_delete_value(
                        self, key, mutable, name,
                    ) {
                        Ok(()) => 0x103,
                        Err(status) => status,
                    };
                }
                EditOwner::BootWal | EditOwner::LegacyJournal => {}
            }
        }
        self.registry_target_delete_value(key, &name)
    }

    /// `NtDeleteKey`: delete a leaf key (`references/reactos/ntoskrnl/config/ntapi.c`).
    pub(super) unsafe fn nt_delete_key_admitted(&mut self, args: &[u64]) -> u32 {
        const DELETE_ACCESS: u32 = 0x0001_0000;
        const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;
        let key = match self.resolve_registry_key(args[0], DELETE_ACCESS) {
            Ok(key) => key,
            Err(status) => return status,
        };
        if key == MACHINE_ROOT_KEY || key == USER_ROOT_KEY {
            return STATUS_CANNOT_DELETE;
        }
        if self.cm_system_key_target(key).is_some() {
            let retained = match crate::registry_mutation_work::retain_hosted_existing(self, key) {
                Ok(retained) => retained,
                Err(status) => return status,
            };
            let information = match retained.information() {
                Ok(information) => information,
                Err(status) => { retained.abort(self); return status; }
            };
            if information.subkey_count != 0 {
                retained.abort(self);
                return STATUS_CANNOT_DELETE;
            }
            return match crate::registry_mutation_work::submit_hosted_existing(
                self, retained, information.mount_generation,
                nt_config_client::SystemHiveMutation::DeleteKey {
                    path: &information.path,
                },
            ) {
                Ok(()) => 0x103,
                Err(status) => status,
            };
        }
        let stats = match self.registry_key_stats(key) {
            Ok(stats) => stats,
            Err(status) => return status,
        };
        if stats.subkeys != 0 {
            return STATUS_CANNOT_DELETE;
        }
        if let Some(index) = overlay_key_idx(key) {
            let Some(path) = self.overlay.path(index).map(alloc::string::String::from)
            else {
                return 0xC000_0034;
            };
            if self.overlay.detach_subtree(&path) == 0 {
                return 0xC000_0034;
            }
            self.registry_key_deleted(&path);
            return 0;
        }
        let key_path = self.registry_target_path(key);
        if let Some(mutable_key) = self.mutable_registry_key(key) {
            if mutable_key.hive == HIVE_SEL_SYSTEM {
                return STATUS_INVALID_HANDLE;
            }
            match self.mutable_edit_owner() {
                EditOwner::NotReady => return STATUS_DEVICE_NOT_READY,
                EditOwner::NativeWal => {
                    return match crate::mutable_hive_mutation_work::submit_hosted_delete_key(
                        self, key, mutable_key,
                    ) {
                        Ok(()) => 0x103,
                        Err(status) => status,
                    };
                }
                EditOwner::BootWal | EditOwner::LegacyJournal => {}
            }
            return match self.journal_delete_mutable_key(mutable_key) {
                Ok(()) => {
                    if let Some(path) = key_path.as_deref() {
                        let _ = self.overlay.detach_subtree(path);
                    }
                    0
                }
                Err(status) => status,
            };
        }
        0xC000_0022 // STATUS_ACCESS_DENIED: borrowed regf keys are read-only.
    }
}
