//! Handle reads stay on the opened Key authority; only namespace roots enumerate live mounts.

use super::*;

impl ExecNtHandler {
    fn runtime_key_stats(&self, key: u64) -> Result<RegistryKeyStats, u32> {
        let (_, bytes) = unsafe {
            config_manager_runtime_key_operation(
                key,
                nt_config_abi::runtime_key_op::INFO,
                0,
                "",
                0,
                &[],
            )
        }
        .map_err(|status| status as u32)?;
        let info =
            nt_config_abi::CmRuntimeKeyInfo::from_bytes(&bytes).ok_or(STATUS_INVALID_PARAMETER)?;
        Ok(RegistryKeyStats {
            subkeys: info.subkeys,
            max_subkey_name_bytes: info.max_subkey_name,
            max_subkey_class_bytes: info.max_subkey_class,
            values: info.values,
            max_value_name_bytes: info.max_value_name,
            max_value_data_bytes: info.max_value_data,
        })
    }
    pub(crate) fn registry_key_class(
        &self,
        target: KeyRef,
    ) -> Result<Option<alloc::string::String>, u32> {
        if let Some(key) = self.cm_system_key_target(target) {
            return unsafe { config_manager_query_leased_system_hive_key_information(key.lease) }
                .map(|information| information.class_name)
                .map_err(|status| status as u32);
        }
        if let Some(index) = overlay_key_idx(target) {
            if self.overlay.path(index).is_none() {
                return Err(STATUS_INVALID_HANDLE);
            }
            return Ok(self.overlay.key_class(index).map(Into::into));
        }
        if let Some(key) = self.mutable_key_handle(target) {
            return Ok(self.mutable_hives.key_class(key).map(Into::into));
        }
        if let Some((hive, key)) = self.base_hive(target) {
            return hive.key_class(key).map_err(|_| 0xC000_014C);
        }
        if let Some(key) = self.cm_runtime_key_target(target) {
            return unsafe { config_manager_runtime_key_class(key.key) }
                .map_err(|status| status as u32);
        }
        if is_virtual_registry_key(target) {
            return Ok(None);
        }
        Err(STATUS_INVALID_HANDLE)
    }

    pub(crate) fn registry_value_by_index_with<R>(
        &self,
        target: KeyRef,
        index: usize,
        mut visit: impl FnMut(&str, u32, &[u8], Option<ResolvedHiveValue>) -> R,
    ) -> Result<Option<R>, u32> {
        if let Some(key) = self.cm_system_key_target(target) {
            return match unsafe {
                crate::config_manager_enumerate_leased_system_hive_value(key.lease, index as u32)
            } {
                Ok(value) => Ok(Some(visit(
                    &value.name,
                    value.value_type,
                    &value.data,
                    None,
                ))),
                Err(status) if status as u32 == STATUS_NO_MORE_ENTRIES => Ok(None),
                Err(status) => Err(status as u32),
            };
        }
        if let Some(key) = self.cm_runtime_key_target(target) {
            return match unsafe {
                config_manager_runtime_key_operation(
                    key.key,
                    nt_config_abi::runtime_key_op::ENUM_VALUE,
                    index as u32,
                    "",
                    0,
                    &[],
                )
            } {
                Ok((reply, bytes)) => {
                    let split =
                        usize::try_from(reply.detail1).map_err(|_| STATUS_INVALID_PARAMETER)?;
                    let name = runtime_name(bytes.get(..split).ok_or(STATUS_INVALID_PARAMETER)?)?;
                    Ok(Some(visit(
                        &name,
                        reply.detail0 as u32,
                        &bytes[split..],
                        None,
                    )))
                }
                Err(status) if status as u32 == STATUS_NO_MORE_ENTRIES => Ok(None),
                Err(status) => Err(status as u32),
            };
        }
        if let Some(overlay) = overlay_key_idx(target) {
            if self.overlay.path(overlay).is_none() {
                return Err(STATUS_INVALID_HANDLE);
            }
            return Ok(self
                .overlay
                .value_by_index(overlay, index)
                .map(|(name, ty, data)| visit(name, ty, data, None)));
        }
        if let Some(key) = self.mutable_key_handle(target) {
            return Ok(self
                .mutable_hives
                .value_ref_by_index(key, index)
                .map(|(source, name, ty, data)| visit(name, ty as u32, data, Some(source))));
        }
        if let Some((hive, key)) = self.base_hive(target) {
            return Ok(
                hive.value_by_index_with(key, index, |name, ty, data| visit(name, ty, data, None))
            );
        }
        if is_virtual_registry_key(target) {
            return Ok(None);
        }
        Err(STATUS_INVALID_HANDLE)
    }

    fn mutable_key_stats_exact(&self, key: ResolvedHiveKey) -> Result<RegistryKeyStats, u32> {
        let hive = self
            .mutable_hives
            .hive(key.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let mut stats = RegistryKeyStats::default();
        for index in 0..hive.subkey_count(key.key) {
            let name = hive
                .subkey_name_by_index(key.key, index)
                .ok_or(STATUS_INVALID_HANDLE)?;
            stats.add_subkey(
                utf16le_byte_len(name),
                hive.subkey_class_by_index(key.key, index)
                    .map(utf16le_byte_len)
                    .unwrap_or(0),
            );
        }
        for index in 0..hive.value_count(key.key) {
            let (name, _, data) = hive
                .value_by_index(key.key, index)
                .ok_or(STATUS_INVALID_HANDLE)?;
            stats.add_value(utf16le_byte_len(name), data.len());
        }
        Ok(stats)
    }

    fn base_key_stats_exact(&self, target: KeyRef) -> Result<RegistryKeyStats, u32> {
        let (hive, key) = self.base_hive(target).ok_or(STATUS_INVALID_HANDLE)?;
        let mut stats = RegistryKeyStats::default();
        for index in 0..hive.subkey_count(key) {
            let (name, child) = hive
                .subkey_by_index(key, index)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let class = hive.key_class(child).map_err(|_| 0xC000_014Cu32)?;
            stats.add_subkey(
                utf16le_byte_len(&name),
                class.as_deref().map(utf16le_byte_len).unwrap_or(0),
            );
        }
        for index in 0..hive.value_count(key) {
            hive.value_by_index_with(key, index, |name, _, data| {
                stats.add_value(utf16le_byte_len(name), data.len())
            })
            .ok_or(STATUS_INVALID_HANDLE)?;
        }
        Ok(stats)
    }

    pub(crate) fn registry_key_stats(&self, target: KeyRef) -> Result<RegistryKeyStats, u32> {
        if let Some(key) = self.cm_system_key_target(target) {
            return unsafe { config_manager_query_leased_system_hive_key_information(key.lease) }
                .map(|information| RegistryKeyStats::from_leased_key(&information))
                .map_err(|status| status as u32);
        }
        if let Some(key) = self.cm_runtime_key_target(target) {
            return self.runtime_key_stats(key.key);
        }
        if let Some(key) = self.mutable_key_handle(target) {
            return self.mutable_key_stats_exact(key);
        }
        if self.base_hive(target).is_some() {
            return self.base_key_stats_exact(target);
        }
        let mut stats = RegistryKeyStats::default();
        for index in 0.. {
            let Some(child) = self.registry_subkey_by_index(target, index, false)? else {
                break;
            };
            stats.add_subkey(
                utf16le_byte_len(&child.name),
                child
                    .class_name
                    .as_deref()
                    .map(utf16le_byte_len)
                    .unwrap_or(0),
            );
        }
        for index in 0.. {
            if self
                .registry_value_by_index_with(target, index, |name, _, data, _| {
                    stats.add_value(utf16le_byte_len(name), data.len())
                })?
                .is_none()
            {
                break;
            }
        }
        Ok(stats)
    }

    pub(crate) fn registry_subkey_by_index(
        &self,
        target: KeyRef,
        index: usize,
        include_stats: bool,
    ) -> Result<Option<RegistrySubkeyEntry>, u32> {
        if let Some(key) = self.cm_system_key_target(target) {
            return match unsafe {
                crate::config_manager_enumerate_leased_system_hive_subkey(key.lease, index as u32)
            } {
                Ok(child) => {
                    let stats = if include_stats {
                        RegistryKeyStats::from_leased_subkey(&child)
                    } else {
                        RegistryKeyStats::default()
                    };
                    Ok(Some(RegistrySubkeyEntry {
                        name: child.name,
                        class_name: child.class_name,
                        stats,
                    }))
                }
                Err(status) if status as u32 == STATUS_NO_MORE_ENTRIES => Ok(None),
                Err(status) => Err(status as u32),
            };
        }
        if let Some(key) = self.cm_runtime_key_target(target) {
            return match unsafe {
                config_manager_runtime_key_operation(
                    key.key,
                    nt_config_abi::runtime_key_op::ENUM_KEY,
                    index as u32,
                    "",
                    0,
                    &[],
                )
            } {
                Ok((reply, bytes)) => Ok(Some(RegistrySubkeyEntry {
                    name: runtime_name(&bytes)?,
                    class_name: unsafe { config_manager_runtime_key_class(reply.detail0) }
                        .map_err(|status| status as u32)?,
                    stats: if include_stats {
                        self.runtime_key_stats(reply.detail0)?
                    } else {
                        RegistryKeyStats::default()
                    },
                })),
                Err(status) if status as u32 == STATUS_NO_MORE_ENTRIES => Ok(None),
                Err(status) => Err(status as u32),
            };
        }
        if let Some(key) = self.mutable_key_handle(target) {
            let hive = self
                .mutable_hives
                .hive(key.hive)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let Some(name) = hive.subkey_name_by_index(key.key, index) else {
                return Ok(None);
            };
            let child = hive
                .open_subkey(key.key, name)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let stats = if include_stats {
                self.mutable_key_stats_exact(ResolvedHiveKey {
                    hive: key.hive,
                    key: child,
                })?
            } else {
                RegistryKeyStats::default()
            };
            return Ok(Some(RegistrySubkeyEntry {
                name: name.into(),
                class_name: hive.key_class(child).map(Into::into),
                stats,
            }));
        }
        if let Some((hive, key)) = self.base_hive(target) {
            let Some((name, child)) = hive.subkey_by_index(key, index) else {
                return Ok(None);
            };
            let stats = if include_stats {
                self.base_key_stats_exact(hive_sel(target) | child)?
            } else {
                RegistryKeyStats::default()
            };
            return Ok(Some(RegistrySubkeyEntry {
                name,
                class_name: hive.key_class(child).map_err(|_| 0xC000_014Cu32)?,
                stats,
            }));
        }
        if let Some(overlay) = overlay_key_idx(target) {
            let path = self.overlay.path(overlay).ok_or(STATUS_INVALID_HANDLE)?;
            let Some(name) = self.overlay.subkey_by_index(path, index) else {
                return Ok(None);
            };
            let child_path = alloc::format!("{}\\{}", path, name);
            let child = self
                .overlay
                .find(&child_path)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let stats = if include_stats {
                self.registry_key_stats(OVERLAY_KEY_TAG | child as u32)?
            } else {
                RegistryKeyStats::default()
            };
            return Ok(Some(RegistrySubkeyEntry {
                name: name.into(),
                class_name: self.overlay.key_class(child).map(Into::into),
                stats,
            }));
        }
        if is_virtual_registry_key(target) {
            let path = self
                .registry_target_path(target)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let children = self.registry_mounted_hive_subkeys(&path);
            return children
                .get(index)
                .map(|name| self.registry_subkey_entry_for_name(&path, name.clone(), include_stats))
                .transpose();
        }
        Err(STATUS_INVALID_HANDLE)
    }
}

fn runtime_name(bytes: &[u8]) -> Result<alloc::string::String, u32> {
    if bytes.len() % 2 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    alloc::string::String::from_utf16(
        &bytes
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect::<alloc::vec::Vec<_>>(),
    )
    .map_err(|_| STATUS_INVALID_PARAMETER)
}
