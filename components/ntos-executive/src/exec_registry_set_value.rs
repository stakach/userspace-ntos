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
        if matches!(unsafe { crate::fs_loader::exec_fs_mount_identity() }
            .and_then(crate::fs_loader::exec_block_route_kind),
            Some(nt_fs::BlockSourceKind::Native | nt_fs::BlockSourceKind::Draining)) {
            return Err(nt_fs::STATUS_NOT_SUPPORTED);
        }
        if self.boot_v2_mutable_hive_journal() {
            return self.boot_v2_set_mutable_value(key, name, value_type, data);
        }
        let _path_scope = allocator::enter_scope(b"registry.mutable-hive-path");
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
            let _prepare_scope = allocator::enter_scope(b"hive.prepare-value");
            manager
                .try_set_value(hive, key.key, &relative, name, value_type, data)
                .map_err(Self::mutable_hive_set_value_status)?
        };
        if receipt.durable {
            self.note_mutable_hive_journal_record(key.hive);
        }
        Ok(())
    }

    fn boot_v2_set_mutable_value(
        &mut self, key: ResolvedHiveKey, name: &str,
        value_type: nt_hive_core::RegistryValueType, data: &[u8],
    ) -> Result<(), u32> {
        let relative = self.mutable_key_relative_path(key).ok_or(STATUS_INVALID_HANDLE)?;
        let mut log_path = self.mutable_hive_checkpoint_path_owned(key.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        log_path.try_reserve(4).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
        log_path.push_str(".LOG");
        let mut prepared = self.mutable_hives.prepare_owned_set_value(
            key.hive, key.key, &relative, name, value_type, data.to_vec(),
        ).map_err(|error| match error {
            nt_hive_core::SetValueError::KeyNotFound => STATUS_INVALID_HANDLE,
            nt_hive_core::SetValueError::InsufficientResources => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
            nt_hive_core::SetValueError::RetainedPublication => 0xC000_00A3,
        })?;
        let journal = match unsafe { crate::writable_fs::hive_wal::begin_boot_hive_journal(
            &log_path, prepared.record()) } {
            Ok(journal) => journal,
            Err(status) => {
                self.mutable_hives.release_unentered_owned_set_value(prepared)
                    .expect("unentered Boot value reservation");
                return Err(status);
            }
        };
        if let Err(status) = unsafe { crate::writable_fs::hive_wal::prepare_boot_hive_journal(journal) } {
            if unsafe { crate::writable_fs::hive_wal::abort_unentered_boot_hive_journal(journal) }.is_err() {
                core::mem::forget(prepared);
                panic!("Boot value journal preparation left an uncertain owner");
            }
            self.mutable_hives.release_unentered_owned_set_value(prepared)
                .expect("unentered Boot value reservation");
            return Err(status);
        }
        unsafe { prepared.mark_entered(); }
        let receipt = match unsafe { crate::writable_fs::hive_wal::enter_boot_hive_journal(journal) } {
            Ok(receipt) => receipt,
            Err(status) => {
                print_str(b"[profile-setup] Boot value WAL uncertain status=0x");
                print_hex(status);
                print_str(b"\n");
                core::mem::forget(prepared);
                panic!("Boot value journal did not reach exact anchor");
            }
        };
        let (_, continuation, pair) = match nt_fs::publish_anchored_hive_value(
            &mut self.mutable_hives, prepared, receipt.anchored,
            receipt.file_id, receipt.expected_log_len, &receipt.log_path,
        ) {
            Ok(parts) => parts,
            Err((_, prepared, anchored)) => {
                core::mem::forget(prepared);
                core::mem::forget(anchored);
                panic!("Boot value anchor did not match retained hive edit");
            }
        };
        if let Err((status, continuation, pair)) = unsafe {
            crate::writable_fs::hive_wal::install_boot_hive_publication(journal, continuation, pair)
        } {
            print_str(b"[profile-setup] Boot value continuation status=0x");
            print_hex(status);
            print_str(b"\n");
            core::mem::forget(continuation);
            core::mem::forget(pair);
            panic!("Boot value continuation installation failed");
        }
        self.note_mutable_hive_journal_record(key.hive);
        Ok(())
    }

    pub(crate) fn mutable_hive_set_value_status(err: nt_hive_core::HiveSetValueError) -> u32 {
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
