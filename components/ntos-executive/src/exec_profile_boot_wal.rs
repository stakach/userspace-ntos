//! Boot-route v2 WAL ownership for mutable hive child and security setup edits.

use super::*;

impl ExecNtHandler {
    pub(super) fn boot_v2_mutable_hive_journal(&self) -> bool {
        !crate::writable_fs::legacy_snapshot_writes_allowed()
            && matches!(
                unsafe { crate::fs_loader::exec_fs_mount_identity() }
                    .and_then(crate::fs_loader::exec_block_route_kind),
                Some(nt_fs::BlockSourceKind::Boot)
            )
    }

    pub(super) fn boot_v2_create_secured_mutable_subkey(
        &mut self,
        parent: ResolvedHiveKey,
        leaf: &str,
        class: Option<&str>,
        descriptor: &[u8],
    ) -> Result<ResolvedHiveKey, u32> {
        let relative = self
            .mutable_key_relative_path(parent)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let mut log_path = self
            .mutable_hive_checkpoint_path_owned(parent.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        log_path
            .try_reserve(4)
            .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
        log_path.push_str(".LOG");
        let mut prepared = self
            .mutable_hives
            .prepare_owned_create_child(
                parent.hive,
                parent.key,
                &relative,
                leaf,
                class,
                descriptor.to_vec(),
            )
            .map_err(|error| match error {
                nt_hive_core::CreateChildError::InvalidName => 0xC000_0033,
                nt_hive_core::CreateChildError::ParentNotFound => STATUS_INVALID_HANDLE,
                nt_hive_core::CreateChildError::NameCollision => 0xC000_0035,
                nt_hive_core::CreateChildError::EmptySecurityDescriptor => 0xC000_0079,
                nt_hive_core::CreateChildError::ChildMustBeVolatile => 0xC000_0181,
                nt_hive_core::CreateChildError::InsufficientResources => {
                    nt_fs::STATUS_INSUFFICIENT_RESOURCES
                }
                nt_hive_core::CreateChildError::RetainedPublication => 0xC000_00A3,
            })?;
        let journal = match unsafe {
            crate::writable_fs::hive_wal::begin_boot_hive_journal(&log_path, prepared.record())
        } {
            Ok(journal) => journal,
            Err(status) => {
                self.mutable_hives
                    .release_unentered_owned_create_child(prepared)
                    .expect("unentered Boot child reservation");
                return Err(status);
            }
        };
        if let Err(status) =
            unsafe { crate::writable_fs::hive_wal::prepare_boot_hive_journal(journal) }
        {
            if unsafe { crate::writable_fs::hive_wal::abort_unentered_boot_hive_journal(journal) }
                .is_err()
            {
                core::mem::forget(prepared);
                panic!("Boot child journal preparation left an uncertain owner");
            }
            self.mutable_hives
                .release_unentered_owned_create_child(prepared)
                .expect("unentered Boot child reservation");
            return Err(status);
        }
        // The physical WAL effect may become uncertain after this point. Keep the reservation
        // pinned and halt rather than replaying or publishing from a scalar status.
        unsafe {
            prepared.mark_entered();
        }
        let receipt =
            match unsafe { crate::writable_fs::hive_wal::enter_boot_hive_journal(journal) } {
                Ok(receipt) => receipt,
                Err(status) => {
                    print_str(b"[profile-setup] Boot child WAL uncertain status=0x");
                    print_hex(status);
                    print_str(b"\n");
                    core::mem::forget(prepared);
                    panic!("Boot child journal did not reach exact anchor");
                }
            };
        let (child, continuation, pair) = match nt_fs::publish_anchored_hive_child(
            &mut self.mutable_hives,
            prepared,
            receipt.anchored,
            receipt.file_id,
            receipt.expected_log_len,
            &receipt.log_path,
        ) {
            Ok(parts) => parts,
            Err((_, prepared, anchored)) => {
                core::mem::forget(prepared);
                core::mem::forget(anchored);
                panic!("Boot child anchor did not match retained hive edit");
            }
        };
        if let Err((status, continuation, pair)) = unsafe {
            crate::writable_fs::hive_wal::install_boot_hive_publication(journal, continuation, pair)
        } {
            print_str(b"[profile-setup] Boot child continuation status=0x");
            print_hex(status);
            print_str(b"\n");
            core::mem::forget(continuation);
            core::mem::forget(pair);
            panic!("Boot child continuation installation failed");
        }
        self.note_mutable_hive_journal_record(parent.hive);
        Ok(ResolvedHiveKey {
            hive: parent.hive,
            key: child,
        })
    }

    pub(super) fn boot_v2_set_mutable_key_security_descriptor(
        &mut self,
        key: ResolvedHiveKey,
        descriptor: &[u8],
    ) -> Result<(), u32> {
        let relative = self
            .mutable_key_relative_path(key)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let mut log_path = self
            .mutable_hive_checkpoint_path_owned(key.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        log_path
            .try_reserve(4)
            .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
        log_path.push_str(".LOG");
        let mut prepared = self
            .mutable_hives
            .prepare_owned_set_key_security(key.hive, key.key, &relative, descriptor.to_vec())
            .map_err(|error| match error {
                nt_hive_core::SetKeySecurityError::KeyNotFound => STATUS_INVALID_HANDLE,
                nt_hive_core::SetKeySecurityError::KeyMustBeDurable => 0xC000_0181,
                nt_hive_core::SetKeySecurityError::InsufficientResources => {
                    nt_fs::STATUS_INSUFFICIENT_RESOURCES
                }
                nt_hive_core::SetKeySecurityError::RetainedPublication => 0xC000_00A3,
            })?;
        let journal = match unsafe {
            crate::writable_fs::hive_wal::begin_boot_hive_journal(&log_path, prepared.record())
        } {
            Ok(journal) => journal,
            Err(status) => {
                self.mutable_hives
                    .release_unentered_owned_set_key_security(prepared)
                    .expect("unentered Boot security reservation");
                return Err(status);
            }
        };
        if let Err(status) =
            unsafe { crate::writable_fs::hive_wal::prepare_boot_hive_journal(journal) }
        {
            if unsafe { crate::writable_fs::hive_wal::abort_unentered_boot_hive_journal(journal) }
                .is_err()
            {
                core::mem::forget(prepared);
                panic!("Boot security journal preparation left an uncertain owner");
            }
            self.mutable_hives
                .release_unentered_owned_set_key_security(prepared)
                .expect("unentered Boot security reservation");
            return Err(status);
        }
        unsafe {
            prepared.mark_entered();
        }
        let receipt =
            match unsafe { crate::writable_fs::hive_wal::enter_boot_hive_journal(journal) } {
                Ok(receipt) => receipt,
                Err(status) => {
                    print_str(b"[profile-setup] Boot security WAL uncertain status=0x");
                    print_hex(status);
                    print_str(b"\n");
                    core::mem::forget(prepared);
                    panic!("Boot security journal did not reach exact anchor");
                }
            };
        let (continuation, pair) = match nt_fs::publish_anchored_hive_security(
            &mut self.mutable_hives,
            prepared,
            receipt.anchored,
            receipt.file_id,
            receipt.expected_log_len,
            &receipt.log_path,
        ) {
            Ok(parts) => parts,
            Err((_, prepared, anchored)) => {
                core::mem::forget(prepared);
                core::mem::forget(anchored);
                panic!("Boot security anchor did not match retained hive edit");
            }
        };
        if let Err((status, continuation, pair)) = unsafe {
            crate::writable_fs::hive_wal::install_boot_hive_publication(journal, continuation, pair)
        } {
            print_str(b"[profile-setup] Boot security continuation status=0x");
            print_hex(status);
            print_str(b"\n");
            core::mem::forget(continuation);
            core::mem::forget(pair);
            panic!("Boot security continuation installation failed");
        }
        self.note_mutable_hive_journal_record(key.hive);
        Ok(())
    }
}
