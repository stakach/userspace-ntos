//! Boot-route v2 WAL ownership for mutable hive edits made inside the call.

use super::*;
use crate::mutable_hive_edit_route::EditOwner;
use crate::mutable_hive_prepared_edit::{AnchoredRecord, PreparedEdit};

impl ExecNtHandler {
    /// The owner of a mutable-hive edit on the mounted volume's current block route.
    pub(crate) fn mutable_edit_owner(&self) -> EditOwner {
        crate::mutable_hive_edit_route::edit_owner(
            unsafe { crate::fs_loader::exec_fs_mount_identity() }
                .and_then(crate::fs_loader::exec_block_route_kind),
            !crate::writable_fs::legacy_snapshot_writes_allowed(),
        )
    }

    pub(super) fn boot_v2_mutable_hive_journal(&self) -> bool {
        self.mutable_edit_owner() == EditOwner::BootWal
    }

    /// Anchor one exact prepared edit in the Boot-route WAL, then publish it. Every failure
    /// after the record may have entered keeps the edit pinned and halts: no replay, no reuse.
    fn boot_v2_journal(&mut self, hive: u32, mut prepared: PreparedEdit, what: &[u8])
        -> Result<Option<nt_hive_core::CellId>, u32>
    {
        let mut log_path = self
            .mutable_hive_checkpoint_path_owned(hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if log_path.try_reserve(4).is_err() {
            prepared.release_unentered(&mut self.mutable_hives)
                .ok().expect("unentered Boot edit reservation");
            return Err(nt_fs::STATUS_INSUFFICIENT_RESOURCES);
        }
        log_path.push_str(".LOG");
        let journal = match unsafe {
            crate::writable_fs::hive_wal::begin_boot_hive_journal(&log_path, prepared.record())
        } {
            Ok(journal) => journal,
            Err(status) => {
                prepared.release_unentered(&mut self.mutable_hives)
                    .ok().expect("unentered Boot edit reservation");
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
                panic!("Boot edit journal preparation left an uncertain owner");
            }
            prepared.release_unentered(&mut self.mutable_hives)
                .ok().expect("unentered Boot edit reservation");
            return Err(status);
        }
        // The physical WAL effect may become uncertain after this point. Keep the reservation
        // pinned and halt rather than replaying or publishing from a scalar status.
        unsafe { prepared.mark_entered(); }
        let receipt =
            match unsafe { crate::writable_fs::hive_wal::enter_boot_hive_journal(journal) } {
                Ok(receipt) => receipt,
                Err(status) => {
                    print_str(b"[profile-setup] Boot ");
                    print_str(what);
                    print_str(b" WAL uncertain status=0x");
                    print_hex(status);
                    print_str(b"\n");
                    core::mem::forget(prepared);
                    panic!("Boot edit journal did not reach exact anchor");
                }
            };
        let record = AnchoredRecord { anchored: receipt.anchored, file_id: receipt.file_id,
            expected_log_len: receipt.expected_log_len, log_path: &receipt.log_path };
        let (child, continuation, pair) = match prepared.publish(&mut self.mutable_hives, record) {
            Ok(published) => published,
            Err((prepared, anchored)) => {
                core::mem::forget(prepared);
                core::mem::forget(anchored);
                panic!("Boot edit anchor did not match retained hive edit");
            }
        };
        if let Err((status, continuation, pair)) = unsafe {
            crate::writable_fs::hive_wal::install_boot_hive_publication(journal, continuation, pair)
        } {
            print_str(b"[profile-setup] Boot ");
            print_str(what);
            print_str(b" continuation status=0x");
            print_hex(status);
            print_str(b"\n");
            core::mem::forget(continuation);
            core::mem::forget(pair);
            panic!("Boot edit continuation installation failed");
        }
        self.note_mutable_hive_journal_record(hive);
        Ok(child)
    }

    pub(super) fn boot_v2_create_secured_mutable_subkey(
        &mut self,
        parent: ResolvedHiveKey,
        leaf: &str,
        class: Option<&str>,
        descriptor: &[u8],
        kind: nt_hive_core::KeyKind,
    ) -> Result<ResolvedHiveKey, u32> {
        let relative = self
            .mutable_key_relative_path(parent)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let prepared = self
            .mutable_hives
            .prepare_owned_create_child_of_kind(
                parent.hive,
                parent.key,
                &relative,
                leaf,
                class,
                descriptor.to_vec(),
                kind,
            )
            .map_err(|error| match error {
                nt_hive_core::CreateChildError::InvalidName => 0xC000_0033,
                nt_hive_core::CreateChildError::ParentNotFound => STATUS_INVALID_HANDLE,
                nt_hive_core::CreateChildError::NameCollision => 0xC000_0035,
                nt_hive_core::CreateChildError::EmptySecurityDescriptor => 0xC000_0079,
                nt_hive_core::CreateChildError::ChildMustBeVolatile => 0xC000_0181,
                nt_hive_core::CreateChildError::ParentIsSymbolicLink => 0xC000_0022,
                nt_hive_core::CreateChildError::InsufficientResources => {
                    nt_fs::STATUS_INSUFFICIENT_RESOURCES
                }
                nt_hive_core::CreateChildError::RetainedPublication => 0xC000_00A3,
            })?;
        let child = self.boot_v2_journal(parent.hive, PreparedEdit::Child(prepared), b"child")?
            .expect("published Boot child");
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
        let prepared = self
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
        self.boot_v2_journal(key.hive, PreparedEdit::Security(prepared), b"security")
            .map(|_| ())
    }

    pub(super) fn boot_v2_set_mutable_value(
        &mut self, key: ResolvedHiveKey, name: &str,
        value_type: nt_hive_core::RegistryValueType, data: &[u8],
    ) -> Result<(), u32> {
        let relative = self.mutable_key_relative_path(key).ok_or(STATUS_INVALID_HANDLE)?;
        let prepared = self.mutable_hives.prepare_owned_set_value(
            key.hive, key.key, &relative, name, value_type, data.to_vec(),
        ).map_err(|error| match error {
            nt_hive_core::SetValueError::KeyNotFound => STATUS_INVALID_HANDLE,
            nt_hive_core::SetValueError::InsufficientResources => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
            nt_hive_core::SetValueError::RetainedPublication => 0xC000_00A3,
        })?;
        self.boot_v2_journal(key.hive, PreparedEdit::Value(prepared), b"value").map(|_| ())
    }

    /// `ZwDeleteValueKey` on the Boot route of a WAL volume: anchored like a set (#424).
    pub(super) fn boot_v2_delete_mutable_value(&mut self, key: ResolvedHiveKey, name: &str)
        -> Result<(), u32>
    {
        let relative = self.mutable_key_relative_path(key).ok_or(STATUS_INVALID_HANDLE)?;
        let prepared = self.mutable_hives
            .prepare_owned_delete_value(key.hive, key.key, &relative, name)
            .map_err(crate::mutable_hive_mutation_work::delete_value_error)?;
        self.boot_v2_journal(key.hive, PreparedEdit::DeleteValue(prepared), b"delete-value")
            .map(|_| ())
    }

    /// `ZwDeleteKey` of a leaf on the Boot route of a WAL volume (#424).
    pub(super) fn boot_v2_delete_mutable_key(&mut self, key: ResolvedHiveKey) -> Result<(), u32> {
        let relative = self.mutable_key_relative_path(key).ok_or(STATUS_INVALID_HANDLE)?;
        let prepared = self.mutable_hives
            .prepare_owned_delete_key(key.hive, key.key, &relative)
            .map_err(crate::mutable_hive_mutation_work::delete_key_error)?;
        self.boot_v2_journal(key.hive, PreparedEdit::DeleteKey(prepared), b"delete-key")
            .map(|_| ())
    }
}
