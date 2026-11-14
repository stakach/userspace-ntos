//! Registry requests that NT completes only once a hive is durable: `NtFlushKey` and
//! `NtUnloadKey*`.
//!
//! Each request is resolved once, against the caller's handles and memory, into a form that
//! names kernel state only. The durable step then runs on that form.
use super::*;

/// What one `NtFlushKey` makes durable (`CmFlushKey`, ReactOS `ntoskrnl/config/cmapi.c:1938`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlushScope {
    /// A key of the volatile master hive: `CmpDoFlushAll(FALSE)` over every mounted hive.
    All,
    /// The SYSTEM hive the Configuration Manager owns.
    System,
    /// One mounted mutable hive, by selector.
    Hive(u32),
    /// A key with no hive storage behind it.
    Nothing,
}

/// A hive `NtUnloadKey*` resolved from the caller's OBJECT_ATTRIBUTES.
pub(crate) struct UnloadTarget {
    /// Canonical mount path of the hive.
    pub(crate) canon: alloc::string::String,
    /// The Event to signal once the hive is detached, leased by the caller of the resolution.
    pub(crate) event_index: Option<usize>,
}

impl ExecNtHandler {
    /// Classify the key an `NtFlushKey` names and count the call.
    pub(super) fn registry_flush_scope(&self, key: KeyRef) -> FlushScope {
        REG_FLUSH_KEY_CALLS.fetch_add(1, Ordering::Relaxed);
        if let Some(index) = overlay_key_idx(key) {
            if self.overlay.is_volatile(index).unwrap_or(false) {
                REG_FLUSH_KEY_VOLATILE.fetch_add(1, Ordering::Relaxed);
                return FlushScope::All;
            }
            FlushScope::Nothing
        } else if self.cm_system_key_target(key).is_some() {
            REG_FLUSH_KEY_MUTABLE.fetch_add(1, Ordering::Relaxed);
            FlushScope::System
        } else if let Some(mutable_key) = self.mutable_registry_key(key) {
            REG_FLUSH_KEY_MUTABLE.fetch_add(1, Ordering::Relaxed);
            FlushScope::Hive(mutable_key.hive)
        } else {
            FlushScope::Nothing
        }
    }

    /// Make everything in `scope` durable. A key in ReactOS' volatile master hive drives
    /// `CmpDoFlushAll(FALSE)`; keys in mounted mutable hives checkpoint through the writable
    /// filesystem. Dynamic `NtLoadKey` profile hives write back to their source file, while
    /// boot-mounted hives write full images or committed journal sidecars under
    /// `system32\config`.
    pub(super) fn flush_registry_scope(&mut self, scope: FlushScope) -> u32 {
        match scope {
            FlushScope::Nothing => nt_fs::STATUS_SUCCESS,
            FlushScope::All => self.flush_all_mutable_hives_preserving_headroom(
                BOOT_HIVE_FLUSH_POST_CHECKPOINT_HEADROOM,
            ),
            FlushScope::System => {
                REG_FLUSH_KEY_MUTABLE_DIRTY_CELLS.store(0, Ordering::Relaxed);
                self.checkpoint_system_hive_from_config_manager()
            }
            FlushScope::Hive(hive_sel) => {
                let dirty = self
                    .mutable_hives
                    .hive(hive_sel)
                    .map_or(0, |hive| hive.dirty_count());
                REG_FLUSH_KEY_MUTABLE_DIRTY_CELLS.store(dirty as u64, Ordering::Relaxed);
                if is_dynamic_hive_selector(hive_sel) {
                    self.checkpoint_dynamic_mutable_hive(hive_sel, dirty)
                } else {
                    self.checkpoint_non_system_boot_mutable_hive_preserving_headroom(
                        hive_sel,
                        dirty,
                        BOOT_HIVE_FLUSH_POST_CHECKPOINT_HEADROOM,
                    )
                }
            }
        }
    }

    /// `NtUnloadKey*` — ReactOS `ntoskrnl/config/ntapi.c:1796` (`NtUnloadKey2`) plus the event
    /// form: resolve the hive, make it durable, detach it, and release the Event lease the
    /// resolution took, on every exit.
    pub(super) unsafe fn nt_unload_key(&mut self, target_oa: u64, flags: u32, event: u64) -> u32 {
        let mut event_lease = None;
        let status = match self.resolve_unload_key(target_oa, flags, event, &mut event_lease) {
            Ok(target) => self.unload_mounted_hive(&target.canon, target.event_index),
            Err(status) => status,
        };
        if let Some(event) = event_lease {
            self.release_transfer_event(event);
        }
        status
    }

    /// Validate an `NtUnloadKey*` and name the mount it addresses.
    ///
    /// # Safety
    /// Reads the caller's OBJECT_ATTRIBUTES through the bounds-checked cross-AS reader.
    ///
    /// The optional Event is leased into `event_lease` when its handle is resolved; the caller
    /// releases it once the request has completed.
    unsafe fn resolve_unload_key(
        &mut self,
        target_oa: u64,
        flags: u32,
        event: u64,
        event_lease: &mut Option<nt_io_manager::FileTransferEvent>,
    ) -> Result<UnloadTarget, u32> {
        const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const REG_FORCE_UNLOAD: u32 = 0x0000_0001;
        NT_UNLOAD_KEY_CALLS.fetch_add(1, Ordering::Relaxed);
        if flags != 0 && flags != REG_FORCE_UNLOAD {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !self.current_token_has_privilege(nt_security::SE_RESTORE) {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        // The unload commits the hive volume before it signals, and that can run other work.
        // The lease keeps the caller's Event, and so its index, until the signal.
        let event_index = if event != 0 {
            match self.lease_event_for_operation(event, EVENT_MODIFY_STATE) {
                Ok(event) => {
                    *event_lease = Some(event);
                    Some(event.native_identity as usize)
                }
                Err(status) => {
                    NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
                    return Err(status);
                }
            }
        } else {
            None
        };
        let oa = target_oa;
        let mut rd = [0u8; 8];
        if oa == 0 || !self.xas_read(oa + 8, &mut rd) {
            return Err(0xC000_0005); // STATUS_ACCESS_VIOLATION
        }
        let root_dir = u64::from_le_bytes(rd);
        let root_target = if root_dir == 0 {
            None
        } else {
            Some(self.resolve_registry_key(root_dir, 0)?)
        };
        let name = self.effective_objattr_name("", oa);
        let Some(full) = self.user_namespace_target(root_target, &name) else {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return Err(STATUS_INVALID_PARAMETER);
        };
        Ok(UnloadTarget { canon: nt_hive_core::canon_path(&full), event_index })
    }

    /// Detach a hive `NtLoadKey*` mounted: the mount goes, its backing slot is released, and
    /// the write overlay's keys under that path are detached too — otherwise the writes made
    /// through the mount would keep answering at the same path and the "unload" would be
    /// cosmetic. `CmUnloadKey` flushes the hive first (`cmapi.c:2271`), so nothing is released
    /// until the hive and the volume holding it are durable.
    pub(crate) fn unload_mounted_hive(&mut self, canon: &str, event_index: Option<usize>) -> u32 {
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
        let Some(index) = self.hive_mounts.iter().position(|m| m.canon == canon) else {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if !self.hive_mounts[index].dynamic {
            // `.Default` is mounted by the boot, not by a caller: refusing to unload it is the
            // same refusal NT makes for a hive it did not load on request.
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_INVALID_PARAMETER;
        }
        let Some(hive) = self.mutable_hives.hive(self.hive_mounts[index].sel) else {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_INVALID_HANDLE;
        };
        if hive.retained_value_journal().is_some() {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return STATUS_UNSUCCESSFUL;
        }
        let hive_sel = self.hive_mounts[index].sel;
        let dirty = hive.dirty_count();
        let status = self.checkpoint_dynamic_mutable_hive(hive_sel, dirty);
        if status != nt_fs::STATUS_SUCCESS {
            self.writable_fs_dirty = true;
            self.writable_fs_commit_required = true;
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return status;
        }
        // `try_flush` checkpoints the image and log, but an earlier failed volume snapshot can
        // still own dirty bytes. Never release the dynamic mount or slot on that refusal.
        let status = self.publish_volume_for_caller(b"NtUnloadKey");
        if status != nt_fs::STATUS_SUCCESS {
            NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return status;
        }
        let mount = self.hive_mounts.remove(index);
        let _ = self.mutable_hives.unmount(&mount.mount);
        let mut mutable_handles_invalidated = 0usize;
        for entry in self.mutable_key_handles.iter_mut() {
            if entry.as_ref().is_some_and(|key| key.hive == mount.sel) {
                *entry = None;
                mutable_handles_invalidated += 1;
            }
        }
        let overlay_detached = self.overlay.detach_subtree(canon);
        NT_UNLOAD_KEY_DETACHED.fetch_add(1, Ordering::Relaxed);
        if let Some(index) = event_index {
            let status = self.signal_event_index(index);
            if status != 0 {
                return status;
            }
        }
        print_str(b"[cm-load] NtUnloadKey DETACHED ");
        print_ascii_str(&mount.mount);
        print_str(b" overlay-keys=");
        print_u64(overlay_detached as u64);
        print_str(b" mutable-handles=");
        print_u64(mutable_handles_invalidated as u64);
        print_str(b" mounts-left=");
        print_u64(self.hive_mounts.len() as u64);
        print_str(b"\n");
        0
    }

    /// Publish the volume snapshot a completed registry write is part of. A refusal keeps the
    /// durable requirement owed to the next service boundary.
    fn publish_volume_for_caller(&mut self, reason: &[u8]) -> u32 {
        let commit_result = {
            let _transient = crate::allocator::enter_transient();
            let _alloc_ctx = crate::allocator::enter_context(
                crate::allocator::ALLOC_CTX_WRITABLE_SNAPSHOT,
            );
            unsafe { crate::writable_fs::checkpoint_dirty_volume() }
        };
        if let Err(status) = commit_result {
            self.writable_fs_dirty = true;
            self.writable_fs_commit_required = true;
            return status;
        }
        self.complete_committed_mutable_hive_journal_snapshot(reason);
        self.writable_fs_commit_required = false;
        nt_fs::STATUS_SUCCESS
    }
}
