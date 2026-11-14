//! Registry requests that NT completes only once their data is durable: `NtFlushKey`
//! (`CmFlushKey` → `HvSyncHive`), `NtSaveKey*` (`HvWriteHive` ends in the file flush) and
//! `NtUnloadKey*` (`CmUnloadKey` flushes before it unlinks).
//!
//! Each request is resolved once, against the caller's handles and memory, into a
//! [`DurableRegistryRequest`] that names kernel state only. One attempt either completes it or
//! reports `STATUS_DEVICE_BUSY`: the volume checkpoint or another reserve owner is in flight.
//! That answer never reaches the caller. The request is parked with the caller's Reply and
//! attempted again at later service turns (`mutable_hive_mutation_work`).
use super::*;
use crate::volume_checkpoint_deferral::{Publication, PublicationTarget, STATUS_DEVICE_BUSY};

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

enum DurableKind {
    Flush(FlushScope),
    /// The image is written and its File flushed; the volume snapshot holding it is owed.
    Save,
    Unload {
        target: UnloadTarget,
        /// Keeps `target.event_index` valid until the request is released.
        event: Option<nt_io_manager::FileTransferEvent>,
    },
}

/// A resolved request and the publication it waits for. It can be attempted any number of
/// times; [`ExecNtHandler::release_durable_registry_request`] ends it.
pub(crate) struct DurableRegistryRequest {
    kind: DurableKind,
    /// Set by the first attempt to reach the volume, after the request's bytes were written.
    publication: Option<PublicationTarget>,
}

impl DurableRegistryRequest {
    fn new(kind: DurableKind) -> Self {
        Self { kind, publication: None }
    }

    pub(crate) fn name(&self) -> &'static [u8] {
        match self.kind {
            DurableKind::Flush(_) => b"flush-key",
            DurableKind::Save => b"save-key",
            DurableKind::Unload { .. } => b"unload-key",
        }
    }
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
    /// `CmpDoFlushAll(FALSE)` over SYSTEM and every mounted mutable hive. On the WAL volume
    /// format each hive is proven durable in place and nothing is written; a WAL fold stays
    /// with the service loop. On the legacy format dynamic `NtLoadKey` profile hives write back
    /// to their source file and boot-mounted hives write full images under `system32\config`.
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
                self.sync_mutable_hive(hive_sel, dirty, BOOT_HIVE_FLUSH_POST_CHECKPOINT_HEADROOM)
            }
        }
    }

    /// `HvSyncHive` for one mounted mutable hive other than SYSTEM.
    ///
    /// On the WAL volume format every acknowledged edit is already durable in the hive's
    /// sidecar, so the flush proves that under the reserve. The primary image may lag; a
    /// full-image checkpoint is refused on that format and is never attempted. The legacy
    /// format writes the image.
    pub(super) fn sync_mutable_hive(
        &mut self,
        hive_sel: u32,
        dirty_cells: usize,
        min_post_checkpoint_headroom: usize,
    ) -> u32 {
        if self.mutable_hives.hive(hive_sel)
            .is_some_and(|hive| hive.retained_value_journal().is_some())
        {
            return STATUS_UNSUCCESSFUL;
        }
        if dirty_cells == 0 {
            return nt_fs::STATUS_SUCCESS;
        }
        if !crate::writable_fs::legacy_snapshot_writes_allowed() {
            return self.verify_durable_v2_mutable_hive(hive_sel);
        }
        if is_dynamic_hive_selector(hive_sel) {
            self.checkpoint_dynamic_mutable_hive(hive_sel, dirty_cells)
        } else {
            self.checkpoint_non_system_boot_mutable_hive_preserving_headroom(
                hive_sel,
                dirty_cells,
                min_post_checkpoint_headroom,
            )
        }
    }

    fn verify_durable_v2_mutable_hive(&self, hive_sel: u32) -> u32 {
        let Some(hive) = self.mutable_hives.hive(hive_sel) else {
            return STATUS_INVALID_HANDLE;
        };
        let Some(mut log_path) = self.mutable_hive_checkpoint_path_owned(hive_sel) else {
            return STATUS_INVALID_HANDLE;
        };
        if log_path.try_reserve(4).is_err() {
            return nt_fs::STATUS_INSUFFICIENT_RESOURCES;
        }
        log_path.push_str(".LOG");
        let status = unsafe { crate::writable_fs::verify_durable_hive_wal(&log_path, hive.sequence) }
            .err()
            .unwrap_or(nt_fs::STATUS_SUCCESS);
        if status != nt_fs::STATUS_SUCCESS && status != STATUS_DEVICE_BUSY {
            print_str(b"[cm-flush] hive WAL proof failed status=0x");
            print_hex(status);
            print_str(b" sequence=");
            print_u64(hive.sequence);
            print_str(b" path=");
            print_ascii_str(&log_path);
            print_str(b"\n");
        }
        status
    }

    /// `NtFlushKey` on the key the caller named.
    pub(super) unsafe fn nt_flush_key(&mut self, key: KeyRef) -> u32 {
        let scope = self.registry_flush_scope(key);
        self.complete_or_park_durable_registry_request(DurableRegistryRequest::new(
            DurableKind::Flush(scope),
        ))
    }

    /// The tail of a successful `NtSaveKey*`: the image is in its File, and the caller is kept
    /// until the volume snapshot holding it has published.
    pub(super) unsafe fn complete_saved_key(&mut self) -> u32 {
        self.complete_or_park_durable_registry_request(DurableRegistryRequest::new(
            DurableKind::Save,
        ))
    }

    /// Attempt `request` once. `STATUS_DEVICE_BUSY` means in flight: nothing was consumed and
    /// the same request can be attempted again.
    pub(crate) fn attempt_durable_registry_request(
        &mut self,
        request: &mut DurableRegistryRequest,
    ) -> u32 {
        let DurableRegistryRequest { kind, publication } = request;
        match kind {
            DurableKind::Flush(scope) => self.flush_registry_scope(*scope),
            DurableKind::Save => self.publish_volume_for_caller(publication, b"NtSaveKey"),
            DurableKind::Unload { target, .. } => {
                self.unload_mounted_hive(&target.canon, target.event_index, publication)
            }
        }
    }

    /// End a request, whatever its outcome: release what its resolution leased.
    pub(crate) fn release_durable_registry_request(&mut self, request: DurableRegistryRequest) {
        if let DurableKind::Unload { event: Some(event), .. } = request.kind {
            self.release_transfer_event(event);
        }
    }

    /// Complete `request` now, or park the caller until it can complete. Returns the syscall
    /// status: `STATUS_PENDING` once the caller's Reply belongs to the parked request.
    unsafe fn complete_or_park_durable_registry_request(
        &mut self,
        mut request: DurableRegistryRequest,
    ) -> u32 {
        let status = self.attempt_durable_registry_request(&mut request);
        if status != STATUS_DEVICE_BUSY {
            self.release_durable_registry_request(request);
            return status;
        }
        match crate::mutable_hive_mutation_work::submit_hosted_durability(self, request) {
            Ok(()) => 0x103,
            // The caller cannot be kept, so it cannot be told its data is durable.
            Err((status, request)) => {
                self.release_durable_registry_request(request);
                status
            }
        }
    }

    /// `NtUnloadKey*` — ReactOS `ntoskrnl/config/ntapi.c:1796` (`NtUnloadKey2`) plus the event
    /// form: resolve the hive, make it durable, detach it, and release the Event lease the
    /// resolution took, on every exit.
    pub(super) unsafe fn nt_unload_key(
        &mut self,
        target_oa: u64,
        flags: u32,
        event_handle: u64,
    ) -> u32 {
        let mut event = None;
        match self.resolve_unload_key(target_oa, flags, event_handle, &mut event) {
            Ok(target) => self.complete_or_park_durable_registry_request(
                DurableRegistryRequest::new(DurableKind::Unload { target, event }),
            ),
            Err(status) => {
                if let Some(event) = event {
                    self.release_transfer_event(event);
                }
                status
            }
        }
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
    fn unload_mounted_hive(
        &mut self,
        canon: &str,
        event_index: Option<usize>,
        publication: &mut Option<PublicationTarget>,
    ) -> u32 {
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
        let status = self.sync_mutable_hive(hive_sel, dirty, 0);
        if status != nt_fs::STATUS_SUCCESS {
            self.writable_fs_dirty = true;
            self.writable_fs_commit_required = true;
            if status != STATUS_DEVICE_BUSY {
                NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
            return status;
        }
        // The hive is durable, but an earlier volume snapshot can still own dirty bytes of its
        // file. Never release the dynamic mount or slot before that snapshot has published.
        let status = self.publish_volume_for_caller(publication, b"NtUnloadKey");
        if status != nt_fs::STATUS_SUCCESS {
            if status != STATUS_DEVICE_BUSY {
                NT_UNLOAD_KEY_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
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

    /// Publish the volume snapshot a completed registry write is part of, for a caller that
    /// is kept until it has published. `publication` is fixed by the first attempt: only a
    /// checkpoint begun after it can hold the caller's bytes. `STATUS_DEVICE_BUSY` means that
    /// checkpoint is in flight; a refusal keeps the requirement owed to the service boundary.
    fn publish_volume_for_caller(
        &mut self,
        publication: &mut Option<PublicationTarget>,
        reason: &[u8],
    ) -> u32 {
        let target = *publication.get_or_insert_with(|| {
            PublicationTarget::after(crate::writable_fs::checkpoint_epochs().0)
        });
        // A second attempt follows only a consumed publication that predates the target.
        for _ in 0..2 {
            let attempt = {
                let _transient = crate::allocator::enter_transient();
                let _alloc_ctx = crate::allocator::enter_context(
                    crate::allocator::ALLOC_CTX_WRITABLE_SNAPSHOT,
                );
                unsafe { crate::writable_fs::checkpoint_dirty_volume() }
            };
            if attempt.is_ok() {
                self.complete_committed_mutable_hive_journal_snapshot(reason);
            }
            match target.classify(attempt, crate::writable_fs::checkpoint_epochs().1) {
                Publication::Durable { settled } => {
                    if settled {
                        self.writable_fs_commit_required = false;
                    }
                    return nt_fs::STATUS_SUCCESS;
                }
                Publication::Again => {}
                Publication::InFlight => {
                    self.writable_fs_dirty = true;
                    self.writable_fs_commit_required = true;
                    return STATUS_DEVICE_BUSY;
                }
                Publication::Failed(status) => {
                    self.writable_fs_dirty = true;
                    self.writable_fs_commit_required = true;
                    return status;
                }
            }
        }
        self.writable_fs_dirty = true;
        self.writable_fs_commit_required = true;
        STATUS_DEVICE_BUSY
    }
}
