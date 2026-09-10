//! Retained local File cleanup at the serialized service-loop boundary.

use super::*;

pub(crate) unsafe fn file_io_waiter_count(file_id: u64) -> Result<u32, u32> {
    mounted_namespace_fs()?
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?
        .zw_file_io_state(file_id)
        .map(|state| state.waiters)
}

pub(crate) unsafe fn cancel_file_io_waiter(file_id: u64) -> Result<u32, u32> {
    let fs = mounted_namespace_fs()?.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let result = fs.zw_cancel_file_io_waiter(file_id);
    publish_file_cleanup_effects(fs);
    result
}

pub(crate) unsafe fn cancel_promoted_file_io(file_id: u64, tid: u64) -> Result<u32, u32> {
    let fs = mounted_namespace_fs()?.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let result = fs
        .zw_cancel_promoted_file_io(file_id, tid)
        .map(|release| release.waiters);
    publish_file_cleanup_effects(fs);
    result
}

pub(crate) unsafe fn promote_file_io_waiter(file_id: u64, tid: u64) -> Result<u32, u32> {
    mounted_namespace_fs()?
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?
        .zw_promote_file_io_waiter(file_id, tid)
}

pub(super) fn publish_file_cleanup_effects(fs: &mut nt_fs::FileSystem) {
    let effects = fs.take_file_cleanup_effects();
    if effects.namespace_changed {
        mark_snapshot_dirty();
    }
    if effects.notifications_completed {
        crate::service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    }
}

/// Retry each retained cleanup once, including objects whose process handle is already gone.
/// The filesystem keeps failed cleanup ownership; an unrelated syscall never inherits its error.
pub(crate) unsafe fn redrive_file_cleanup_work() {
    // Do not mount or materialize a filesystem merely to look for retained work.
    let Some(fs) = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS)).as_mut() else {
        return;
    };
    let mut cursor = 0;
    while let Some((index, file_id)) = fs.pending_file_cleanup_from(cursor) {
        let previous_error = fs
            .zw_file_io_state(file_id)
            .ok()
            .and_then(|state| state.cleanup_error);
        if let Err(status) = fs.zw_redrive_file_cleanup(file_id) {
            if previous_error != Some(status) {
                print_str(b"[local-file-cleanup] retained file=");
                print_u64(file_id);
                print_str(b" status=0x");
                print_hex(status);
                print_str(b"\n");
            }
        }
        cursor = index + 1;
    }
    publish_file_cleanup_effects(fs);
}
