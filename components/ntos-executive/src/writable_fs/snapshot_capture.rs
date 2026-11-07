//! One reusable, immutable volume image per physical snapshot lease.

use super::*;

static mut REUSABLE_IMAGE: Option<alloc::vec::Vec<u8>> = None;

pub(super) struct CapturedSnapshot {
    image: alloc::vec::Vec<u8>,
}

impl CapturedSnapshot {
    /// The caller retains the exact reserve lease until this guard is dropped. Reentrant native
    /// I/O cannot acquire that lease and therefore cannot take this buffer during a commit.
    pub(super) unsafe fn capture(
        _lease: &snapshot_storage::Lease,
        fs: &nt_fs::FileSystem,
    ) -> Result<Self, u32> {
        let slot = &mut *core::ptr::addr_of_mut!(REUSABLE_IMAGE);
        let mut capture = Self {
            image: slot.take().unwrap_or_default(),
        };
        {
            // Some checkpoint callers run inside a transient scope; the captured image must
            // survive native I/O and be reusable after this scope ends.
            let _durable = crate::allocator::enter_durable();
            fs.export_volume_snapshot_into(&mut capture.image)
                .map_err(|error| match error {
                    nt_fs::MemFsSnapshotError::OutOfMemory => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
                    _ => 0xC000_0001,
                })?;
        }
        Ok(capture)
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.image
    }
}

impl AsRef<[u8]> for CapturedSnapshot {
    fn as_ref(&self) -> &[u8] { self.as_slice() }
}

impl Drop for CapturedSnapshot {
    fn drop(&mut self) {
        self.image.clear();
        let slot = unsafe { &mut *core::ptr::addr_of_mut!(REUSABLE_IMAGE) };
        assert!(slot.is_none(), "snapshot capture returned without exclusive reserve ownership");
        *slot = Some(core::mem::take(&mut self.image));
    }
}
