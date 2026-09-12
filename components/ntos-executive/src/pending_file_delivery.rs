//! Scope the terminal prefix so nested dispatch cannot take over its pending I/O owner.

use crate::*;
use nt_io_manager::{
    PendingFileApcDeliveryLease, PendingFileApcError, PendingFileApcPhase, PendingFileIoIdentity,
};

pub(super) struct Delivery {
    lease: PendingFileApcDeliveryLease,
    apc_owned: bool,
}

impl Delivery {
    pub(super) unsafe fn begin(
        identity: PendingFileIoIdentity,
        irp_id: u64,
    ) -> Result<Self, PendingFileApcError> {
        let table = &mut *core::ptr::addr_of_mut!(PENDING_FILE_IO);
        let apc_owned = table.apc(identity).is_ok();
        let lease = table.begin_apc_delivery(identity, irp_id)?;
        Ok(Self { lease, apc_owned })
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        let result = unsafe {
            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO)).finish_apc_delivery(&mut self.lease)
        };
        match result {
            Ok(Some(PendingFileApcPhase::Ready { .. } | PendingFileApcPhase::Complete)) => {
                pending_file_apc::schedule_redrive();
                service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
            }
            Ok(None) => pending_file_apc::schedule_admission(),
            Ok(_) => {}
            // Ordinary, non-APC teardown still uses its existing destructive extraction path.
            // A stale lease cannot clear a replacement row; APC-owned rows cannot be extracted.
            Err(PendingFileApcError::WrongIdentity) if !self.apc_owned => {}
            Err(error) => panic!("pending File delivery lost its entered owner: {:?}", error),
        }
    }
}
