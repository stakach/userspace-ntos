use super::{PendingFileIo, PendingFileIoIdentity, PendingFileIoTable};

impl PendingFileIoTable {
    /// Retire only the selected owner generation and its expected current IRP.
    pub fn finish_owner_exact(
        &mut self,
        identity: PendingFileIoIdentity,
        expected_irp: u64,
    ) -> Option<PendingFileIo> {
        self.get_exact(identity)?;
        self.finish_exact(identity.slot, expected_irp)
    }

    /// Preserve the specialized CREATE rollback policy while rejecting stale owner generations.
    pub fn take_create_owner_exact(
        &mut self,
        identity: PendingFileIoIdentity,
        expected_irp: u64,
    ) -> Option<PendingFileIo> {
        self.get_exact(identity)?;
        self.take_create_exact(identity.slot, expected_irp)
    }

    /// Detach the selected consumer without transferring the retained IRP or Busy ownership.
    pub fn abandon_transfer_owner_exact(
        &mut self,
        identity: PendingFileIoIdentity,
        expected_irp: u64,
    ) -> Option<PendingFileIo> {
        self.get_exact(identity)?;
        self.abandon_transfer_exact(identity.slot, expected_irp)
    }

    /// A rename/link owner keeps its identity while changing its exact IRP correlation.
    pub fn retarget_set_file_name_irp_owner_exact(
        &mut self,
        identity: PendingFileIoIdentity,
        old_irp_id: u64,
        new_irp_id: u64,
    ) -> Option<()> {
        self.get_exact(identity)?;
        self.retarget_set_file_name_irp_exact(identity.slot, old_irp_id, new_irp_id)
    }

    pub fn retarget_set_file_name_query_owner_exact(
        &mut self,
        identity: PendingFileIoIdentity,
        old_irp_id: u64,
        new_irp_id: u64,
        new_major: u8,
        target_file_id: u64,
    ) -> Option<()> {
        self.get_exact(identity)?;
        self.retarget_set_file_name_query_exact(
            identity.slot,
            old_irp_id,
            new_irp_id,
            new_major,
            target_file_id,
        )
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
