//! The physical FAT source and the mounted File device have distinct mount identities.

use nt_memory_manager::SectionMountId;

#[derive(Clone, Copy)]
pub(crate) struct ExecVolumeDevice {
    pub(crate) physical_mount: SectionMountId,
    pub(crate) logical_mount: SectionMountId,
    pub(crate) device_id: u64,
}

impl ExecVolumeDevice {
    /// A live Device binding is authority only for its own logical File mount.
    pub(crate) fn exact_device(
        self,
        requested_physical: SectionMountId,
        live_logical: Option<SectionMountId>,
    ) -> Option<u64> {
        (self.physical_mount == requested_physical
            && live_logical == Some(self.logical_mount))
            .then_some(self.device_id)
    }
}
