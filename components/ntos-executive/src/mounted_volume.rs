//! Executive publication identities. Storage-host mount parsing must not mutate this owner.
use nt_memory_manager::{SectionMountId, SectionMountIds};

static mut MOUNT_IDS: SectionMountIds = SectionMountIds::new();

pub(crate) unsafe fn allocate_mount_id() -> Result<SectionMountId, u32> {
    (&mut *core::ptr::addr_of_mut!(MOUNT_IDS))
        .allocate()
        .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
}
