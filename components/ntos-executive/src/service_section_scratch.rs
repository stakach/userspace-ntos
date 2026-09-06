//! Copied-capability ownership for the serialized section scratch mapping.
use super::*;
use nt_memory_manager::section_scratch::{SectionScratch, SectionScratchIo};

static mut SECTION_SCRATCH: SectionScratch = SectionScratch::new();

struct ScratchIo {
    address: u64,
}

impl SectionScratchIo for ScratchIo {
    fn copy_frame(&mut self, frame: u64) -> Result<u64, u32> {
        let (alias, error) = unsafe { copy_cap_r(frame) };
        if error == 0 {
            Ok(alias)
        } else {
            // copy_cap_r recycles its reserved slot on every failed CNode_Copy.
            Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
        }
    }

    fn map_alias(&mut self, alias: u64) -> Result<(), u32> {
        if unsafe { page_map_r(alias, self.address, RO_NX, CAP_INIT_THREAD_VSPACE) } == 0 {
            Ok(())
        } else {
            Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
        }
    }

    fn delete_alias(&mut self, alias: u64) -> Result<(), u32> {
        // CNode_Delete finalizes this alias's mapping and TLB entries before clearing its slot.
        // Unlike PageUnmap, it also accepts a slot already emptied by canonical-owner revoke.
        if unsafe { cnode_delete_recycle_r(alias) } == 0 {
            Ok(())
        } else {
            Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
        }
    }
}

pub(super) unsafe fn with_section_frame(
    frame: u64,
    scratch_base: u64,
    transfer: impl FnOnce(u64) -> (u32, usize),
) -> (u32, usize) {
    let Some(address) = scratch_base.checked_add(DEMAND_SCRATCH_WINDOW - 0x4000) else {
        return (nt_address_space::STATUS_INVALID_PARAMETER, 0);
    };
    // Serialized executive work only: transfer must not pump events or dispatch hosted callbacks.
    // A callback-capable adapter must reject reentry before borrowing this global owner.
    (&mut *core::ptr::addr_of_mut!(SECTION_SCRATCH)).with_frame(
        frame,
        &mut ScratchIo { address },
        |_| transfer(address),
    )
}

pub(super) unsafe fn drain_section_scratch() -> Result<(), u32> {
    (&mut *core::ptr::addr_of_mut!(SECTION_SCRATCH)).drain(&mut ScratchIo { address: 0 })
}
