//! Copied-capability ownership for the serialized section scratch mapping.
use super::*;
use nt_memory_manager::section_scratch::{SectionAliasAccess, SectionScratch, SectionScratchIo};

static mut SECTION_SCRATCH: SectionScratch = SectionScratch::new();
static SECTION_SCRATCH_BORROWED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

struct ScratchBorrow;
impl ScratchBorrow {
    fn acquire() -> Result<Self, u32> {
        SECTION_SCRATCH_BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
impl Drop for ScratchBorrow {
    fn drop(&mut self) {
        SECTION_SCRATCH_BORROWED.store(false, Ordering::Release);
    }
}

struct ScratchIo;

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

    fn map_alias(
        &mut self,
        alias: u64,
        address: u64,
        access: SectionAliasAccess,
    ) -> Result<(), u32> {
        let rights = match access {
            SectionAliasAccess::ReadOnly => RO_NX,
            SectionAliasAccess::ReadWrite => RW_NX,
        };
        if unsafe { page_map_r(alias, address, rights, CAP_INIT_THREAD_VSPACE) } == 0 {
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
    let _borrow = match ScratchBorrow::acquire() {
        Ok(guard) => guard,
        Err(status) => return (status, 0),
    };
    // The global owner retains allocation capacity and failed cleanup across request scopes.
    let _durable = allocator::enter_durable();
    (&mut *core::ptr::addr_of_mut!(SECTION_SCRATCH)).with_frame(
        frame,
        address,
        &mut ScratchIo,
        |_| transfer(address),
    )
}

pub(super) unsafe fn drain_section_scratch() -> Result<(), u32> {
    let _borrow = ScratchBorrow::acquire()?;
    (&mut *core::ptr::addr_of_mut!(SECTION_SCRATCH)).drain(&mut ScratchIo)
}

#[path = "service_section_file_io.rs"]
mod file_io;
pub(crate) use file_io::{
    service_read_file_coherent, service_resize_file_coherent, service_write_file_coherent,
};
