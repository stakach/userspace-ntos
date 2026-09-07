//! Root-only DLL prefetch ownership. These frames are not process residency records.
use crate::*;
use nt_memory_manager::prefetch::{PrefetchFrames, PrefetchIo, PrefetchPage, PrefetchProcess};
use nt_memory_manager::retained_alias::AliasRetirementIo;

static mut FRAMES: PrefetchFrames = PrefetchFrames::new();

fn process(pi: u64) -> Result<(PrefetchProcess, u64), u32> {
    let runtime = usize::try_from(pi)
        .ok()
        .and_then(hosted_process_runtime_for_pi)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    Ok((
        PrefetchProcess {
            pi,
            generation: runtime.generation,
        },
        runtime.scratch_base,
    ))
}

fn lookup(pi: u64, page: u64) -> Result<Option<PrefetchPage>, u32> {
    hosted_thread_memory_access(pi, page, 4096)?;
    if !unsafe { (&*core::ptr::addr_of!(FRAMES)).contains(pi, page) } {
        return Ok(None);
    }
    let (process, _) = process(pi)?;
    unsafe { (&*core::ptr::addr_of!(FRAMES)).lookup(process, page) }
}

pub(crate) fn client_copyin_frame_unavailable(pi: u64, page: u64) -> bool {
    lookup(pi, page).is_err()
}

pub(crate) fn client_copyin_frame_get(pi: u64, page: u64) -> u64 {
    lookup(pi, page).ok().flatten().map_or(0, |page| page.frame)
}

pub(crate) fn client_copyin_frame_alias_get(pi: u64, page: u64) -> u64 {
    lookup(pi, page).ok().flatten().map_or(0, |page| page.alias)
}

struct Cleanup;

fn checked(label: u64) -> Result<(), u32> {
    if label == 0 {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}

impl AliasRetirementIo for Cleanup {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { page_unmap_r(cap) })
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { cnode_delete_r(cap) })
    }
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_empty(slot) }
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
    fn recycle_unretyped_slot(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_unretyped(slot) }
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}

struct Fill<'a> {
    pe: &'a nt_pe_loader::PeFile<'a>,
    rva: u32,
}

impl AliasRetirementIo for Fill<'_> {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        Cleanup.unmap(cap)
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        Cleanup.delete(cap)
    }
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u32> {
        Cleanup.recycle_slot(slot)
    }
    fn recycle_unretyped_slot(&mut self, slot: u64) -> Result<(), u32> {
        Cleanup.recycle_unretyped_slot(slot)
    }
}

impl PrefetchIo for Fill<'_> {
    fn allocate(&mut self) -> (u64, u32) {
        let (cap, label) = unsafe { alloc_frame_r() };
        (cap, checked(label).err().unwrap_or(0))
    }
    fn map(&mut self, cap: u64, alias: u64) -> Result<(), u32> {
        checked(unsafe { page_map_r(cap, alias, RW_NX, CAP_INIT_THREAD_VSPACE) })
    }
    fn fill(&mut self, alias: u64) -> Result<(), u32> {
        // This existing PE copier is infallible; its return value is mapping rights, not status.
        let _ = unsafe { img_spawn::fill_image_page(self.pe, self.rva, alias) };
        Ok(())
    }
}

pub(crate) fn client_copyin_frame_retry_retirement(pi: u64, page: u64) -> Result<(), u32> {
    hosted_thread_memory_access(pi, page, 4096)?;
    if !unsafe { (&*core::ptr::addr_of!(FRAMES)).contains(pi, page) } {
        return Ok(());
    }
    let (process, _) = process(pi)?;
    unsafe { (&mut *core::ptr::addr_of_mut!(FRAMES)).retry_retirement(process, page, &mut Cleanup) }
}

pub(crate) fn client_copyin_frame_build(
    pi: u64,
    page: u64,
    scratch_base: u64,
    pe: &nt_pe_loader::PeFile,
    rva: u32,
) -> Result<(), u32> {
    hosted_thread_memory_access(pi, page, 4096)?;
    let (process, owner_scratch) = process(pi)?;
    if scratch_base != owner_scratch {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    unsafe {
        let frames = &mut *core::ptr::addr_of_mut!(FRAMES);
        let reservation = frames.reserve(process, page, |index| {
            EXECUTIVE_SCRATCH_LAYOUT.alias_address(owner_scratch, index as u64)
        })?;
        // The backend only uses direct capability syscalls and the immutable PE; no registry reentry.
        frames.build(reservation, &mut Fill { pe, rva })
    }
}

pub(crate) fn client_copyin_frame_drop_process(pi: u64) -> (u64, u64) {
    if client_copyin_frame_process_is_empty(pi) {
        return (0, 0);
    }
    let Ok((process, _)) = process(pi) else {
        return (0, 1);
    };
    unsafe { (&mut *core::ptr::addr_of_mut!(FRAMES)).retire_process(process, &mut Cleanup) }
}

pub(crate) fn client_copyin_frame_process_is_empty(pi: u64) -> bool {
    unsafe { (&*core::ptr::addr_of!(FRAMES)).process_is_empty(pi) }
}
