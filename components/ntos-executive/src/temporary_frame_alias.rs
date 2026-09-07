//! Durable ownership of sequential executive scratch mappings.
use super::*;
use nt_memory_manager::temporary_alias::{TemporaryAlias, TemporaryAliasIo, TemporaryAliasSource};

static mut ALIAS: TemporaryAlias = TemporaryAlias::new();
static BORROWED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

struct Borrow;
impl Borrow {
    fn acquire() -> Result<Self, u32> {
        BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
impl Drop for Borrow {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}

struct Io;
fn status(error: u64) -> Result<(), u32> {
    if error == 0 {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
impl TemporaryAliasIo for Io {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        // The owner retains the live slot. Root-slot pins also prohibit capability deletion,
        // so they cannot represent a scratch slot whose contents must change after each copy.
        try_alloc_slot().ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
    fn copy(&mut self, source: u64, slot: u64) -> Result<(), u32> {
        status(unsafe { copy_cap_into_r(source, slot) })
    }
    fn map(&mut self, slot: u64, address: u64, writable: bool) -> Result<(), u32> {
        status(unsafe {
            page_map_r(
                slot,
                address,
                if writable { RW_NX } else { RO_NX },
                CAP_INIT_THREAD_VSPACE,
            )
        })
    }
    fn delete(&mut self, slot: u64) -> Result<(), u32> {
        // CNode_Delete acknowledges mapping/TLB finalization as well as clearing the cap.
        status(unsafe { cnode_delete_r(slot) })
    }
}

pub(super) unsafe fn drain() -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    (&mut *core::ptr::addr_of_mut!(ALIAS)).drain(&mut Io)
}

/// Deny-only queries cannot perform IPC while registry/runtime tables are borrowed.
pub(super) fn memory_available(pi: u64, base: u64, size: u64) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    let owner = unsafe { &*core::ptr::addr_of!(ALIAS) };
    owner.memory_available(pi, base, size)
}

pub(super) fn process_available(pi: u64) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    unsafe { (&*core::ptr::addr_of!(ALIAS)).process_available(pi) }
}

pub(super) fn backing_release_available() -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    unsafe { (&*core::ptr::addr_of!(ALIAS)).backing_release_available() }
}

pub(super) fn owns_root_cap(cap: u64) -> bool {
    if cap == 0 {
        return false;
    }
    let Ok(_borrow) = Borrow::acquire() else {
        return true;
    };
    unsafe { (&*core::ptr::addr_of!(ALIAS)).owns_slot(cap) }
}

pub(super) unsafe fn with_frame<T>(
    source: TemporaryAliasSource,
    address: u64,
    writable: bool,
    access: impl FnOnce(u64) -> T,
) -> Result<T, u32> {
    let _borrow = Borrow::acquire()?;
    (&mut *core::ptr::addr_of_mut!(ALIAS)).with_frame(source, address, writable, &mut Io, access)
}

fn scratch_address(base: u64) -> Result<u64, u32> {
    if base == 0 || base & 0xfff != 0 {
        return Err(nt_address_space::STATUS_INVALID_PARAMETER);
    }
    base.checked_add(DEMAND_SCRATCH_WINDOW)
        .map(|end| end - 0x1000)
        .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)
}

pub(super) unsafe fn with_scratch_range<T>(
    frame: u64,
    scratch_base: u64,
    range: core::ops::Range<usize>,
    writable: bool,
    access: impl FnOnce(u64) -> T,
) -> Result<T, u32> {
    let address = scratch_address(scratch_base)?;
    if range.start > range.end || range.end > 0x1000 || frame == 0 {
        return Err(nt_address_space::STATUS_INVALID_PARAMETER);
    }
    let _borrow = Borrow::acquire()?;
    let owner = &mut *core::ptr::addr_of_mut!(ALIAS);
    owner.drain(&mut Io)?;
    owner.with_range(
        TemporaryAliasSource {
            scope: nt_memory_manager::temporary_alias::TemporaryAliasScope::Frame,
            frame,
        },
        address,
        range,
        writable,
        &mut Io,
        access,
    )
}

#[inline(never)]
pub(super) unsafe fn copy_page(
    source: u64,
    destination: u64,
    scratch_base: u64,
) -> Result<(), u32> {
    let address = scratch_address(scratch_base)?;
    if source == 0 || destination == 0 {
        return Err(nt_address_space::STATUS_INVALID_PARAMETER);
    }
    let _borrow = Borrow::acquire()?;
    let owner = &mut *core::ptr::addr_of_mut!(ALIAS);
    owner.drain(&mut Io)?;
    owner.copy_page(
        source,
        destination,
        address,
        &mut Io,
        |address, bytes| {
            core::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), bytes.len())
        },
        |address, bytes| {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len())
        },
    )
}
