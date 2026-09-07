//! Durable ownership of the resident client-copy scratch mapping.
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

pub(super) unsafe fn with_frame(
    source: TemporaryAliasSource,
    address: u64,
    writable: bool,
    access: impl FnOnce(u64),
) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    (&mut *core::ptr::addr_of_mut!(ALIAS))
        .with_frame(source, address, writable, &mut Io, access)
        .is_ok()
}
