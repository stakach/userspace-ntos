//! Retained native resources shared by executor bootstrap probes.
//!
//! A cap slot is recorded before retype, and a refused or uncertain native effect leaves its
//! owner intact. These small helpers allocate and invoke; the caller owns the lifetime policy.

use alloc::alloc::alloc;
use alloc::boxed::Box;
use core::alloc::Layout;

use crate::*;

#[derive(Clone, Copy)]
pub(crate) struct ProbeFailure {
    pub(crate) stage: &'static [u8],
    pub(crate) status: u64,
}

impl ProbeFailure {
    pub(super) const fn at(stage: &'static [u8], status: u64) -> Self {
        Self { stage, status }
    }
}

/// One allocated CSpace slot. The caller retains it even when native retype fails or is unsure.
pub(super) struct OwnedCap(u64);

impl OwnedCap {
    pub(super) fn value(&self) -> u64 {
        self.0
    }
}

pub(super) fn checked(stage: &'static [u8], result: u64) -> Result<(), ProbeFailure> {
    if result == 0 {
        Ok(())
    } else {
        Err(ProbeFailure::at(stage, result))
    }
}

pub(super) fn try_box<T>(value: T, stage: &'static [u8]) -> Result<Box<T>, ProbeFailure> {
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        return Err(ProbeFailure::at(stage, u64::MAX));
    }
    let ptr = unsafe { alloc(layout) }.cast::<T>();
    if ptr.is_null() {
        return Err(ProbeFailure::at(stage, u64::MAX));
    }
    unsafe {
        ptr.write(value);
        Ok(Box::from_raw(ptr))
    }
}

/// # Safety
/// The caller must retain `owned` and its allocated slot across every possibly effective retype.
pub(super) unsafe fn retype_owned(
    owned: &mut Option<OwnedCap>,
    object: u64,
    bits: u32,
    fresh: bool,
    stage: &'static [u8],
) -> Result<u64, ProbeFailure> {
    let slot = if fresh {
        try_alloc_slot_run(1)
    } else {
        try_alloc_slot()
    }
    .ok_or(ProbeFailure::at(stage, u64::MAX))?;
    *owned = Some(OwnedCap(slot));
    checked(stage, unsafe {
        untyped_retype_r(CAP_INIT_UNTYPED, object, bits, 1, slot)
    })?;
    Ok(owned.as_ref().ok_or(ProbeFailure::at(stage, 0))?.value())
}

/// # Safety
/// `tcb` must be the exact live TCB capability retained by the calling native owner.
pub(super) unsafe fn resume_owned_tcb(tcb: u64) -> u64 {
    let reply: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rdx") SYS_CALL as u64 => _,
            inout("rdi") tcb => _,
            inout("rsi") LBL_TCB_RESUME << 12 => reply,
            inout("r10") 0u64 => _,
            inout("r8") 0u64 => _,
            inout("r9") 0u64 => _,
            in("r12") 0u64,
            in("r13") 0u64,
            lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    reply
}
