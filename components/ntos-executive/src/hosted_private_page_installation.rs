//! Retained private-page mapping and acknowledged rollback before registry publication.

use super::*;
use nt_memory_manager::private_page_installation::{
    InstallationCap, InstallationEffect, PrivatePageInstallOutcome, PrivatePageInstallation,
    PrivatePageInstallationIo, PrivatePagePublication,
};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Target {
    pi: usize,
    process: nt_memory_manager::ProcessIdentity,
    page: u64,
    protection: u32,
    pml4: u64,
    scratch_base: u64,
    alias: u64,
    initialize_from: Option<u64>,
}

static mut OWNER: PrivatePageInstallation<Target> = PrivatePageInstallation::new();
static BORROWED: AtomicBool = AtomicBool::new(false);

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

fn effect(error: u64) -> InstallationEffect {
    if error == 0 {
        InstallationEffect::Acknowledged
    } else {
        // These synchronous capability invocations return an authoritative refusal with no effect.
        InstallationEffect::Refused(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}

struct Io<'a> {
    handler: &'a ExecNtHandler,
}
fn target_is_current(handler: &ExecNtHandler, target: &Target) -> bool {
    handler.capture_process_identity(target.pi) == Some(target.process)
        && handler
            .loop_ctx
            .and_then(|ctx| unsafe { ctx.for_process(target.pi) })
            .is_some_and(|ctx| unsafe {
                (&*ctx.procs).get(target.pi).is_some_and(|process| {
                    target.pml4 != 0
                        && process.pml4 == target.pml4
                        && target.scratch_base != 0
                        && process.scratch_base == target.scratch_base
                })
            })
}
impl PrivatePageInstallationIo<Target> for Io<'_> {
    fn acquire_frame(&mut self, target: &Target) -> Result<InstallationCap, u32> {
        unsafe {
            frame_acquisition::acquire(target.scratch_base).map(|cap| InstallationCap { cap })
        }
        .map_err(|status| {
            VM_FAIL_FRAME.fetch_add(1, Ordering::Relaxed);
            status
        })
    }
    fn initialize_frame(&mut self, target: &Target, frame: InstallationCap) -> InstallationEffect {
        if !target_is_current(self.handler, target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        if let Err(status) = unsafe { frame_recycle::validate_owned_backing(frame.cap) } {
            return InstallationEffect::Refused(status);
        }
        if let Some(source) = target.initialize_from {
            // A copy can modify the destination before scratch-alias cleanup refuses. Never
            // replay or release either backing after such an uncertain initializer result.
            match unsafe {
                temporary_frame_alias::copy_page(source, frame.cap, target.scratch_base)
            } {
                Ok(()) => InstallationEffect::Acknowledged,
                Err(status) => InstallationEffect::Uncertain(status),
            }
        } else {
            // Frame acquisition already zeroed this exclusively owned, unmapped backing.
            InstallationEffect::Acknowledged
        }
    }
    fn reserve_alias(&mut self, _: &Target) -> Result<InstallationCap, u32> {
        try_alloc_slot()
            .map(|cap| InstallationCap { cap })
            .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
    fn copy_alias(&mut self, frame: InstallationCap, alias: InstallationCap) -> InstallationEffect {
        let error = unsafe { copy_cap_into_r(frame.cap, alias.cap) };
        if error != 0 {
            VM_FAIL_ALIAS.fetch_add(1, Ordering::Relaxed);
        }
        effect(error)
    }
    fn map_frame(&mut self, target: &Target, frame: InstallationCap) -> InstallationEffect {
        if !target_is_current(self.handler, target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        if let Err(status) = unsafe { frame_recycle::validate_owned_backing(frame.cap) } {
            return InstallationEffect::Refused(status);
        }
        let error = unsafe {
            page_map_r(
                frame.cap,
                target.page,
                vm_page_rights(target.protection),
                target.pml4,
            )
        };
        if error != 0 && VM_FAIL_MAP.fetch_add(1, Ordering::Relaxed) < 8 {
            unsafe {
                print_str(b"[vm-map-fail] pi=");
                print_u64(target.pi as u64);
                print_str(b" page=");
                print_hex_u64(target.page);
                print_str(b" prot=");
                print_hex(target.protection);
                print_str(b" label=");
                print_u64(error);
                print_str(b" known-frame=");
                print_hex_u64(csrss_frame_get_exact(target.pi as u64, target.page).0);
                print_str(b"\n");
            }
        }
        effect(error)
    }
    fn map_alias(&mut self, target: &Target, alias: InstallationCap) -> InstallationEffect {
        if !target_is_current(self.handler, target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        let error = unsafe { page_map_r(alias.cap, target.alias, RW_NX, CAP_INIT_THREAD_VSPACE) };
        if error != 0 {
            VM_FAIL_ALIAS.fetch_add(1, Ordering::Relaxed);
        }
        effect(error)
    }
    fn publish(&mut self, publication: PrivatePagePublication<Target>) -> InstallationEffect {
        let target = publication.descriptor;
        if !target_is_current(self.handler, &target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        let alias_cap = publication.alias.map_or(0, |alias| alias.cap);
        if unsafe {
            csrss_frame_put_at_cap(
                target.pi as u64,
                nt_memory_manager::MemoryLifetime::Process(target.process),
                target.page,
                publication.frame.cap,
                target.alias,
                alias_cap,
            )
        } {
            vm_watch(b"map", target.pi, target.page, publication.frame.cap);
            InstallationEffect::Acknowledged
        } else {
            VM_FAIL_REGISTRY.fetch_add(1, Ordering::Relaxed);
            InstallationEffect::Refused(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
        }
    }
    fn unmap(&mut self, cap: InstallationCap) -> InstallationEffect {
        unsafe { effect(page_unmap_r(cap.cap)) }
    }
    fn delete_alias(&mut self, alias: InstallationCap) -> InstallationEffect {
        unsafe { effect(cnode_delete_r(alias.cap)) }
    }
    fn recycle_alias(&mut self, alias: InstallationCap) -> InstallationEffect {
        match unsafe { root_slot_recycle::publish_unretyped(alias.cap) } {
            Ok(()) => InstallationEffect::Acknowledged,
            Err(_) => InstallationEffect::Refused(nt_address_space::STATUS_INVALID_PARAMETER),
        }
    }
    fn release_frame(&mut self, frame: InstallationCap) -> InstallationEffect {
        // The pure owner has acknowledged every mapping and alias retirement first.
        unsafe {
            if let Err(status) = frame_recycle::prepare(frame.cap) {
                return InstallationEffect::Refused(status);
            }
            match frame_recycle::publish(frame.cap) {
                Ok(()) => InstallationEffect::Acknowledged,
                Err(status) => InstallationEffect::Refused(status),
            }
        }
    }
}

fn result(outcome: PrivatePageInstallOutcome) -> Result<(), u32> {
    match outcome {
        PrivatePageInstallOutcome::Published => Ok(()),
        PrivatePageInstallOutcome::Failed(status)
        | PrivatePageInstallOutcome::CleanupPending(status)
        | PrivatePageInstallOutcome::Quarantined(status) => Err(status),
    }
}

pub(super) unsafe fn map_private_page(
    handler: &mut ExecNtHandler,
    pi: usize,
    page: u64,
    protection: u32,
    pml4: u64,
    scratch_base: u64,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let owner = &mut *core::ptr::addr_of_mut!(OWNER);
    // Cleanup is an explicit operation on its retained owner, never a side effect of a new fault.
    if !owner.is_idle() {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    let process = handler
        .capture_process_identity(pi)
        .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
    let mut target = Target {
        pi,
        process,
        page,
        protection,
        pml4,
        scratch_base,
        alias: 0,
        initialize_from: None,
    };
    if !target_is_current(handler, &target) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    hosted_thread_memory_access(pi as u64, page, nt_address_space::PAGE_SIZE)?;
    if handler.restore_process_pagefile_page(pi, page, pml4, scratch_base)? {
        return Ok(());
    }
    handler.ensure_process_working_set_admission(pi, page, scratch_base)?;
    ensure_process_user_page_table(handler, pi, page, pml4)?;
    if !target_is_current(handler, &target) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let alias = if page >= SMSS_ALLOC_VA && page < SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
        heap_mirror_for_pi(pi) + (page - SMSS_ALLOC_VA)
    } else {
        0
    };
    target.alias = alias;
    owner.begin(target, alias != 0)?;
    result(owner.advance(&mut Io { handler }))
}

/// Image COW uses the same retained owner, but fills from canonical backing before user mapping.
pub(super) unsafe fn map_private_page_from_frame(
    handler: &mut ExecNtHandler,
    pi: usize,
    page: u64,
    protection: u32,
    pml4: u64,
    scratch_base: u64,
    source: u64,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let owner = &mut *core::ptr::addr_of_mut!(OWNER);
    if !owner.is_idle() {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    frame_recycle::validate_owned_backing(source)?;
    let process = handler
        .capture_process_identity(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let target = Target {
        pi,
        process,
        page,
        protection,
        pml4,
        scratch_base,
        alias: 0,
        initialize_from: Some(source),
    };
    if !target_is_current(handler, &target) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    hosted_thread_memory_access(pi as u64, page, nt_address_space::PAGE_SIZE)?;
    handler.ensure_process_working_set_admission(pi, page, scratch_base)?;
    ensure_process_user_page_table(handler, pi, page, pml4)?;
    owner.begin(target, false)?;
    result(owner.advance(&mut Io { handler }))
}

pub(super) fn references_source_cap(cap: u64) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return true;
    };
    unsafe {
        (&*core::ptr::addr_of!(OWNER))
            .descriptor()
            .is_some_and(|target| target.initialize_from == Some(cap))
    }
}

pub(super) fn process_available(pi: u64) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    unsafe {
        (&*core::ptr::addr_of!(OWNER))
            .descriptor()
            .is_none_or(|target| target.pi as u64 != pi)
    }
}

pub(super) fn owns_root_cap(cap: u64) -> bool {
    if cap == 0 {
        return false;
    }
    let Ok(_borrow) = Borrow::acquire() else {
        return true;
    };
    unsafe { (&*core::ptr::addr_of!(OWNER)).owns_cap(cap) }
}

pub(super) unsafe fn drain_for_process(
    handler: &ExecNtHandler,
    process: nt_memory_manager::ProcessIdentity,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let owner = &mut *core::ptr::addr_of_mut!(OWNER);
    if owner
        .descriptor()
        .is_some_and(|target| target.process == process)
    {
        let _ = owner.advance(&mut Io { handler });
        if !owner.is_idle() {
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
    }
    Ok(())
}
