//! Existing transition backing remains owned until resident publication or rollback ACK.
use super::*;
use nt_memory_manager::private_page_installation::{InstallationCap, InstallationEffect};
use nt_memory_manager::transition_page_restoration::{
    TransitionPageRestoration, TransitionRestorationIo, TransitionRestorationOutcome,
};
use nt_memory_manager::PagefilePage;

#[derive(Clone, Copy, Eq, PartialEq)]
struct Target {
    pi: usize,
    process: nt_memory_manager::ProcessIdentity,
    page: u64,
    pml4: u64,
    scratch_base: u64,
    alias: u64,
}
static mut OWNER: Option<TransitionPageRestoration<Target>> = None;
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

fn current(handler: &ExecNtHandler, target: Target) -> bool {
    handler.capture_process_identity(target.pi) == Some(target.process)
        && handler.hosted_process_vspace(target.pi) == Some(target.pml4)
        && handler
            .loop_ctx
            .and_then(|ctx| unsafe { ctx.for_process(target.pi) })
            .is_some_and(|ctx| unsafe {
                (&*ctx.procs).get(target.pi).is_some_and(|process| {
                    process.pml4 == target.pml4 && process.scratch_base == target.scratch_base
                })
            })
}
fn effect(label: u64) -> InstallationEffect {
    if label == 0 {
        InstallationEffect::Acknowledged
    } else {
        InstallationEffect::Refused(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
struct Io<'a> {
    handler: &'a ExecNtHandler,
    target: Target,
}
impl TransitionRestorationIo<Target> for Io<'_> {
    fn map_frame(&mut self, target: &Target, source: PagefilePage) -> InstallationEffect {
        if *target != self.target
            || !current(self.handler, *target)
            || source.lifetime != nt_memory_manager::MemoryLifetime::Process(target.process)
        {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        if let Err(status) = unsafe { frame_recycle::validate_owned_backing(source.backing) } {
            return InstallationEffect::Refused(status);
        }
        unsafe {
            effect(page_map_r(
                source.backing,
                target.page,
                vm_page_rights(source.protection),
                target.pml4,
            ))
        }
    }
    fn reserve_alias(&mut self, _: &Target) -> Result<InstallationCap, u32> {
        try_alloc_slot()
            .map(|cap| InstallationCap { cap })
            .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
    fn copy_alias(&mut self, source: PagefilePage, alias: InstallationCap) -> InstallationEffect {
        unsafe { effect(copy_cap_into_r(source.backing, alias.cap)) }
    }
    fn map_alias(&mut self, target: &Target, alias: InstallationCap) -> InstallationEffect {
        if *target != self.target || !current(self.handler, *target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        unsafe {
            effect(page_map_r(
                alias.cap,
                target.alias,
                RW_NX,
                CAP_INIT_THREAD_VSPACE,
            ))
        }
    }
    fn publish_resident(
        &mut self,
        target: &Target,
        source: PagefilePage,
        alias: Option<InstallationCap>,
    ) -> InstallationEffect {
        if *target != self.target
            || !current(self.handler, *target)
            || unsafe { csrss_frame_get_exact_record(target.pi as u64, target.page) }.is_some()
        {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        if unsafe {
            csrss_frame_put_at_cap(
                target.pi as u64,
                source.lifetime,
                target.page,
                source.backing,
                target.alias,
                alias.map_or(0, |cap| cap.cap),
            )
        } {
            InstallationEffect::Acknowledged
        } else {
            InstallationEffect::Refused(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
        }
    }
    fn unmap(&mut self, cap: InstallationCap) -> InstallationEffect {
        if !current(self.handler, self.target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        unsafe { effect(page_unmap_r(cap.cap)) }
    }
    fn delete_alias(&mut self, cap: InstallationCap) -> InstallationEffect {
        unsafe { effect(cnode_delete_r(cap.cap)) }
    }
    fn recycle_alias(&mut self, cap: InstallationCap, _: bool) -> InstallationEffect {
        match unsafe { root_slot_recycle::publish_unretyped(cap.cap) } {
            Ok(()) => InstallationEffect::Acknowledged,
            Err(_) => InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE),
        }
    }
    fn restore_available(&mut self, source: PagefilePage) -> InstallationEffect {
        if !current(self.handler, self.target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        match unsafe { (&mut *core::ptr::addr_of_mut!(PROCESS_PAGEFILE)).restore(source) } {
            Ok(()) => InstallationEffect::Acknowledged,
            Err(status) => InstallationEffect::Refused(status),
        }
    }
}

unsafe fn advance(handler: &ExecNtHandler) -> Result<bool, u32> {
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    let owner = slot.as_mut().ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let target = owner.descriptor();
    let outcome = owner.advance(&mut Io { handler, target });
    if owner.is_settled() {
        *slot = None;
    }
    match outcome {
        TransitionRestorationOutcome::Published => Ok(true),
        TransitionRestorationOutcome::Restored(status)
        | TransitionRestorationOutcome::CleanupPending(status)
        | TransitionRestorationOutcome::Quarantined(status) => Err(status),
    }
}

/// A taken transition is absent from the pagefile table but remains exclusive physical ownership.
pub(crate) fn memory_available(pi: u64, base: u64, size: u64) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    let Some(owner) = (unsafe { &*core::ptr::addr_of!(OWNER) }).as_ref() else {
        return true;
    };
    let source = owner.source();
    if source.owner != pi || size == 0 || owner.is_settled() {
        return true;
    }
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    let Some(page_end) = source.page.checked_add(nt_address_space::PAGE_SIZE) else {
        return false;
    };
    end <= source.page || base >= page_end
}

pub(crate) unsafe fn resume(
    handler: &ExecNtHandler,
    pi: usize,
    page: u64,
    pml4: u64,
    scratch_base: u64,
) -> Result<Option<bool>, u32> {
    let _borrow = Borrow::acquire()?;
    let process = handler
        .capture_process_identity(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if page & 4095 != 0
        || page >= USER_ADDRESS_LIMIT
        || pml4 == 0
        || scratch_base == 0
        || !current(
            handler,
            Target {
                pi,
                process,
                page,
                pml4,
                scratch_base,
                alias: 0,
            },
        )
    {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let Some(owner) = (&*core::ptr::addr_of!(OWNER)).as_ref() else {
        return Ok(None);
    };
    let target = owner.descriptor();
    if target.pi != pi
        || target.page != page
        || target.pml4 != pml4
        || target.scratch_base != scratch_base
        || !current(handler, target)
    {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    advance(handler).map(Some)
}

pub(crate) unsafe fn begin(
    handler: &ExecNtHandler,
    pi: usize,
    process: nt_memory_manager::ProcessIdentity,
    pml4: u64,
    scratch_base: u64,
    source: PagefilePage,
) -> Result<bool, u32> {
    let _borrow = Borrow::acquire()?;
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    if slot.is_some() {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    let alias =
        if source.page >= SMSS_ALLOC_VA && source.page < SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
            heap_mirror_for_pi(pi) + (source.page - SMSS_ALLOC_VA)
        } else {
            0
        };
    let target = Target {
        pi,
        process,
        page: source.page,
        pml4,
        scratch_base,
        alias,
    };
    if !current(handler, target)
        || source.owner != pi as u64
        || source.lifetime != nt_memory_manager::MemoryLifetime::Process(process)
        || csrss_frame_get_exact_record(pi as u64, source.page).is_some()
    {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    frame_recycle::validate_owned_backing(source.backing)?;
    let owner = TransitionPageRestoration::new(target, source, alias != 0)?;
    let pagefile = &mut *core::ptr::addr_of_mut!(PROCESS_PAGEFILE);
    if pagefile.page_for(pi as u64, source.lifetime, source.page) != Some(source) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let taken = pagefile
        .take_for(pi as u64, source.lifetime, source.page)?
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    assert_eq!(
        taken, source,
        "serialized transition owner changed during transfer"
    );
    *slot = Some(owner); // Exclusive real backing is recorded before the first map effect.
    advance(handler)
}

pub(crate) unsafe fn drain_process(
    handler: &ExecNtHandler,
    pi: usize,
    process: nt_memory_manager::ProcessIdentity,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    let Some(owner) = slot.as_mut() else {
        return Ok(());
    };
    let target = owner.descriptor();
    if target.pi != pi {
        return Ok(());
    }
    if target.process != process || !current(handler, target) || !owner.begin_retirement(&target) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let outcome = owner.advance(&mut Io { handler, target });
    if owner.is_settled() {
        *slot = None;
    }
    match outcome {
        TransitionRestorationOutcome::Restored(_) => Ok(()),
        _ => Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES),
    }
}
