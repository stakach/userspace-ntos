//! Canonical private backing residency shared by copy, lock and root faults.
use super::*;
use nt_address_space::private_fault::{
    plan_private_read_fault, PrivateFaultBacking, PrivateReadFaultPlan,
};
use nt_address_space::{FaultAccess, ImageFaultObservation};
use nt_memory_manager::private_page_installation::{InstallationCap, InstallationEffect};
use nt_memory_manager::resident_mapping_revalidation::{
    ResidentMappingRevalidation, ResidentMappingRevalidationIo, ResidentMappingRevalidationOutcome,
};

const INVALID: u32 = nt_process::STATUS_INVALID_HANDLE;
const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentPrivatePage {
    pi: usize,
    process: nt_memory_manager::ProcessIdentity,
    page: u64,
    pml4: u64,
    scratch: u64,
    protection: u32,
    record: nt_memory_manager::ClientFrameRecord,
}

/// Retained pump hint, not permission to service a fault or resume its parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentReadFaultCapture {
    child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    page: u64,
    information: nt_address_space::VmBasicInformation,
    record: nt_memory_manager::ClientFrameRecord,
}

static BORROWED: AtomicBool = AtomicBool::new(false);
static mut REVALIDATION: Option<ResidentMappingRevalidation<ResidentPrivatePage>> = None;
struct Borrow;
impl Borrow {
    fn acquire() -> Result<Self, u32> {
        BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| RESOURCES)
    }
}
impl Drop for Borrow {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}

/// Only allocation metadata is consulted; registered-frame inference is not a VAD authority.
unsafe fn canonical_private_information(
    pi: usize,
    page: u64,
) -> Option<nt_address_space::VmBasicInformation> {
    let info = if let Some(info) = process_committed_mapping_basic_information(pi as u64, page) {
        info
    } else {
        let map = process_vm_region_map(pi)?;
        map.extent_at(page)?;
        map.query_basic(page, USER_ADDRESS_LIMIT).ok()?
    };
    (info.type_ == nt_address_space::MEM_PRIVATE).then_some(info)
}

fn retained_record(
    pi: usize,
    process: nt_memory_manager::ProcessIdentity,
    page: u64,
) -> Result<Option<nt_memory_manager::ClientFrameRecord>, u32> {
    let record = unsafe { (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).get(pi as u64, page) };
    if record.is_some_and(|row| {
        !row.is_resident()
            || row.lifetime != nt_memory_manager::MemoryLifetime::Process(process)
            || !row.owns_frame
            || row.owned_backing_cap == 0
    }) {
        return Err(INVALID);
    }
    Ok(record)
}

struct ResidentIo<'a> {
    handler: &'a ExecNtHandler,
}
impl ResidentMappingRevalidationIo<ResidentPrivatePage> for ResidentIo<'_> {
    fn validate_current(
        &mut self,
        target: &ResidentPrivatePage,
        mapped: InstallationCap,
        backing: InstallationCap,
    ) -> Result<(), u32> {
        let ctx = self
            .handler
            .loop_ctx
            .and_then(|ctx| unsafe { ctx.for_process(target.pi) })
            .ok_or(INVALID)?;
        let current = unsafe { (&*ctx.procs).get(target.pi).copied() }.ok_or(INVALID)?;
        if self.handler.capture_process_identity(target.pi) != Some(target.process)
            || current.pml4 != target.pml4
            || current.scratch_base != target.scratch
            || target.pml4 == 0
            || target.scratch == 0
            || retained_record(target.pi, target.process, target.page)? != Some(target.record)
            || mapped.cap != target.record.frame
            || backing.cap != target.record.owned_backing_cap
        {
            return Err(INVALID);
        }
        let info =
            unsafe { canonical_private_information(target.pi, target.page) }.ok_or(INVALID)?;
        if info.state != nt_address_space::MEM_COMMIT || info.protect != target.protection {
            return Err(INVALID);
        }
        unsafe {
            frame_recycle::validate_owned_backing(backing.cap)?;
        }
        Ok(())
    }
    fn frame_address(&mut self, cap: InstallationCap) -> Result<u64, u32> {
        unsafe { get_frame_paddr_checked(cap.cap) }
    }
    fn map_existing(
        &mut self,
        target: &ResidentPrivatePage,
        mapped: InstallationCap,
    ) -> InstallationEffect {
        let error = unsafe {
            page_map_r(
                mapped.cap,
                target.page,
                vm_page_rights(target.protection),
                target.pml4,
            )
        };
        if error == 0 {
            InstallationEffect::Acknowledged
        } else {
            InstallationEffect::Refused(RESOURCES)
        }
    }
}

/// Deny-only fence; an uncertain existing mapping cannot be retired or read through another path.
pub(crate) fn memory_available(pi: u64, base: u64, size: u64) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    unsafe {
        (&*core::ptr::addr_of!(REVALIDATION))
            .as_ref()
            .is_none_or(|owner| {
                let target = owner.descriptor();
                !owner.blocks_retirement()
                    || target.pi as u64 != pi
                    || size == 0
                    || base
                        .checked_add(size)
                        .is_some_and(|end| end <= target.page || base >= target.page + 4096)
            })
    }
}

/// Pump hint only: authentication precedes this call and root revalidates after releasing borrows.
/// No handler pointer, native invocation, allocation, alias mutation or residency effect occurs here.
pub(crate) unsafe fn resident_read_fault_candidate(
    child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    parent: nt_memory_manager::ProcessIdentity,
    registers: [u64; 4],
) -> Option<ResidentReadFaultCapture> {
    // The singleton effect owner cannot be displaced by another receive child, even when its
    // range is disjoint. Acquire only long enough to copy this deny-only observation.
    {
        let _borrow = Borrow::acquire().ok()?;
        if (&*core::ptr::addr_of!(REVALIDATION)).is_some() {
            return None;
        }
    }
    if !child.process.is_valid()
        || !parent.is_valid()
        || child.process == parent
        || child.tcb <= 1
        || child.tid == 0
        || registers[2] != 0
    {
        return None;
    }
    let page = registers[1] & !0xfff;
    if registers[3] & 0x12 != 0 || hosted_thread_memory_access(child.pi as u64, page, 4096).is_err()
    {
        return None;
    }
    let Some(info) = canonical_private_information(child.pi, page) else {
        return None;
    };
    let Ok(Some(record)) = retained_record(child.pi, child.process, page) else {
        return None;
    };
    if !matches!(
        plan_private_read_fault(
            page,
            info,
            FaultAccess::Read,
            ImageFaultObservation::from_x86_error(registers[3]),
            PrivateFaultBacking::Resident(record),
        ),
        Ok(PrivateReadFaultPlan::Revalidate { .. })
    ) {
        return None;
    }
    Some(ResidentReadFaultCapture {
        child,
        page,
        information: info,
        record,
    })
}

impl ExecNtHandler {
    /// Root-only servicing of an already authenticated, retained receive child. A changed
    /// resident record or VAD is refusal, never an invitation to allocate or restore a page.
    pub(crate) unsafe fn service_captured_private_read_fault(
        &mut self,
        capture: ResidentReadFaultCapture,
        binding: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    ) -> Result<(), u32> {
        if capture.child != binding
            || self
                .admit_hosted_thread_ingress(binding.badge)
                .map(|runtime| runtime.binding())
                .ok()
                != Some(binding)
            || canonical_private_information(binding.pi, capture.page) != Some(capture.information)
            || retained_record(binding.pi, binding.process, capture.page)? != Some(capture.record)
        {
            return Err(INVALID);
        }
        let plan = match plan_private_read_fault(
            capture.page,
            capture.information,
            FaultAccess::Read,
            ImageFaultObservation::NotPresent,
            PrivateFaultBacking::Resident(capture.record),
        )? {
            PrivateReadFaultPlan::Revalidate { .. } => nt_address_space::vm_access_page_plan(
                capture.page,
                capture.information,
                FaultAccess::Read,
            )?,
            _ => return Err(INVALID),
        };
        self.private_page_residency(binding.pi, plan, ImageFaultObservation::NotPresent)
    }

    pub(super) unsafe fn ensure_private_page_residency(
        &mut self,
        pi: usize,
        plan: nt_address_space::VmResidencyPagePlan,
    ) -> Result<(), u32> {
        // KUSER is an explicitly published borrowed transport mapping, not demand-zero storage.
        if plan.page == KUSER_VA && kuser_page_alias_get(pi) != 0 {
            return Ok(());
        }
        self.private_page_residency(pi, plan, ImageFaultObservation::CopyAccess)
    }

    pub(crate) unsafe fn service_committed_private_page_residency(
        &mut self,
        pi: usize,
        page: u64,
        access: FaultAccess,
        observation: ImageFaultObservation,
    ) -> Result<Option<()>, u32> {
        let Some(info) = canonical_private_information(pi, page) else {
            return Ok(None);
        };
        if info.protect & nt_address_space::PAGE_GUARD != 0 {
            return Ok(None);
        }
        let plan = nt_address_space::vm_access_page_plan(page, info, access)?;
        self.private_page_residency(pi, plan, observation)?;
        Ok(Some(()))
    }

    unsafe fn private_page_residency(
        &mut self,
        pi: usize,
        plan: nt_address_space::VmResidencyPagePlan,
        observation: ImageFaultObservation,
    ) -> Result<(), u32> {
        let process = self.capture_process_identity(pi).ok_or(INVALID)?;
        let ctx = self
            .loop_ctx
            .and_then(|ctx| ctx.for_process(pi))
            .ok_or(INVALID)?;
        let current = (&*ctx.procs).get(pi).copied().ok_or(INVALID)?;
        if current.pml4 == 0 || current.scratch_base == 0 {
            return Err(INVALID);
        }
        let record = retained_record(pi, process, plan.page)?;
        let info = match canonical_private_information(pi, plan.page) {
            Some(info) => info,
            // Existing non-VAD transport frames remain copyable, but never authorize allocation.
            None if observation == ImageFaultObservation::CopyAccess && record.is_some() => {
                self.query_memory_basic_information(pi, plan.page)?
            }
            None => return Err(INVALID),
        };
        if nt_address_space::vm_access_page_plan(plan.page, info, plan.access)? != plan {
            return Err(INVALID);
        }
        if observation == ImageFaultObservation::Protection {
            return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
        }
        // An exact retained transition may resume before the ordinary-access fence. Its own
        // transaction validates the original process/frame and never manufactures a fresh page.
        if record.is_none()
            && self.restore_process_pagefile_page(
                pi,
                plan.page,
                current.pml4,
                current.scratch_base,
            )?
        {
            return Ok(());
        }
        hosted_thread_memory_access(pi as u64, plan.page, 4096)?;
        if plan.access == FaultAccess::Read && observation == ImageFaultObservation::NotPresent {
            let backing = if let Some(record) = record {
                PrivateFaultBacking::Resident(record)
            } else if (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).contains(pi as u64, plan.page) {
                PrivateFaultBacking::Unavailable
            } else {
                PrivateFaultBacking::DemandZero
            };
            // Any still-retained pagefile owner forbids demand-zero replacement.
            plan_private_read_fault(plan.page, info, plan.access, observation, backing)?;
        }
        if let Some(record) = record {
            frame_recycle::validate_owned_backing(record.owned_backing_cap)?;
            if observation == ImageFaultObservation::CopyAccess {
                return Ok(());
            }
            let _borrow = Borrow::acquire()?;
            let target = ResidentPrivatePage {
                pi,
                process,
                page: plan.page,
                pml4: current.pml4,
                scratch: current.scratch_base,
                protection: plan.map_protection,
                record,
            };
            let pending = &mut *core::ptr::addr_of_mut!(REVALIDATION);
            if let Some(owner) = pending {
                if owner.descriptor() != target {
                    return Err(RESOURCES);
                }
            } else {
                *pending = Some(ResidentMappingRevalidation::begin(
                    target,
                    InstallationCap { cap: record.frame },
                    InstallationCap {
                        cap: record.owned_backing_cap,
                    },
                    true,
                )?);
            }
            match pending
                .as_mut()
                .ok_or(INVALID)?
                .advance(&mut ResidentIo { handler: self })
            {
                ResidentMappingRevalidationOutcome::Revalidated => {
                    *pending = None;
                    Ok(())
                }
                ResidentMappingRevalidationOutcome::Refused(status) => {
                    *pending = None;
                    Err(status)
                }
                ResidentMappingRevalidationOutcome::Quarantined(status) => Err(status),
            }
        } else {
            // Exact pagefile restoration is checked inside the retained installer before allocation.
            vm_map_private_page(
                self,
                pi,
                plan.page,
                plan.map_protection,
                current.pml4,
                current.scratch_base,
            )
        }
    }
}
