//! Deferred VM-copy page admission and physical access without provider I/O.

use super::*;
use nt_address_space::copy::{copy_page_plan_checked, CopyPagePlan, MemoryCopyFailure,
    STATUS_GUARD_PAGE_VIOLATION};
use nt_address_space::{FaultAccess, ImageFaultObservation, VmResidencySource, PAGE_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyPageAdmission {
    Resident,
    NeedsRoutedPageIn,
}

impl ExecNtHandler {
    /// Admit protection and residency before any physical copy. A routed Section or image page
    /// that needs provider bytes is returned to the owned syscall coordinator without I/O.
    pub(crate) unsafe fn copy_page_admission(
        &mut self, pi: usize, address: u64, access: FaultAccess,
    ) -> Result<CopyPageAdmission, u32> {
        let page = address & !(PAGE_SIZE - 1);
        hosted_thread_memory_access(pi as u64, page, PAGE_SIZE)?;
        let process = self.capture_process_identity(pi).ok_or(STATUS_INVALID_HANDLE)?;
        let ctx = self.loop_ctx.and_then(|ctx| ctx.for_process(pi))
            .ok_or(STATUS_INVALID_HANDLE)?;
        let target = (&*ctx.procs).get(pi).copied()
            .filter(|target| target.pml4 != 0 && target.scratch_base != 0)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let info = self.query_memory_basic_information(pi, page)?;
        let plan = copy_page_plan_checked(page, info, access, pi != self.pi)
            .map_err(|failure| match failure {
                MemoryCopyFailure::UserFault(nt_address_space::STATUS_NOT_COMMITTED)
                | MemoryCopyFailure::Retry(nt_address_space::STATUS_NOT_COMMITTED) =>
                    STATUS_ACCESS_VIOLATION,
                other => other.status(),
            })?;
        let admission = match plan {
            CopyPagePlan::ConsumeGuard(plan) => {
                self.consume_copy_guard(pi, info, plan)?;
                return Err(STATUS_GUARD_PAGE_VIOLATION);
            }
            CopyPagePlan::Resident(plan) => match plan.source {
                VmResidencySource::Private => {
                    self.ensure_private_page_residency(pi, plan)?;
                    CopyPageAdmission::Resident
                }
                VmResidencySource::Mapped => {
                    match crate::service_sec_image::service_generic_section_fault(
                        self, ctx.generic_sections, pi, page, target.pml4,
                        target.scratch_base,
                        if access == FaultAccess::Read { FaultAccess::Lock } else { access },
                        true, false,
                    )? {
                        crate::service_sec_image::GenericSectionFaultResult::Mapped =>
                            CopyPageAdmission::Resident,
                        crate::service_sec_image::GenericSectionFaultResult::RoutedPageIn =>
                            CopyPageAdmission::NeedsRoutedPageIn,
                        crate::service_sec_image::GenericSectionFaultResult::Unmapped =>
                            return Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES),
                    }
                }
                VmResidencySource::Image => {
                    match self.admit_native_image_copy_page(pi, page, access)? {
                        Some(true) => CopyPageAdmission::NeedsRoutedPageIn,
                        Some(false) => CopyPageAdmission::Resident,
                        None => {
                            crate::service_sec_image::service_legacy_image_page_residency(
                                self, pi, page, access, ImageFaultObservation::CopyAccess,
                            )?;
                            CopyPageAdmission::Resident
                        }
                    }
                }
            },
        };
        if self.capture_process_identity(pi) != Some(process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(admission)
    }

    /// The caller has already admitted access and residency for this exact process and page.
    /// No fault handler or routed provider is entered from this physical read.
    pub(crate) unsafe fn copy_read_resident_page(
        &mut self, pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        address: u64, output: &mut [u8],
    ) -> Result<(), u32> {
        if output.is_empty() { return Ok(()); }
        if output.len() as u64 > PAGE_SIZE - address % PAGE_SIZE
            || self.capture_process_identity(pi) != Some(process)
        { return Err(STATUS_ACCESS_VIOLATION); }
        hosted_thread_memory_access(pi as u64, address, output.len() as u64)?;
        if address & !(PAGE_SIZE - 1) == KUSER_VA {
            let alias = kuser_page_alias_get(pi);
            if alias == 0 { return Err(STATUS_ACCESS_VIOLATION); }
            core::ptr::copy_nonoverlapping(
                (alias + address % PAGE_SIZE) as *const u8, output.as_mut_ptr(), output.len());
        } else {
            let ctx = self.loop_ctx.and_then(|ctx| ctx.for_process(pi))
                .ok_or(STATUS_INVALID_HANDLE)?;
            if !client_copyin_process_mapped_for(
                pi as u64, process, address, output, ctx.scratch_base,
            ) { return Err(STATUS_ACCESS_VIOLATION); }
        }
        if self.capture_process_identity(pi) != Some(process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    /// This page-contained write has been entered once by the coordinator. A refused alias or
    /// release is reported as an error; the coordinator must not retry an uncertain write.
    pub(crate) unsafe fn copy_write_resident_page(
        &mut self, pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
        address: u64, input: &[u8],
    ) -> Result<(), u32> {
        if input.is_empty() { return Ok(()); }
        if input.len() as u64 > PAGE_SIZE - address % PAGE_SIZE
            || self.capture_process_identity(pi) != Some(process)
        { return Err(STATUS_ACCESS_VIOLATION); }
        hosted_thread_memory_access(pi as u64, address, input.len() as u64)?;
        let ctx = self.loop_ctx.and_then(|ctx| ctx.for_process(pi))
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !crate::img_spawn::client_copyout_mapped_admitted_for(
            pi as u64, process, address, input, ctx.scratch_base,
        ) { return Err(STATUS_ACCESS_VIOLATION); }
        if self.capture_process_identity(pi) != Some(process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }
}
