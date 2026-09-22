//! Canonical external NT identities, separate from hosted scheduler correlation handles.

use super::*;

pub(super) unsafe fn project(
    inst: DriverInstance,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> Result<(u64, u64, u64, u64, u64), u32> {
    let _durable = crate::allocator::enter_durable();
    let domain = instance_domain_identity(inst).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let target = crate::ps_object_provider::ProviderRoot::hosted(domain, inst.pml4)?;
    crate::ps_object_backing::register_provider(target)?;
    crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        let thread = caller.original_thread();
        let process_body = pm.process_kernel_object(thread.process_id()).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let thread_body = pm.thread_kernel_object(thread.thread_id()).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        use nt_kernel_abi::ps_reactos_x64::{EPROCESS_BODY_BYTES, ETHREAD_BODY_BYTES};
        use crate::ps_object_backing::PublishedBody;
        for (body, address, bytes) in [
            (PublishedBody::Process, process_body, EPROCESS_BODY_BYTES),
            (PublishedBody::Thread, thread_body, ETHREAD_BODY_BYTES),
        ] {
            if driver_ps_pool_alias::contains(address, bytes) {
                driver_ps_pool_alias::grant(inst, address, bytes)?;
            } else {
                crate::ps_object_backing::grant_published_body(
                    pm, thread, body, target, crate::ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed),
                )?;
            }
        }
        Ok((u64::from(thread.process_id()), u64::from(thread.thread_id()),
            process_body, thread_body,
            pm.thread(thread.thread_id()).ok_or(nt_process::STATUS_INVALID_HANDLE)?.teb_base))
    })
}

pub(super) unsafe fn retire(inst: DriverInstance) -> Result<(), u32> {
    driver_ps_pool_alias::retire(inst)?;
    if !crate::ps_object_backing::references_provider_vspace(inst.pml4) { return Ok(()); }
    let domain = instance_domain_identity(inst).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let target = crate::ps_object_provider::ProviderRoot::hosted(domain, inst.pml4)?;
    crate::ps_object_backing::retire_provider(
        target, crate::ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed),
    )
}
