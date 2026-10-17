//! Hosted `PsSetCreateProcessNotifyRoutineEx` registration and exit callback transport.
//!
//! Image metadata is published before DriverEntry, since dxgkrnl registers from its eager global
//! initialization. The PM owns callback tickets; this module owns only the exact driver image and
//! physical route needed to execute them. No PM borrow spans a component pump.

use super::*;
use nt_kernel_exec::hosted_process_exit_notify::{
    HostedImageIdentity, HostedProcessExitDelivery, HostedProcessNotifyBinding,
    HostedProcessNotifyTransport, ProcessExitDispatchResult, ProcessNotifyRegisterError,
};

pub(crate) const LABEL: u64 = 0x7C7;

#[derive(Clone, Copy)]
struct ImageRecord {
    instance: usize,
    binding: HostedProcessNotifyBinding,
}

#[derive(Clone, Copy)]
struct Registration {
    instance: usize,
    callback: u64,
    binding: HostedProcessNotifyBinding,
}

static mut IMAGES: Vec<ImageRecord> = Vec::new();
static mut REGISTRATIONS: Vec<Registration> = Vec::new();
static mut NEXT_IMAGE_GENERATION: u64 = 1;

fn transport(inst: DriverInstance) -> HostedProcessNotifyTransport {
    HostedProcessNotifyTransport {
        domain_id: inst.hosted_domain_id,
        domain_cookie: inst.hosted_domain_cookie,
        endpoint: inst.fault_ep,
        vspace: inst.pml4,
        shared: inst.exec_shared_va,
    }
}

/// Resolve a callback against one live image publication. Other native exports use this same
/// generation proof so each provider image has only one authoritative publication record.
pub(super) unsafe fn published_image_for_callback(
    instance_index: usize,
    inst: DriverInstance,
    callback: u64,
) -> Option<HostedImageIdentity> {
    let current = transport(inst);
    if !current.is_valid() { return None; }
    let mut matches = (&*core::ptr::addr_of!(IMAGES)).iter().filter(|image| {
        image.instance == instance_index
            && image.binding.transport == current
            && image.binding.image.owner_for_callback(callback).is_some()
    });
    let image = matches.next()?.binding.image;
    matches.next().is_none().then_some(image)
}

/// Called after the relocated primary image and its physical fault endpoint are admitted, but
/// before DriverEntry runs. Dependency images can use the same operation. Each publication
/// receives a fresh generation.
pub(super) unsafe fn publish_image(
    instance_index: usize,
    run_base: u64,
    image_len: u64,
) -> Result<(), u32> {
    let inst = instance(instance_index).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let route = transport(inst);
    if !route.is_valid() || instance_domain_identity(inst).is_none() {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let next = NEXT_IMAGE_GENERATION.checked_add(1)
        .ok_or(nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
    let binding = HostedProcessNotifyBinding {
        image: HostedImageIdentity {
            run_base,
            image_len,
            publication_generation: NEXT_IMAGE_GENERATION,
        },
        transport: route,
    };
    if binding.image.owner_for_callback(run_base).is_none() {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let images = &mut *core::ptr::addr_of_mut!(IMAGES);
    let end = run_base.checked_add(image_len).ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
    if images.iter().any(|entry| {
        let other = entry.binding.image;
        entry.instance == instance_index
            && entry.binding.transport == route
            && other.run_base.checked_add(other.image_len)
                .is_none_or(|other_end| run_base < other_end && other.run_base < end)
    }) {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    images.try_reserve(1).map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
    images.push(ImageRecord { instance: instance_index, binding });
    NEXT_IMAGE_GENERATION = next;
    Ok(())
}

/// A component-side ntoskrnl export. The root service captures the exact image/transport owner.
pub(super) extern "win64" fn ps_set_create_process_notify_routine_ex(
    callback: u64,
    remove: u8,
) -> i32 {
    if callback == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let (words, raw, unused0, unused1, unused2) = call_on4_raw(
            (LABEL << 12) | 4,
            callback,
            u64::from(remove != 0),
            0,
            0,
        );
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || unused0 != 0 || unused1 != 0 || unused2 != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, callback, words, raw]);
        }
        raw as u32 as i32
    }
}

/// The pump checks label, shape, badge and active Reply before entering this service. We recheck
/// the physical instance and PM caller so a numeric callback address cannot register itself.
pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    callback: u64,
    remove: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> i32 {
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return STATUS_INVALID_HANDLE;
    };
    if hosted_driver_caller(index, inst, caller_badge).is_none() || remove > 1 {
        return STATUS_INVALID_HANDLE;
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return status as i32,
    };
    let valid_caller = unsafe {
        crate::service_sec_image::with_provider_process_manager(|pm| {
            pm.validate_native_handle_caller(caller)
        })
    };
    if let Err(status) = valid_caller {
        return status as i32;
    }
    let current = transport(inst);
    if !current.is_valid() {
        return STATUS_INVALID_HANDLE;
    }
    unsafe {
        let Some(published) = published_image_for_callback(index, inst, callback) else {
            return STATUS_INVALID_PARAMETER;
        };
        let image = HostedProcessNotifyBinding { image: published, transport: current };
        let owner = published.owner_for_callback(callback).unwrap();
        let owner = nt_process::ProcessExitNotifyOwner {
            image_base: owner.image_base,
            image_generation: owner.image_generation,
        };
        let registrations = &mut *core::ptr::addr_of_mut!(REGISTRATIONS);
        if remove != 0 {
            let Some(position) = registrations.iter().position(|row| {
                row.instance == index && row.callback == callback && row.binding == image
            }) else { return STATUS_INVALID_PARAMETER; };
            match crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.unregister_process_exit_notify(owner, callback)
            }) {
                Ok(()) => { registrations.remove(position); STATUS_SUCCESS }
                Err(status) => status as i32,
            }
        } else {
            if registrations.try_reserve(1).is_err() {
                return nt_process::STATUS_INSUFFICIENT_RESOURCES as i32;
            }
            let result = image.register(callback, |_owner, address| {
                crate::service_sec_image::with_provider_process_manager(|pm| {
                    pm.register_process_exit_notify(owner, address)
                })
            });
            match result {
                Ok(()) => {
                    registrations.push(Registration { instance: index, callback, binding: image });
                    STATUS_SUCCESS
                }
                Err(ProcessNotifyRegisterError::InvalidBinding) => STATUS_INVALID_PARAMETER,
                Err(ProcessNotifyRegisterError::Registration(status)) => status as i32,
            }
        }
    }
}

/// A registration blocks image/domain retirement until explicit removal. This also blocks a
/// pending or uncertain exit callback because Process Manager refuses its removal while leased.
pub(super) unsafe fn blocks_instance_retirement(instance_index: usize) -> bool {
    (&*core::ptr::addr_of!(REGISTRATIONS))
        .iter().any(|row| row.instance == instance_index)
}

/// Drop publication records only after the caller has refused retirement for live registrations.
pub(super) unsafe fn retire_instance_images(instance_index: usize) -> Result<(), u32> {
    if blocks_instance_retirement(instance_index) {
        return Err(nt_process::STATUS_DEVICE_BUSY);
    }
    (&mut *core::ptr::addr_of_mut!(IMAGES)).retain(|image| image.instance != instance_index);
    Ok(())
}

/// Dispatch one already-claimed PM ticket. The native terminal hook must call
/// `complete_exit_notification` only after this returns `Ok(())`; an error retains the PM ticket
/// in-flight and must never trigger a callback retry.
pub(crate) unsafe fn dispatch_exit_notification(
    ticket: nt_process::ProcessExitNotification,
) -> Result<(), i32> {
    let row = {
        let registrations = &*core::ptr::addr_of!(REGISTRATIONS);
        registrations.iter().copied().find(|row| {
            row.callback == ticket.callback
                && row.binding.image.run_base == ticket.owner.image_base
                && row.binding.image.publication_generation == ticket.owner.image_generation
        })
    }.ok_or(STATUS_INVALID_HANDLE)?;
    let inst = instance(row.instance).ok_or(STATUS_INVALID_HANDLE)?;
    let live_binding = {
        let images = &*core::ptr::addr_of!(IMAGES);
        images.iter().copied().find(|image| {
            image.instance == row.instance && image.binding == row.binding
        }).map(|image| image.binding)
    }.ok_or(STATUS_INVALID_HANDLE)?;
    if transport(inst) != live_binding.transport || !inst.ready || inst.faulted {
        return Err(STATUS_INVALID_HANDLE);
    }
    let view = HostedProcessExitDelivery {
        owner: nt_kernel_exec::hosted_process_exit_notify::HostedProcessNotifyOwner {
            image_base: ticket.owner.image_base,
            image_generation: ticket.owner.image_generation,
        },
        callback: ticket.callback,
        process_id: ticket.process_id,
        process_object: ticket.process_object,
    };
    let plan = row.binding.plan_exit(view, live_binding).ok_or(STATUS_INVALID_HANDLE)?;
    let code = ExecVaWindow::try_for_instance(row.instance)
        .map(|window| window.code_va).ok_or(STATUS_INVALID_HANDLE)?;
    let target = crate::ps_object_provider::ProviderRoot::hosted(
        instance_domain_identity(inst).ok_or(STATUS_INVALID_HANDLE)?, inst.pml4,
    ).map_err(|status| status as i32)?;
    let projected = crate::service_sec_image::with_provider_process_manager(|pm| {
        if pm.process_sequence_for_kernel_process_object(ticket.process_object)? != ticket.process_sequence {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let (body, _) = pm.lookup_kernel_process_by_id(ticket.process_id)?;
        if body != ticket.process_object {
            pm.release_kernel_object_pointer(body)?;
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let mapped = if driver_ps_pool_alias::contains(
            body, nt_kernel_abi::ps_reactos_x64::EPROCESS_BODY_BYTES,
        ) {
            driver_ps_pool_alias::grant(inst, body, nt_kernel_abi::ps_reactos_x64::EPROCESS_BODY_BYTES)
        } else {
            crate::ps_object_backing::grant_referenced_body(
                pm, body, target, crate::ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed),
            )
        };
        if let Err(status) = mapped {
            pm.release_kernel_object_pointer(body)?;
            return Err(status);
        }
        Ok(())
    }).map_err(|status| status as i32);
    projected?;
    let result = plan.execute(
        |call, _transport| {
            dispatch_hosted_component_target(
                row.instance, inst, code, call.callback,
                [call.process_object, u64::from(call.process_id), call.create_info, 0],
                [0u64; PROVIDER_CALLBACK_STACK_QWORDS],
                crate::initial_system_driver_caller(),
            ).map(|_| ()).map_err(|_| STATUS_UNSUCCESSFUL)
        },
        || Ok::<(), i32>(()),
    );
    match result {
        ProcessExitDispatchResult::Completed => {
            crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.release_kernel_object_pointer(ticket.process_object).map(|_| ())
            }).map_err(|status| status as i32)
        }
        ProcessExitDispatchResult::CallbackUncertain(status)
        | ProcessExitDispatchResult::AcknowledgementPending(status) => Err(status),
    }
}

pub(crate) fn complete_exit_notification(
    pm: &mut nt_process::ProcessManager,
    ticket: nt_process::ProcessExitNotification,
) -> Result<(), u32> {
    pm.complete_process_exit_notification(ticket)
}
