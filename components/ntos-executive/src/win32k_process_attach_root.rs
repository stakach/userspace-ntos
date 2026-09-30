//! Canonical process-attach ownership for an executing win32k logical thread.

use super::*;
use core::ptr::read_volatile;
use nt_kernel_exec::process_attach::{ProcessAttachState, SavedAttachState};
use nt_user_host::{client_alias_window::WindowOwner, process_identity::ProcessGeneration};
use nt_user_host::provider_kernel_activation::{KernelProviderCaller, KernelProviderServiceEnvelope};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

const INVALID_PARAMETER: i32 = nt_process::STATUS_INVALID_PARAMETER as i32;
const INVALID_HANDLE: i32 = nt_process::STATUS_INVALID_HANDLE as i32;
const INSUFFICIENT_RESOURCES: i32 = nt_process::STATUS_INSUFFICIENT_RESOURCES as i32;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Target {
    eprocess: u64,
    owner: Option<WindowOwner>,
}

struct StackSave {
    address: u64,
    token: SavedAttachState,
    marker: u64,
    retained_process: Option<u64>,
}

struct ThreadAttach {
    caller: AttachCaller,
    state: ProcessAttachState<Target>,
    plain_reference: Option<u64>,
    stack: Vec<StackSave>,
    inflight: Option<AttachIntent>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttachCaller {
    Logical(ProviderLogicalCaller),
    Kernel(KernelProviderCaller),
}

struct AttachIntent {
    operation: u64,
    process: u64,
    retained_process: Option<u64>,
}

static mut THREAD_ATTACHMENTS: Vec<ThreadAttach> = Vec::new();

pub(super) unsafe fn select_effective_client(
    caller: ProviderLogicalCaller,
    original: WindowOwner,
) -> bool {
    let records = &*core::ptr::addr_of!(THREAD_ATTACHMENTS);
    let Some(record) = records.iter().find(|record| record.caller == AttachCaller::Logical(caller)) else {
        return w32_client_attach(original);
    };
    if record.state.original().owner != Some(original) {
        return false;
    }
    select(record.state.current()).is_ok()
}

pub(crate) unsafe fn retire_thread_attach(client: Win32kClientContext) -> bool {
    let records = &mut *core::ptr::addr_of_mut!(THREAD_ATTACHMENTS);
    let Some(index) = records.iter().position(|record| {
        let AttachCaller::Logical(caller) = record.caller else { return false; };
        caller.pi() == client.pi as usize
            && caller.process().pid as u64 == client.pid
            && caller.process().generation == ProcessGeneration::Hosted(client.generation)
            && u64::from(caller.thread().thread_id()) == client.tid
    }) else {
        return true;
    };
    let record = &records[index];
    if record.inflight.is_some()
        || record.state.active_depth() != 0
        || record.plain_reference.is_some()
        || !record.stack.is_empty()
    {
        return false;
    }
    let record = records.swap_remove(index);
    record.state.retire(client.tid).is_ok()
}

pub(crate) unsafe fn retire_kernel_attach(caller: KernelProviderCaller) -> bool {
    let records = &mut *core::ptr::addr_of_mut!(THREAD_ATTACHMENTS);
    let Some(index) = records.iter().position(|record| record.caller == AttachCaller::Kernel(caller)) else {
        return true;
    };
    let record = &records[index];
    if record.inflight.is_some()
        || record.state.active_depth() != 0
        || record.plain_reference.is_some()
        || !record.stack.is_empty()
    {
        return false;
    }
    let record = records.swap_remove(index);
    record.state.retire(u64::from(caller.thread().thread_id())).is_ok()
}

unsafe fn resolve_target(eprocess: u64, vspace: u64) -> Option<Target> {
    if crate::ps_bootstrap::is_initial_system_process(eprocess) {
        return Some(Target { eprocess, owner: None });
    }
    let handler = crate::service_sec_image::registry_live_handler().ok()?;
    let pid = handler.pm.pid_for_kernel_process_object(eprocess)?;
    if handler.pm.kernel_process_state(eprocess)?.exit_process_called {
        return None;
    }
    let mut found = None;
    for pi in 0..crate::MAX_PI {
        if handler.pm_pid_for_pi(pi) != Some(pid) {
            continue;
        }
        let generation = handler.hosted_process_generation(pi)?;
        if generation == 0 || found.is_some() {
            return None;
        }
        found = Some(WindowOwner {
            pi,
            process: nt_user_host::process_identity::ProcessIdentity {
                pid,
                generation: ProcessGeneration::Hosted(generation),
            },
            vspace,
        });
    }
    Some(Target { eprocess, owner: Some(found?) })
}

unsafe fn retain_target(target: Target) -> bool {
    target.owner.is_none()
        || crate::service_sec_image::with_provider_process_manager(|pm| {
            pm.retain_kernel_object_pointer(target.eprocess).map(|_| ())
        }).is_ok()
}

unsafe fn release_target(target: u64) -> bool {
    crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.release_kernel_object_pointer(target).map(|_| ())
    }).is_ok()
}

unsafe fn select(target: &Target) -> Result<(), ()> {
    match target.owner {
        Some(owner) => unsafe { w32_client_attach(owner) }.then_some(()).ok_or(()),
        None => match unsafe { attached_owner() } {
            Some(owner) => unsafe { detach_attached_client_process(owner) }.map_err(|_| ()),
            None => Ok(()),
        },
    }
}

unsafe fn current_record(
    caller: AttachCaller,
    tid: u64,
    original: Target,
) -> Result<&'static mut ThreadAttach, i32> {
    let records = &mut *core::ptr::addr_of_mut!(THREAD_ATTACHMENTS);
    if let Some(index) = records.iter().position(|record| record.caller == caller) {
        let record = &mut records[index];
        if *record.state.original() != original {
            return Err(INVALID_HANDLE);
        }
        return Ok(record);
    }
    records.try_reserve(1).map_err(|_| INSUFFICIENT_RESOURCES)?;
    records.push(ThreadAttach {
        caller,
        state: ProcessAttachState::new(tid, original),
        plain_reference: None,
        stack: Vec::new(),
        inflight: None,
    });
    Ok(records.last_mut().unwrap())
}

/// The pump authenticates the physical source. This service additionally requires the exact
/// active logical caller, native ETHREAD and a live, generation-matched process projection.
pub(crate) unsafe fn service_process_attach(
    channel: &crate::spawn_hosts::PumpChannel,
    envelope: KernelProviderServiceEnvelope,
    operation: u64,
    target_eprocess: u64,
    saved_state_va: u64,
    ethread: u64,
) -> (i32, u64, u64, u64) {
    if channel.pml4 != WIN32K_HOST_PML4.load(Ordering::Acquire) {
        return (INVALID_HANDLE, 0, 0, 0);
    }
    let (caller, original, tid) = match (channel.logical_caller, channel.kernel_caller) {
        (Some(caller), None) => {
            if caller.pi() as u64 != channel.client_pi
                || channel.client_generation == 0
                || !crate::win32k_glue::registry_logical_caller_is_current(channel)
            {
                return (INVALID_HANDLE, 0, 0, 0);
            }
            let original_eprocess = {
                let Ok(handler) = crate::service_sec_image::registry_live_handler() else {
                    return (INVALID_HANDLE, 0, 0, 0);
                };
                if !handler.validate_provider_logical_caller(caller)
                    || handler.pm.thread_kernel_object(caller.thread().thread_id()) != Some(ethread)
                    || handler.hosted_process_generation(caller.pi()) != Some(channel.client_generation)
                {
                    return (INVALID_HANDLE, 0, 0, 0);
                }
                let Some(eprocess) = handler.pm.process_kernel_object(caller.thread().process_id()) else {
                    return (INVALID_HANDLE, 0, 0, 0);
                };
                eprocess
            };
            (
                AttachCaller::Logical(caller),
                Target {
                    eprocess: original_eprocess,
                    owner: Some(WindowOwner {
                        pi: caller.pi(),
                        process: caller.process(),
                        vspace: channel.pml4,
                    }),
                },
                u64::from(caller.thread().thread_id()),
            )
        }
        (None, Some(caller)) => {
            if crate::service_sec_image::kernel_provider_activation::validate_win32k_service_call(
                channel,
                envelope,
                (crate::win32k_subsystem::W32_PROCESS_ATTACH_LABEL << 12) | 4,
            ).is_err() {
                return (INVALID_HANDLE, 0, 0, 0);
            }
            let Some(system) = crate::ps_bootstrap::initial_system_projection() else {
                return (INVALID_HANDLE, 0, 0, 0);
            };
            if caller.thread().thread_id() != system.identity.thread_id()
                || caller.thread().process_id() != system.identity.process_id()
                || ethread != system.thread_body
            {
                return (INVALID_HANDLE, 0, 0, 0);
            }
            (
                AttachCaller::Kernel(caller),
                Target { eprocess: system.process_body, owner: None },
                u64::from(caller.thread().thread_id()),
            )
        }
        _ => return (INVALID_HANDLE, 0, 0, 0),
    };
    let stack_address = match operation {
        crate::win32k_subsystem::W32_ATTACH_STACK
        | crate::win32k_subsystem::W32_ATTACH_UNSTACK => {
            // The imported win32k call sites save KAPC_STATE in a stack local. Other kernel VAs
            // require their own retained, generation-checked alias; a raw pointer is not enough.
            let Some(route) = channel.ingress_route else { return (INVALID_HANDLE, 0, 0, 0); };
            if saved_state_va & 7 != 0 {
                return (INVALID_PARAMETER, 0, 0, 0);
            }
            let Some(address) = win32k_stack_alias_for_route(route, saved_state_va, 0x30) else {
                return (INVALID_PARAMETER, 0, 0, 0);
            };
            Some(address)
        }
        _ if saved_state_va == 0 => None,
        _ => return (INVALID_PARAMETER, 0, 0, 0),
    };
    let record = match current_record(caller, tid, original) {
        Ok(record) => record,
        Err(status) => return (status, 0, 0, 0),
    };
    if record.inflight.is_some() {
        return (INVALID_HANDLE, 0, 0, 0);
    }
    record.inflight = Some(AttachIntent {
        operation,
        process: record.state.current().eprocess,
        retained_process: None,
    });
    if select(record.state.current()).is_err() {
        return (INSUFFICIENT_RESOURCES, 0, 0, 0);
    }
    record.inflight = None;
    let before = *record.state.current();
    let mut saved_marker = 0;
    let result = match operation {
        crate::win32k_subsystem::W32_ATTACH_PLAIN if target_eprocess != 0 => {
            let Some(target) = resolve_target(target_eprocess, channel.pml4) else {
                return (INVALID_HANDLE, 0, 0, 0);
            };
            let retain = target != before && target.owner.is_some();
            if retain && !retain_target(target) {
                return (INVALID_HANDLE, 0, 0, 0);
            }
            let inflight = &mut record.inflight;
            let result = record.state.attach(tid, target, |_| true, |_, to| {
                *inflight = Some(AttachIntent {
                    operation,
                    process: to.eprocess,
                    retained_process: retain.then_some(to.eprocess),
                });
                select(to)
            });
            if result.is_ok() && retain {
                record.plain_reference = Some(target.eprocess);
            } else if result.is_err() && record.inflight.is_none() && retain && !release_target(target.eprocess) {
                return (INSUFFICIENT_RESOURCES, 0, 0, 0);
            }
            if result.is_ok() {
                record.inflight = None;
            }
            result
        }
        crate::win32k_subsystem::W32_ATTACH_DETACH if target_eprocess == 0 => {
            let inflight = &mut record.inflight;
            let result = record.state.detach(tid, |_, to| {
                *inflight = Some(AttachIntent {
                    operation,
                    process: to.eprocess,
                    retained_process: None,
                });
                select(to)
            });
            if result.is_ok() {
                record.inflight = None;
                if let Some(reference) = record.plain_reference.take() {
                    if !release_target(reference) {
                        crate::provider_bugcheck::report(0xc4, [crate::win32k_subsystem::W32_PROCESS_ATTACH_LABEL, reference, 1, 0]);
                    }
                }
            }
            result
        }
        crate::win32k_subsystem::W32_ATTACH_STACK if target_eprocess != 0 => {
            let Some(target) = resolve_target(target_eprocess, channel.pml4) else {
                return (INVALID_HANDLE, 0, 0, 0);
            };
            if record.stack.iter().any(|save| save.address == saved_state_va) {
                return (INVALID_PARAMETER, 0, 0, 0);
            }
            if record.stack.try_reserve(1).is_err() {
                return (INSUFFICIENT_RESOURCES, 0, 0, 0);
            }
            let retain = target != before && target.owner.is_some();
            if retain && !retain_target(target) {
                return (INVALID_HANDLE, 0, 0, 0);
            }
            let inflight = &mut record.inflight;
            match record.state.stack_attach(tid, target, |_| true, |_, to| {
                *inflight = Some(AttachIntent {
                    operation,
                    process: to.eprocess,
                    retained_process: retain.then_some(to.eprocess),
                });
                select(to)
            }) {
                Ok(token) => {
                    record.inflight = None;
                    saved_marker = if target == before { 1 } else if record.state.is_attached() && before != original { before.eprocess } else { 0 };
                    record.stack.push(StackSave {
                        address: saved_state_va,
                        token,
                        marker: saved_marker,
                        retained_process: retain.then_some(target.eprocess),
                    });
                    Ok(())
                }
                Err(error) => {
                    if record.inflight.is_none() && retain && !release_target(target.eprocess) {
                        return (INSUFFICIENT_RESOURCES, 0, 0, 0);
                    }
                    Err(error)
                }
            }
        }
        crate::win32k_subsystem::W32_ATTACH_UNSTACK if target_eprocess == 0 => {
            let Some(save) = record.stack.last() else { return (INVALID_PARAMETER, 0, 0, 0); };
            if save.address != saved_state_va || stack_address.is_none() {
                return (INVALID_PARAMETER, 0, 0, 0);
            }
            let marker = read_volatile((stack_address.unwrap() + 0x20) as *const u64);
            if marker != save.marker {
                return (INVALID_PARAMETER, 0, 0, 0);
            }
            let inflight = &mut record.inflight;
            let result = record.state.unstack_detach(tid, save.token, |_, to| {
                *inflight = Some(AttachIntent {
                    operation,
                    process: to.eprocess,
                    retained_process: None,
                });
                select(to)
            });
            if result.is_ok() {
                record.inflight = None;
                let save = record.stack.pop().unwrap();
                if let Some(reference) = save.retained_process {
                    if !release_target(reference) {
                        crate::provider_bugcheck::report(0xc4, [crate::win32k_subsystem::W32_PROCESS_ATTACH_LABEL, reference, 2, 0]);
                    }
                }
            }
            result
        }
        _ => return (INVALID_PARAMETER, 0, 0, 0),
    };
    if result.is_err() {
        return (INVALID_PARAMETER, 0, 0, 0);
    }
    // The mapped save is only a checked destination; the component writes the KAPC_STATE after
    // this acknowledged transition and validates it again before a matching detach.
    let _ = stack_address;
    (0, record.state.current().eprocess, saved_marker, u64::from(record.state.is_attached()))
}
