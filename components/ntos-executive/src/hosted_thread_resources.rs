//! One-shot construction/retirement receipts for hosted arbitrary-entry thread resources.

use super::*;

#[derive(Clone, Copy)]
enum Resource {
    Root { cap: u64, mapped: bool },
    Child { cnode: u64, slot: u64 },
    TransferredReply(u64),
}

#[derive(Clone, Copy, PartialEq)]
enum Step {
    Unmap,
    Delete,
    Recycle,
}

struct Construction {
    instance: usize,
    handle: u64,
    domain: HostedDomainIdentity,
    pml4: u64,
    tcb: u64,
    resources: Vec<Resource>,
    ready: bool,
    shared_entered: bool,
    shared_retired: bool,
    stopped: bool,
    entered: bool,
    cursor: usize,
    step: Step,
    finished: bool,
    thread: Option<nt_process::ThreadLifetime>,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
    reference: Option<nt_process::native_handle::NativeThreadProcessReference>,
}

static mut OWNERS: Vec<Construction> = Vec::new();

unsafe fn owner(id: usize) -> &'static mut Construction {
    (&mut *core::ptr::addr_of_mut!(OWNERS))
        .get_mut(id)
        .expect("retained thread construction")
}

pub(super) unsafe fn begin(
    instance: usize,
    handle: u64,
    domain: HostedDomainIdentity,
    pml4: u64,
) -> Option<usize> {
    let _durable = crate::allocator::enter_durable();
    let mut resources = Vec::new();
    resources
        .try_reserve_exact(FSD_WORKER_STACK_FRAMES as usize * 2 + 16)
        .ok()?;
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    owners.try_reserve(1).ok()?;
    let id = owners.len();
    owners.push(Construction {
        instance,
        handle,
        domain,
        pml4,
        tcb: 0,
        resources,
        ready: false,
        shared_entered: false,
        shared_retired: false,
        stopped: false,
        entered: false,
        cursor: 0,
        step: Step::Unmap,
        finished: false,
        thread: None,
        caller: None,
        reference: None,
    });
    Some(id)
}

pub(super) unsafe fn initialize_actor(id: usize, entry: u64, argument: u64) -> Result<(), u32> {
    let lifetime = crate::service_sec_image::with_provider_process_manager(|pm| {
        let system = pm.initial_system_identity().ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let tid = pm.create_thread(system.process_id(), entry, argument, true)?;
        pm.thread_lifetime(tid).ok_or(nt_process::STATUS_INVALID_HANDLE)
    })?;
    // Construction retains the new identity before body allocation can enter native effects.
    owner(id).thread = Some(lifetime);
    crate::service_sec_image::with_provider_process_manager(|pm| {
        crate::ps_object_backing::prepare_thread(
            pm, lifetime, crate::ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed),
        )?;
        crate::ps_object_backing::publish_system_worker(pm, lifetime)?;
        let caller = pm.capture_native_handle_caller(lifetime, nt_types::AccessMode::KernelMode)?;
        let reference = pm.reference_native_requestor(caller)?;
        owner(id).caller = Some(caller);
        owner(id).reference = Some(reference);
        Ok(())
    })
}

pub(super) unsafe fn registry_caller(
    runtime: HostedDriverThreadRuntime,
) -> Result<nt_process::native_handle::NativeHandleCaller, u32> {
    if !matches(runtime.construction, runtime) || owner(runtime.construction).stopped {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    crate::service_sec_image::with_provider_process_manager(|pm| {
        let row = owner(runtime.construction);
        row.reference.as_ref().ok_or(nt_process::STATUS_INVALID_HANDLE)?.validate(pm)?;
        let caller = row.caller.ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        pm.validate_native_handle_caller(caller)?;
        Ok(caller)
    })
}

pub(super) unsafe fn initialize_kpcr(
    id: usize, inst: DriverInstance, component: u64, executive: u64,
) -> Result<(), u32> {
    let caller = owner(id).caller.ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let (_, _, _, thread, _) = driver_ps_context::project(inst, caller)?;
    core::ptr::write_bytes(executive as *mut u8, 0, 0x1000);
    write_volatile((executive + 0x18) as *mut u64, component);
    write_volatile((executive + 0x20) as *mut u64, component + 0x180);
    write_volatile((executive + 0x188) as *mut u64, thread);
    Ok(())
}

unsafe fn retire_actor(id: usize) -> Result<(), u32> {
    let exit_status = (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_TABLES)).as_ref()
        .and_then(|tables| tables.get(owner(id).instance))
        .and_then(|table| table.get(owner(id).handle))
        .and_then(|thread| thread.exit_status)
        .unwrap_or(STATUS_UNSUCCESSFUL) as u32;
    crate::service_sec_image::with_provider_process_manager(|pm| {
        let row = owner(id);
        if let Some(lifetime) = row.thread {
            if pm.thread_lifetime(lifetime.thread_id()) != Some(lifetime) {
                return Err(nt_process::STATUS_INVALID_HANDLE);
            }
            pm.terminate_thread(lifetime.thread_id(), exit_status)?;
            if let Some(reference) = row.reference.as_mut() { reference.release(pm)?; }
            row.reference = None;
            row.caller = None;
            row.thread = None;
        }
        Ok(())
    })
}

pub(super) unsafe fn root(id: usize, cap: u64) {
    let row = owner(id);
    assert!(!row.ready && cap != 0 && row.resources.len() < row.resources.capacity());
    row.resources.push(Resource::Root { cap, mapped: false });
}

/// Record a possible mapping before the syscall. Cleanup requires an acknowledged Unmap even
/// when construction failed before the map outcome could be established.
pub(super) unsafe fn mapping(id: usize, cap: u64) {
    let row = owner(id);
    let resource = row
        .resources
        .iter_mut()
        .find(
            |resource| matches!(resource, Resource::Root { cap: retained, .. } if *retained == cap),
        )
        .expect("mapping without retained cap");
    *resource = Resource::Root { cap, mapped: true };
}

pub(super) unsafe fn child(id: usize, cnode: u64, slot: u64) {
    let row = owner(id);
    assert!(!row.ready && row.resources.len() < row.resources.capacity());
    row.resources.push(Resource::Child { cnode, slot });
}

pub(super) unsafe fn tcb(id: usize, tcb: u64) {
    owner(id).tcb = tcb;
}

pub(super) unsafe fn ready(id: usize) {
    owner(id).ready = true;
}

pub(super) unsafe fn shared_reply(id: usize, reply: u64) {
    let row = owner(id);
    assert!(!row.ready && reply != 0 && row.resources.len() < row.resources.capacity());
    row.resources.push(Resource::TransferredReply(reply));
}

pub(super) unsafe fn enter_shared(id: usize, reply: u64) {
    let row = owner(id);
    assert!(row.ready && !row.shared_entered);
    let resource = row
        .resources
        .iter_mut()
        .find(|resource| matches!(resource, Resource::TransferredReply(cap) if *cap == reply))
        .expect("shared enrollment without retained empty Reply");
    let _ = resource;
    row.shared_entered = true;
}

pub(super) unsafe fn matches(id: usize, runtime: HostedDriverThreadRuntime) -> bool {
    let row = owner(id);
    row.instance == runtime.instance
        && row.handle == runtime.handle
        && row.domain == runtime.domain
        && row.pml4 == runtime.pml4
        && row.tcb == runtime.tcb
        && row.ready
        && row.shared_entered
}

/// No root/child alias may be released until transport retirement has acknowledged Stop and
/// drained the exact peer. Each entered cleanup effect is permanently fenced on failure.
pub(super) unsafe fn retire(id: usize, shared_retired: bool) -> bool {
    if owner(id).finished {
        return true;
    }
    if owner(id).entered || (owner(id).shared_entered && !shared_retired) {
        return false;
    }
    if !owner(id).stopped {
        if owner(id).shared_entered {
            owner(id).stopped = true;
        } else {
            let tcb = owner(id).tcb;
            if tcb != 0 {
                owner(id).entered = true;
                if tcb_suspend_r(tcb) != 0 {
                    return false;
                }
                owner(id).entered = false;
            }
            owner(id).stopped = true;
        }
        owner(id).cursor = owner(id).resources.len();
    }
    if retire_actor(id).is_err() { return false; }
    while owner(id).cursor != 0 {
        let index = owner(id).cursor - 1;
        let resource = owner(id).resources[index];
        if let Resource::TransferredReply(reply) = resource {
            if !owner(id).shared_entered
                && crate::spawn_hosts::shared_ingress::owner::runtime::return_initial_reply(
                    reply,
                    owner(id).tcb,
                )
                .is_err()
            {
                return false;
            }
            owner(id).cursor -= 1;
            owner(id).step = Step::Unmap;
            continue;
        }
        let step = owner(id).step;
        let status = match (resource, step) {
            (Resource::Root { cap, mapped: true }, Step::Unmap) => {
                owner(id).entered = true;
                page_unmap_r(cap)
            }
            (_, Step::Unmap) => 0,
            (Resource::Root { cap, .. }, Step::Delete) => {
                owner(id).entered = true;
                cnode_delete_r(cap)
            }
            (Resource::Child { cnode, slot }, Step::Delete) => {
                owner(id).entered = true;
                cnode_delete_in_cnode_r(cnode, slot)
            }
            (Resource::Root { cap, .. }, Step::Recycle) => {
                owner(id).entered = true;
                if crate::root_slot_recycle::publish_empty(cap).is_ok() {
                    0
                } else {
                    u64::MAX
                }
            }
            (_, Step::Recycle) => 0,
            (Resource::TransferredReply(_), _) => unreachable!(),
        };
        if status != 0 {
            return false;
        }
        owner(id).entered = false;
        owner(id).step = match step {
            Step::Unmap => Step::Delete,
            Step::Delete => Step::Recycle,
            Step::Recycle => {
                owner(id).cursor -= 1;
                Step::Unmap
            }
        };
    }
    owner(id).finished = true;
    true
}

/// Failed pre-enrollment builders have no shared executor authority; reclaim only their exact
/// retained construction, and keep uncertain effects visible to domain-quiescence checks.
pub(super) unsafe fn retire_unpublished(instance: usize) {
    let count = (&*core::ptr::addr_of!(OWNERS)).len();
    for id in 0..count {
        if owner(id).instance != instance || owner(id).shared_entered || owner(id).finished {
            continue;
        }
        if retire(id, false) {
            let handle = owner(id).handle;
            if let Some(table) = hosted_driver_thread_table_mut(instance) {
                let _ = table.remove(handle);
            }
        }
    }
}

pub(super) unsafe fn quiescent(instance: usize) -> bool {
    (&*core::ptr::addr_of!(OWNERS))
        .iter()
        .all(|row| row.instance != instance || row.finished)
}

pub(super) unsafe fn retained(instance: usize, handle: u64) -> bool {
    (&*core::ptr::addr_of!(OWNERS))
        .iter()
        .any(|row| row.instance == instance && row.handle == handle && !row.finished)
}

/// Semantic termination precedes transport cancellation; the physical source remains resolvable
/// until shared ingress has acknowledged stop, drained Calls and removed endpoint aliases.
pub(super) unsafe fn retire_thread(instance_index: usize, handle: u64) -> bool {
    let Some(runtime) = (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES))
        .as_ref()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.instance == instance_index && row.handle == handle)
        })
        .copied()
    else {
        return true;
    };
    if !matches(runtime.construction, runtime) {
        return false;
    }
    let Some(thread) = (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_TABLES))
        .as_ref()
        .and_then(|tables| tables.get(instance_index))
        .and_then(|table| table.get(handle))
    else {
        return false;
    };
    if thread.exit_status.is_none() {
        return false;
    }
    let Some(enrollment) = hosted_ingress_sources::thread_enrollment(instance_index, handle) else {
        return false;
    };
    let Some(route) = enrollment.route else {
        return false;
    };
    if !owner(runtime.construction).shared_retired {
        let _ = cancel_hosted_driver_waits_for_thread(instance_index, handle);
        let _ = crate::spawn_hosts::shared_ingress::owner::runtime::quarantine(route);
        if crate::spawn_hosts::shared_ingress::owner::runtime::cancel_parked_service(route).is_err()
            || crate::spawn_hosts::shared_ingress::owner::runtime::retire(route).is_err()
        {
            return false;
        }
        owner(runtime.construction).shared_retired = true;
    }
    if !retire(runtime.construction, true) {
        return false;
    }
    // These are memory-only removals after every native owner acknowledged retirement.
    if let Some(waiters) = (&mut *core::ptr::addr_of_mut!(HOSTED_DRIVER_WAITERS)).as_mut() {
        waiters.retain(|row| row.instance != instance_index || row.thread_handle != handle);
    }
    if !hosted_ingress_sources::finish_physical_retirement(enrollment.physical) {
        return false;
    }
    hosted_driver_thread_table_mut(instance_index)
        .expect("retiring thread table")
        .remove(handle)
        .expect("retiring thread receipt");
    let rows = hosted_driver_thread_runtimes_mut();
    let index = rows
        .iter()
        .position(|row| {
            row.instance == instance_index
                && row.handle == handle
                && row.domain == runtime.domain
                && row.tcb == runtime.tcb
        })
        .expect("retiring physical thread");
    rows.remove(index);
    true
}
