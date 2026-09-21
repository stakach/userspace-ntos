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
    });
    Some(id)
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
