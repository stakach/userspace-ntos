//! Primary physical resource release after shared peer retirement, with no effect replay.

use super::*;

#[derive(Clone, Copy)]
enum Effect {
    ClearHeader(u64),
    MapBank(crate::spawn_hosts::ComponentMapCapBank),
    Unmap(u64),
    Delete(u64),
    Recycle(u64),
    Child { cnode: u64, slot: u64 },
}

struct Release {
    instance: usize,
    domain: HostedDomainIdentity,
    tcb: u64,
    pml4: u64,
    effects: Vec<Effect>,
    next: usize,
    entered: bool,
    shared_retired: bool,
    finished: bool,
}

static mut RELEASES: Vec<Release> = Vec::new();

unsafe fn row(index: usize) -> &'static mut Release {
    (&mut *core::ptr::addr_of_mut!(RELEASES))
        .get_mut(index)
        .expect("retained primary release")
}

fn delete(effects: &mut Vec<Effect>, cap: u64) {
    if cap != 0 {
        effects.push(Effect::Delete(cap));
        effects.push(Effect::Recycle(cap));
    }
}

unsafe fn prepare(
    instance_index: usize,
    inst: DriverInstance,
    domain: HostedDomainIdentity,
) -> Option<usize> {
    if let Some(index) = (&*core::ptr::addr_of!(RELEASES)).iter().position(|row| {
        row.instance == instance_index
            && row.domain == domain
            && row.tcb == inst.tcb
            && row.pml4 == inst.pml4
    }) {
        return Some(index);
    }
    let exec = (&*core::ptr::addr_of!(DRIVER_EXEC_MAPPED_CAPS))
        .as_ref()
        .and_then(|rows| rows.get(instance_index));
    let paging = (&*core::ptr::addr_of!(HOSTED_PAGING_MAPPINGS)).as_ref();
    let paging_count = paging.map_or(0, |rows| {
        rows.iter()
            .filter(|row| row.domain == domain && row.pml4 == inst.pml4)
            .count()
    });
    let runs = [
        (inst.stack_frame_base, inst.stack_frame_count),
        (inst.image_frame_base, inst.image_frames),
        (inst.pool_frame_base, FSD_POOL_FRAMES),
        (inst.data_frame_base, FSD_DATA_FRAMES),
        (inst.shared_frame_base, FSD_SHARED_FRAMES),
        (inst.arg_frame_base, FSD_ARG_FRAMES),
    ];
    let frame_count = runs
        .iter()
        .filter(|(base, _)| *base != 0)
        .try_fold(0usize, |total, (_, count)| {
            total.checked_add(usize::try_from(*count).ok()?)
        })?;
    let capacity = frame_count
        .checked_mul(2)?
        .checked_add(exec.map_or(0, Vec::len).checked_mul(3)?)?
        .checked_add(paging_count.checked_mul(2)?)?
        .checked_add(CT_IO_PORT_CAPACITY as usize + 32)?;
    let _durable = crate::allocator::enter_durable();
    let mut effects = Vec::new();
    effects.try_reserve_exact(capacity).ok()?;
    if inst.exec_shared_va != 0 {
        effects.push(Effect::ClearHeader(inst.exec_shared_va));
    }
    effects.push(Effect::MapBank(inst.map_cap_bank));
    if inst.kuser_map_cap != 0 {
        effects.push(Effect::Unmap(inst.kuser_map_cap));
        delete(&mut effects, inst.kuser_map_cap);
    }
    if let Some(caps) = exec {
        for &cap in caps {
            if cap != 0 {
                effects.push(Effect::Unmap(cap));
                delete(&mut effects, cap);
            }
        }
    }
    for (base, count) in runs {
        if base != 0 {
            for offset in (0..count).rev() {
                delete(&mut effects, base.checked_add(offset)?);
            }
        }
    }
    if let Some(mappings) = paging {
        for mapping in mappings
            .iter()
            .rev()
            .filter(|row| row.domain == domain && row.pml4 == inst.pml4)
        {
            delete(&mut effects, mapping.cap);
        }
    }
    if inst.cnode != 0 {
        effects.push(Effect::Child {
            cnode: inst.cnode,
            slot: CT_RESULT_NTFN,
        });
        for slot in 0..CT_IO_PORT_CAPACITY {
            effects.push(Effect::Child {
                cnode: inst.cnode,
                slot: CT_IO_PORT_BASE + slot,
            });
        }
        effects.push(Effect::Child {
            cnode: inst.cnode,
            slot: CT_PML4,
        });
    }
    for cap in [
        inst.sched_context,
        inst.tcb,
        inst.cnode,
        inst.raw_cnode,
        inst.pml4,
    ] {
        delete(&mut effects, cap);
    }
    // The shared owner alone retires CT_FAULT/root aliases and owns all canonical/spare Replies.
    // inst.fault_ep is the global shared endpoint, never a per-driver deletion obligation.
    let releases = &mut *core::ptr::addr_of_mut!(RELEASES);
    releases.try_reserve(1).ok()?;
    let index = releases.len();
    releases.push(Release {
        instance: instance_index,
        domain,
        tcb: inst.tcb,
        pml4: inst.pml4,
        effects,
        next: 0,
        entered: false,
        shared_retired: false,
        finished: false,
    });
    // Transfer these ownership receipts before any native effect. Failed release retains them here.
    if let Some(caps) = (&mut *core::ptr::addr_of_mut!(DRIVER_EXEC_MAPPED_CAPS))
        .as_mut()
        .and_then(|rows| rows.get_mut(instance_index))
    {
        caps.clear();
    }
    if let Some(mappings) = (&mut *core::ptr::addr_of_mut!(HOSTED_PAGING_MAPPINGS)).as_mut() {
        mappings.retain(|row| row.domain != domain || row.pml4 != inst.pml4);
    }
    Some(index)
}

pub(super) unsafe fn started(instance_index: usize, inst: DriverInstance) -> bool {
    instance_domain_identity(inst).is_some_and(|domain| {
        (&*core::ptr::addr_of!(RELEASES)).iter().any(|row| {
            row.instance == instance_index
                && row.domain == domain
                && row.tcb == inst.tcb
                && row.pml4 == inst.pml4
        })
    })
}

pub(super) unsafe fn release(instance_index: usize, inst: DriverInstance) -> bool {
    let Some(domain) = instance_domain_identity(inst) else {
        return false;
    };
    let Some(enrollment) = hosted_ingress_sources::primary_enrollment(instance_index) else {
        return false;
    };
    let Some(route) = enrollment.route else {
        return false;
    };
    // Do not transfer resource catalogs until all other semantic owners have retired. A journal
    // switches subsequent clear_instance attempts directly to physical cleanup.
    if !started(instance_index, inst)
        && (!hosted_thread_resources::quiescent(instance_index)
            || (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES))
                .as_ref()
                .is_some_and(|rows| rows.iter().any(|row| row.instance == instance_index))
            || (&*core::ptr::addr_of!(HOSTED_DRIVER_WAITERS))
                .as_ref()
                .is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row.instance == instance_index
                            && (row.thread_handle != inst.main_thread_id
                                || row.wake_status.is_none())
                    })
                }))
    {
        return false;
    }
    let Some(index) = prepare(instance_index, inst, domain) else {
        return false;
    };
    if row(index).finished {
        return true;
    }
    if row(index).entered {
        return false;
    }
    if !row(index).shared_retired {
        let _ = hosted_driver_thread_table_mut(instance_index).and_then(|table| {
            table
                .terminate(
                    inst.main_thread_id,
                    nt_status::NtStatus::CANCELLED.raw() as i32,
                )
                .ok()
        });
        if !hosted_driver_thread_table_mut(instance_index)
            .and_then(|table| table.get(inst.main_thread_id))
            .is_some_and(|thread| thread.exit_status.is_some())
        {
            return false;
        }
        let _ = crate::spawn_hosts::shared_ingress::owner::runtime::quarantine(route);
        if crate::spawn_hosts::shared_ingress::owner::runtime::cancel_parked_service(route).is_err()
            || crate::spawn_hosts::shared_ingress::owner::runtime::retire(route).is_err()
        {
            return false;
        }
        row(index).shared_retired = true;
        if let Some(waiters) = (&mut *core::ptr::addr_of_mut!(HOSTED_DRIVER_WAITERS)).as_mut() {
            waiters.retain(|waiter| {
                waiter.instance != instance_index
                    || waiter.thread_handle != inst.main_thread_id
                    || waiter.shared.route != route
            });
        }
    }
    // Exact primary stop/drain and worker retirement precede canonical Ps alias teardown.
    if driver_thread_projection::retire_stopped(route, inst).is_err() { return false; }
    if driver_ps_context::retire(inst).is_err() { return false; }
    while row(index).next < row(index).effects.len() {
        let effect = row(index).effects[row(index).next];
        row(index).entered = true;
        let status = match effect {
            Effect::ClearHeader(shared) => {
                clear_shared_registry_identity_at(shared);
                0
            }
            Effect::MapBank(bank) => {
                if crate::spawn_hosts::release_component_map_cap_bank(bank).failures == 0 {
                    0
                } else {
                    u64::MAX
                }
            }
            Effect::Unmap(cap) => page_unmap_r(cap),
            Effect::Delete(cap) => cnode_delete_r(cap),
            Effect::Recycle(cap) => {
                if crate::root_slot_recycle::publish_empty(cap).is_ok() {
                    0
                } else {
                    u64::MAX
                }
            }
            Effect::Child { cnode, slot } => cnode_delete_in_cnode_r(cnode, slot),
        };
        if status != 0 {
            return false;
        }
        row(index).next += 1;
        row(index).entered = false;
    }
    if !hosted_ingress_sources::finish_physical_retirement(enrollment.physical) {
        return false;
    }
    if let Some(table) = hosted_driver_thread_table_mut(instance_index) {
        let _ = table.remove(inst.main_thread_id);
    }
    row(index).finished = true;
    true
}
