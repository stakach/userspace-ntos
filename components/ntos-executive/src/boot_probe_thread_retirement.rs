//! Retire one-shot boot proof executors after their observable result is owned by the executive.

use super::*;
use nt_user_host::one_shot_thread_retirement::OneShotThreadRetirement;

unsafe fn suspend_exact(owner: &mut OneShotThreadRetirement, tcb: u64) {
    let request = owner.suspension_request().expect("one-shot TCB suspend already entered");
    assert_eq!(request, tcb, "one-shot TCB identity changed");
    let status = tcb_suspend_r(request);
    assert!(owner.acknowledge_suspension(status == 0), "one-shot TCB suspend unacknowledged");
}

unsafe fn delete_exact_tcb(owner: &mut OneShotThreadRetirement, tcb: u64) {
    let request = owner.retirement_request().expect("one-shot TCB was not suspended");
    assert_eq!(request, tcb, "one-shot TCB identity changed");
    let status = cnode_delete_recycle_r(request);
    assert!(owner.acknowledge_retirement(status == 0), "one-shot TCB delete unacknowledged");
}

pub(crate) unsafe fn retire_synthetic_second(spawn: SyntheticSecondSpawn) {
    let tcb = spawn.tcb;
    let mut owner = OneShotThreadRetirement::new(tcb).expect("synthetic second TCB absent");
    suspend_exact(&mut owner, tcb);
    for frame in spawn.stack_frames.into_iter().rev() {
        assert_eq!(cnode_delete_recycle_r(frame), 0);
    }
    assert_eq!(cnode_delete_recycle_r(spawn.ipc_buffer), 0);
    for slot in [CT_FAULT, CT_PML4] {
        assert_eq!(cnode_delete_in_cnode_r(spawn.cnode, slot), 0);
    }
    assert_eq!(cnode_delete_recycle_r(spawn.sched_context), 0);
    delete_exact_tcb(&mut owner, tcb);
    for cap in [spawn.cnode, spawn.raw_cnode, spawn.fault_endpoint] {
        assert_eq!(cnode_delete_recycle_r(cap), 0);
    }
    assert!(owner.is_retired());
    print_str(b"[boot-probe-retire] synthetic second resources retired\n");
}

pub(crate) unsafe fn retire_storage_host(
    component: spawn_hosts::SpawnedComponent,
    result_badged: u64,
    result: u64,
    fault: u64,
) {
    let tcb = component.tcb;
    let mut owner = OneShotThreadRetirement::new(tcb).expect("storage host TCB absent");
    suspend_exact(&mut owner, tcb);

    // Only component-owned copies and private frames are released. The executive's original
    // AHCI and staging-buffer capabilities remain mapped for later boot consumers.
    assert_eq!(spawn_hosts::release_component_map_cap_bank(component.map_cap_bank).failures, 0);
    for offset in (0..component.stack_frame_count).rev() {
        assert_eq!(cnode_delete_recycle_r(component.stack_frame_base + offset), 0);
    }
    for slot in [CT_RESULT_NTFN, CT_FAULT, CT_PML4] {
        assert_eq!(cnode_delete_in_cnode_r(component.cnode, slot), 0);
    }
    assert_eq!(cnode_delete_recycle_r(component.sched_context), 0);
    delete_exact_tcb(&mut owner, tcb);
    for cap in [component.cnode, component.raw_cnode, component.pml4,
        result_badged, result, fault] {
        assert_eq!(cnode_delete_recycle_r(cap), 0);
    }
    assert!(owner.is_retired());
    print_str(b"[boot-probe-retire] storage host resources retired\n");
}
