use super::*;
use crate::native_handle::PsHandleType;
use crate::HandleObject;
use nt_types::AccessMode;

fn fixture() -> (ProcessManager, ProcessId, crate::ThreadId) {
    let mut pm = ProcessManager::new();
    let system_pid = pm.create_process("System", None, None);
    let system_tid = pm.create_thread(system_pid, 0, 0, true).unwrap();
    pm.designate_initial_system(system_pid, system_tid).unwrap();
    assert!(pm.publish_process_kernel_object(system_pid, 0x1000));
    assert!(pm.publish_thread_kernel_object(system_tid, 0x2000));
    let pid = pm.create_process("retiring", None, None);
    let tid = pm.create_thread(pid, 0x5000, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x3000));
    assert!(pm.publish_thread_kernel_object(tid, 0x4000));
    (pm, pid, tid)
}

fn terminate(pm: &mut ProcessManager, pid: ProcessId) {
    pm.terminate_process(pid, 0).unwrap();
    assert!(pm.process_object_delete_ready(pid));
}

#[test]
fn withdrawal_removes_all_public_identity_but_keeps_exact_metadata() {
    let (mut pm, pid, tid) = fixture();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    terminate(&mut pm, pid);
    let ticket = pm.withdraw_process_object_if_unreferenced(pid).unwrap();
    assert_eq!(ticket.pid(), pid);
    assert!(pm.process(pid).is_none());
    assert!(pm.thread(tid).is_none());
    assert!(pm.thread_lifetime(tid).is_none());
    assert!(pm.client_id(tid).is_none());
    assert!(pm.process_kernel_object(pid).is_none());
    assert!(pm.thread_kernel_object(tid).is_none());
    assert_eq!(
        pm.lookup_kernel_process_by_id(pid),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.lookup_kernel_thread_by_id(tid),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.retain_kernel_object_pointer(0x3000),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.retain_kernel_object_pointer(0x4000),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.process_object_retirement_snapshot(&ticket).unwrap(),
        ProcessObjectRetirementSnapshot {
            pid,
            process_body: Some(0x3000),
            thread_count: 1,
        }
    );
    assert_eq!(
        pm.process_object_retirement_thread(&ticket, 0).unwrap(),
        RetiredThreadObjectSnapshot {
            lifetime,
            body: Some(0x4000),
        }
    );
    assert_eq!(
        pm.process_object_retirement_thread(&ticket, 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(pm.abort_process_creation(pid).is_none());
    assert!(pm.delete_process_object_if_unreferenced(pid).is_none());
    assert_eq!(
        pm.withdraw_process_object_if_unreferenced(pid).unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    assert_eq!(
        pm.finish_process_object_retirement(ticket)
            .unwrap()
            .deleted_threads,
        1
    );
}

#[test]
fn all_process_and_thread_body_addresses_remain_reserved_until_finish() {
    let (mut pm, pid, tid) = fixture();
    let second_tid = pm.create_thread(pid, 0x6000, 0, false).unwrap();
    assert!(pm.publish_thread_kernel_object(second_tid, 0x5000));
    terminate(&mut pm, pid);
    let ticket = pm.withdraw_process_object_if_unreferenced(pid).unwrap();
    let replacement = pm.create_process("replacement", None, None);
    let replacement_tid = pm.create_thread(replacement, 0x7000, 0, false).unwrap();
    for body in [0x3000, 0x4000, 0x5000] {
        assert!(!pm.publish_process_kernel_object(replacement, body));
        assert!(!pm.publish_thread_kernel_object(replacement_tid, body));
    }
    assert_eq!(
        pm.process_object_retirement_snapshot(&ticket)
            .unwrap()
            .thread_count,
        2
    );
    assert_eq!(
        pm.process_object_retirement_thread(&ticket, 0)
            .unwrap()
            .lifetime
            .thread_id(),
        tid
    );
    assert_eq!(
        pm.process_object_retirement_thread(&ticket, 1)
            .unwrap()
            .lifetime
            .thread_id(),
        second_tid
    );
    assert_eq!(
        pm.finish_process_object_retirement(ticket)
            .unwrap()
            .deleted_threads,
        2
    );
    assert!(pm.publish_process_kernel_object(replacement, 0x4000));
    assert!(pm.publish_thread_kernel_object(replacement_tid, 0x3000));
}

#[test]
fn foreign_manager_rejects_ticket_without_consuming_either_hidden_row() {
    let (mut pm, pid, _) = fixture();
    let (mut foreign, same_pid, _) = fixture();
    assert_eq!(pid, same_pid);
    terminate(&mut pm, pid);
    terminate(&mut foreign, same_pid);
    let ticket = pm.withdraw_process_object_if_unreferenced(pid).unwrap();
    let foreign_ticket = foreign
        .withdraw_process_object_if_unreferenced(same_pid)
        .unwrap();
    assert_eq!(
        foreign.process_object_retirement_snapshot(&ticket),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        foreign.release_retired_process_job_memory(&ticket, 0),
        Err(STATUS_INVALID_HANDLE)
    );
    let (status, ticket) = foreign
        .finish_process_object_retirement(ticket)
        .unwrap_err();
    assert_eq!(status, STATUS_INVALID_HANDLE);
    assert!(pm.process_object_retirement_snapshot(&ticket).is_ok());
    assert!(foreign
        .process_object_retirement_snapshot(&foreign_ticket)
        .is_ok());
    pm.finish_process_object_retirement(ticket).unwrap();
    foreign
        .finish_process_object_retirement(foreign_ticket)
        .unwrap();
}

#[test]
fn missing_designation_and_running_process_fail_before_mutation() {
    let mut undesignated = ProcessManager::new();
    let pid = undesignated.create_process("no-root", None, None);
    undesignated.terminate_process(pid, 0).unwrap();
    assert_eq!(
        undesignated
            .withdraw_process_object_if_unreferenced(pid)
            .unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    assert!(undesignated.process(pid).is_some());
    let (mut pm, pid, tid) = fixture();
    let process_state = pm.process(pid).unwrap().state;
    let thread_state = pm.thread(tid).unwrap().state;
    assert_eq!(
        pm.withdraw_process_object_if_unreferenced(pid).unwrap_err(),
        STATUS_PENDING
    );
    assert_eq!(pm.process(pid).unwrap().state, process_state);
    assert_eq!(pm.thread(tid).unwrap().state, thread_state);
    assert!(pm.process_object_retirements.is_empty());
}

#[test]
fn pointer_and_wait_references_prevent_withdrawal_atomically() {
    for blocker in 0..4 {
        let (mut pm, pid, tid) = fixture();
        terminate(&mut pm, pid);
        match blocker {
            0 => {
                pm.processes
                    .get_mut(&pid)
                    .unwrap()
                    .kernel_pointer_references = 1
            }
            1 => pm.threads.get_mut(&tid).unwrap().kernel_pointer_references = 1,
            2 => pm.processes.get_mut(&pid).unwrap().wait_references = 1,
            _ => pm.threads.get_mut(&tid).unwrap().wait_references = 1,
        }
        assert_eq!(
            pm.withdraw_process_object_if_unreferenced(pid).unwrap_err(),
            STATUS_PENDING
        );
        assert_eq!(pm.process_kernel_object(pid), Some(0x3000));
        assert_eq!(pm.thread_kernel_object(tid), Some(0x4000));
        assert!(pm.process_object_retirements.is_empty());
    }
}

#[test]
fn process_and_thread_gui_state_must_be_detached_before_withdrawal() {
    for process_gui in [false, true] {
        let (mut pm, pid, tid) = fixture();
        terminate(&mut pm, pid);
        if process_gui {
            pm.set_process_win32(pid, 0x8000);
        } else {
            pm.set_thread_win32(tid, 0x9000);
        }
        assert_eq!(
            pm.withdraw_process_object_if_unreferenced(pid).unwrap_err(),
            STATUS_PENDING
        );
        assert!(pm.process(pid).is_some());
        assert!(pm.thread(tid).is_some());
    }
}

#[test]
fn handles_block_admission_then_cannot_be_reopened_after_withdrawal() {
    for thread_handle in [false, true] {
        let (mut pm, pid, tid) = fixture();
        let system = pm.initial_system_identity().unwrap();
        let object = if thread_handle {
            HandleObject::Thread(tid)
        } else {
            HandleObject::Process(pid)
        };
        let handle = pm
            .insert_handle(system.process_id(), object, u32::MAX)
            .unwrap();
        pm.terminate_process(pid, 0).unwrap();
        assert_eq!(
            pm.withdraw_process_object_if_unreferenced(pid).unwrap_err(),
            STATUS_PENDING
        );
        assert_eq!(pm.take_handle(system.process_id(), handle), Ok(object));
        let ticket = pm.withdraw_process_object_if_unreferenced(pid).unwrap();
        assert_eq!(
            pm.insert_handle(system.process_id(), object, u32::MAX),
            Err(STATUS_INVALID_HANDLE)
        );
        let caller = pm
            .capture_native_handle_caller(system.thread(), AccessMode::KernelMode)
            .unwrap();
        assert!(pm
            .reference_native_ps_handle(
                caller,
                u64::from(handle),
                Some(if thread_handle {
                    PsHandleType::Thread
                } else {
                    PsHandleType::Process
                }),
                0
            )
            .is_err());
        pm.finish_process_object_retirement(ticket).unwrap();
    }
}

#[test]
fn dropped_ticket_does_not_free_records_or_body_reservations() {
    let (mut pm, pid, _) = fixture();
    terminate(&mut pm, pid);
    let ticket = pm.withdraw_process_object_if_unreferenced(pid).unwrap();
    drop(ticket);
    let replacement = pm.create_process("replacement", None, None);
    assert!(!pm.publish_process_kernel_object(replacement, 0x3000));
    assert!(pm.process_object_is_withdrawn(pid));
    assert!(pm.abort_process_creation(pid).is_none());
}

#[test]
fn delayed_payload_and_job_accounting_remain_owned_until_explicit_finish() {
    let (mut pm, pid, _) = fixture();
    let token = nt_security::TokenId::from_raw(7).unwrap();
    let port = crate::ExceptionPortEndpoint::new(8).unwrap();
    pm.replace_process_primary_token(pid, Some(token)).unwrap();
    pm.processes.get_mut(&pid).unwrap().exception_port_endpoint = Some(port);
    let job = pm.create_job(0).unwrap();
    assert_eq!(
        pm.assign_process_to_job(job, pid),
        Ok(crate::STATUS_SUCCESS)
    );
    let charge = pm.prepare_job_memory_charge(pid, 0x3000).unwrap().unwrap();
    pm.commit_job_memory_charge(charge).unwrap();
    terminate(&mut pm, pid);
    let ticket = pm.withdraw_process_object_if_unreferenced(pid).unwrap();
    assert_eq!(pm.process_job(pid), Some(job));
    assert_eq!(pm.remove_process_job_reference(pid), None);
    assert_eq!(pm.process_job(pid), Some(job));
    assert_eq!(pm.job_memory_usage(pid), Ok((0x3000, 0x3000)));
    let (status, ticket) = pm.finish_process_object_retirement(ticket).unwrap_err();
    assert_eq!(status, STATUS_PENDING);
    assert!(pm.process_object_retirement_snapshot(&ticket).is_ok());
    assert_eq!(pm.process_job(pid), Some(job));
    assert_eq!(
        pm.release_job_memory(pid, 0x1000),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.release_retired_process_job_memory(&ticket, 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.release_retired_process_job_memory(&ticket, 0x4000),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(pm.job_memory_usage(pid), Ok((0x3000, 0x3000)));
    pm.release_retired_process_job_memory(&ticket, 0x3000)
        .unwrap();
    assert_eq!(pm.job_memory_usage(pid), Ok((0, 0)));
    let deletion = pm.finish_process_object_retirement(ticket).unwrap();
    assert_eq!(deletion.primary_token, Some(token));
    assert_eq!(deletion.exception_port, Some(port));
    assert_eq!(deletion.job, Some(job));
    assert_eq!(deletion.deleted_threads, 1);
    assert_eq!(pm.process_job(pid), None);
}

#[test]
fn hidden_slots_are_reused_without_reusing_canonical_identity() {
    let (mut pm, pid, _) = fixture();
    terminate(&mut pm, pid);
    let ticket = pm.withdraw_process_object_if_unreferenced(pid).unwrap();
    pm.finish_process_object_retirement(ticket).unwrap();
    assert_eq!(pm.process_object_retirements.len(), 1);
    let next = pm.create_process("next", None, None);
    let next_tid = pm.create_thread(next, 0x7000, 0, false).unwrap();
    assert_ne!(next, pid);
    assert!(pm.publish_process_kernel_object(next, 0x3000));
    assert!(pm.publish_thread_kernel_object(next_tid, 0x4000));
    terminate(&mut pm, next);
    let ticket = pm.withdraw_process_object_if_unreferenced(next).unwrap();
    assert_eq!(pm.process_object_retirements.len(), 1);
    assert_eq!(ticket.pid(), next);
    pm.finish_process_object_retirement(ticket).unwrap();
}

#[test]
fn inconsistent_thread_membership_is_rejected_without_partial_removal() {
    let (mut pm, pid, tid) = fixture();
    terminate(&mut pm, pid);
    pm.threads.get_mut(&tid).unwrap().process_id =
        pm.initial_system_identity().unwrap().process_id();
    assert_eq!(
        pm.withdraw_process_object_if_unreferenced(pid).unwrap_err(),
        STATUS_INVALID_PARAMETER
    );
    assert!(pm.process(pid).is_some());
    assert!(pm.thread(tid).is_some());
    assert!(pm.process_object_retirements.is_empty());
}

#[test]
fn duplicate_thread_list_entry_cannot_partially_withdraw_process() {
    let (mut pm, pid, first) = fixture();
    let second = pm.create_thread(pid, 0x6000, 0, false).unwrap();
    terminate(&mut pm, pid);
    let process = pm.processes.get_mut(&pid).unwrap();
    assert_eq!(process.threads.entries.len(), 2);
    process.threads.entries[1] = first;
    assert_eq!(
        pm.withdraw_process_object_if_unreferenced(pid).unwrap_err(),
        STATUS_INVALID_PARAMETER
    );
    assert!(pm.process(pid).is_some());
    assert!(pm.thread(first).is_some());
    assert!(pm.thread(second).is_some());
    assert!(pm.process_object_retirements.is_empty());
}
