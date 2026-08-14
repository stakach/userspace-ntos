use super::*;
use nt_driver_test_fixtures::{minimal_pe, DEFAULT_IMAGE_BASE};

#[test]
fn client_ids_are_handle_shaped_and_globally_unique() {
    let mut pm = ProcessManager::new();
    let first_pid = pm.create_process("first.exe", None, None);
    let second_pid = pm.create_process("second.exe", Some(first_pid), None);
    let first_tid = pm.create_thread(first_pid, 0x1000, 0, false).unwrap();
    let second_tid = pm.create_thread(second_pid, 0x2000, 0, false).unwrap();
    let third_pid = pm.create_process("third.exe", Some(second_pid), None);
    let third_tid = pm.create_thread(third_pid, 0x3000, 0, false).unwrap();

    let ids = [
        first_pid, second_pid, first_tid, second_tid, third_pid, third_tid,
    ];
    assert_eq!(ids, [4, 8, 12, 16, 20, 24]);
    assert!(ids
        .iter()
        .all(|id| *id != 0 && *id % CLIENT_ID_GRANULARITY == 0));
    for (index, id) in ids.iter().enumerate() {
        assert!(!ids[index + 1..].contains(id));
    }
    assert_eq!(
        pm.client_id(second_tid),
        Some(ClientId {
            unique_process: second_pid,
            unique_thread: second_tid
        })
    );
}

#[test]
fn process_thread_lifecycle_and_signal() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("test.exe", None, None);
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Created);
    // First thread makes the process Running + becomes the main thread.
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Running);
    assert_eq!(pm.process(pid).unwrap().main_thread, Some(tid));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Ready);
    // Client ID.
    assert_eq!(
        pm.client_id(tid),
        Some(ClientId {
            unique_process: pid,
            unique_thread: tid
        })
    );
    // State transitions.
    pm.set_thread_state(tid, ThreadState::Running).unwrap();
    pm.set_thread_state(tid, ThreadState::Waiting).unwrap();
    // Terminating the last non-system thread terminates + signals the process.
    assert!(!pm.is_process_signaled(pid));
    pm.terminate_thread(tid, 0).unwrap();
    assert!(pm.is_thread_signaled(tid));
    assert!(pm.is_process_signaled(pid));
    assert_eq!(pm.wait_process(pid), Some(0));
    // No new threads in a terminating process.
    assert_eq!(
        pm.create_thread(pid, 0, 0, false),
        Err(STATUS_PROCESS_IS_TERMINATING)
    );
}

#[test]
fn yield_candidate_requires_runnable_peer_thread() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("yield.exe", None, None);
    let current = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    pm.set_thread_state(current, ThreadState::Running).unwrap();

    assert!(!pm.has_yield_candidate(current));

    let waiting = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    pm.set_thread_state(waiting, ThreadState::Waiting).unwrap();
    assert!(!pm.has_yield_candidate(current));

    let suspended = pm.create_thread(pid, 0x3000, 0, false).unwrap();
    pm.suspend_thread(suspended).unwrap();
    assert!(!pm.has_yield_candidate(current));

    let ready = pm.create_thread(pid, 0x4000, 0, false).unwrap();
    assert!(pm.has_yield_candidate(current));

    pm.set_thread_state(ready, ThreadState::Terminated).unwrap();
    assert!(!pm.has_yield_candidate(current));

    let other_pid = pm.create_process("other.exe", None, None);
    let running = pm.create_thread(other_pid, 0x5000, 0, false).unwrap();
    pm.set_thread_state(running, ThreadState::Running).unwrap();
    assert!(pm.has_yield_candidate(current));
}

#[test]
fn nested_thread_suspend_resume_tracks_previous_count() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("suspended.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();

    assert_eq!(pm.suspend_thread(tid), Ok(0));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Suspended);
    assert_eq!(pm.suspend_thread(tid), Ok(1));
    assert_eq!(pm.thread(tid).unwrap().suspend_count, 2);

    assert_eq!(pm.resume_thread(tid), Ok(2));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Suspended);
    assert_eq!(pm.resume_thread(tid), Ok(1));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Ready);
    assert_eq!(pm.resume_thread(tid), Ok(0));
}

#[test]
fn system_thread_does_not_exit_process() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("svc.exe", None, None);
    let sys = pm.create_thread(pid, 0x2000, 0, true).unwrap(); // system thread
    let usr = pm.create_thread(pid, 0x3000, 0, false).unwrap();
    pm.terminate_thread(usr, 7).unwrap(); // last *non-system* thread → process exits
    assert!(pm.is_process_signaled(pid));
    assert_eq!(pm.wait_process(pid), Some(7));
    // The system thread was terminated by the process exit.
    assert!(pm.is_thread_signaled(sys));
}

#[test]
fn dormant_pool_thread_does_not_keep_process_alive() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    let main = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let pool = pm.create_thread(pid, 0, 0, false).unwrap();
    pm.set_thread_state(pool, ThreadState::Initialized).unwrap();
    pm.terminate_thread(main, 7).unwrap();
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Terminated);
    assert_eq!(pm.thread(pool).unwrap().state, ThreadState::Terminated);
}

#[test]
fn exit_thread_marks_thread_without_terminating_process() {
    // The hosted csrss.exe case: its init thread exits via NtTerminateThread while CSRSRV's API
    // worker threads keep the process running. `exit_thread` must mark JUST that ETHREAD terminated
    // (signalled + exit status) and leave the EPROCESS Running — no last-thread cascade.
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("csrss.exe", None, None);
    let main = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Running);
    pm.exit_thread(main, 0x1234).unwrap();
    assert!(pm.is_thread_signaled(main));
    assert_eq!(pm.thread(main).unwrap().exit_status, Some(0x1234));
    // Process stays Running (unlike terminate_thread, which would cascade to process exit).
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Running);
    assert!(!pm.is_process_signaled(pid));
    // Unknown tid is rejected.
    assert_eq!(pm.exit_thread(0xDEAD, 0), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn handle_table_operations() {
    let mut pm = ProcessManager::new();
    let p1 = pm.create_process("a.exe", None, None);
    let p2 = pm.create_process("b.exe", None, None);
    let h = pm
        .insert_handle(p1, HandleObject::Process(p2), 0x1F_0000)
        .unwrap();
    assert_eq!(pm.lookup_handle(p1, h), Some(HandleObject::Process(p2)));
    assert_eq!(pm.handle_access(p1, h), Some(0x1F_0000));
    // Handles are process-local.
    assert_eq!(pm.lookup_handle(p2, h), None);
    // Duplicate into p2's table.
    let h2 = pm.duplicate_handle(p1, h, p2).unwrap();
    assert_eq!(pm.lookup_handle(p2, h2), Some(HandleObject::Process(p2)));
    assert_eq!(pm.handle_access(p2, h2), Some(0x1F_0000));
    let h3 = pm
        .duplicate_handle_with_access(p1, h, p2, Some(0x100000))
        .unwrap();
    assert_eq!(pm.lookup_handle(p2, h3), Some(HandleObject::Process(p2)));
    assert_eq!(pm.handle_access(p2, h3), Some(0x100000));
    // Close.
    pm.close_handle(p1, h).unwrap();
    assert_eq!(pm.lookup_handle(p1, h), None);
    assert_eq!(pm.close_handle(p1, h), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn typed_handles_must_reference_live_process_manager_objects() {
    let mut pm = ProcessManager::new();
    let owner = pm.create_process("owner.exe", None, None);

    assert_eq!(
        pm.insert_handle(owner, HandleObject::Process(0), PROCESS_ALL_ACCESS),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.insert_handle(owner, HandleObject::Process(0xdead), PROCESS_ALL_ACCESS),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.insert_handle(owner, HandleObject::Thread(0), THREAD_ALL_ACCESS),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.insert_handle(owner, HandleObject::Thread(0xbeef), THREAD_ALL_ACCESS),
        Err(STATUS_INVALID_HANDLE)
    );

    let target = pm.create_process("target.exe", None, None);
    let thread = pm.create_thread(target, 0x1000, 0, false).unwrap();
    assert!(pm
        .insert_handle(owner, HandleObject::Process(target), PROCESS_ALL_ACCESS)
        .is_ok());
    assert!(pm
        .insert_handle(owner, HandleObject::Thread(thread), THREAD_ALL_ACCESS)
        .is_ok());
    assert!(pm.insert_handle(owner, HandleObject::Opaque(0), 0).is_ok());
}

#[test]
fn process_security_descriptor_uses_process_handle_access() {
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;

    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let target = pm.create_process("target.exe", None, None);
    let read_only = pm
        .insert_handle(caller, HandleObject::Process(target), READ_CONTROL)
        .unwrap();

    assert_eq!(
        pm.process_security_descriptor(caller, u64::MAX, READ_CONTROL)
            .unwrap(),
        &nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR[..]
    );
    assert_eq!(
        pm.set_process_security_descriptor(caller, read_only as u64, WRITE_DAC, alloc::vec![]),
        Err(STATUS_ACCESS_DENIED)
    );

    let empty_dacl_sd = alloc::vec![
        1, 0, 0x04, 0x80, // revision, control: self-relative + DACL present
        0, 0, 0, 0, // owner
        0, 0, 0, 0, // group
        0, 0, 0, 0, // SACL
        20, 0, 0, 0, // DACL
        2, 0, 8, 0, // ACL revision + size
        0, 0, 0, 0, // ACE count + padding
    ];
    pm.set_process_security_descriptor(caller, u64::MAX, WRITE_DAC, empty_dacl_sd.clone())
        .unwrap();
    assert_eq!(
        pm.process_security_descriptor(caller, u64::MAX, READ_CONTROL)
            .unwrap(),
        empty_dacl_sd.as_slice()
    );
}

#[test]
fn thread_security_descriptor_uses_thread_handle_access() {
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;

    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let current = pm.create_thread(caller, 0x1000, 0, false).unwrap();
    let target = pm.create_thread(caller, 0x2000, 0, false).unwrap();
    let read_only = pm
        .insert_handle(caller, HandleObject::Thread(target), READ_CONTROL)
        .unwrap();

    assert_eq!(
        pm.thread_security_descriptor(caller, current, u64::MAX - 1, READ_CONTROL)
            .unwrap(),
        &nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR[..]
    );
    assert_eq!(
        pm.set_thread_security_descriptor(
            caller,
            current,
            read_only as u64,
            WRITE_DAC,
            alloc::vec![]
        ),
        Err(STATUS_ACCESS_DENIED)
    );

    let writable = pm
        .insert_handle(
            caller,
            HandleObject::Thread(target),
            READ_CONTROL | WRITE_DAC,
        )
        .unwrap();
    let empty_dacl_sd = alloc::vec![
        1, 0, 0x04, 0x80, // revision, control: self-relative + DACL present
        0, 0, 0, 0, // owner
        0, 0, 0, 0, // group
        0, 0, 0, 0, // SACL
        20, 0, 0, 0, // DACL
        2, 0, 8, 0, // ACL revision + size
        0, 0, 0, 0, // ACE count + padding
    ];
    pm.set_thread_security_descriptor(
        caller,
        current,
        writable as u64,
        WRITE_DAC,
        empty_dacl_sd.clone(),
    )
    .unwrap();
    assert_eq!(
        pm.thread_security_descriptor(caller, current, read_only as u64, READ_CONTROL)
            .unwrap(),
        empty_dacl_sd.as_slice()
    );
}

#[test]
fn queue_user_apc_requires_thread_set_context_access() {
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let current = pm.create_thread(caller, 0x1000, 0, false).unwrap();
    let target = pm.create_thread(caller, 0x2000, 0, false).unwrap();
    let read_only = pm
        .insert_handle(caller, HandleObject::Thread(target), THREAD_GENERIC_READ)
        .unwrap();
    let writable = pm
        .insert_handle(caller, HandleObject::Thread(target), THREAD_SET_CONTEXT)
        .unwrap();
    let apc = UserApc {
        routine: 0x1111,
        normal_context: 0x2222,
        system_argument1: 0x3333,
        system_argument2: 0x4444,
    };

    assert_eq!(
        pm.queue_user_apc(caller, current, read_only as u64, apc),
        Err(STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        pm.queue_user_apc(caller, current, writable as u64, apc),
        Ok(target)
    );
    assert!(pm.has_user_apc(target));
    assert_eq!(pm.peek_user_apc(target), Some(apc));
    assert_eq!(pm.take_user_apc(target), Some(apc));
    assert_eq!(pm.take_user_apc(target), None);
}

#[test]
fn queue_user_apc_supports_current_thread_pseudo_handle() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("self.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let apc = UserApc {
        routine: 0x10,
        normal_context: 0x20,
        system_argument1: 0x30,
        system_argument2: 0x40,
    };

    assert_eq!(pm.queue_user_apc(pid, tid, u64::MAX - 1, apc), Ok(tid));
    assert_eq!(pm.take_user_apc(tid), Some(apc));
}

#[test]
fn user_apc_queue_is_fifo_and_bounded() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("fifo.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    for index in 0..THREAD_USER_APC_QUEUE_CAP {
        assert_eq!(
            pm.queue_user_apc(
                pid,
                tid,
                u64::MAX - 1,
                UserApc {
                    routine: index as u64,
                    normal_context: index as u64 + 0x100,
                    system_argument1: index as u64 + 0x200,
                    system_argument2: index as u64 + 0x300,
                },
            ),
            Ok(tid)
        );
    }
    assert_eq!(
        pm.queue_user_apc(
            pid,
            tid,
            u64::MAX - 1,
            UserApc {
                routine: 0xffff,
                normal_context: 0,
                system_argument1: 0,
                system_argument2: 0,
            },
        ),
        Err(STATUS_NO_MEMORY)
    );
    for index in 0..THREAD_USER_APC_QUEUE_CAP {
        assert_eq!(
            pm.take_user_apc(tid),
            Some(UserApc {
                routine: index as u64,
                normal_context: index as u64 + 0x100,
                system_argument1: index as u64 + 0x200,
                system_argument2: index as u64 + 0x300,
            })
        );
    }
    assert_eq!(pm.take_user_apc(tid), None);
}

#[test]
fn user_apc_queue_rejects_system_and_terminated_threads() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("lifecycle.exe", None, None);
    let main = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let worker = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let system = pm.create_thread(pid, 0x3000, 0, true).unwrap();
    let worker_handle = pm
        .insert_handle(pid, HandleObject::Thread(worker), THREAD_SET_CONTEXT)
        .unwrap();
    let system_handle = pm
        .insert_handle(pid, HandleObject::Thread(system), THREAD_SET_CONTEXT)
        .unwrap();
    let apc = UserApc {
        routine: 1,
        normal_context: 2,
        system_argument1: 3,
        system_argument2: 4,
    };

    assert_eq!(
        pm.queue_user_apc(pid, main, system_handle as u64, apc),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.queue_user_apc(pid, main, worker_handle as u64, apc),
        Ok(worker)
    );
    assert!(pm.has_user_apc(worker));
    pm.terminate_thread(worker, 0).unwrap();
    assert!(!pm.has_user_apc(worker));
    assert_eq!(
        pm.queue_user_apc(pid, main, worker_handle as u64, apc),
        Err(STATUS_UNSUCCESSFUL)
    );
    pm.close_handle(pid, worker_handle).unwrap();
    assert_eq!(pm.queue_user_apc(pid, main, u64::MAX - 1, apc), Ok(main));
    pm.clear_user_apcs(main);
    assert_eq!(
        pm.queue_user_apc(pid, main, worker_handle as u64, apc),
        Err(STATUS_INVALID_HANDLE)
    );
    pm.reuse_reclaimed_thread(worker, 0x4000, false).unwrap();
    assert_eq!(pm.take_user_apc(worker), None);
}

#[test]
fn open_process_by_client_id_mints_local_access_checked_handles() {
    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let target = pm.create_process("target.exe", None, None);
    let target_tid = pm.create_thread(target, 0x1000, 0, false).unwrap();

    let pid_handle = pm
        .open_process_by_client_id(
            caller,
            ClientId {
                unique_process: target,
                unique_thread: 0,
            },
            PROCESS_QUERY_INFORMATION,
        )
        .unwrap();
    assert_eq!(
        pm.lookup_handle(caller, pid_handle),
        Some(HandleObject::Process(target))
    );
    assert_eq!(
        pm.handle_access(caller, pid_handle),
        Some(PROCESS_QUERY_INFORMATION)
    );
    assert_eq!(
        pm.resolve_process_handle(caller, pid_handle as u64, PROCESS_QUERY_INFORMATION),
        Ok(target)
    );
    assert_eq!(
        pm.resolve_process_handle(caller, pid_handle as u64, PROCESS_CREATE_THREAD),
        Err(STATUS_ACCESS_DENIED)
    );
    assert_eq!(pm.lookup_handle(target, pid_handle), None);

    let cid_handle = pm
        .open_process_by_client_id(
            caller,
            ClientId {
                unique_process: target,
                unique_thread: target_tid,
            },
            PROCESS_CREATE_THREAD,
        )
        .unwrap();
    assert_eq!(
        pm.handle_access(caller, cid_handle),
        Some(PROCESS_CREATE_THREAD)
    );
    assert_eq!(pm.handle_count(caller), 2);
}

#[test]
fn open_process_by_client_id_rejects_invalid_ids_without_minting() {
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let target = pm.create_process("target.exe", None, None);
    let other = pm.create_process("other.exe", None, None);
    let target_tid = pm.create_thread(target, 0x1000, 0, false).unwrap();

    for (client_id, status) in [
        (
            ClientId {
                unique_process: other,
                unique_thread: target_tid,
            },
            STATUS_INVALID_CID,
        ),
        (
            ClientId {
                unique_process: target,
                unique_thread: 0xDEAD,
            },
            STATUS_INVALID_CID,
        ),
        (
            ClientId {
                unique_process: 0xDEAD,
                unique_thread: 0,
            },
            STATUS_INVALID_PARAMETER,
        ),
    ] {
        assert_eq!(
            pm.open_process_by_client_id(caller, client_id, 0x1F_FFFF),
            Err(status)
        );
        assert_eq!(pm.handle_count(caller), 0);
    }
    assert_eq!(
        pm.open_process_by_client_id(
            0xDEAD,
            ClientId {
                unique_process: target,
                unique_thread: 0,
            },
            0x1F_FFFF,
        ),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(pm.handle_count(caller), 0);
}

#[test]
fn process_default_hard_error_mode_defaults_sets_and_inherits() {
    let mut pm = ProcessManager::new();
    let root = pm.create_process("smss.exe", None, None);

    assert_eq!(
        pm.process_default_hard_error_processing(root),
        Some(SEM_FAILCRITICALERRORS)
    );
    pm.set_process_default_hard_error_processing(root, 0x0003)
        .unwrap();
    assert_eq!(pm.process_default_hard_error_processing(root), Some(0x0003));

    let child = pm.create_process("csrss.exe", Some(root), None);
    assert_eq!(
        pm.process_default_hard_error_processing(child),
        Some(0x0003)
    );

    pm.set_process_default_hard_error_processing(child, 0)
        .unwrap();
    assert_eq!(pm.process_default_hard_error_processing(child), Some(0));
    assert_eq!(pm.process_default_hard_error_processing(root), Some(0x0003));
    assert_eq!(
        pm.set_process_default_hard_error_processing(0xDEAD, 0),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn process_generic_access_mapping_matches_nt_object_policy() {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const PROCESS_TERMINATE: u32 = 0x0000_0001;

    assert_eq!(map_process_access(PROCESS_TERMINATE), PROCESS_TERMINATE);
    assert_eq!(map_process_access(GENERIC_READ), PROCESS_GENERIC_READ);
    assert_eq!(map_process_access(GENERIC_WRITE), PROCESS_GENERIC_WRITE);
    assert_eq!(map_process_access(GENERIC_EXECUTE), PROCESS_GENERIC_EXECUTE);
    assert_eq!(map_process_access(GENERIC_ALL), PROCESS_ALL_ACCESS);
    assert_eq!(map_process_access(MAXIMUM_ALLOWED), PROCESS_ALL_ACCESS);
    assert_eq!(
        map_process_access(GENERIC_READ | GENERIC_WRITE | PROCESS_TERMINATE),
        PROCESS_GENERIC_READ | PROCESS_GENERIC_WRITE | PROCESS_TERMINATE
    );
}

#[test]
fn native_process_client_id_capture_never_truncates_handles() {
    assert_eq!(
        process_client_id_from_native(0x1234, 0x5678),
        Ok(ClientId {
            unique_process: 0x1234,
            unique_thread: 0x5678,
        })
    );
    assert_eq!(
        process_client_id_from_native(u32::MAX as u64 + 1, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        process_client_id_from_native(u32::MAX as u64 + 1, 1),
        Err(STATUS_INVALID_CID)
    );
    assert_eq!(
        process_client_id_from_native(1, u32::MAX as u64 + 1),
        Err(STATUS_INVALID_CID)
    );
}

#[test]
fn open_thread_by_client_id_mints_local_access_checked_handles() {
    const THREAD_QUERY_INFORMATION: u32 = 0x0040;
    const THREAD_SUSPEND_RESUME: u32 = 0x0002;

    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let target = pm.create_process("target.exe", None, None);
    let tid = pm.create_thread(target, 0x1000, 0, false).unwrap();

    let handle = pm
        .open_thread_by_client_id(
            caller,
            ClientId {
                unique_process: target,
                unique_thread: tid,
            },
            THREAD_QUERY_INFORMATION,
        )
        .unwrap();
    assert_eq!(
        pm.lookup_handle(caller, handle),
        Some(HandleObject::Thread(tid))
    );
    assert_eq!(pm.lookup_handle(target, handle), None);
    assert_eq!(
        pm.handle_access(caller, handle),
        Some(THREAD_QUERY_INFORMATION)
    );
    assert_eq!(
        pm.resolve_thread_handle(caller, 0, handle as u64, THREAD_QUERY_INFORMATION),
        Ok(tid)
    );
    assert_eq!(
        pm.resolve_thread_handle(caller, 0, handle as u64, THREAD_SUSPEND_RESUME),
        Err(STATUS_ACCESS_DENIED)
    );

    let process_agnostic = pm
        .open_thread_by_client_id(
            caller,
            ClientId {
                unique_process: 0,
                unique_thread: tid,
            },
            THREAD_SUSPEND_RESUME,
        )
        .unwrap();
    assert_eq!(pm.handle_count(caller), 2);
    assert_eq!(
        pm.handle_access(caller, process_agnostic),
        Some(THREAD_SUSPEND_RESUME)
    );
}

#[test]
fn open_thread_by_client_id_rejects_invalid_ids_without_minting() {
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let target = pm.create_process("target.exe", None, None);
    let other = pm.create_process("other.exe", None, None);
    let tid = pm.create_thread(target, 0x1000, 0, false).unwrap();

    for (client_id, status) in [
        (
            ClientId {
                unique_process: other,
                unique_thread: tid,
            },
            STATUS_INVALID_CID,
        ),
        (
            ClientId {
                unique_process: target,
                unique_thread: 0,
            },
            STATUS_INVALID_CID,
        ),
        (
            ClientId {
                unique_process: target,
                unique_thread: 0xDEAD,
            },
            STATUS_INVALID_CID,
        ),
        (
            ClientId {
                unique_process: 0,
                unique_thread: 0xDEAD,
            },
            STATUS_INVALID_PARAMETER,
        ),
    ] {
        assert_eq!(
            pm.open_thread_by_client_id(caller, client_id, THREAD_ALL_ACCESS),
            Err(status)
        );
        assert_eq!(pm.handle_count(caller), 0);
    }
    assert_eq!(
        pm.open_thread_by_client_id(
            0xDEAD,
            ClientId {
                unique_process: target,
                unique_thread: tid,
            },
            THREAD_ALL_ACCESS,
        ),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn thread_access_and_native_client_id_mapping_match_nt_policy() {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

    assert_eq!(map_thread_access(GENERIC_READ), THREAD_GENERIC_READ);
    assert_eq!(map_thread_access(GENERIC_WRITE), THREAD_GENERIC_WRITE);
    assert_eq!(map_thread_access(GENERIC_EXECUTE), THREAD_GENERIC_EXECUTE);
    assert_eq!(map_thread_access(GENERIC_ALL), THREAD_ALL_ACCESS);
    assert_eq!(map_thread_access(MAXIMUM_ALLOWED), THREAD_ALL_ACCESS);
    assert_eq!(
        thread_client_id_from_native(0, 0x1234),
        Ok(ClientId {
            unique_process: 0,
            unique_thread: 0x1234,
        })
    );
    assert_eq!(
        thread_client_id_from_native(0, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(thread_client_id_from_native(1, 0), Err(STATUS_INVALID_CID));
    assert_eq!(
        thread_client_id_from_native(u32::MAX as u64 + 1, 1),
        Err(STATUS_INVALID_CID)
    );
    assert_eq!(
        thread_client_id_from_native(0, u32::MAX as u64 + 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        thread_client_id_from_native(1, u32::MAX as u64 + 1),
        Err(STATUS_INVALID_CID)
    );
}

#[test]
fn token_handles_preserve_owner_and_access() {
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let owner = pm.create_process("owner.exe", None, None);
    let handle = pm
        .insert_handle(caller, HandleObject::Token(owner), 0x28)
        .unwrap();
    assert_eq!(
        pm.lookup_handle(caller, handle),
        Some(HandleObject::Token(owner))
    );
    assert_eq!(pm.handle_access(caller, handle), Some(0x28));
    assert_eq!(pm.lookup_handle(owner, handle), None);
    pm.close_handle(caller, handle).unwrap();
    assert_eq!(pm.lookup_handle(caller, handle), None);
}

#[test]
fn stable_token_handles_return_identity_on_close() {
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let token = nt_security::TokenId::from_raw(7).unwrap();
    let handle = pm
        .insert_handle(caller, HandleObject::TokenObject(token), 0x2c)
        .unwrap();

    assert_eq!(
        pm.take_handle(caller, handle),
        Ok(HandleObject::TokenObject(token))
    );
    assert_eq!(pm.lookup_handle(caller, handle), None);
    assert_eq!(pm.take_handle(caller, handle), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn thread_impersonation_replaces_reverts_and_falls_back_to_primary() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("security.exe", None, None);
    let first = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let second = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let primary = nt_security::TokenId::from_raw(1).unwrap();
    let impersonation = nt_security::TokenId::from_raw(2).unwrap();
    pm.replace_process_primary_token(pid, Some(primary))
        .unwrap();

    assert_eq!(pm.effective_token(first), Some(primary));
    assert_eq!(pm.effective_token(second), Some(primary));
    let context = ImpersonationContext {
        token: impersonation,
        copy_on_open: false,
        effective_only: false,
        level: nt_security::SecurityImpersonationLevel::Impersonation,
    };
    assert_eq!(
        pm.replace_thread_impersonation(first, Some(context)),
        Ok(None)
    );
    assert_eq!(pm.thread_impersonation(first), Some(context));
    assert_eq!(pm.effective_token(first), Some(impersonation));
    assert_eq!(pm.effective_token(second), Some(primary));

    assert_eq!(
        pm.replace_thread_impersonation(first, None),
        Ok(Some(context))
    );
    assert_eq!(pm.thread_impersonation(first), None);
    assert_eq!(pm.effective_token(first), Some(primary));
}

#[test]
fn break_on_termination_state_is_persistent_and_handle_checked() {
    const PROCESS_QUERY_INFORMATION: u32 = 0x400;
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let target = pm.create_process("target.exe", Some(caller), None);
    let thread = pm.create_thread(target, 0x1000, 0, false).unwrap();
    assert_eq!(pm.process_break_on_termination(target), Some(false));
    assert_eq!(pm.thread_break_on_termination(thread), Some(false));
    pm.set_process_break_on_termination(target, true).unwrap();
    pm.set_thread_break_on_termination(thread, true).unwrap();
    assert_eq!(pm.process_break_on_termination(target), Some(true));
    assert_eq!(pm.thread_break_on_termination(thread), Some(true));
    assert_eq!(pm.critical_process_termination_code(target), Some(0xF4));
    assert_eq!(pm.critical_thread_termination_code(thread), Some(0xF4));
    pm.set_thread_break_on_termination(thread, false).unwrap();
    assert_eq!(pm.critical_thread_termination_code(thread), Some(0xEF));

    let denied = pm
        .insert_handle(caller, HandleObject::Process(target), 0)
        .unwrap();
    assert_eq!(
        pm.resolve_process_handle(caller, denied as u64, PROCESS_QUERY_INFORMATION),
        Err(STATUS_ACCESS_DENIED)
    );
    let allowed = pm
        .insert_handle(
            caller,
            HandleObject::Process(target),
            PROCESS_QUERY_INFORMATION,
        )
        .unwrap();
    assert_eq!(
        pm.resolve_process_handle(caller, allowed as u64, PROCESS_QUERY_INFORMATION),
        Ok(target)
    );
    assert_eq!(
        pm.resolve_process_handle(caller, u64::MAX, PROCESS_QUERY_INFORMATION),
        Ok(caller)
    );
}

#[test]
fn reserved_handle_table_never_reallocates() {
    // The pre-reservable slot table (the executive's non-leaking heap-reset solution): reserve
    // capacity up front, then a burst of inserts writes into pre-allocated storage with NO
    // reallocation (capacity stays constant → the durable table never allocates during a call).
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    pm.reserve_handles(pid, 256);
    let cap0 = pm.handle_capacity(pid);
    assert!(cap0 >= 256);
    let mut handles = alloc::vec::Vec::new();
    for i in 0..200u64 {
        let h = pm
            .insert_handle(pid, HandleObject::Opaque(0x5A5A_0000 + i), 0)
            .unwrap();
        handles.push(h);
    }
    // No reallocation across the whole burst.
    assert_eq!(pm.handle_capacity(pid), cap0);
    assert_eq!(pm.handle_count(pid), 200);
    // Handles are the NT convention: non-zero multiples of 4, dense from 4.
    assert_eq!(handles[0], 4);
    assert_eq!(handles[1], 8);
    assert_eq!(
        pm.lookup_handle(pid, 4),
        Some(HandleObject::Opaque(0x5A5A_0000))
    );
    // Closing frees the slot; the next insert reuses it (still no realloc).
    pm.close_handle(pid, 4).unwrap();
    assert_eq!(pm.lookup_handle(pid, 4), None);
    let reused = pm
        .insert_handle(pid, HandleObject::Opaque(0xBEEF), 0)
        .unwrap();
    assert_eq!(reused, 4); // first free slot reused
    assert_eq!(pm.handle_capacity(pid), cap0);
    // Malformed handles are rejected, not panics.
    assert_eq!(pm.lookup_handle(pid, 0), None);
    assert_eq!(pm.lookup_handle(pid, 3), None); // not a multiple of 4
    assert_eq!(pm.close_handle(pid, 0), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn pre_created_main_thread_bound_at_spawn() {
    // The host pre-creates the main thread as an identity at boot (entry unknown), then binds the
    // real image entry at spawn (alloc-free), and terminates for the lifecycle teardown.
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap(); // entry unknown at boot
    assert_eq!(pm.main_thread(pid), Some(tid));
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Running);
    // Bind the entry at "spawn".
    assert!(pm.set_thread_start_address(tid, 0x1400_18e60));
    assert_eq!(pm.thread(tid).unwrap().start_address, 0x1400_18e60);
    assert!(!pm.set_thread_start_address(9999, 0)); // unknown tid rejected, not a panic
                                                    // Teardown: terminate the process → signalled, thread terminated, exit status readable.
    assert!(!pm.is_process_signaled(pid));
    pm.terminate_process(pid, 0x1234).unwrap();
    assert!(pm.is_process_signaled(pid));
    assert!(pm.is_thread_signaled(tid));
    assert_eq!(pm.wait_process(pid), Some(0x1234));
}

#[test]
fn null_terminate_process_leaves_current_thread_running() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("shutdown.exe", None, None);
    let current = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let worker = pm.create_thread(pid, 0x2000, 0, false).unwrap();

    pm.terminate_process_other_threads_at(pid, current, 0x55aa, 123)
        .unwrap();

    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Running);
    assert_ne!(pm.thread(current).unwrap().state, ThreadState::Terminated);
    assert_eq!(pm.thread(current).unwrap().exit_status, None);
    assert_eq!(pm.thread(worker).unwrap().state, ThreadState::Terminated);
    assert_eq!(pm.thread(worker).unwrap().exit_status, Some(0x55aa));
    assert!(!pm.is_process_signaled(pid));
    assert_eq!(pm.wait_process(pid), None);
}

#[test]
fn runtime_thread_create_with_teb_and_handle() {
    // The general NtCreateThread service: a host pre-creates a POOL of extra ETHREADs at boot (below
    // its reset mark), then at runtime NtCreateThread pops one, binds the caller-supplied start
    // routine + parameter (alloc-free), maps the thread's TEB and records its base, and mints a typed
    // Thread(tid) handle in the CALLER's handle table. NtQueryInformationThread then resolves that
    // handle back to the real TEB base + ClientId {pid, tid}.
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("winlogon.exe", None, None);
    pm.reserve_handles(pid, 16);
    let main = pm.create_thread(pid, 0, 0, false).unwrap(); // main (identity at boot)
                                                            // Pool: one extra ETHREAD pre-created at boot (entry/teb unknown yet).
    let listener = pm.create_thread(pid, 0, 0, false).unwrap();
    assert_ne!(listener, main);
    assert_eq!(pm.main_thread(pid), Some(main)); // the pool thread is NOT the main thread
                                                 // Runtime NtCreateThread: bind the RPC listener start routine + record its mapped TEB.
    assert!(pm.set_thread_start_address(listener, 0x7ff0_1234));
    assert!(pm.set_thread_teb(listener, 0x0000_0100_1049_0000));
    assert_eq!(pm.thread_teb(listener), Some(0x0000_0100_1049_0000));
    assert_eq!(pm.thread_teb(main), Some(0)); // TEB unbound until mapped
    assert!(!pm.set_thread_teb(9999, 0)); // unknown tid rejected, not a panic
                                          // Mint a typed Thread(tid) handle in the caller's table → resolvable for 162.
    let h = pm
        .insert_handle(pid, HandleObject::Thread(listener), 0)
        .unwrap();
    assert_eq!(
        pm.lookup_handle(pid, h),
        Some(HandleObject::Thread(listener))
    );
    // The ClientId a host writes to NtCreateThread's *ClientId out-param.
    assert_eq!(
        pm.client_id(listener),
        Some(ClientId {
            unique_process: pid,
            unique_thread: listener
        })
    );
}

#[test]
fn multiple_runtime_threads_have_distinct_handles_cids_and_tebs() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("winlogon.exe", None, None);
    pm.reserve_handles(pid, 16);
    let main = pm.create_thread(pid, 0, 0, false).unwrap();
    let mut seen = alloc::vec::Vec::new();

    for index in 0..3u64 {
        let tid = pm.create_thread(pid, 0, index, false).unwrap();
        let teb = 0x0000_0100_1049_0000 + index * 0x60000;
        assert!(pm.set_thread_start_address(tid, 0x7ff0_1000 + index * 0x100));
        assert!(pm.set_thread_teb(tid, teb));
        let handle = pm
            .insert_handle(pid, HandleObject::Thread(tid), 0x0040)
            .unwrap();
        let basic = pm.query_thread_basic(pid, main, handle as u64).unwrap();
        assert_eq!(basic.teb_base_address, teb);
        assert_eq!(
            basic.client_id,
            ClientId {
                unique_process: pid,
                unique_thread: tid
            }
        );
        seen.push((handle, tid, teb));
    }

    assert_ne!(seen[0].0, seen[1].0);
    assert_ne!(seen[1].0, seen[2].0);
    assert_ne!(seen[0].1, seen[2].1);
    assert_ne!(seen[0].2, seen[2].2);
    let worker = seen[1].1;
    let current = pm.query_thread_basic(pid, worker, u64::MAX - 1).unwrap();
    assert_eq!(current.client_id.unique_thread, worker);
    pm.terminate_thread(worker, 0x1234).unwrap();
    let terminated = pm.query_thread_basic(pid, main, seen[1].0 as u64).unwrap();
    assert_eq!(terminated.exit_status, 0x1234);
    assert_eq!(
        pm.query_thread_basic(pid, main, 0),
        Err(STATUS_INVALID_HANDLE)
    );

    let denied = pm
        .insert_handle(pid, HandleObject::Thread(worker), 0)
        .unwrap();
    assert_eq!(
        pm.query_thread_basic(pid, main, denied as u64),
        Err(STATUS_ACCESS_DENIED)
    );
}

#[test]
fn thread_query_classes_use_access_checked_state_and_real_times() {
    const THREAD_QUERY_INFORMATION: u32 = 0x0040;
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("query.exe", None, None);
    let current = pm.create_thread(pid, 0x1000, 0, true).unwrap();
    let target = pm.create_thread(pid, 0x2000, 0, true).unwrap();
    let unused_pool = pm.create_thread(pid, 0, 0, true).unwrap();
    pm.set_thread_state(unused_pool, ThreadState::Initialized)
        .unwrap();
    assert_eq!(pm.suspend_thread(target), Ok(0));
    assert!(pm.set_thread_times(target, 100, 900, 30, 40));
    pm.set_thread_disable_boost(target, true).unwrap();
    pm.set_thread_hide_from_debugger(target).unwrap();
    pm.set_thread_name(target, &[b'r' as u16, b'p' as u16, b'c' as u16])
        .unwrap();
    pm.set_thread_break_on_termination(target, true).unwrap();
    let handle = pm
        .insert_handle(pid, HandleObject::Thread(target), THREAD_QUERY_INFORMATION)
        .unwrap();

    assert_eq!(
        pm.query_thread_basic(pid, current, handle as u64)
            .unwrap()
            .exit_status,
        STATUS_PENDING
    );
    assert_eq!(
        pm.query_thread_basic(pid, current, handle as u64)
            .unwrap()
            .priority,
        DEFAULT_PROCESS_BASE_PRIORITY
    );
    pm.set_thread_priority(target, 10).unwrap();
    pm.set_thread_base_priority(target, 2).unwrap();
    pm.set_thread_affinity_mask(target, 1).unwrap();
    pm.set_thread_ideal_processor(target, 1).unwrap();
    let basic = pm.query_thread_basic(pid, current, handle as u64).unwrap();
    assert_eq!(basic.priority, 10);
    assert_eq!(basic.base_priority, 2);
    assert_eq!(basic.affinity_mask, 1);
    assert_eq!(pm.thread_ideal_processor(target), Some(1));
    assert_eq!(
        pm.set_thread_priority(target, HIGH_PRIORITY + 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.set_thread_base_priority(target, THREAD_BASE_PRIORITY_MAX + 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.set_thread_affinity_mask(target, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.set_thread_affinity_mask(target, 2),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.set_thread_ideal_processor(target, MAXIMUM_PROCESSORS + 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.query_thread_times(pid, current, handle as u64).unwrap(),
        ThreadTimes {
            create_time: 100,
            exit_time: 0,
            kernel_time: 30,
            user_time: 40,
        }
    );
    assert_eq!(
        pm.thread_start_address(pid, current, handle as u64),
        Ok(0x2000)
    );
    pm.set_thread_win32_start_address(target, 0x3000).unwrap();
    assert_eq!(pm.thread(target).unwrap().start_address, 0x2000);
    assert_eq!(
        pm.thread_start_address(pid, current, handle as u64),
        Ok(0x3000)
    );
    assert_eq!(pm.query_thread_u32(pid, current, handle as u64, 12), Ok(0));
    assert_eq!(pm.query_thread_u32(pid, current, handle as u64, 14), Ok(1));
    assert_eq!(pm.query_thread_u32(pid, current, handle as u64, 17), Ok(1));
    assert_eq!(pm.query_thread_u32(pid, current, handle as u64, 18), Ok(1));
    assert_eq!(pm.query_thread_u32(pid, current, handle as u64, 20), Ok(0));
    let mut name = [0u16; THREAD_NAME_MAX_UNITS];
    assert_eq!(
        pm.query_thread_name(pid, current, handle as u64, &mut name),
        Ok(3)
    );
    assert_eq!(&name[..3], &[b'r' as u16, b'p' as u16, b'c' as u16]);
    assert_eq!(
        pm.set_thread_name(target, &[0x41; THREAD_NAME_MAX_UNITS + 1]),
        Err(0xC000_009A)
    );
    pm.set_thread_name(target, &[]).unwrap();
    assert_eq!(
        pm.query_thread_name(pid, current, handle as u64, &mut name),
        Ok(0)
    );

    pm.terminate_thread(current, 0).unwrap();
    assert_eq!(pm.query_thread_u32(pid, target, handle as u64, 12), Ok(1));
    pm.terminate_thread(target, 0x1234).unwrap();
    assert_eq!(pm.query_thread_u32(pid, target, handle as u64, 20), Ok(1));
    assert_eq!(
        pm.query_thread_times(pid, target, handle as u64)
            .unwrap()
            .exit_time,
        900
    );
}

#[test]
fn process_query_classes_use_access_checked_state_and_real_times() {
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let caller_thread = pm.create_thread(caller, 0x1000, 0, false).unwrap();
    let target = pm.create_process("target.exe", Some(caller), None);
    assert!(pm.set_peb_base(target, 0x0000_0100_1602_0000));
    assert!(!pm.set_peb_base(0xffff_ffff, 0x1234));
    let target_main = pm.create_thread(target, 0x2000, 0, false).unwrap();
    let target_worker = pm.create_thread(target, 0x3000, 0, false).unwrap();
    assert!(pm.set_thread_times(target_main, 100, 0, 30, 40));
    assert!(pm.set_thread_times(target_worker, 120, 0, 3, 4));
    pm.insert_handle(target, HandleObject::Opaque(0xabc), 0)
        .unwrap();
    pm.insert_handle(target, HandleObject::Opaque(0xdef), 0)
        .unwrap();

    let handle = pm
        .insert_handle(
            caller,
            HandleObject::Process(target),
            PROCESS_QUERY_INFORMATION,
        )
        .unwrap();
    let denied = pm
        .insert_handle(caller, HandleObject::Process(target), 0)
        .unwrap();

    let basic = pm.query_process_basic(caller, handle as u64).unwrap();
    assert_eq!(basic.exit_status, STATUS_PENDING);
    assert_eq!(basic.peb_base_address, 0x0000_0100_1602_0000);
    assert_eq!(basic.affinity_mask, 1);
    assert_eq!(basic.base_priority, DEFAULT_PROCESS_BASE_PRIORITY);
    assert_eq!(basic.unique_process_id, target);
    assert_eq!(basic.inherited_from_unique_process_id, caller);
    assert_eq!(
        pm.query_process_basic(caller, denied as u64),
        Err(STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        pm.query_process_times(caller, handle as u64).unwrap(),
        ProcessTimes {
            create_time: 100,
            exit_time: 0,
            kernel_time: 33,
            user_time: 44,
        }
    );
    assert_eq!(pm.query_process_handle_count(caller, handle as u64), Ok(2));
    assert_eq!(pm.query_process_debug_port(caller, handle as u64), Ok(0));
    assert_eq!(pm.query_process_debug_flags(caller, handle as u64), Ok(1));
    assert_eq!(
        pm.query_process_priority_class(caller, handle as u64),
        Ok(PROCESS_PRIORITY_CLASS_NORMAL)
    );
    assert_eq!(pm.query_process_session_id(caller, handle as u64), Ok(0));
    let native_session_child = pm.create_process("native-session-child.exe", Some(target), None);
    let native_session_child_handle = pm
        .insert_handle(
            caller,
            HandleObject::Process(native_session_child),
            PROCESS_QUERY_INFORMATION,
        )
        .unwrap();
    assert_eq!(
        pm.query_process_session_id(caller, native_session_child_handle as u64),
        Ok(0)
    );
    assert_eq!(
        pm.query_process_session_id(caller, denied as u64),
        Err(STATUS_ACCESS_DENIED)
    );
    pm.set_process_session_id(target, 3).unwrap();
    assert_eq!(pm.query_process_session_id(caller, handle as u64), Ok(3));
    pm.set_process_base_priority(target, 11).unwrap();
    assert_eq!(
        pm.query_process_basic(caller, handle as u64)
            .unwrap()
            .base_priority,
        11
    );
    assert_eq!(
        pm.set_process_base_priority(target, HIGH_PRIORITY + 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    let session_child = pm.create_process("session-child.exe", Some(target), None);
    let session_child_handle = pm
        .insert_handle(
            caller,
            HandleObject::Process(session_child),
            PROCESS_QUERY_INFORMATION,
        )
        .unwrap();
    assert_eq!(
        pm.query_process_session_id(caller, session_child_handle as u64),
        Ok(3)
    );
    assert_eq!(
        pm.query_process_basic(caller, session_child_handle as u64)
            .unwrap()
            .base_priority,
        11
    );
    assert_eq!(
        pm.set_process_session_id(0xffff_ffff, 1),
        Err(STATUS_INVALID_HANDLE)
    );
    pm.set_process_priority_class(target, PROCESS_PRIORITY_CLASS_ABOVE_NORMAL)
        .unwrap();
    pm.set_process_foreground(target, true).unwrap();
    assert_eq!(
        pm.query_process_priority_class(caller, handle as u64),
        Ok(PROCESS_PRIORITY_CLASS_ABOVE_NORMAL)
    );
    assert_eq!(pm.query_process_foreground(caller, handle as u64), Ok(true));
    pm.set_process_priority_class(target, PROCESS_PRIORITY_CLASS_INVALID)
        .unwrap();
    pm.set_process_foreground(target, false).unwrap();
    assert_eq!(
        pm.query_process_priority_class(caller, handle as u64),
        Ok(PROCESS_PRIORITY_CLASS_INVALID)
    );
    assert_eq!(
        pm.query_process_foreground(caller, handle as u64),
        Ok(false)
    );
    assert_eq!(
        pm.set_process_priority_class(target, PROCESS_PRIORITY_CLASS_ABOVE_NORMAL + 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(pm.process_exception_port(target), None);
    pm.set_process_exception_port(target, 0xCAFE).unwrap();
    assert_eq!(pm.process_exception_port(target), Some(0xCAFE));
    assert_eq!(
        pm.set_process_exception_port(target, 0xBEEF),
        Err(STATUS_PORT_ALREADY_SET)
    );

    let debug = pm
        .create_debug_object(dbgk::DBGK_KILL_PROCESS_ON_EXIT)
        .unwrap();
    pm.debug_active_process(
        target,
        debug,
        ClientId {
            unique_process: caller,
            unique_thread: caller_thread,
        },
    )
    .unwrap();
    assert_eq!(
        pm.query_process_debug_port(caller, handle as u64),
        Ok(u64::MAX)
    );
    assert_eq!(pm.query_process_debug_flags(caller, handle as u64), Ok(0));

    pm.terminate_process_at(target, 0x55aa, 700).unwrap();
    assert_eq!(
        pm.query_process_basic(caller, handle as u64)
            .unwrap()
            .exit_status,
        0x55aa
    );
    assert_eq!(
        pm.query_process_times(caller, handle as u64)
            .unwrap()
            .exit_time,
        700
    );
    assert_eq!(pm.query_process_debug_flags(caller, handle as u64), Ok(0));
}

#[test]
fn debug_object_handles_report_last_reference() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("debugger.exe", None, None);
    let object = pm.create_debug_object(0).unwrap();
    assert_eq!(pm.debug_object(object).unwrap().handle_count(), 0);

    let first = pm
        .insert_handle(
            pid,
            HandleObject::DebugObject(object),
            dbgk::DEBUG_OBJECT_ALL_ACCESS,
        )
        .unwrap();
    let second = pm
        .insert_handle(
            pid,
            HandleObject::DebugObject(object),
            dbgk::DEBUG_OBJECT_ALL_ACCESS,
        )
        .unwrap();
    assert_eq!(pm.debug_object(object).unwrap().handle_count(), 2);

    assert_eq!(
        pm.take_handle_for_close(pid, first).unwrap(),
        HandleObject::DebugObject(object)
    );
    assert_eq!(pm.release_debug_object_handle(object), Some(false));
    assert!(pm.debug_object(object).is_some());
    assert_eq!(pm.debug_object(object).unwrap().handle_count(), 1);

    assert_eq!(
        pm.take_handle_for_close(pid, second).unwrap(),
        HandleObject::DebugObject(object)
    );
    assert_eq!(pm.release_debug_object_handle(object), Some(true));
    assert_eq!(pm.destroy_debug_object(object), 0);
    assert!(pm.debug_object(object).is_none());
}

#[test]
fn terminate_thread_handle_resolution_checks_identity_type_and_access() {
    const THREAD_TERMINATE: u32 = 0x0001;
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let other = pm.create_process("other.exe", None, None);
    let current = pm.create_thread(caller, 0x1000, 0, false).unwrap();
    let remote = pm.create_thread(other, 0x2000, 0, false).unwrap();

    assert_eq!(
        pm.resolve_thread_handle(caller, current, u64::MAX - 1, THREAD_TERMINATE),
        Ok(current)
    );
    assert_eq!(
        pm.resolve_terminate_thread_handle(caller, current, 0, THREAD_TERMINATE),
        Ok(current)
    );
    assert_eq!(
        pm.resolve_terminate_thread_handle(caller, current, u64::MAX - 1, THREAD_TERMINATE,),
        Ok(current)
    );
    let denied = pm
        .insert_handle(caller, HandleObject::Thread(remote), 0)
        .unwrap();
    assert_eq!(
        pm.resolve_thread_handle(caller, current, denied as u64, THREAD_TERMINATE),
        Err(STATUS_ACCESS_DENIED)
    );
    let allowed = pm
        .insert_handle(caller, HandleObject::Thread(remote), THREAD_TERMINATE)
        .unwrap();
    assert_eq!(
        pm.resolve_thread_handle(caller, current, allowed as u64, THREAD_TERMINATE),
        Ok(remote)
    );
    assert_eq!(
        pm.resolve_thread_handle(caller, current, 0, THREAD_TERMINATE),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.resolve_thread_handle(caller, current, u64::MAX, THREAD_TERMINATE),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn terminated_thread_is_reclaimable_only_after_handles_close() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    let main = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let worker = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let handle = pm
        .insert_handle(pid, HandleObject::Thread(worker), 0x1F_FFFF)
        .unwrap();
    pm.terminate_thread(worker, 0x1234).unwrap();
    assert_eq!(pm.thread(worker).unwrap().exit_status, Some(0x1234));
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Running);
    assert!(!pm.can_reclaim_thread(worker));
    pm.close_handle(pid, handle).unwrap();
    assert!(pm.can_reclaim_thread(worker));
    assert!(!pm.can_reclaim_thread(main));
    assert!(!pm.can_reclaim_thread(0xDEAD));
}

#[test]
fn reclaimed_runtime_thread_can_be_reused_only_after_handle_close() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    let _main = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let worker = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let handle = pm
        .insert_handle(pid, HandleObject::Thread(worker), 0x1f_ffff)
        .unwrap();

    pm.terminate_thread(worker, 0x1234).unwrap();
    assert_eq!(
        pm.reuse_reclaimed_thread(worker, 0x3000, true),
        Err(STATUS_INVALID_PARAMETER)
    );
    pm.close_handle(pid, handle).unwrap();
    pm.reuse_reclaimed_thread(worker, 0x3000, true).unwrap();

    let thread = pm.thread(worker).unwrap();
    assert_eq!(thread.start_address, 0x3000);
    assert_eq!(thread.state, ThreadState::Suspended);
    assert_eq!(thread.exit_status, None);
    assert_eq!(thread.suspend_count, 1);
    assert_eq!(thread.teb_base, 0);
    assert!(!pm.can_reclaim_thread(worker));
}

#[test]
fn termination_timestamps_are_one_shot_and_cover_process_cascades() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    let main = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let worker = pm.create_thread(pid, 0x2000, 0, false).unwrap();

    pm.terminate_thread_at(worker, 0x1234, 100).unwrap();
    pm.terminate_thread_at(worker, 0x5678, 200).unwrap();
    assert_eq!(pm.thread(worker).unwrap().exit_status, Some(0x1234));
    assert_eq!(pm.thread(worker).unwrap().exit_time_100ns, 100);

    pm.terminate_thread_at(main, 0x9ABC, 300).unwrap();
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Terminated);
    assert_eq!(pm.thread(main).unwrap().exit_time_100ns, 300);
    assert_eq!(pm.thread(worker).unwrap().exit_time_100ns, 100);
}

#[test]
fn hosted_process_and_thread_tables_can_be_reserved() {
    let mut pm = ProcessManager::new();
    pm.reserve_process_capacity(16);
    pm.reserve_thread_capacity(16 * 3);
    let process_cap = pm.process_capacity();
    let thread_cap = pm.thread_capacity();
    assert!(process_cap >= 16);
    assert!(thread_cap >= 48);

    for index in 0..16 {
        let pid = pm.create_process("hosted.exe", None, None);
        pm.reserve_process_threads(pid, 3);
        assert!(pm.process_thread_capacity(pid) >= 3);
        for slot in 0..3 {
            pm.create_thread(pid, 0x1000 + index * 0x100 + slot, 0, false)
                .unwrap();
        }
    }

    assert_eq!(pm.process_capacity(), process_cap);
    assert_eq!(pm.thread_capacity(), thread_cap);
}

#[test]
fn unnamed_threads_do_not_allocate_name_buffers() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    assert_eq!(pm.thread(tid).unwrap().thread_name.capacity(), 0);

    pm.set_thread_name(tid, &[b'r' as u16, b'p' as u16, b'c' as u16])
        .unwrap();
    assert!(pm.thread(tid).unwrap().thread_name.capacity() >= 3);
    let mut name = [0u16; THREAD_NAME_MAX_UNITS];
    assert_eq!(
        pm.query_thread_name(pid, tid, u64::MAX - 1, &mut name),
        Ok(3)
    );
    assert_eq!(&name[..3], &[b'r' as u16, b'p' as u16, b'c' as u16]);

    pm.set_thread_name(tid, &[]).unwrap();
    assert_eq!(
        pm.query_thread_name(pid, tid, u64::MAX - 1, &mut name),
        Ok(0)
    );
    assert_eq!(pm.thread(tid).unwrap().thread_name.len(), 0);
}

#[test]
fn close_by_object_tag() {
    // The convergence hybrid: a host tags each entry with its own handle VALUE (Opaque) and closes
    // by that tag on NtClose, without knowing this table's internal slot-handle.
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    pm.reserve_handles(pid, 16);
    pm.insert_handle(pid, HandleObject::Opaque(0x5A5A_0001), 0)
        .unwrap();
    pm.insert_handle(pid, HandleObject::Opaque(0x5A5A_0002), 0)
        .unwrap();
    assert_eq!(pm.handle_count(pid), 2);
    assert!(pm.close_handle_by_object(pid, HandleObject::Opaque(0x5A5A_0001)));
    assert_eq!(pm.handle_count(pid), 1);
    // Idempotent-safe: closing an absent tag reports false (the host still returns SUCCESS to match
    // the prior no-op NtClose behavior).
    assert!(!pm.close_handle_by_object(pid, HandleObject::Opaque(0x5A5A_0001)));
    assert!(!pm.close_handle_by_object(pid, HandleObject::Opaque(0xDEAD)));
    // Typed entries coexist and are matched by identity.
    let other = pm.create_process("b.exe", None, None);
    pm.insert_handle(pid, HandleObject::Process(other), 0)
        .unwrap();
    assert!(pm.close_handle_by_object(pid, HandleObject::Process(other)));
    assert_eq!(pm.handle_count(pid), 1); // the surviving Opaque(0x5A5A_0002)
}

#[test]
fn count_handle_object_references_across_processes() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    let object = HandleObject::Opaque(0x4f42_4a4e_0000_0042);
    let first_handle = pm.insert_handle(first, object, 0).unwrap();
    let second_handle = pm.insert_handle(second, object, 0).unwrap();
    let other_handle = pm
        .insert_handle(second, HandleObject::Opaque(0x4f42_4a4e_0000_0043), 0)
        .unwrap();

    assert_eq!(pm.handle_object_count(object), 2);
    pm.close_handle(first, first_handle).unwrap();
    assert_eq!(pm.handle_object_count(object), 1);
    pm.close_handle(second, other_handle).unwrap();
    assert_eq!(pm.handle_object_count(object), 1);
    pm.close_handle(second, second_handle).unwrap();
    assert_eq!(pm.handle_object_count(object), 0);
}

#[test]
fn image_section_load_and_run_entry() {
    // Stage 1 (spec §20): load a PE with no imports, get a valid entry point.
    let mut pm = ProcessManager::new();
    let pe = minimal_pe();
    let sid = pm
        .create_image_section("noimp.exe", &pe, DEFAULT_IMAGE_BASE)
        .unwrap();
    let sec = pm.image_section(sid).unwrap();
    assert!(sec.size_of_image() > 0);
    assert_eq!(sec.load_base(), DEFAULT_IMAGE_BASE);
    assert!(sec.entry_point() >= DEFAULT_IMAGE_BASE); // entry within the image
    assert!(sec.entry_point() < DEFAULT_IMAGE_BASE + sec.size_of_image() as u64);
    // Create a process from the image + a main thread starting at the entry point.
    let pid = pm.create_process("noimp.exe", None, Some(sid));
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Ready);
    let entry = pm.image_section(sid).unwrap().entry_point();
    let tid = pm.create_thread(pid, entry, 0, false).unwrap();
    assert_eq!(pm.thread(tid).unwrap().start_address, entry);
}

#[test]
fn image_section_shared_across_processes() {
    // Stage 4 (spec §20, §13.7): two processes from the same image share the read-only section.
    let mut pm = ProcessManager::new();
    let pe = minimal_pe();
    let s1 = pm
        .create_image_section("shared.exe", &pe, DEFAULT_IMAGE_BASE)
        .unwrap();
    let s2 = pm
        .create_image_section("shared.exe", &pe, DEFAULT_IMAGE_BASE)
        .unwrap();
    assert_eq!(s1, s2); // same image section reused
    assert_eq!(pm.image_section(s1).unwrap().map_refs(), 2);
    let bytes_ptr = pm.image_section(s1).unwrap().image_bytes().as_ptr();
    let p1 = pm.create_process("shared.exe", None, Some(s1));
    let p2 = pm.create_process("shared.exe", None, Some(s2));
    // Both processes reference the identical immutable image bytes.
    assert_eq!(
        pm.image_section(s1).unwrap().image_bytes().as_ptr(),
        bytes_ptr
    );
    // Terminating one process releases its map ref; the section survives for the other.
    pm.terminate_process(p1, 0).unwrap();
    assert_eq!(pm.image_section(s1).unwrap().map_refs(), 1);
    assert!(!pm.is_process_signaled(p2));
}

#[test]
fn invalid_image_rejected() {
    let mut pm = ProcessManager::new();
    assert_eq!(
        pm.create_image_section("bad.exe", b"not a PE image at all", 0x140000000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
}

#[test]
fn win32_process_thread_context_slots() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("winlogon.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();

    // Slots start empty — win32k has not attached yet.
    assert_eq!(pm.process_win32(pid), None);
    assert_eq!(pm.thread_win32(tid), None);
    assert_eq!(pm.process_kernel_object(pid), None);
    assert_eq!(pm.thread_kernel_object(tid), None);
    assert_eq!(pm.process_window_station(pid), None);

    // The executive owns EPROCESS / ETHREAD body addresses; win32k parks its
    // opaque W32PROCESS / W32THREAD pointers on those objects.
    assert!(pm.set_process_kernel_object(pid, 0xFFFF_8000_1000_0000));
    assert!(pm.set_thread_kernel_object(tid, 0xFFFF_8000_2000_0000));
    assert!(pm.set_process_win32(pid, 0xFFFF_9E00_1234_0000));
    assert!(pm.set_thread_win32(tid, 0xFFFF_9E00_5678_0000));
    assert!(pm.set_process_window_station(pid, 0xFFFF_9E00_9ABC_0000));
    assert_eq!(pm.process_kernel_object(pid), Some(0xFFFF_8000_1000_0000));
    assert_eq!(pm.thread_kernel_object(tid), Some(0xFFFF_8000_2000_0000));
    assert_eq!(
        pm.pid_for_kernel_process_object(0xFFFF_8000_1000_0000),
        Some(pid)
    );
    assert_eq!(
        pm.tid_for_kernel_thread_object(0xFFFF_8000_2000_0000),
        Some(tid)
    );
    assert_eq!(pm.process_win32(pid), Some(0xFFFF_9E00_1234_0000));
    assert_eq!(pm.thread_win32(tid), Some(0xFFFF_9E00_5678_0000));
    assert_eq!(pm.process_window_station(pid), Some(0xFFFF_9E00_9ABC_0000));

    // Setting NULL clears the slot (win32k detaches on process/thread teardown).
    assert!(pm.set_process_kernel_object(pid, 0));
    assert!(pm.set_thread_kernel_object(tid, 0));
    assert!(pm.set_process_win32(pid, 0));
    assert_eq!(pm.process_kernel_object(pid), None);
    assert_eq!(pm.thread_kernel_object(tid), None);
    assert_eq!(
        pm.pid_for_kernel_process_object(0xFFFF_8000_1000_0000),
        None
    );
    assert_eq!(pm.tid_for_kernel_thread_object(0xFFFF_8000_2000_0000), None);
    assert_eq!(pm.process_win32(pid), None);

    // Unknown pid/tid is rejected, not a panic.
    assert!(!pm.set_process_kernel_object(9999, 1));
    assert!(!pm.set_thread_kernel_object(9999, 1));
    assert!(!pm.set_process_win32(9999, 1));
    assert!(!pm.set_thread_win32(9999, 1));
    assert_eq!(pm.process_kernel_object(9999), None);
    assert_eq!(pm.thread_kernel_object(9999), None);
    assert_eq!(pm.process_win32(9999), None);
    assert_eq!(pm.thread_win32(9999), None);
}

#[test]
fn win32_callouts_established_once() {
    let mut pm = ProcessManager::new();
    assert_eq!(pm.win32_callouts(), None);
    let c = Win32Callouts {
        table: 0xFFFF_F800_0020_0000,
        process_callout: 0xFFFF_F800_0020_1000,
        thread_callout: 0xFFFF_F800_0020_2000,
        global_atom_callout: 0xFFFF_F800_0020_3000,
    };
    // First establish returns no prior registration.
    assert_eq!(pm.establish_win32_callouts(c), None);
    assert_eq!(pm.win32_callouts(), Some(c));
    // A re-establish returns the prior table (win32k only calls once).
    let c2 = Win32Callouts {
        table: 0xDEAD,
        ..Default::default()
    };
    assert_eq!(pm.establish_win32_callouts(c2), Some(c));
    assert_eq!(pm.win32_callouts(), Some(c2));
}

#[test]
fn handle_values_are_process_local() {
    // Path 1b — process-local dense handle VALUES: two DISTINCT processes each allocate their
    // first handle and BOTH get the same dense value (4), yet it refers to a DIFFERENT object in
    // each. Real NT handle namespaces are per-process; a global value scheme could not do this.
    let mut pm = ProcessManager::new();
    let a = pm.create_process("proc_a.exe", None, None);
    let b = pm.create_process("proc_b.exe", None, None);
    let ha = pm
        .insert_handle(a, HandleObject::Opaque(0xA11CE), 0)
        .unwrap();
    let hb = pm.insert_handle(b, HandleObject::Opaque(0xB0B), 0).unwrap();
    assert_eq!(ha, 4);
    assert_eq!(hb, 4); // COLLIDES with a's value — legal, they're in different namespaces
    assert_eq!(pm.lookup_handle(a, 4), Some(HandleObject::Opaque(0xA11CE)));
    assert_eq!(pm.lookup_handle(b, 4), Some(HandleObject::Opaque(0xB0B)));
    // b's value 4 is invisible in a and vice-versa (no cross-process aliasing).
    assert_ne!(pm.lookup_handle(a, 4), pm.lookup_handle(b, 4));
}

#[test]
fn file_objects_are_typed_and_process_local() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    let first_handle = pm.insert_handle(first, HandleObject::File(41), 1).unwrap();
    let second_handle = pm.insert_handle(second, HandleObject::File(99), 2).unwrap();
    assert_eq!(first_handle, second_handle);
    assert_eq!(
        pm.lookup_handle(first, first_handle),
        Some(HandleObject::File(41))
    );
    assert_eq!(
        pm.lookup_handle(second, second_handle),
        Some(HandleObject::File(99))
    );
}

#[test]
fn disk_file_handles_preserve_backing_extent() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("reader.exe", None, None);
    let object = HandleObject::DiskFile {
        first_cluster: 0x1234,
        size: 0x5678,
    };
    let handle = pm.insert_handle(pid, object, 0x0012_0089).unwrap();
    assert_eq!(pm.lookup_handle(pid, handle), Some(object));
    assert_eq!(pm.handle_access(pid, handle), Some(0x0012_0089));
}

#[test]
fn directory_handles_preserve_backing_identity_and_access() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("walker.exe", None, None);
    let object = HandleObject::Directory {
        first_cluster: 0x2345,
        object_id: 7,
    };
    let handle = pm.insert_handle(pid, object, 0x0010_0020).unwrap();
    assert_eq!(pm.lookup_handle(pid, handle), Some(object));
    assert_eq!(pm.handle_access(pid, handle), Some(0x0010_0020));
    assert_eq!(pm.close_handle(pid, handle), Ok(()));
    assert_eq!(pm.lookup_handle(pid, handle), None);
}

#[test]
fn process_teardown_can_drain_typed_handles() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("owner.exe", None, None);
    let file = HandleObject::File(41);
    let directory = HandleObject::Directory {
        first_cluster: 0x2345,
        object_id: 7,
    };
    pm.insert_handle(pid, file, 1).unwrap();
    pm.insert_handle(pid, directory, 1).unwrap();
    assert_eq!(pm.take_any_handle(pid), Some(file));
    assert_eq!(pm.take_any_handle(pid), Some(directory));
    assert_eq!(pm.take_any_handle(pid), None);
    assert_eq!(pm.handle_count(pid), 0);
}

#[test]
fn boot_status_file_handle_is_typed_and_process_local() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    let first_handle = pm
        .insert_handle(first, HandleObject::BootStatusFile, 0x3)
        .unwrap();
    let second_handle = pm
        .insert_handle(second, HandleObject::BootStatusFile, 0x1)
        .unwrap();
    assert_eq!(first_handle, second_handle);
    assert_eq!(
        pm.lookup_handle(first, first_handle),
        Some(HandleObject::BootStatusFile)
    );
    assert_eq!(
        pm.lookup_handle(second, second_handle),
        Some(HandleObject::BootStatusFile)
    );
    assert_eq!(pm.handle_access(first, first_handle), Some(0x3));
}

#[test]
fn io_completion_objects_are_typed_and_process_local() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    let first_handle = pm
        .insert_handle(first, HandleObject::IoCompletion(3), 0x3)
        .unwrap();
    let second_handle = pm
        .insert_handle(second, HandleObject::IoCompletion(7), 0x1)
        .unwrap();
    assert_eq!(first_handle, second_handle);
    assert_eq!(
        pm.lookup_handle(first, first_handle),
        Some(HandleObject::IoCompletion(3))
    );
    assert_eq!(
        pm.lookup_handle(second, second_handle),
        Some(HandleObject::IoCompletion(7))
    );
    assert_eq!(pm.handle_access(first, first_handle), Some(0x3));
}

#[test]
fn registry_key_handles_have_independent_process_local_lifetimes() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    let target = HandleObject::RegistryKey(0x1234);

    let first_a = pm.insert_handle(first, target, 0x3).unwrap();
    let first_b = pm.insert_handle(first, target, 0x1).unwrap();
    let second_a = pm.insert_handle(second, target, 0x2).unwrap();

    assert_eq!(pm.lookup_handle(first, first_a), Some(target));
    assert_eq!(pm.lookup_handle(first, first_b), Some(target));
    assert_eq!(pm.lookup_handle(second, second_a), Some(target));
    assert_eq!(pm.handle_access(first, first_a), Some(0x3));
    assert_eq!(pm.handle_access(first, first_b), Some(0x1));

    pm.close_handle(first, first_a).unwrap();
    assert_eq!(pm.lookup_handle(first, first_a), None);
    assert_eq!(pm.lookup_handle(first, first_b), Some(target));
    assert_eq!(pm.lookup_handle(second, second_a), Some(target));
}

#[test]
fn handle_flags_are_process_local_and_duplicated() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    let target = HandleObject::Opaque(0x44);

    let first_handle = pm.insert_handle(first, target, 0x3).unwrap();
    let second_handle = pm.insert_handle(second, target, 0x3).unwrap();
    assert_eq!(first_handle, second_handle);
    assert_eq!(
        pm.handle_flags(first, first_handle),
        Some(HandleFlags::default())
    );

    let flags = HandleFlags {
        inherit: true,
        protect_from_close: true,
    };
    pm.set_handle_flags(first, first_handle, flags).unwrap();
    assert_eq!(pm.handle_flags(first, first_handle), Some(flags));
    assert_eq!(
        pm.handle_flags(second, second_handle),
        Some(HandleFlags::default())
    );

    let duplicate = pm.duplicate_handle(first, first_handle, second).unwrap();
    assert_eq!(pm.lookup_handle(second, duplicate), Some(target));
    assert_eq!(pm.handle_flags(second, duplicate), Some(flags));
}

#[test]
fn protected_handle_close_fails_without_releasing_slot() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    let object = HandleObject::Opaque(0x5150);
    let handle = pm.insert_handle(pid, object, 0).unwrap();

    pm.set_handle_flags(
        pid,
        handle,
        HandleFlags {
            inherit: false,
            protect_from_close: true,
        },
    )
    .unwrap();
    assert_eq!(
        pm.close_handle(pid, handle),
        Err(STATUS_HANDLE_NOT_CLOSABLE)
    );
    assert_eq!(pm.lookup_handle(pid, handle), Some(object));

    assert_eq!(pm.take_handle(pid, handle), Ok(object));
    assert_eq!(pm.lookup_handle(pid, handle), None);
}

#[test]
fn process_cookie_is_nonzero_process_local_and_first_writer_wins() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);

    assert_eq!(pm.process_cookie(first), Some(0));
    assert_eq!(pm.get_or_initialize_process_cookie(first, 0), None);
    assert_eq!(
        pm.get_or_initialize_process_cookie(first, 0x1122_3344),
        Some(0x1122_3344)
    );
    assert_eq!(
        pm.get_or_initialize_process_cookie(first, 0xaabb_ccdd),
        Some(0x1122_3344)
    );
    assert_eq!(
        pm.get_or_initialize_process_cookie(second, 0x5566_7788),
        Some(0x5566_7788)
    );
    assert_eq!(pm.process_cookie(0xffff_fffe), None);
}

// --- Dbgk: the user-mode debugging plane, driven through the ProcessManager -------------------

fn attach_debugger(pm: &mut ProcessManager) -> (ProcessId, ThreadId, ProcessId, DebugObjectId) {
    let debugger = pm.create_process("dbg.exe", None, None);
    let dbg_thread = pm.create_thread(debugger, 0x100, 0, false).unwrap();
    let target = pm.create_process("target.exe", None, None);
    if let Some(p) = pm.processes.get_mut(&target) {
        p.image_base = 0x0000_0001_4000_0000;
    }
    let main = pm.create_thread(target, 0x2000, 0, false).unwrap();
    let object = pm
        .create_debug_object(dbgk::DBGK_KILL_PROCESS_ON_EXIT)
        .unwrap();
    let posted = pm
        .debug_active_process(
            target,
            object,
            ClientId {
                unique_process: debugger,
                unique_thread: dbg_thread,
            },
        )
        .unwrap();
    assert_eq!(
        posted, 1,
        "one live thread → one fake create-process message"
    );
    (target, main, debugger, object)
}

#[test]
fn dbgk_attach_installs_the_debug_port_and_posts_fake_create_messages() {
    let mut pm = ProcessManager::new();
    let (target, main, _debugger, object) = attach_debugger(&mut pm);
    assert_eq!(pm.process_debug_port(target), Some(object));
    assert!(pm.is_process_being_debugged(target));
    assert!(pm.process(target).unwrap().create_reported());
    let debug_object = pm.debug_object(object).unwrap();
    assert_eq!(debug_object.len(), 1);
    assert!(debug_object.kill_process_on_exit());
    // The fake message was activated by DbgkpSetProcessDebugObject → the debugger is signalled.
    assert!(debug_object.events_present());
    assert!(!debug_object.events()[0].is_inactive());
    assert_eq!(debug_object.events()[0].client_id.unique_thread, main);
    assert_eq!(
        debug_object.events()[0].message.state(),
        dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
    );
}

#[test]
fn dbgk_attach_rejects_self_double_attach_and_dead_targets() {
    let mut pm = ProcessManager::new();
    let (target, _main, debugger, _object) = attach_debugger(&mut pm);
    // Already attached.
    let second = pm.create_debug_object(0).unwrap();
    assert_eq!(
        pm.debug_active_process(
            target,
            second,
            ClientId {
                unique_process: debugger,
                unique_thread: 0
            }
        ),
        Err(dbgk::STATUS_PORT_ALREADY_SET)
    );
    // Self-attach.
    assert_eq!(
        pm.debug_active_process(
            debugger,
            second,
            ClientId {
                unique_process: debugger,
                unique_thread: 0
            }
        ),
        Err(STATUS_ACCESS_DENIED)
    );
    // A process with no live thread cannot be attached.
    let empty = pm.create_process("empty.exe", None, None);
    assert_eq!(
        pm.debug_active_process(
            empty,
            second,
            ClientId {
                unique_process: debugger,
                unique_thread: 0
            }
        ),
        Err(STATUS_UNSUCCESSFUL)
    );
    // A terminating target is refused.
    let dying = pm.create_process("dying.exe", None, None);
    pm.create_thread(dying, 0x10, 0, false).unwrap();
    pm.terminate_process(dying, 0).unwrap();
    assert_eq!(
        pm.debug_active_process(
            dying,
            second,
            ClientId {
                unique_process: debugger,
                unique_thread: 0
            }
        ),
        Err(STATUS_PROCESS_IS_TERMINATING)
    );
    assert_eq!(pm.debug_object_count(), 2);
}

#[test]
fn dbgk_wait_opens_handles_and_renders_the_state_change() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    let result = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(result.state, dbgk::DBG_CREATE_PROCESS_STATE_CHANGE);
    assert_eq!(
        result.client_id,
        ClientId {
            unique_process: target,
            unique_thread: main
        }
    );
    // DbgkpOpenHandles opened REAL handles in the DEBUGGER's handle table.
    assert_ne!(result.handle_to_process, 0);
    assert_ne!(result.handle_to_thread, 0);
    assert_eq!(
        pm.lookup_handle(debugger, result.handle_to_process),
        Some(HandleObject::Process(target))
    );
    assert_eq!(
        pm.lookup_handle(debugger, result.handle_to_thread),
        Some(HandleObject::Thread(main))
    );
    // The rendered DBGUI_WAIT_STATE_CHANGE carries them + the image base.
    let sc = &result.state_change;
    let u64_at = |o: usize| u64::from_le_bytes(sc[o..o + 8].try_into().unwrap());
    assert_eq!(
        u32::from_le_bytes(sc[0..4].try_into().unwrap()),
        dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
    );
    assert_eq!(u64_at(0x08), target as u64);
    assert_eq!(u64_at(0x10), main as u64);
    assert_eq!(u64_at(0x18), result.handle_to_process as u64);
    assert_eq!(u64_at(0x20), result.handle_to_thread as u64);
    assert_eq!(u64_at(0x38), 0x0000_0001_4000_0000); // BaseOfImage
    assert_eq!(u64_at(0x50), 0x2000); // InitialThread.StartAddress
                                      // A second wait with the event still outstanding reports nothing.
    assert!(pm.wait_for_debug_event(object, debugger).unwrap().is_none());
}

#[test]
fn dbgk_thread_create_and_exit_generate_real_events() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    // Retrieve + continue the attach message so the queue is clear.
    pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();
    assert_eq!(pm.debug_object(object).unwrap().len(), 0);

    // EVENT SOURCE 1: a thread create in the debugged process.
    let worker = pm.create_thread(target, 0x3000, 0, false).unwrap();
    assert_eq!(pm.debug_object(object).unwrap().len(), 1);
    let created = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(created.state, dbgk::DBG_CREATE_THREAD_STATE_CHANGE);
    assert_eq!(created.client_id.unique_thread, worker);
    assert_eq!(
        u64::from_le_bytes(created.state_change[0x28..0x30].try_into().unwrap()),
        0x3000
    );
    pm.debug_continue(object, created.client_id, dbgk::DBG_CONTINUE)
        .unwrap();

    // EVENT SOURCE 2: a thread exit (no cascade — the main thread keeps the process alive).
    pm.exit_thread(worker, 0x1234).unwrap();
    let exited = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(exited.state, dbgk::DBG_EXIT_THREAD_STATE_CHANGE);
    assert_eq!(exited.client_id.unique_thread, worker);
    assert_eq!(
        u32::from_le_bytes(exited.state_change[0x18..0x1c].try_into().unwrap()),
        0x1234
    );
    pm.debug_continue(object, exited.client_id, dbgk::DBG_CONTINUE)
        .unwrap();

    // EVENT SOURCE 3: process exit.
    pm.terminate_process(target, 0x99).unwrap();
    let dead = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(dead.state, dbgk::DBG_EXIT_PROCESS_STATE_CHANGE);
    assert_eq!(
        u32::from_le_bytes(dead.state_change[0x18..0x1c].try_into().unwrap()),
        0x99
    );
}

#[test]
fn dbgk_thread_hide_from_debugger_suppresses_live_thread_reports() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();

    let worker = pm.create_thread(target, 0x3000, 0, false).unwrap();
    let created = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(created.state, dbgk::DBG_CREATE_THREAD_STATE_CHANGE);
    assert_eq!(created.client_id.unique_thread, worker);
    pm.debug_continue(object, created.client_id, dbgk::DBG_CONTINUE)
        .unwrap();
    assert!(pm.debug_object(object).unwrap().is_empty());

    pm.set_thread_hide_from_debugger(worker).unwrap();

    let record = dbgk::ExceptionRecord::access_violation(0x7FFE_1000, 0, 0x10);
    assert_eq!(pm.report_exception(target, worker, record, true), None);
    assert!(pm.debug_object(object).unwrap().is_empty());

    const DLL_BASE: u64 = 0x0000_0000_8000_0000;
    assert_eq!(
        pm.report_module_load(target, worker, module_at(DLL_BASE, 0)),
        None
    );
    assert_eq!(
        pm.module_count(target),
        1,
        "hidden reporting suppresses Dbgk notification, not mapped-image tracking"
    );
    assert!(pm.debug_object(object).unwrap().is_empty());

    assert_eq!(pm.report_module_unload(target, worker, DLL_BASE), None);
    assert_eq!(pm.module_count(target), 0);
    assert!(pm.debug_object(object).unwrap().is_empty());

    pm.exit_thread(worker, 0x1234).unwrap();
    assert!(pm.debug_object(object).unwrap().is_empty());
    assert!(pm.wait_for_debug_event(object, debugger).unwrap().is_none());
}

#[test]
fn dbgk_thread_hide_from_debugger_does_not_hide_process_exit_by_main_thread_proxy() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();

    pm.set_thread_hide_from_debugger(main).unwrap();
    pm.terminate_process(target, 0x1234).unwrap();

    let exited = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(exited.state, dbgk::DBG_EXIT_PROCESS_STATE_CHANGE);
    assert_eq!(exited.client_id.unique_process, target);
    assert_eq!(exited.client_id.unique_thread, main);
}

#[test]
fn dbgk_continue_serialises_multiple_events_for_one_process() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    let worker = pm.create_thread(target, 0x3000, 0, false).unwrap();
    assert_eq!(pm.debug_object(object).unwrap().len(), 2);

    // Only ONE event at a time is reported for a given debuggee process.
    let first = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(first.client_id.unique_thread, main);
    assert!(pm.wait_for_debug_event(object, debugger).unwrap().is_none());

    // A continue for a thread with no read event fails.
    assert_eq!(
        pm.debug_continue(
            object,
            ClientId {
                unique_process: target,
                unique_thread: worker
            },
            dbgk::DBG_CONTINUE
        ),
        Err(STATUS_INVALID_PARAMETER)
    );

    let resolved = pm
        .debug_continue(object, first.client_id, dbgk::DBG_EXCEPTION_NOT_HANDLED)
        .unwrap();
    assert_eq!(resolved.returned_status, dbgk::DBG_EXCEPTION_NOT_HANDLED);
    // …and now the worker's create event becomes reportable.
    let second = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(second.client_id.unique_thread, worker);
    assert_eq!(second.state, dbgk::DBG_CREATE_THREAD_STATE_CHANGE);
}

#[test]
fn dbgk_detach_clears_the_port_and_flushes_queued_events() {
    let mut pm = ProcessManager::new();
    let (target, _main, debugger, object) = attach_debugger(&mut pm);
    pm.create_thread(target, 0x3000, 0, false).unwrap();
    assert_eq!(pm.debug_object(object).unwrap().len(), 2);

    assert_eq!(pm.remove_process_debug(target, object), Ok(2));
    assert_eq!(pm.process_debug_port(target), None);
    assert!(!pm.is_process_being_debugged(target));
    assert!(pm.debug_object(object).unwrap().is_empty());
    assert!(!pm.debug_object(object).unwrap().events_present());
    // A second detach reports PORT_NOT_SET.
    assert_eq!(
        pm.remove_process_debug(target, object),
        Err(dbgk::STATUS_PORT_NOT_SET)
    );
    // Detached: further lifecycle events are NOT reported.
    pm.create_thread(target, 0x4000, 0, false).unwrap();
    assert!(pm.debug_object(object).unwrap().is_empty());
    assert!(pm.wait_for_debug_event(object, debugger).unwrap().is_none());
}

#[test]
fn dbgk_destroying_the_object_detaches_every_debuggee() {
    let mut pm = ProcessManager::new();
    let (target, _main, debugger, object) = attach_debugger(&mut pm);
    assert_eq!(pm.destroy_debug_object(object), 1);
    assert_eq!(pm.process_debug_port(target), None);
    assert!(!pm.is_process_being_debugged(target));
    assert!(pm.debug_object(object).is_none());
    assert_eq!(
        pm.wait_for_debug_event(object, debugger),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(pm.debug_object_count(), 0);
}

#[test]
fn dbgk_deleted_process_debug_port_waits_for_exit_event_continue() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    let created = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();
    pm.close_handle(debugger, created.handle_to_process)
        .unwrap();
    let process_handle = pm
        .insert_handle(debugger, HandleObject::Process(target), PROCESS_ALL_ACCESS)
        .unwrap();

    pm.terminate_process(target, 0x99).unwrap();
    assert_eq!(pm.process_debug_port(target), Some(object));
    pm.close_handle(debugger, process_handle).unwrap();
    assert_eq!(
        pm.process_debug_port(target),
        Some(object),
        "the queued ExitProcess event still references the process"
    );

    let exited = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(exited.state, dbgk::DBG_EXIT_PROCESS_STATE_CHANGE);
    pm.debug_continue(object, exited.client_id, dbgk::DBG_CONTINUE)
        .unwrap();
    assert_eq!(pm.process_debug_port(target), None);
    assert!(!pm.is_process_being_debugged(target));
    assert!(pm.debug_object(object).unwrap().is_empty());
}

#[test]
fn dbgk_deleted_process_debug_port_waits_for_last_process_handle() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    let created = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();
    pm.close_handle(debugger, created.handle_to_process)
        .unwrap();
    let process_handle = pm
        .insert_handle(debugger, HandleObject::Process(target), PROCESS_ALL_ACCESS)
        .unwrap();

    pm.terminate_process(target, 0x99).unwrap();
    let exited = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(exited.state, dbgk::DBG_EXIT_PROCESS_STATE_CHANGE);
    pm.debug_continue(object, exited.client_id, dbgk::DBG_CONTINUE)
        .unwrap();
    assert_eq!(
        pm.process_debug_port(target),
        Some(object),
        "a process handle still references the terminated debuggee"
    );

    pm.close_handle(debugger, process_handle).unwrap();
    assert_eq!(pm.process_debug_port(target), None);
    assert!(!pm.is_process_being_debugged(target));
}

#[test]
fn dbgk_undebugged_processes_queue_nothing() {
    let mut pm = ProcessManager::new();
    let mut pm_object = ProcessManager::new();
    let object = pm_object.create_debug_object(0).unwrap();
    let pid = pm.create_process("plain.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    pm.exit_thread(tid, 0).unwrap();
    pm.terminate_process(pid, 0).unwrap();
    // No debug port anywhere → the plane is inert (this is the live-boot shape).
    assert_eq!(pm.debug_object_count(), 0);
    assert!(pm_object.debug_object(object).unwrap().is_empty());
}

// --- DbgkMapViewOfSection / DbgkUnMapViewOfSection: the module load/unload event source ---------

fn module_at(base: u64, file_handle: u64) -> ProcessModule {
    ProcessModule {
        pid: 0, // filled in by the recorder
        base,
        file_handle,
        debug_info_file_offset: 0x1234,
        debug_info_size: 0x56,
        name_pointer: 0x7FFE_1028,
    }
}

#[test]
fn dbgk_module_load_posts_load_dll_and_tracks_the_view() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    // Drain the attach-time fake create message so the load below is the outstanding event.
    pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();

    const DLL_BASE: u64 = 0x0000_0000_8000_0000;
    assert_eq!(
        pm.report_module_load(target, main, module_at(DLL_BASE, 0)),
        Some(object)
    );
    assert_eq!(pm.module_count(target), 1);
    let result = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(result.state, dbgk::DBG_LOAD_DLL_STATE_CHANGE);
    assert_eq!(
        result.client_id,
        ClientId {
            unique_process: target,
            unique_thread: main
        }
    );
    let sc = &result.state_change;
    let u32_at = |o: usize| u32::from_le_bytes(sc[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(sc[o..o + 8].try_into().unwrap());
    assert_eq!(u32_at(0x00), dbgk::DBG_LOAD_DLL_STATE_CHANGE);
    assert_eq!(u64_at(0x18), 0); // no debuggee file handle to duplicate
    assert_eq!(u64_at(0x20), DLL_BASE); // BaseOfDll
    assert_eq!(u32_at(0x28), 0x1234); // DebugInfoFileOffset
    assert_eq!(u32_at(0x2c), 0x56); // DebugInfoSize
    assert_eq!(u64_at(0x30), 0x7FFE_1028); // NamePointer
}

#[test]
fn dbgk_module_load_duplicates_the_image_file_handle_into_the_debugger() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();

    // The DEBUGGEE's own handle to the image file — meaningless in the debugger's namespace until
    // `DbgkpOpenHandles` duplicates it.
    let file = HandleObject::File(0xF11E);
    let debuggee_handle = pm.insert_handle(target, file, 0x0012_0089).unwrap();
    assert_eq!(
        pm.report_module_load(
            target,
            main,
            module_at(0x0000_0000_9000_0000, debuggee_handle as u64)
        ),
        Some(object)
    );
    let result = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_ne!(result.handle_to_file, 0);
    assert_ne!(
        result.handle_to_file, debuggee_handle,
        "the debugger gets its OWN handle value"
    );
    assert_eq!(
        pm.lookup_handle(debugger, result.handle_to_file),
        Some(file)
    );
    // DUPLICATE_SAME_ACCESS.
    assert_eq!(
        pm.handle_access(debugger, result.handle_to_file),
        Some(0x0012_0089)
    );
    // …and it is the value the rendered state change carries.
    assert_eq!(
        u64::from_le_bytes(result.state_change[0x18..0x20].try_into().unwrap()),
        result.handle_to_file as u64
    );
}

#[test]
fn dbgk_module_unload_reports_only_tracked_image_views() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();

    const DLL_BASE: u64 = 0x0000_0000_8000_0000;
    pm.report_module_load(target, main, module_at(DLL_BASE, 0));
    pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();

    // A base that was never an IMAGE view reports nothing — `MmUnmapViewOfSection`'s `if (DbgBase)`.
    assert_eq!(pm.report_module_unload(target, main, 0xDEAD_0000), None);
    assert!(pm.debug_object(object).unwrap().is_empty());
    // The tracked view does report, and stops being tracked.
    assert_eq!(
        pm.report_module_unload(target, main, DLL_BASE),
        Some(object)
    );
    assert_eq!(pm.module_count(target), 0);
    let result = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(result.state, dbgk::DBG_UNLOAD_DLL_STATE_CHANGE);
    assert_eq!(
        u64::from_le_bytes(result.state_change[0x18..0x20].try_into().unwrap()),
        DLL_BASE
    );
    // A second unmap of the same base is no longer a tracked view.
    assert_eq!(pm.report_module_unload(target, main, DLL_BASE), None);
}

#[test]
fn dbgk_attach_posts_fake_module_messages_after_the_thread_messages() {
    let mut pm = ProcessManager::new();
    // A debug object must exist for the map path to track anything at all (the live-boot gate).
    let object = pm.create_debug_object(0).unwrap();
    let debugger = pm.create_process("dbg.exe", None, None);
    let dbg_thread = pm.create_thread(debugger, 0x100, 0, false).unwrap();
    let target = pm.create_process("target.exe", None, None);
    pm.set_image_base(target, 0x0000_0001_4000_0000);
    let main = pm.create_thread(target, 0x2000, 0, false).unwrap();
    let second = pm.create_thread(target, 0x2100, 0, false).unwrap();

    // Two DLLs + the EXE's own view map BEFORE the attach — nothing is debugged, so nothing posts.
    const A: u64 = 0x0000_0000_8000_0000;
    const B: u64 = 0x0000_0000_8100_0000;
    pm.report_module_load(target, main, module_at(A, 0));
    pm.report_module_load(target, main, module_at(B, 0));
    pm.report_module_load(target, main, module_at(0x0000_0001_4000_0000, 0));
    assert_eq!(pm.module_count(target), 3);
    assert!(pm.debug_object(object).unwrap().is_empty());

    let posted = pm
        .debug_active_process(
            target,
            object,
            ClientId {
                unique_process: debugger,
                unique_thread: dbg_thread,
            },
        )
        .unwrap();
    // 2 thread messages + 2 module messages; the EXE's own view is NOT re-reported (the
    // create-process message already carries `base_of_image`).
    assert_eq!(posted, 4);
    let events = pm.debug_object(object).unwrap().events();
    assert_eq!(events.len(), 4);
    assert_eq!(
        events[0].message.state(),
        dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
    );
    assert_eq!(
        events[1].message.state(),
        dbgk::DBG_CREATE_THREAD_STATE_CHANGE
    );
    assert_eq!(events[1].client_id.unique_thread, second);
    // The module messages come LAST and are attributed to the FIRST reported thread.
    for (index, base) in [(2usize, A), (3, B)] {
        assert_eq!(
            events[index].message.state(),
            dbgk::DBG_LOAD_DLL_STATE_CHANGE
        );
        assert_eq!(events[index].client_id.unique_thread, main);
        assert_eq!(
            events[index].message,
            dbgk::DbgKmMessage::LoadDll {
                file_handle: 0,
                base_of_dll: base,
                debug_info_file_offset: 0x1234,
                debug_info_size: 0x56,
                name_pointer: 0, // cleared for a FAKE message
            }
        );
        // All fake messages are NOWAIT, and only the first of them is eligible.
        assert!(events[index].flags & dbgk::DEBUG_EVENT_NOWAIT != 0);
        assert!(events[index].is_inactive());
        assert!(events[index].backout_thread.is_none());
    }
    assert!(
        !events[0].is_inactive(),
        "the create-process message is activated first"
    );

    // Retrieving them: one event per debuggee process at a time, in queue order.
    for expected in [
        dbgk::DBG_CREATE_PROCESS_STATE_CHANGE,
        dbgk::DBG_CREATE_THREAD_STATE_CHANGE,
        dbgk::DBG_LOAD_DLL_STATE_CHANGE,
        dbgk::DBG_LOAD_DLL_STATE_CHANGE,
    ] {
        let result = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
        assert_eq!(result.state, expected);
        pm.debug_continue(object, result.client_id, dbgk::DBG_CONTINUE)
            .unwrap();
    }
    assert!(pm.debug_object(object).unwrap().is_empty());
}

#[test]
fn dbgk_attach_does_not_report_initialized_pool_threads() {
    let mut pm = ProcessManager::new();
    let object = pm.create_debug_object(0).unwrap();
    let debugger = pm.create_process("dbg.exe", None, None);
    let dbg_thread = pm.create_thread(debugger, 0x100, 0, false).unwrap();
    let target = pm.create_process("target.exe", None, None);
    let main = pm.create_thread(target, 0x2000, 0, false).unwrap();
    let dormant = pm.create_thread(target, 0, 0, false).unwrap();
    pm.set_thread_state(dormant, ThreadState::Initialized)
        .unwrap();

    assert_eq!(
        pm.debug_active_process(
            target,
            object,
            ClientId {
                unique_process: debugger,
                unique_thread: dbg_thread,
            },
        )
        .unwrap(),
        1
    );

    let events = pm.debug_object(object).unwrap().events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].message.state(),
        dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
    );
    assert_eq!(events[0].client_id.unique_thread, main);
}

#[test]
fn dbgk_existing_thread_create_reports_claimed_pool_thread() {
    let mut pm = ProcessManager::new();
    let object = pm.create_debug_object(0).unwrap();
    let debugger = pm.create_process("dbg.exe", None, None);
    let dbg_thread = pm.create_thread(debugger, 0x100, 0, false).unwrap();
    let target = pm.create_process("target.exe", None, None);
    let main = pm.create_thread(target, 0x2000, 0, false).unwrap();
    let dormant = pm.create_thread(target, 0, 0, false).unwrap();
    pm.set_thread_state(dormant, ThreadState::Initialized)
        .unwrap();

    assert_eq!(
        pm.debug_active_process(
            target,
            object,
            ClientId {
                unique_process: debugger,
                unique_thread: dbg_thread,
            },
        )
        .unwrap(),
        1
    );
    pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();

    assert_eq!(pm.report_existing_thread_create(dormant), None);

    const START: u64 = 0x0000_0001_7000_4321;
    assert!(pm.set_thread_start_address(dormant, START));
    pm.set_thread_state(dormant, ThreadState::Running).unwrap();
    assert_eq!(pm.report_existing_thread_create(dormant), Some(object));

    let created = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(created.state, dbgk::DBG_CREATE_THREAD_STATE_CHANGE);
    assert_eq!(created.client_id.unique_process, target);
    assert_eq!(created.client_id.unique_thread, dormant);
    assert_eq!(
        u64::from_le_bytes(created.state_change[0x28..0x30].try_into().unwrap()),
        START
    );
}

#[test]
fn dbgk_module_tracking_is_inert_without_a_debug_object() {
    // ★ THE LIVE-BOOT SHAPE. With no DEBUG_OBJECT in the system the map/unmap reporting path
    // records nothing and posts nothing, so a host's section-mapping path is untouched.
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("plain.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    assert_eq!(
        pm.report_module_load(pid, tid, module_at(0x8000_0000, 0)),
        None
    );
    assert_eq!(pm.module_count(pid), 0);
    assert_eq!(pm.report_module_unload(pid, tid, 0x8000_0000), None);
    assert_eq!(pm.debug_object_count(), 0);
}

#[test]
fn dbgk_module_tracking_respects_its_reserved_capacity() {
    let mut pm = ProcessManager::new();
    pm.reserve_modules(3);
    let _object = pm.create_debug_object(0).unwrap();
    let pid = pm.create_process("many.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    for i in 0..6u64 {
        pm.report_module_load(pid, tid, module_at(0x8000_0000 + i * 0x10_0000, 0));
    }
    assert_eq!(pm.module_count(pid), 3, "the table is capped, never grown");
    // Re-mapping a tracked base REPLACES its record rather than consuming another slot…
    pm.report_module_load(pid, tid, module_at(0x8000_0000, 0x99));
    assert_eq!(pm.module_count(pid), 3);
    let mut out = [ProcessModule::default(); 4];
    assert_eq!(pm.process_modules_into(pid, &mut out), 3);
    assert_eq!(out[0].file_handle, 0x99);
    // …and a freed slot is reused.
    assert!(pm.report_module_unload(pid, tid, 0x8010_0000).is_none()); // not debugged: no post
    assert_eq!(pm.module_count(pid), 2);
    pm.report_module_load(pid, tid, module_at(0x9000_0000, 0));
    assert_eq!(pm.module_count(pid), 3);
}

// --- DbgkForwardException: the exception / breakpoint / single-step event source -----------------

#[test]
fn dbgk_forward_exception_queues_a_first_chance_exception_event() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    // Drain the attach-time fake create message so the exception is the outstanding event.
    let create = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(create.state, dbgk::DBG_CREATE_PROCESS_STATE_CHANGE);
    pm.debug_continue(
        object,
        ClientId {
            unique_process: target,
            unique_thread: main,
        },
        dbgk::DBG_CONTINUE,
    )
    .unwrap();

    // A REAL page fault: STATUS_ACCESS_VIOLATION at RIP 0x7FFE_1000 touching 0x0000_0018 for write.
    let record = dbgk::ExceptionRecord::access_violation(0x7FFE_1000, 1, 0x18);
    let posted = pm.report_exception(target, main, record, true);
    assert_eq!(
        posted,
        Some(object),
        "a debugged process reports to its port"
    );
    let debug_object = pm.debug_object(object).unwrap();
    assert_eq!(debug_object.len(), 1);
    // Queuing a non-NOWAIT event signals the debugger awake.
    assert!(debug_object.events_present());
    assert_eq!(
        debug_object.events()[0].message.api_number(),
        dbgk::DBGKM_EXCEPTION_API
    );

    // The debugger retrieves it: DbgExceptionStateChange for the faulting CLIENT_ID, carrying the
    // whole EXCEPTION_RECORD + FirstChance in the rendered DBGUI_WAIT_STATE_CHANGE.
    let result = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(result.state, dbgk::DBG_EXCEPTION_STATE_CHANGE);
    assert_eq!(result.client_id.unique_process, target);
    assert_eq!(result.client_id.unique_thread, main);
    let sc = &result.state_change;
    let u32_at = |o: usize| u32::from_le_bytes(sc[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(sc[o..o + 8].try_into().unwrap());
    assert_eq!(u32_at(0x18), dbgk::STATUS_ACCESS_VIOLATION);
    assert_eq!(u64_at(0x28), 0x7FFE_1000, "ExceptionAddress");
    assert_eq!(u32_at(0x30), 2, "NumberParameters");
    assert_eq!(u64_at(0x38), 1, "ExceptionInformation[0] = write access");
    assert_eq!(
        u64_at(0x40),
        0x18,
        "ExceptionInformation[1] = fault address"
    );
    assert_eq!(u32_at(0xb0), 1, "FirstChance");

    // DBG_CONTINUE resolves it and its returned status is recorded on the event.
    let resolved = pm
        .debug_continue(
            object,
            ClientId {
                unique_process: target,
                unique_thread: main,
            },
            dbgk::DBG_CONTINUE,
        )
        .unwrap();
    assert_eq!(resolved.returned_status, dbgk::DBG_CONTINUE);
    assert!(pm.debug_object(object).unwrap().is_empty());
}

#[test]
fn dbgk_forward_exception_refines_breakpoint_single_step_and_second_chance() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    let _ = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    let client = ClientId {
        unique_process: target,
        unique_thread: main,
    };
    pm.debug_continue(object, client, dbgk::DBG_CONTINUE)
        .unwrap();

    // int3 → DbgBreakpointStateChange; a second-chance report clears FirstChance.
    let record = dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, 0x4010_00);
    assert_eq!(
        pm.report_exception(target, main, record, false),
        Some(object)
    );
    let result = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(result.state, dbgk::DBG_BREAKPOINT_STATE_CHANGE);
    assert_eq!(
        u32::from_le_bytes(result.state_change[0xb0..0xb4].try_into().unwrap()),
        0,
        "SecondChance ⇒ FirstChance == 0"
    );
    pm.debug_continue(object, client, dbgk::DBG_EXCEPTION_NOT_HANDLED)
        .unwrap();

    // Trap 1 (#DB) → DbgSingleStepStateChange.
    let code = dbgk::exception_code_for_trap(1);
    assert_eq!(code, dbgk::STATUS_SINGLE_STEP);
    assert_eq!(
        pm.report_exception(
            target,
            main,
            dbgk::ExceptionRecord::new(code, 0x401002),
            true
        ),
        Some(object)
    );
    let result = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(result.state, dbgk::DBG_SINGLE_STEP_STATE_CHANGE);
}

#[test]
fn dbgk_forward_exception_is_inert_without_a_debug_port() {
    let mut pm = ProcessManager::new();
    let (target, main, _debugger, object) = attach_debugger(&mut pm);
    // A process that was never attached reports nothing at all.
    let plain = pm.create_process("plain.exe", None, None);
    let plain_tid = pm.create_thread(plain, 0x1000, 0, false).unwrap();
    let record = dbgk::ExceptionRecord::new(dbgk::STATUS_ACCESS_VIOLATION, 0x1234);
    assert_eq!(pm.report_exception(plain, plain_tid, record, true), None);
    assert_eq!(
        pm.debug_object(object).unwrap().len(),
        1,
        "only the fake create"
    );

    // ...and neither does a DETACHED one — this is the live-boot shape (no debugger anywhere), the
    // gate the fault path checks before it diverts anything.
    pm.remove_process_debug(target, object).unwrap();
    assert!(!pm.is_process_being_debugged(target));
    assert_eq!(pm.report_exception(target, main, record, true), None);
    assert!(pm.debug_object(object).unwrap().is_empty());
}

#[test]
fn dbgk_debug_object_ids_enumerates_every_live_object() {
    let mut pm = ProcessManager::new();
    let mut ids = [0u32; 4];
    assert_eq!(pm.debug_object_ids_into(&mut ids), 0);
    let a = pm.create_debug_object(0).unwrap();
    let b = pm
        .create_debug_object(dbgk::DBGK_KILL_PROCESS_ON_EXIT)
        .unwrap();
    assert_eq!(pm.debug_object_ids_into(&mut ids), 2);
    assert_eq!(&ids[..2], &[a, b]);
    // A short output buffer truncates rather than overflowing.
    let mut one = [0u32; 1];
    assert_eq!(pm.debug_object_ids_into(&mut one), 1);
    pm.destroy_debug_object(a);
    assert_eq!(pm.debug_object_ids_into(&mut ids), 1);
    assert_eq!(ids[0], b);
}

#[test]
fn dbgk_trap_vectors_map_to_the_ntstatus_kidispatchexception_reports() {
    use super::dbgk as d;
    assert_eq!(
        d::exception_code_for_trap(0),
        d::STATUS_INTEGER_DIVIDE_BY_ZERO
    );
    assert_eq!(d::exception_code_for_trap(1), d::STATUS_SINGLE_STEP);
    assert_eq!(d::exception_code_for_trap(3), d::STATUS_BREAKPOINT);
    assert_eq!(d::exception_code_for_trap(4), d::STATUS_INTEGER_OVERFLOW);
    assert_eq!(
        d::exception_code_for_trap(5),
        d::STATUS_ARRAY_BOUNDS_EXCEEDED
    );
    assert_eq!(d::exception_code_for_trap(6), d::STATUS_ILLEGAL_INSTRUCTION);
    assert_eq!(d::exception_code_for_trap(13), d::STATUS_ACCESS_VIOLATION);
    assert_eq!(d::exception_code_for_trap(14), d::STATUS_ACCESS_VIOLATION);
    assert_eq!(
        d::exception_code_for_trap(17),
        d::STATUS_DATATYPE_MISALIGNMENT
    );
    assert_eq!(
        d::exception_code_for_debug_exception_reason(d::SEL4_DEBUG_REASON_SOFTWARE_BREAK_REQUEST),
        d::STATUS_BREAKPOINT
    );
    for reason in [
        d::SEL4_DEBUG_REASON_DATA_BREAKPOINT,
        d::SEL4_DEBUG_REASON_INSTRUCTION_BREAKPOINT,
        d::SEL4_DEBUG_REASON_SINGLE_STEP,
    ] {
        assert_eq!(
            d::exception_code_for_debug_exception_reason(reason),
            d::STATUS_SINGLE_STEP
        );
    }
    assert_eq!(
        d::exception_code_for_debug_exception_reason(0xff),
        d::STATUS_BREAKPOINT
    );
    // Unclassified vectors report the generic user-fault code, never panic.
    assert_eq!(d::exception_code_for_trap(0xFF), d::STATUS_ACCESS_VIOLATION);
    // The record builders clamp at EXCEPTION_MAXIMUM_PARAMETERS.
    let record = d::ExceptionRecord::new(d::STATUS_BREAKPOINT, 0x20).with_parameters(&[7u64; 20]);
    assert_eq!(record.number_parameters, 15);
    assert_eq!(record.exception_information[14], 7);
}

// --- TARGET-SIDE BLOCKING: the reporting thread parks on the event until NtDebugContinue ---------

/// A blocked reporter for `tid`, in the given fault/syscall flavour.
fn reporter(kind: u8, tid: ThreadId, cap: u64) -> dbgk::ReporterBlock {
    dbgk::ReporterBlock {
        kind,
        reply_cap: cap,
        pi: 7,
        tid: tid as u64,
        badge: 0,
        resume_ip: 0x7FFE_1000,
        resume_sp: 0x1_0000,
        resume_flags: 0x202,
        resume_status: 0,
    }
}

#[test]
fn dbgk_reporter_block_rides_on_the_debug_event_and_comes_back_from_continue() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    let client = ClientId {
        unique_process: target,
        unique_thread: main,
    };
    // Drain the attach-time fake create message (a NOWAIT event — never blocks a reporter).
    let create = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(create.state, dbgk::DBG_CREATE_PROCESS_STATE_CHANGE);
    pm.debug_continue(object, client, dbgk::DBG_CONTINUE)
        .unwrap();

    // The fault path: post the exception, then park the reporting thread on it.
    let record = dbgk::ExceptionRecord::access_violation(0x7FFE_1000, 1, 0x18);
    assert_eq!(
        pm.report_exception(target, main, record, true),
        Some(object)
    );
    assert_eq!(pm.blocked_reporter_count(object), 0, "not blocked yet");
    let block = reporter(dbgk::DBGK_BLOCK_VM_FAULT, main, 0xBEEF);
    assert!(pm.block_reporter(object, client, block));
    assert_eq!(pm.blocked_reporter_count(object), 1);

    // The debugger retrieves the event; the reporter stays blocked across the wait.
    let seen = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    assert_eq!(seen.state, dbgk::DBG_EXCEPTION_STATE_CHANGE);
    assert_eq!(pm.blocked_reporter_count(object), 1);

    // The continue hands the block back — this is `DbgkpWakeTarget`'s input.
    let resolved = pm
        .debug_continue(object, client, dbgk::DBG_CONTINUE)
        .unwrap();
    assert_eq!(resolved.reporter_block(), Some(block));
    assert_eq!(
        dbgk::wake_action(&block, dbgk::DBG_CONTINUE),
        dbgk::WakeAction::Resume
    );
    assert_eq!(pm.blocked_reporter_count(object), 0, "event is gone");
}

#[test]
fn dbgk_set_context_updates_a_blocked_reporter_resume_context() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    let client = ClientId {
        unique_process: target,
        unique_thread: main,
    };
    let _ = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(object, client, dbgk::DBG_CONTINUE)
        .unwrap();

    assert_eq!(
        pm.report_exception(
            target,
            main,
            dbgk::ExceptionRecord::new(dbgk::STATUS_SINGLE_STEP, 0x401000),
            true
        ),
        Some(object)
    );
    let block = reporter(dbgk::DBGK_BLOCK_USER_EXCEPTION, main, 0xC0DE);
    assert!(pm.block_reporter(object, client, block));
    assert!(pm.update_blocked_reporter_context(
        client,
        Some(0x402000),
        Some(0x7000_1000),
        Some(0x302),
    ));

    let _ = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    let resolved = pm
        .debug_continue(object, client, dbgk::DBG_CONTINUE)
        .unwrap();
    let updated = resolved.reporter_block().unwrap();
    assert_eq!(updated.resume_ip, 0x402000);
    assert_eq!(updated.resume_sp, 0x7000_1000);
    assert_eq!(updated.resume_flags, 0x302);
}

#[test]
fn dbgk_wake_action_maps_every_continue_status_for_both_flavours() {
    let fault = reporter(dbgk::DBGK_BLOCK_USER_EXCEPTION, 9, 1);
    let syscall = reporter(dbgk::DBGK_BLOCK_SYSCALL, 9, 1);
    assert!(fault.is_fault() && !syscall.is_fault());
    for kind in [
        dbgk::DBGK_BLOCK_VM_FAULT,
        dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
        dbgk::DBGK_BLOCK_USER_EXCEPTION,
    ] {
        assert!(reporter(kind, 9, 1).is_fault());
    }
    // DBG_CONTINUE / DBG_EXCEPTION_HANDLED resume both flavours.
    for status in [dbgk::DBG_CONTINUE, dbgk::DBG_EXCEPTION_HANDLED] {
        assert_eq!(dbgk::wake_action(&fault, status), dbgk::WakeAction::Resume);
        assert_eq!(
            dbgk::wake_action(&syscall, status),
            dbgk::WakeAction::Resume
        );
    }
    // NOT_HANDLED: a FAULT reporter is left blocked (the fault site's own handling stands); a
    // syscall-reported event has no exception to decline, so the syscall completes.
    assert_eq!(
        dbgk::wake_action(&fault, dbgk::DBG_EXCEPTION_NOT_HANDLED),
        dbgk::WakeAction::LeaveBlocked
    );
    assert_eq!(
        dbgk::wake_action(&syscall, dbgk::DBG_EXCEPTION_NOT_HANDLED),
        dbgk::WakeAction::Resume
    );
    // DBG_TERMINATE_* are ENFORCED for both flavours, and even with no reporter parked.
    let none = dbgk::ReporterBlock::default();
    assert!(!none.is_blocked());
    for block in [fault, syscall, none] {
        assert_eq!(
            dbgk::wake_action(&block, dbgk::DBG_TERMINATE_THREAD),
            dbgk::WakeAction::TerminateThread
        );
        assert_eq!(
            dbgk::wake_action(&block, dbgk::DBG_TERMINATE_PROCESS),
            dbgk::WakeAction::TerminateProcess
        );
    }
    assert_eq!(
        dbgk::wake_action(&none, dbgk::DBG_CONTINUE),
        dbgk::WakeAction::None
    );
}

#[test]
fn dbgk_teardown_releases_every_blocked_reporter() {
    let mut pm = ProcessManager::new();
    let (target, main, debugger, object) = attach_debugger(&mut pm);
    let client = ClientId {
        unique_process: target,
        unique_thread: main,
    };
    let _ = pm.wait_for_debug_event(object, debugger).unwrap().unwrap();
    pm.debug_continue(object, client, dbgk::DBG_CONTINUE)
        .unwrap();

    let record = dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, 0x401000);
    assert_eq!(
        pm.report_exception(target, main, record, true),
        Some(object)
    );
    let block = reporter(dbgk::DBGK_BLOCK_DEBUG_EXCEPTION, main, 0xC0DE);
    assert!(pm.block_reporter(object, client, block));

    // A never-blocked event for a DIFFERENT process is untouched by the pid-scoped drain.
    let other = pm.create_process("other.exe", None, None);
    let other_thread = pm.create_thread(other, 0x10, 0, false).unwrap();
    pm.debug_active_process(
        other,
        object,
        ClientId {
            unique_process: debugger,
            unique_thread: 1,
        },
    )
    .unwrap();
    let other_client = ClientId {
        unique_process: other,
        unique_thread: other_thread,
    };
    let other_block = reporter(dbgk::DBGK_BLOCK_SYSCALL, other_thread, 0xFEED);
    assert_eq!(
        pm.report_exception(
            other,
            other_thread,
            dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, 0x20),
            true
        ),
        Some(object)
    );
    assert!(pm.block_reporter(object, other_client, other_block));
    assert_eq!(pm.blocked_reporter_count(object), 2);

    // Detaching ONE debuggee releases only its reporter (`DbgkClearProcessDebugObject`).
    let released = pm.drain_blocked_reporters(object, Some(target));
    assert_eq!(released.len(), 1);
    assert_eq!(released[0], (client, block));
    assert_eq!(pm.blocked_reporter_count(object), 1);

    // Destroying the object releases the rest (`DbgkpCloseObject`) — nothing stays parked.
    let released = pm.drain_blocked_reporters(object, None);
    assert_eq!(released.len(), 1);
    assert_eq!(released[0], (other_client, other_block));
    assert_eq!(pm.blocked_reporter_count(object), 0);
}

#[test]
fn dbgk_block_reporter_refuses_nowait_and_unblocked_events() {
    let mut pm = ProcessManager::new();
    let (target, main, _debugger, object) = attach_debugger(&mut pm);
    let client = ClientId {
        unique_process: target,
        unique_thread: main,
    };
    // The only queued event is the attach-time NOWAIT fake create message: NT never blocks a
    // reporter on one, so neither do we.
    let block = reporter(dbgk::DBGK_BLOCK_VM_FAULT, main, 0x11);
    assert!(!pm.block_reporter(object, client, block));
    assert_eq!(pm.blocked_reporter_count(object), 0);
    // A block with no reply capability is not a block.
    assert_eq!(
        pm.report_exception(
            target,
            main,
            dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, 0x30),
            true
        ),
        Some(object)
    );
    assert!(!pm.block_reporter(object, client, reporter(dbgk::DBGK_BLOCK_VM_FAULT, main, 0)));
    assert!(!pm.block_reporter(object, client, reporter(dbgk::DBGK_BLOCK_NONE, main, 0x22)));
    assert_eq!(pm.blocked_reporter_count(object), 0);
    // The real block lands, and a SECOND block for the same event does not double-park.
    assert!(pm.block_reporter(object, client, block));
    assert!(!pm.block_reporter(
        object,
        client,
        reporter(dbgk::DBGK_BLOCK_VM_FAULT, main, 0x33)
    ));
    assert_eq!(pm.blocked_reporter_count(object), 1);
    // An unknown object is a no-op, never a panic.
    assert!(!pm.block_reporter(object + 99, client, block));
    assert_eq!(pm.blocked_reporter_count(object + 99), 0);
    assert!(pm.drain_blocked_reporters(object + 99, None).is_empty());
}
