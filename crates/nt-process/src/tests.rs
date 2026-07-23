use super::*;
use nt_driver_test_fixtures::{minimal_pe, DEFAULT_IMAGE_BASE};

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
        let handle = pm.insert_handle(pid, HandleObject::Thread(tid), 0).unwrap();
        let basic = pm.query_thread_basic(pid, handle as u64).unwrap();
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
    let current = pm.query_thread_basic(pid, u64::MAX - 1).unwrap();
    assert_eq!(current.client_id.unique_thread, main);
    assert_eq!(pm.query_thread_basic(pid, 0), Err(STATUS_INVALID_HANDLE));
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
    assert_eq!(thread.state, ThreadState::Initialized);
    assert_eq!(thread.exit_status, None);
    assert_eq!(thread.suspend_count, 0);
    assert_eq!(thread.teb_base, 0);
    assert!(!pm.can_reclaim_thread(worker));
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
    assert_eq!(pm.process_window_station(pid), None);

    // win32k parks its opaque W32PROCESS / W32THREAD pointers.
    assert!(pm.set_process_win32(pid, 0xFFFF_9E00_1234_0000));
    assert!(pm.set_thread_win32(tid, 0xFFFF_9E00_5678_0000));
    assert!(pm.set_process_window_station(pid, 0xFFFF_9E00_9ABC_0000));
    assert_eq!(pm.process_win32(pid), Some(0xFFFF_9E00_1234_0000));
    assert_eq!(pm.thread_win32(tid), Some(0xFFFF_9E00_5678_0000));
    assert_eq!(pm.process_window_station(pid), Some(0xFFFF_9E00_9ABC_0000));

    // Setting NULL clears the slot (win32k detaches on process/thread teardown).
    assert!(pm.set_process_win32(pid, 0));
    assert_eq!(pm.process_win32(pid), None);

    // Unknown pid/tid is rejected, not a panic.
    assert!(!pm.set_process_win32(9999, 1));
    assert!(!pm.set_thread_win32(9999, 1));
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
fn append_only_handles_never_recycle_a_closed_value() {
    // With no_reuse set, a closed handle VALUE is never handed out again — the guarantee the
    // executive's per-process DLL registry relies on (a recycled value would collide with a stale
    // external binding to the old handle). Contrast `reserved_handle_table_never_reallocates`,
    // which asserts the DEFAULT reuse behavior.
    let mut pm = ProcessManager::new();
    pm.set_handle_no_reuse(true);
    let pid = pm.create_process("host.exe", None, None);
    let h0 = pm.insert_handle(pid, HandleObject::Opaque(1), 0).unwrap();
    let h1 = pm.insert_handle(pid, HandleObject::Opaque(2), 0).unwrap();
    assert_eq!((h0, h1), (4, 8));
    pm.close_handle(pid, 4).unwrap();
    assert_eq!(pm.lookup_handle(pid, 4), None);
    // The next insert APPENDS (value 12) — it does NOT recycle the freed value 4.
    let h2 = pm.insert_handle(pid, HandleObject::Opaque(3), 0).unwrap();
    assert_eq!(h2, 12);
    assert_eq!(pm.lookup_handle(pid, 12), Some(HandleObject::Opaque(3)));
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
