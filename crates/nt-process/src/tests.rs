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
    // Close.
    pm.close_handle(p1, h).unwrap();
    assert_eq!(pm.lookup_handle(p1, h), None);
    assert_eq!(pm.close_handle(p1, h), Err(STATUS_INVALID_HANDLE));
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
    assert_eq!(pm.lookup_handle(pid, 4), Some(HandleObject::Opaque(0x5A5A_0000)));
    // Closing frees the slot; the next insert reuses it (still no realloc).
    pm.close_handle(pid, 4).unwrap();
    assert_eq!(pm.lookup_handle(pid, 4), None);
    let reused = pm.insert_handle(pid, HandleObject::Opaque(0xBEEF), 0).unwrap();
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
    let h = pm.insert_handle(pid, HandleObject::Thread(listener), 0).unwrap();
    assert_eq!(pm.lookup_handle(pid, h), Some(HandleObject::Thread(listener)));
    // The ClientId a host writes to NtCreateThread's *ClientId out-param.
    assert_eq!(
        pm.client_id(listener),
        Some(ClientId { unique_process: pid, unique_thread: listener })
    );
}

#[test]
fn close_by_object_tag() {
    // The convergence hybrid: a host tags each entry with its own handle VALUE (Opaque) and closes
    // by that tag on NtClose, without knowing this table's internal slot-handle.
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    pm.reserve_handles(pid, 16);
    pm.insert_handle(pid, HandleObject::Opaque(0x5A5A_0001), 0).unwrap();
    pm.insert_handle(pid, HandleObject::Opaque(0x5A5A_0002), 0).unwrap();
    assert_eq!(pm.handle_count(pid), 2);
    assert!(pm.close_handle_by_object(pid, HandleObject::Opaque(0x5A5A_0001)));
    assert_eq!(pm.handle_count(pid), 1);
    // Idempotent-safe: closing an absent tag reports false (the host still returns SUCCESS to match
    // the prior no-op NtClose behavior).
    assert!(!pm.close_handle_by_object(pid, HandleObject::Opaque(0x5A5A_0001)));
    assert!(!pm.close_handle_by_object(pid, HandleObject::Opaque(0xDEAD)));
    // Typed entries coexist and are matched by identity.
    let other = pm.create_process("b.exe", None, None);
    pm.insert_handle(pid, HandleObject::Process(other), 0).unwrap();
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
    let ha = pm.insert_handle(a, HandleObject::Opaque(0xA11CE), 0).unwrap();
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
    assert_eq!(pm.lookup_handle(first, first_handle), Some(HandleObject::File(41)));
    assert_eq!(pm.lookup_handle(second, second_handle), Some(HandleObject::File(99)));
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
