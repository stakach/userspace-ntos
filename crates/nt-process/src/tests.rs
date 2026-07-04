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
