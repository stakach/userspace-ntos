use super::*;

#[test]
fn kernel_process_export_state_tracks_exact_process_and_job_membership() {
    let mut manager = ProcessManager::new();
    let first = manager.create_process("\\SystemRoot\\System32\\first.exe", None, None);
    let second = manager.create_process("\\SystemRoot\\System32\\second.exe", None, None);
    manager.set_peb_base(first, 0x7000);
    manager.set_process_session_id(first, 3).unwrap();
    manager
        .set_process_priority_class(first, PROCESS_PRIORITY_CLASS_HIGH)
        .unwrap();
    manager.set_process_foreground(first, true).unwrap();
    let job = manager.create_job(3).unwrap();
    assert_eq!(
        manager.assign_process_to_job(job, first),
        Ok(STATUS_SUCCESS)
    );

    let first_state = manager.kernel_process_export_state(first).unwrap();
    assert_eq!(first_state.image_file_name, "\\SystemRoot\\System32\\first.exe");
    assert_eq!(first_state.peb_base_address, 0x7000);
    assert_eq!(first_state.session_id, 3);
    assert_eq!(first_state.priority_class, PROCESS_PRIORITY_CLASS_HIGH);
    assert!(first_state.foreground);
    assert_eq!(first_state.job, Some(job));

    let second_state = manager.kernel_process_export_state(second).unwrap();
    assert_eq!(second_state.image_file_name, "\\SystemRoot\\System32\\second.exe");
    assert_eq!(second_state.peb_base_address, 0);
    assert_eq!(second_state.session_id, 0);
    assert_eq!(second_state.priority_class, PROCESS_PRIORITY_CLASS_NORMAL);
    assert!(!second_state.foreground);
    assert_eq!(second_state.job, None);
    assert!(manager.kernel_process_export_state(u32::MAX).is_none());
}

#[test]
fn kernel_process_export_state_reads_current_job_ui_restrictions() {
    let mut manager = ProcessManager::new();
    let pid = manager.create_process("gui.exe", None, None);
    assert_eq!(manager.kernel_process_export_state(pid).unwrap().job, None);
    let job = manager.create_job(0).unwrap();
    assert_eq!(
        manager.assign_process_to_job(job, pid),
        Ok(STATUS_SUCCESS)
    );
    assert_eq!(manager.job_ui_restrictions(job), Ok(0));
    manager.set_job_ui_restrictions(job, 0x1).unwrap();
    assert_eq!(
        manager.kernel_process_export_state(pid).unwrap().job,
        Some(job)
    );
    assert_eq!(manager.job_ui_restrictions(job), Ok(0x1));
}
