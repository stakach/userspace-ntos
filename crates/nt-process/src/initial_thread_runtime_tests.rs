use super::*;

fn main_thread() -> (ProcessManager, ThreadLifetime) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("ordinary.exe", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    (pm, lifetime)
}

fn metadata(pm: &ProcessManager, tid: ThreadId) -> (u64, u64, u64, i64, bool) {
    let thread = pm.thread(tid).unwrap();
    (
        thread.start_address,
        thread.win32_start_address,
        thread.teb_base,
        thread.create_time_100ns,
        thread.initial_runtime_published,
    )
}

#[test]
fn initial_runtime_publishes_atomically_without_changing_lifetime_or_state() {
    let (mut pm, lifetime) = main_thread();
    let tid = lifetime.thread_id();
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123),
        Ok(())
    );
    assert_eq!(metadata(&pm, tid), (0x1000, 0x1000, 0x7000, 123, true));
    assert_eq!(pm.thread_lifetime(tid), Some(lifetime));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Ready);
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123),
        Ok(())
    );
    let mut moved = pm;
    assert_eq!(
        moved.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123),
        Ok(())
    );
}

#[test]
fn every_conflicting_published_field_rejects_without_partial_changes() {
    let (mut pm, lifetime) = main_thread();
    pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123)
        .unwrap();
    let before = metadata(&pm, lifetime.thread_id());
    for (start, teb, time) in [
        (0x2000, 0x7000, 123),
        (0x1000, 0x8000, 123),
        (0x1000, 0x7000, 456),
    ] {
        assert_eq!(
            pm.publish_initial_thread_runtime(lifetime, start, teb, time),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(metadata(&pm, lifetime.thread_id()), before);
    }
}

#[test]
fn explicit_zero_environment_and_timestamp_are_not_unpublished_defaults() {
    let (mut pm, lifetime) = main_thread();
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 0, 0, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(metadata(&pm, lifetime.thread_id()), (0, 0, 0, 0, false));
    pm.publish_initial_thread_runtime(lifetime, 0x1000, 0, 0)
        .unwrap();
    for (start, teb, time) in [(0x2000, 0, 0), (0x1000, 1, 0), (0x1000, 0, 1)] {
        assert_eq!(
            pm.publish_initial_thread_runtime(lifetime, start, teb, time),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            metadata(&pm, lifetime.thread_id()),
            (0x1000, 0x1000, 0, 0, true)
        );
    }
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 0x1000, 0, 0),
        Ok(())
    );
}

#[test]
fn incompatible_preexisting_fields_do_not_publish_other_fields() {
    for field in 0..4 {
        let (mut pm, lifetime) = main_thread();
        let thread = pm.threads.get_mut(&lifetime.thread_id()).unwrap();
        match field {
            0 => thread.start_address = 0x2000,
            1 => thread.win32_start_address = 0x2000,
            2 => thread.teb_base = 0x8000,
            _ => thread.create_time_100ns = 456,
        }
        let before = metadata(&pm, lifetime.thread_id());
        assert_eq!(
            pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(metadata(&pm, lifetime.thread_id()), before);
    }
}

#[test]
fn published_body_permits_only_already_matching_initialization() {
    let (mut pm, lifetime) = main_thread();
    assert!(pm.publish_thread_kernel_object(lifetime.thread_id(), 0x9000));
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(metadata(&pm, lifetime.thread_id()), (0, 0, 0, 0, false));
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 0, 0, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(pm.thread_kernel_object(lifetime.thread_id()), Some(0x9000));

    let (mut pm, lifetime) = main_thread();
    pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123)
        .unwrap();
    assert!(pm.publish_thread_kernel_object(lifetime.thread_id(), 0x9000));
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123),
        Ok(())
    );
}

#[test]
fn stale_missing_and_wrong_process_snapshots_never_publish() {
    let (mut pm, lifetime) = main_thread();
    let other_pid = pm.create_process("another.exe", None, None);
    for snapshot in [
        ThreadLifetime {
            generation: lifetime.generation + 1,
            ..lifetime
        },
        ThreadLifetime {
            process_id: other_pid,
            ..lifetime
        },
    ] {
        assert_eq!(
            pm.publish_initial_thread_runtime(snapshot, 0x1000, 0x7000, 123),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(metadata(&pm, lifetime.thread_id()), (0, 0, 0, 0, false));
    }
    let missing = ThreadLifetime {
        thread_id: u32::MAX,
        ..lifetime
    };
    assert_eq!(
        pm.publish_initial_thread_runtime(missing, 1, 2, 3),
        Err(STATUS_INVALID_HANDLE)
    );
    pm.threads
        .get_mut(&lifetime.thread_id())
        .unwrap()
        .activation_generation += 1;
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 1, 2, 3),
        Err(STATUS_INVALID_PARAMETER)
    );
    let later = pm.thread_lifetime(lifetime.thread_id()).unwrap();
    assert_eq!(
        pm.publish_initial_thread_runtime(later, 1, 2, 3),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(metadata(&pm, lifetime.thread_id()), (0, 0, 0, 0, false));
}

#[test]
fn nonmain_dormant_and_exited_owners_are_not_initial_runtime_admission() {
    let (mut pm, lifetime) = main_thread();
    let pid = lifetime.process_id();
    for tid in [
        pm.create_thread(pid, 0, 0, false).unwrap(),
        pm.create_dormant_thread(pid).unwrap(),
    ] {
        let other = pm.thread_lifetime(tid).unwrap();
        assert_eq!(
            pm.publish_initial_thread_runtime(other, 1, 2, 3),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(metadata(&pm, tid), (0, 0, 0, 0, false));
    }
    for state in [ProcessState::Exiting, ProcessState::Terminated] {
        pm.processes.get_mut(&pid).unwrap().state = state;
        assert_eq!(
            pm.publish_initial_thread_runtime(lifetime, 1, 2, 3),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(metadata(&pm, lifetime.thread_id()), (0, 0, 0, 0, false));
    }
    pm.processes.get_mut(&pid).unwrap().state = ProcessState::Running;
    pm.terminate_thread(lifetime.thread_id(), 0).unwrap();
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 1, 2, 3),
        Err(STATUS_THREAD_IS_TERMINATING)
    );
    assert_eq!(metadata(&pm, lifetime.thread_id()), (0, 0, 0, 0, false));
}

#[test]
fn compatible_existing_fields_allow_one_exact_initial_publication() {
    for body_first in [false, true] {
        let (mut pm, lifetime) = main_thread();
        let tid = lifetime.thread_id();
        let thread = pm.threads.get_mut(&tid).unwrap();
        thread.start_address = 0x1000;
        thread.win32_start_address = 0x1000;
        thread.teb_base = 0x7000;
        thread.create_time_100ns = 123;
        if body_first {
            assert!(pm.publish_thread_kernel_object(tid, 0x9000));
        } else {
            pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123)
                .unwrap();
        }
        pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123)
            .unwrap();
        assert_eq!(metadata(&pm, tid), (0x1000, 0x1000, 0x7000, 123, true));
    }
}

#[test]
fn independent_win32_entry_update_is_not_overwritten_by_initial_replay() {
    let (mut pm, lifetime) = main_thread();
    pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123)
        .unwrap();
    pm.set_thread_win32_start_address(lifetime.thread_id(), 0x2000)
        .unwrap();
    let before = metadata(&pm, lifetime.thread_id());
    assert_eq!(
        pm.publish_initial_thread_runtime(lifetime, 0x1000, 0x7000, 123),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(metadata(&pm, lifetime.thread_id()), before);
}
