use super::*;
use crate::process_identity::ProcessGeneration;
use nt_process::ProcessManager;

fn identity() -> (ProcessIdentity, ThreadLifetime) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("exit.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    (
        ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(2),
        },
        pm.thread_lifetime(tid).unwrap(),
    )
}

#[test]
fn failed_construction_and_absent_teb_never_read_user_memory() {
    let (process, thread) = identity();
    for (kind, teb) in [
        (ThreadStackExitKind::FailedConstruction, Some(0x10000)),
        (ThreadStackExitKind::FailedConstruction, Some(0)),
        (ThreadStackExitKind::RegisteredThread, None),
    ] {
        assert!(
            ThreadStackReleaseRequest::capture(process, thread, teb, kind, |_, _| panic!(
                "no user policy read permitted"
            ))
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn false_flag_does_not_read_deallocation_stack() {
    let (process, thread) = identity();
    let mut reads = 0;
    assert!(ThreadStackReleaseRequest::capture(
        process,
        thread,
        Some(0x10000),
        ThreadStackExitKind::RegisteredThread,
        |address, bytes| {
            assert_eq!(address, 0x11745);
            assert_eq!(bytes.len(), 1);
            reads += 1;
            bytes[0] = 0;
            Ok(())
        }
    )
    .unwrap()
    .is_none());
    assert_eq!(reads, 1);
}

#[test]
fn true_boolean_captures_actual_base_and_exact_identity_not_recorded_geometry() {
    let (process, thread) = identity();
    let mut reads = 0;
    let request = ThreadStackReleaseRequest::capture(
        process,
        thread,
        Some(0x10000),
        ThreadStackExitKind::RegisteredThread,
        |address, bytes| {
            match reads {
                0 => {
                    assert_eq!(address, 0x11745);
                    bytes[0] = 0xff;
                }
                1 => {
                    assert_eq!(address, 0x11478);
                    bytes.copy_from_slice(&0xabc123u64.to_le_bytes());
                }
                _ => panic!("unexpected reread"),
            }
            reads += 1;
            Ok(())
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(reads, 2);
    assert_eq!(request.deallocation_stack(), 0xabc123);
    assert_eq!(request.teb(), 0x10000);
    assert!(request.matches(process, thread, 0x10000));
    assert!(!request.matches(process, thread, 0x20000));
    assert!(!request.matches(
        ProcessIdentity {
            generation: ProcessGeneration::Hosted(3),
            ..process
        },
        thread,
        0x10000
    ));
}

#[test]
fn either_read_exception_is_preserved_not_misrepresented_as_false() {
    let (process, thread) = identity();
    for fail_at in [0, 1] {
        let mut reads = 0;
        let result = ThreadStackReleaseRequest::capture(
            process,
            thread,
            Some(0x10000),
            ThreadStackExitKind::RegisteredThread,
            |_, bytes| {
                let current = reads;
                reads += 1;
                if current == fail_at {
                    return Err(0xc0000006);
                }
                bytes[0] = 1;
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err(), 0xc0000006);
        assert_eq!(reads, fail_at + 1);
    }
}

#[test]
fn present_zero_and_wrapping_teb_are_errors_not_absence() {
    let (process, thread) = identity();
    for teb in [0, u64::MAX - 0x1000] {
        assert_eq!(
            ThreadStackReleaseRequest::capture(
                process,
                thread,
                Some(teb),
                ThreadStackExitKind::RegisteredThread,
                |_, _| panic!("invalid span must not read")
            )
            .unwrap_err(),
            nt_address_space::STATUS_ACCESS_VIOLATION
        );
    }
}
