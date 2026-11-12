//! User-mode exit ordering shared by the native DLL wrapper and host tests.

/// A returned user start routine exits its thread. When it was the last live thread,
/// process-wide loader detach must run before final process termination.
pub fn exit_user_thread(
    status: u32,
    mut query_last_thread: impl FnMut() -> Result<bool, u32>,
    mut exit_process: impl FnMut(u32),
    mut shutdown_thread: impl FnMut(),
    mut terminate_thread: impl FnMut(u32),
) {
    if matches!(query_last_thread(), Ok(true)) {
        exit_process(status);
        return;
    }
    shutdown_thread();
    terminate_thread(status);
}

/// NT's first process termination phase stops peer threads while the caller remains
/// alive for DLL detach; the handle-form call then terminates the caller.
pub fn exit_user_process(
    status: u32,
    mut terminate_other_threads: impl FnMut(u32),
    mut shutdown_process: impl FnMut(),
    mut terminate_current_process: impl FnMut(u32),
) {
    terminate_other_threads(status);
    shutdown_process();
    terminate_current_process(status);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};

    #[test]
    fn returned_start_thread_exits_process_only_when_last() {
        for (last, expected) in [
            (true, ["query", "process", "", ""]),
            (false, ["query", "thread-detach", "thread", ""]),
        ] {
            let events = RefCell::new([""; 4]);
            let count = Cell::new(0);
            let record = |event| {
                events.borrow_mut()[count.get()] = event;
                count.set(count.get() + 1);
            };
            exit_user_thread(
                0x1234_5678,
                || {
                    record("query");
                    Ok(last)
                },
                |status| {
                    assert_eq!(status, 0x1234_5678);
                    record("process");
                },
                || record("thread-detach"),
                |status| {
                    assert_eq!(status, 0x1234_5678);
                    record("thread");
                },
            );
            assert_eq!(*events.borrow(), expected);
        }
    }

    #[test]
    fn failed_last_thread_query_exits_thread_without_process_detach() {
        let mut process_exit = false;
        let mut thread_exit = false;
        exit_user_thread(
            7,
            || Err(0xc000_000d),
            |_| process_exit = true,
            || {},
            |_| thread_exit = true,
        );
        assert!(!process_exit);
        assert!(thread_exit);
    }

    #[test]
    fn process_exit_stops_other_threads_before_loader_detach_and_final_termination() {
        let events = RefCell::new([""; 3]);
        let count = Cell::new(0);
        let record = |event| {
            events.borrow_mut()[count.get()] = event;
            count.set(count.get() + 1);
        };
        exit_user_process(
            0xfeed_beef,
            |status| {
                assert_eq!(status, 0xfeed_beef);
                record("other-threads");
            },
            || record("process-detach"),
            |status| {
                assert_eq!(status, 0xfeed_beef);
                record("current-process");
            },
        );
        assert_eq!(
            *events.borrow(),
            ["other-threads", "process-detach", "current-process"]
        );
    }
}
