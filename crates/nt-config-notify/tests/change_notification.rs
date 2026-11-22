//! Registry change notification semantics, after NT `cmnotify.c`.

use nt_config_notify::{
    ArmError, Armed, ChangeNotifier, Completion, KeyBody, REG_NOTIFY_CHANGE_ATTRIBUTES,
    REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_CHANGE_SECURITY,
    STATUS_NOTIFY_CLEANUP, STATUS_NOTIFY_ENUM_DIR,
};

const SOFTWARE: &str = r"\REGISTRY\MACHINE\SOFTWARE\Vendor";
const BODY: KeyBody = KeyBody {
    process: 4,
    handle: 0x40,
};
const THREAD: u64 = 100;

fn pending(armed: Armed<u32>) {
    assert!(
        matches!(armed, Armed::Pending(_)),
        "expected a pending request"
    );
}

fn statuses(completions: &[Completion<u32>]) -> Vec<(u32, u32)> {
    completions
        .iter()
        .map(|completion| (completion.request, completion.status))
        .collect()
}

#[test]
fn value_change_completes_a_last_set_watcher_on_that_key() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    let done = notifier.report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET);
    assert_eq!(statuses(&done), [(1, STATUS_NOTIFY_ENUM_DIR)]);
    assert_eq!(done[0].body, BODY);
    assert_eq!(done[0].thread, THREAD);
}

#[test]
fn filter_selects_the_change_kinds_reported() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_NAME, false, THREAD, 1)
            .unwrap(),
    );
    assert!(notifier
        .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
        .is_empty());
    assert!(notifier
        .report_key_changed(
            SOFTWARE,
            REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_SECURITY
        )
        .is_empty());
    let created = format!(r"{SOFTWARE}\New");
    assert_eq!(
        statuses(&notifier.report_subkey_changed(&created)),
        [(1, STATUS_NOTIFY_ENUM_DIR)]
    );
}

#[test]
fn security_change_reports_attributes_and_security() {
    let mut notifier = ChangeNotifier::new();
    let other = KeyBody {
        process: 4,
        handle: 0x44,
    };
    pending(
        notifier
            .arm(
                BODY,
                SOFTWARE,
                REG_NOTIFY_CHANGE_ATTRIBUTES,
                false,
                THREAD,
                1,
            )
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                other,
                SOFTWARE,
                REG_NOTIFY_CHANGE_SECURITY,
                false,
                THREAD,
                2,
            )
            .unwrap(),
    );
    let mut done = statuses(&notifier.report_key_changed(
        SOFTWARE,
        REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_SECURITY,
    ));
    done.sort();
    assert_eq!(
        done,
        [(1, STATUS_NOTIFY_ENUM_DIR), (2, STATUS_NOTIFY_ENUM_DIR)]
    );
}

#[test]
fn a_subkey_change_is_a_name_change_of_its_parent_not_of_itself() {
    let mut notifier = ChangeNotifier::new();
    let child = format!(r"{SOFTWARE}\Child");
    let child_body = KeyBody {
        process: 4,
        handle: 0x48,
    };
    pending(
        notifier
            .arm(child_body, &child, REG_NOTIFY_CHANGE_NAME, true, THREAD, 2)
            .unwrap(),
    );
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_NAME, false, THREAD, 1)
            .unwrap(),
    );
    assert_eq!(
        statuses(&notifier.report_subkey_changed(&child)),
        [(1, STATUS_NOTIFY_ENUM_DIR)]
    );
}

#[test]
fn only_a_tree_watch_sees_changes_below_its_key() {
    let mut notifier = ChangeNotifier::new();
    let tree = KeyBody {
        process: 4,
        handle: 0x44,
    };
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    pending(
        notifier
            .arm(tree, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, true, THREAD, 2)
            .unwrap(),
    );
    let deep = format!(r"{SOFTWARE}\A\B");
    assert_eq!(
        statuses(&notifier.report_key_changed(&deep, REG_NOTIFY_CHANGE_LAST_SET)),
        [(2, STATUS_NOTIFY_ENUM_DIR)]
    );
    // The key itself still reaches the non-tree watcher.
    assert_eq!(
        statuses(&notifier.report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)),
        [(1, STATUS_NOTIFY_ENUM_DIR)]
    );
}

#[test]
fn a_sibling_whose_name_extends_the_watched_name_is_not_below_it() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, true, THREAD, 1)
            .unwrap(),
    );
    assert!(notifier
        .report_key_changed(
            r"\REGISTRY\MACHINE\SOFTWARE\VendorTwo",
            REG_NOTIFY_CHANGE_LAST_SET
        )
        .is_empty());
}

#[test]
fn key_names_match_without_regard_to_case_or_separator_runs() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    assert_eq!(
        notifier
            .report_key_changed(
                r"\registry\machine\\software\VENDOR\",
                REG_NOTIFY_CHANGE_LAST_SET
            )
            .len(),
        1
    );
}

#[test]
fn a_watcher_in_another_hive_is_not_woken() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(
                BODY,
                r"\REGISTRY\USER\S-1-5-18\Software",
                REG_NOTIFY_CHANGE_LAST_SET,
                true,
                THREAD,
                1,
            )
            .unwrap(),
    );
    assert!(notifier
        .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
        .is_empty());
    assert!(notifier
        .report_subkey_changed(r"\REGISTRY\MACHINE\SYSTEM\Select")
        .is_empty());
}

#[test]
fn a_tree_watch_on_the_master_hive_sees_a_mounted_hive() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(
                BODY,
                r"\REGISTRY\MACHINE",
                REG_NOTIFY_CHANGE_LAST_SET,
                true,
                THREAD,
                1,
            )
            .unwrap(),
    );
    assert_eq!(
        notifier
            .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
            .len(),
        1
    );
}

#[test]
fn a_request_is_one_shot_and_the_caller_re_arms() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    assert_eq!(
        notifier
            .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
            .len(),
        1
    );
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 2)
            .unwrap(),
    );
    assert_eq!(
        statuses(&notifier.report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)),
        [(2, STATUS_NOTIFY_ENUM_DIR)]
    );
    assert!(notifier
        .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
        .is_empty());
}

#[test]
fn a_change_between_requests_completes_the_next_request_at_once() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    assert_eq!(
        notifier
            .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
            .len(),
        1
    );
    // No request is posted now: the block remembers the change (NotifyPending).
    assert!(notifier
        .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
        .is_empty());
    let Armed::Posted(completion) = notifier
        .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 2)
        .unwrap()
    else {
        panic!("a remembered change posts the new request immediately");
    };
    assert_eq!(
        (completion.request, completion.status),
        (2, STATUS_NOTIFY_ENUM_DIR)
    );
    // The memory is consumed by that one request.
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 3)
            .unwrap(),
    );
}

#[test]
fn a_change_before_the_first_request_is_never_reported() {
    let mut notifier = ChangeNotifier::<u32>::new();
    assert!(notifier.is_idle());
    assert!(notifier
        .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
        .is_empty());
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    assert_eq!(notifier.posted_requests(), 1);
}

#[test]
fn the_first_request_fixes_the_filter_and_scope_of_a_key_body() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_NAME, false, THREAD, 1)
            .unwrap(),
    );
    // Different parameters on the same handle are accepted and ignored.
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, true, THREAD, 2)
            .unwrap(),
    );
    assert!(notifier
        .report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)
        .is_empty());
    let mut done = statuses(&notifier.report_subkey_changed(&format!(r"{SOFTWARE}\K")));
    done.sort();
    assert_eq!(
        done,
        [(1, STATUS_NOTIFY_ENUM_DIR), (2, STATUS_NOTIFY_ENUM_DIR)]
    );
}

#[test]
fn an_illegal_filter_bit_is_refused_and_the_request_returned() {
    let mut notifier = ChangeNotifier::new();
    let Err(ArmError::InvalidFilter(request)) =
        notifier.arm(BODY, SOFTWARE, 0x10, false, THREAD, 7)
    else {
        panic!("filter outside REG_LEGAL_CHANGE_FILTER");
    };
    assert_eq!(request, 7);
    assert_eq!(notifier.posted_requests(), 0);
}

#[test]
fn closing_the_handle_cleans_up_every_request_posted_through_it() {
    let mut notifier = ChangeNotifier::new();
    let other = KeyBody {
        process: 4,
        handle: 0x44,
    };
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                BODY,
                SOFTWARE,
                REG_NOTIFY_CHANGE_LAST_SET,
                false,
                THREAD + 1,
                2,
            )
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                other,
                SOFTWARE,
                REG_NOTIFY_CHANGE_LAST_SET,
                false,
                THREAD,
                3,
            )
            .unwrap(),
    );
    let mut done = statuses(&notifier.close_key_body(BODY));
    done.sort();
    assert_eq!(
        done,
        [(1, STATUS_NOTIFY_CLEANUP), (2, STATUS_NOTIFY_CLEANUP)]
    );
    // The block is gone with the handle: a reused handle value starts a new session.
    assert_eq!(
        statuses(&notifier.report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)),
        [(3, STATUS_NOTIFY_ENUM_DIR)]
    );
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_NAME, false, THREAD, 4)
            .unwrap(),
    );
    assert!(notifier
        .close_key_body(KeyBody {
            process: 5,
            handle: 0x40
        })
        .is_empty());
}

#[test]
fn deleting_a_key_reports_to_its_parent_and_cleans_up_its_own_watchers() {
    let mut notifier = ChangeNotifier::new();
    let child = format!(r"{SOFTWARE}\Child");
    let child_body = KeyBody {
        process: 8,
        handle: 0x10,
    };
    let unrelated = KeyBody {
        process: 8,
        handle: 0x14,
    };
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_NAME, false, THREAD, 1)
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                child_body,
                &child,
                REG_NOTIFY_CHANGE_LAST_SET,
                false,
                THREAD,
                2,
            )
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                unrelated,
                &format!(r"{SOFTWARE}\Other"),
                REG_NOTIFY_CHANGE_LAST_SET,
                false,
                THREAD,
                3,
            )
            .unwrap(),
    );
    let mut done = statuses(&notifier.key_deleted(&child));
    done.sort();
    assert_eq!(
        done,
        [(1, STATUS_NOTIFY_ENUM_DIR), (2, STATUS_NOTIFY_CLEANUP)]
    );
    assert_eq!(notifier.posted_requests(), 1);
}

#[test]
fn unloading_a_hive_cleans_up_every_watcher_at_or_below_its_root() {
    let mut notifier = ChangeNotifier::new();
    let root = r"\REGISTRY\USER\S-1-5-21-1";
    let below = KeyBody {
        process: 8,
        handle: 0x10,
    };
    let above = KeyBody {
        process: 8,
        handle: 0x14,
    };
    pending(
        notifier
            .arm(BODY, root, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                below,
                &format!(r"{root}\Software"),
                REG_NOTIFY_CHANGE_NAME,
                true,
                THREAD,
                2,
            )
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                above,
                r"\REGISTRY\USER",
                REG_NOTIFY_CHANGE_NAME,
                false,
                THREAD,
                3,
            )
            .unwrap(),
    );
    let mut done = statuses(&notifier.subtree_removed(root));
    done.sort();
    assert_eq!(
        done,
        [
            (1, STATUS_NOTIFY_CLEANUP),
            (2, STATUS_NOTIFY_CLEANUP),
            (3, STATUS_NOTIFY_ENUM_DIR)
        ]
    );
}

#[test]
fn a_process_exit_closes_all_of_its_key_bodies_and_no_others() {
    let mut notifier = ChangeNotifier::new();
    let other = KeyBody {
        process: 9,
        handle: 0x40,
    };
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                other,
                SOFTWARE,
                REG_NOTIFY_CHANGE_LAST_SET,
                false,
                THREAD,
                2,
            )
            .unwrap(),
    );
    assert_eq!(
        statuses(&notifier.close_process(4)),
        [(1, STATUS_NOTIFY_CLEANUP)]
    );
    assert_eq!(notifier.posted_requests(), 1);
    assert!(!notifier.is_idle());
    assert_eq!(notifier.close_process(9).len(), 1);
    assert!(notifier.is_idle());
}

#[test]
fn a_thread_exit_cleans_up_its_requests_and_keeps_the_notify_session() {
    let mut notifier = ChangeNotifier::new();
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
            .unwrap(),
    );
    pending(
        notifier
            .arm(
                BODY,
                SOFTWARE,
                REG_NOTIFY_CHANGE_LAST_SET,
                false,
                THREAD + 1,
                2,
            )
            .unwrap(),
    );
    assert_eq!(
        statuses(&notifier.thread_exited(4, THREAD)),
        [(1, STATUS_NOTIFY_CLEANUP)]
    );
    assert_eq!(
        statuses(&notifier.report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)),
        [(2, STATUS_NOTIFY_ENUM_DIR)]
    );
}

#[test]
fn an_aborted_wait_withdraws_exactly_its_own_request() {
    let mut notifier = ChangeNotifier::new();
    let Armed::Pending(first) = notifier
        .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 1)
        .unwrap()
    else {
        panic!("pending");
    };
    pending(
        notifier
            .arm(BODY, SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET, false, THREAD, 2)
            .unwrap(),
    );
    assert_eq!(notifier.withdraw(first), Some(1));
    assert_eq!(notifier.withdraw(first), None);
    assert_eq!(
        statuses(&notifier.report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET)),
        [(2, STATUS_NOTIFY_ENUM_DIR)]
    );
}

#[test]
fn every_request_posted_on_a_key_body_completes_on_one_change() {
    let mut notifier = ChangeNotifier::new();
    for request in 1..=3 {
        pending(
            notifier
                .arm(
                    BODY,
                    SOFTWARE,
                    REG_NOTIFY_CHANGE_LAST_SET,
                    false,
                    THREAD,
                    request,
                )
                .unwrap(),
        );
    }
    let mut done = statuses(&notifier.report_key_changed(SOFTWARE, REG_NOTIFY_CHANGE_LAST_SET));
    done.sort();
    assert_eq!(done.len(), 3);
    assert_eq!(notifier.posted_requests(), 0);
}
