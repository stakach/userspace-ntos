use super::*;

fn finally(handler: u32) -> ScopeRecord {
    ScopeRecord {
        begin: 0x100,
        end: 0x200,
        handler,
        target: 0,
    }
}

fn except(handler: u32, target: u32) -> ScopeRecord {
    ScopeRecord {
        target,
        ..finally(handler)
    }
}

fn next(scopes: &[ScopeRecord], pc: u64, target: u64, flags: u32, index: &mut u32) -> CScopeAction {
    next_c_scope(pc, target, flags, scopes.len() as u32, index, |i| {
        scopes[i as usize]
    })
}

#[test]
fn cursor_is_published_before_finally_and_resumes_without_repetition() {
    let scopes = [finally(0x300), finally(0x400)];
    let mut index = 0;
    assert_eq!(
        next(&scopes, 0x150, 0, EXCEPTION_UNWINDING, &mut index),
        CScopeAction::Finally { handler_rva: 0x300 }
    );
    assert_eq!(index, 1);
    let mut resumed_index = index; // DispatcherContext carried across a collided unwind
    assert_eq!(
        next(
            &scopes,
            0x150,
            0,
            EXCEPTION_COLLIDED_UNWIND,
            &mut resumed_index
        ),
        CScopeAction::Finally { handler_rva: 0x400 }
    );
    assert_eq!(resumed_index, 2);
    assert_eq!(
        next(&scopes, 0x150, 0, EXCEPTION_UNWINDING, &mut resumed_index),
        CScopeAction::ContinueSearch
    );
}

#[test]
fn search_cursor_skips_finally_and_resumes_at_the_next_filter() {
    let scopes = [finally(0x300), except(0x400, 0x500), except(1, 0x600)];
    let mut index = 0;
    assert_eq!(
        next(&scopes, 0x150, 0, 0, &mut index),
        CScopeAction::Filter {
            handler_rva: 0x400,
            target_rva: 0x500,
            scope_index: 1
        }
    );
    assert_eq!(index, 2);
    assert_eq!(
        next(&scopes, 0x150, 0, 0, &mut index),
        CScopeAction::ExecuteHandler {
            target_rva: 0x600,
            scope_index: 2
        }
    );
    assert_eq!(index, 3);
}

#[test]
fn target_within_scope_suppresses_unwind_without_running_a_finally() {
    let scopes = [finally(0x300), finally(0x400)];
    for target in [0xff, 0x100, 0x150, 0x1ff, 0x200] {
        let mut index = 0;
        let action = next(
            &scopes,
            0x150,
            target,
            EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND,
            &mut index,
        );
        assert_eq!(
            action,
            if (0x100..0x200).contains(&target) {
                CScopeAction::ContinueSearch
            } else {
                CScopeAction::Finally { handler_rva: 0x300 }
            }
        );
        assert_eq!(index, 1);
    }
}

#[test]
fn except_target_stops_before_outer_finalizers() {
    let scopes = [finally(0x300), except(0x400, 0x500), finally(0x600)];
    let mut index = 0;
    assert_eq!(
        next(&scopes, 0x150, 0x500, EXCEPTION_UNWINDING, &mut index),
        CScopeAction::Finally { handler_rva: 0x300 }
    );
    assert_eq!(
        next(&scopes, 0x150, 0x500, EXCEPTION_UNWINDING, &mut index),
        CScopeAction::ContinueSearch
    );
    assert_eq!(index, 2);
}

#[test]
fn every_unwind_phase_selects_finalizers_instead_of_filters() {
    let scopes = [except(0x400, 0x500), finally(0x600)];
    for flags in [
        EXCEPTION_UNWINDING,
        EXCEPTION_EXIT_UNWIND,
        EXCEPTION_TARGET_UNWIND,
        EXCEPTION_COLLIDED_UNWIND,
        EXCEPTION_UNWIND,
    ] {
        let mut index = 0;
        assert_eq!(
            next(&scopes, 0x150, 0, flags, &mut index),
            CScopeAction::Finally { handler_rva: 0x600 }
        );
        assert_eq!(index, 2);
    }
}

#[test]
fn scope_addresses_do_not_alias_after_four_gibibytes() {
    let scopes = [finally(0x300)];
    let mut index = 0;
    assert_eq!(
        next(&scopes, 0x1_0000_0150, 0, EXCEPTION_UNWINDING, &mut index),
        CScopeAction::ContinueSearch
    );
    index = 0;
    assert_eq!(
        next(
            &scopes,
            0x150,
            0x1_0000_0150,
            EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND,
            &mut index
        ),
        CScopeAction::Finally { handler_rva: 0x300 }
    );
}

#[test]
fn cursor_count_boundaries_do_not_read_or_overflow() {
    for (count, start) in [(0, 0), (2, 2), (2, 3), (u32::MAX, u32::MAX)] {
        let mut index = start;
        assert_eq!(
            next_c_scope(0x150, 0, 0, count, &mut index, |_| panic!(
                "exhausted table read"
            )),
            CScopeAction::ContinueSearch
        );
        assert_eq!(index, start);
    }
    let mut index = u32::MAX - 1;
    assert_eq!(
        next_c_scope(0x150, 0, EXCEPTION_UNWINDING, u32::MAX, &mut index, |i| {
            assert_eq!(i, u32::MAX - 1);
            finally(0x300)
        }),
        CScopeAction::Finally { handler_rva: 0x300 }
    );
    assert_eq!(index, u32::MAX);
}

#[test]
fn filter_results_use_sign_including_integer_extremes() {
    let scopes = [except(0x300, 0x400)];
    for verdict in [i32::MIN, -2, -1, 0, 1, 2, i32::MAX] {
        let expected = if verdict < 0 {
            CHandlerAction::ContinueExecution
        } else if verdict > 0 {
            CHandlerAction::ExecuteHandler {
                target_rva: 0x400,
                scope_index: 0,
            }
        } else {
            CHandlerAction::ContinueSearch
        };
        assert_eq!(
            CHandlerAction::from_filter_result(verdict, 0x400, 0),
            expected
        );
        assert_eq!(
            c_specific_handler_search(0x150, &scopes, |_| verdict),
            expected
        );
    }
}
