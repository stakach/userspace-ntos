use super::*;

use nt_component_suspension::{
    ComponentSuspensionLanes, IngressError, IngressExecutionOwner, IngressReceiver,
    LaneBinding, ReservedReceiveError,
};

#[test]
fn resumed_provider_preserves_the_yield_authority_of_its_callback_origin() {
    let nested = resume_yield_caps(true, true);
    assert!(nested.nested_service_wait);
    assert!(!nested.hosted_receive);

    let ordinary = resume_yield_caps(false, true);
    assert!(!ordinary.nested_service_wait);
    assert!(ordinary.hosted_receive);

    for nested_callback in [false, true] {
        let no_caller = resume_yield_caps(nested_callback, false);
        assert!(!no_caller.nested_service_wait);
        assert!(!no_caller.hosted_receive);
    }
}

#[test]
fn busy_idle_receive_after_child_scheduler_yield_keeps_the_running_reply_and_continuation() {
    // The child receive returned a scheduler yield with a new physical Reply. The root loop
    // still owns a running primary dispatch and must give that retained continuation another
    // turn before attempting an Idle receive. This models the Boot 43247312492 lane 17 failure.
    let mut lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
    let lane = lanes.allocate(LaneBinding {
        executor_id: 210390,
        receive_endpoint: 20,
        reply_object: 73489,
    }).unwrap();
    lanes.begin_dispatch(lane, 73489).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let mut root_receive = IngressReceiver::<u64>::new(20, 40000, 1).unwrap();
    let mut continuation = ComponentPumpAccounting::new(true);
    assert_eq!(continuation.after_slice(true, false), PumpDepthDisposition::Retained);

    let preflight = root_receive.begin_receive_for_owner(&lanes, IngressExecutionOwner::Idle);
    assert_eq!(preflight, Err(ReservedReceiveError::Ingress(IngressError::ExecutionBusy)));
    assert_eq!(root_receive.phase(), None); // No native receive was authorized.

    let decision = root_receive_disposition_after_yield(
        &lanes,
        dispatch,
        73489,
        RootReceiveRefusal::IdleExecutionBusyBeforeNativeReceive,
    );
    assert_eq!(decision, RootReceiveDisposition::ResumeRetainedDispatch);
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    assert_eq!(lanes.binding(lane).unwrap().reply_object, 73489);
    assert!(continuation.owns_depth());
    assert_eq!(root_receive.phase(), None);
}

#[test]
fn uncertain_receive_after_child_scheduler_yield_cannot_be_recast_as_a_busy_preflight() {
    let mut lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
    let lane = lanes.allocate(LaneBinding {
        executor_id: 210390,
        receive_endpoint: 20,
        reply_object: 73489,
    }).unwrap();
    lanes.begin_dispatch(lane, 73489).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();

    assert_eq!(
        root_receive_disposition_after_yield(
            &lanes,
            dispatch,
            73489,
            RootReceiveRefusal::NativeReceiveEffectUncertain,
        ),
        RootReceiveDisposition::RetainFailure,
    );
    assert_eq!(
        root_receive_disposition_after_yield(
            &lanes,
            dispatch,
            73461, // Stale Reply from before the child scheduler yield.
            RootReceiveRefusal::IdleExecutionBusyBeforeNativeReceive,
        ),
        RootReceiveDisposition::RetainFailure,
    );
    assert_eq!(lanes.binding(lane).unwrap().reply_object, 73489);
}

#[test]
fn post_reply_receive_keeps_timer_checkpoint_and_idle_receive_behavior() {
    assert!(PostReplyReceiveDemand {
        timer_checkpoint_ready: true,
        queued_dpc: false,
    }.scheduler_yield());
    assert!(!PostReplyReceiveDemand {
        timer_checkpoint_ready: false,
        queued_dpc: false,
    }.scheduler_yield());
}

#[test]
fn queued_dpc_yields_before_retained_receive_without_bootstrap_timer_owner() {
    // QueueDpc has already acknowledged its exact DPC and the service Reply has been sent.
    // An unowned dispatcher bootstrap cannot supply a timer checkpoint; the queued DPC
    // remains scheduler work before this retained component enters physical receive.
    assert!(PostReplyReceiveDemand {
        timer_checkpoint_ready: false,
        queued_dpc: true,
    }.scheduler_yield());
}

#[test]
fn counters_and_depth_follow_the_active_snapshot_across_yields() {
    let mut active = ComponentPumpAccounting::new(true);
    for slice in 1..=4 {
        active.record_fault();
        active.record_fault();
        active.record_demand();
        active.record_assert_skip();
        assert_eq!(
            active.after_slice(true, false),
            PumpDepthDisposition::Retained
        );
        let carried = active;
        assert_eq!(carried.faults(), slice * 2);
        assert_eq!(carried.demand(), slice);
        assert_eq!(carried.assert_skips(), slice);
        assert!(carried.owns_depth());
        // Budgets observe the whole invocation, not a fresh counter for each receive slice.
        assert_eq!(carried.demand() >= 3, slice >= 3);
        assert_eq!(carried.assert_skips() >= 2, slice >= 2);
        active = carried;
    }
    assert_eq!(
        active.after_slice(false, false),
        PumpDepthDisposition::Released
    );
    assert_eq!(active.faults(), 8);
    assert_eq!(active.demand(), 4);
    assert_eq!(active.assert_skips(), 4);
    assert!(!active.owns_depth());
}

#[test]
fn all_counters_saturate_without_reopening_budget() {
    let mut accounting = ComponentPumpAccounting {
        faults: u64::MAX - 1,
        demand: u64::MAX - 1,
        assert_skips: u64::MAX - 1,
        phase: AccountingPhase::Active { owns_depth: true },
    };
    for _ in 0..3 {
        accounting.record_fault();
        accounting.record_demand();
        accounting.record_assert_skip();
        assert_eq!(accounting.faults(), u64::MAX);
        assert_eq!(accounting.demand(), u64::MAX);
        assert_eq!(accounting.assert_skips(), u64::MAX);
        assert_eq!(
            accounting.after_slice(true, false),
            PumpDepthDisposition::Retained
        );
    }
}

#[test]
fn final_release_or_suspension_consumes_depth_once_per_active_snapshot() {
    for suspended in [false, true] {
        let mut accounting = ComponentPumpAccounting::new(true);
        assert_eq!(
            accounting.after_slice(true, false),
            PumpDepthDisposition::Retained
        );
        assert_eq!(
            accounting.after_slice(false, suspended),
            if suspended {
                PumpDepthDisposition::Suspended
            } else {
                PumpDepthDisposition::Released
            }
        );
        assert!(!accounting.owns_depth());
        for (yielded, suspended) in [(false, false), (false, true), (true, false), (true, true)] {
            assert_eq!(
                accounting.after_slice(yielded, suspended),
                PumpDepthDisposition::None
            );
        }
    }
}

#[test]
fn unowned_bootstrap_depth_stays_unowned_while_counters_accumulate() {
    let mut accounting = ComponentPumpAccounting::new(false);
    for (yielded, suspended) in [(true, false), (false, true), (false, false)] {
        accounting.record_fault();
        accounting.record_demand();
        accounting.record_assert_skip();
        assert_eq!(
            accounting.after_slice(yielded, suspended),
            PumpDepthDisposition::None
        );
        assert!(!accounting.owns_depth());
    }
    assert_eq!(accounting.faults(), 3);
    assert_eq!(accounting.demand(), 3);
    assert_eq!(accounting.assert_skips(), 3);
}

#[test]
fn yield_never_releases_or_transfers_depth() {
    let mut accounting = ComponentPumpAccounting::new(true);
    assert_eq!(
        accounting.after_slice(true, true),
        PumpDepthDisposition::Retained
    );
    assert!(accounting.owns_depth());
    assert_eq!(
        accounting.after_slice(false, true),
        PumpDepthDisposition::Suspended
    );
}

#[test]
fn repeated_counted_waits_carry_depth_and_cumulative_budgets() {
    let mut accounting = ComponentPumpAccounting::new(true);
    for count in 1..=4 {
        accounting.record_fault();
        accounting.record_demand();
        accounting.record_assert_skip();
        assert_eq!(
            accounting.after_slice(false, true),
            PumpDepthDisposition::Suspended
        );
        assert_eq!(accounting.resume_suspended(), Some(true));
        assert_eq!(accounting.resume_suspended(), None);
        assert_eq!(accounting.faults(), count);
        assert_eq!(accounting.demand(), count);
        assert_eq!(accounting.assert_skips(), count);
        assert_eq!(
            accounting.after_slice(true, false),
            PumpDepthDisposition::Retained
        );
    }
    assert_eq!(
        accounting.after_slice(false, false),
        PumpDepthDisposition::Released
    );
    assert_eq!(accounting.resume_suspended(), None);
}

#[test]
fn bootstrap_wait_resume_never_invents_or_consumes_dispatch_depth() {
    let mut accounting = ComponentPumpAccounting::new(false);
    for count in 1..=4 {
        accounting.record_fault();
        accounting.record_demand();
        assert_eq!(
            accounting.after_slice(false, true),
            PumpDepthDisposition::None
        );
        assert_eq!(accounting.resume_suspended(), Some(false));
        assert!(!accounting.owns_depth());
        assert_eq!(
            accounting.after_slice(true, false),
            PumpDepthDisposition::None
        );
        assert_eq!(accounting.faults(), count);
        assert_eq!(accounting.demand(), count);
    }
    assert_eq!(
        accounting.after_slice(false, false),
        PumpDepthDisposition::None
    );
    assert_eq!(accounting.resume_suspended(), None);
}

#[test]
fn only_suspension_can_supply_resume_accounting() {
    for owns_depth in [false, true] {
        let mut accounting = ComponentPumpAccounting::new(owns_depth);
        let initial = accounting;
        assert_eq!(accounting.resume_suspended(), None);
        assert_eq!(accounting, initial);
        accounting.after_slice(true, false);
        let yielded = accounting;
        assert_eq!(accounting.resume_suspended(), None);
        assert_eq!(accounting, yielded);
        accounting.after_slice(false, false);
        let finished = accounting;
        assert_eq!(accounting.resume_suspended(), None);
        assert_eq!(accounting, finished);
        accounting.after_slice(false, true);
        assert_eq!(accounting, finished);
    }
}
