use super::*;
use nt_component_suspension::{ResumeDemand, ResumeWake};

fn demand(f: &mut Fixture) -> ResumeDemand {
    let stopped = next_work(f).is_some_and(|(_, work)| work.is_ok());
    ResumeDemand::observe(f.lanes.execution_busy(), stopped, || {
        f.lanes.next_resumable().is_some() || f.activations.has_ready_completion()
    })
}

#[test]
fn stopped_initial_publication_keeps_retry_wake_despite_running_lane() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let mut wake = ResumeWake::new(10, 40).unwrap();
    assert!(f.lanes.execution_busy());
    assert!(next_work(&mut f).unwrap().1.is_ok());
    assert!(demand(&mut f).can_schedule());
    wake.reconcile_demand(demand(&mut f), 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    assert!(admit(&mut f, &mut state, &mut arbiter, 0).is_err());
    assert!(f.lanes.execution_busy());
    wake.finish_pass(&mut pass, 100, demand(&mut f).retains_work(), false)
        .unwrap();
    assert_eq!(wake.next_deadline(), Some(110));
    assert!(state.events.read_state(101));
    assert_eq!(state.event_objects.live_lease_count(), 0);

    let mut pass = wake.begin_pass(110).unwrap().unwrap();
    assert_eq!(
        admit(&mut f, &mut state, &mut arbiter, 1).unwrap(),
        Admission::Satisfied {
            wait_id: 71,
            status: 0
        }
    );
    assert!(!state.events.read_state(101));
    assert_eq!(next_work(&mut f), None);
    assert!(f.lanes.next_resumable().is_some());
    wake.finish_pass(&mut pass, 110, demand(&mut f).retains_work(), true)
        .unwrap();

    let mut pass = wake.begin_pass(120).unwrap().unwrap();
    let _execution = f.resume().unwrap();
    assert!(f.lanes.execution_busy());
    // An entered pump is distinct from a stopped request awaiting publication.
    assert_eq!(next_work(&mut f), None);
    let blocked = demand(&mut f);
    assert_eq!(blocked, ResumeDemand::ExecutionBlocked);
    wake.finish_pass(&mut pass, 120, blocked.retains_work(), false)
        .unwrap();
    wake.reconcile_demand(blocked, 200);
    assert_eq!(wake.next_deadline(), Some(130));
    assert!(f.lanes.next_resumable().is_none());
    assert_eq!(f.state().active_resume(), Some(f.capture));
}

#[test]
fn rejected_repark_retries_from_original_capture_then_releases_execution_wake() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let previous = f.capture;
    let next = next_capture(&mut f, 72);
    assert!(f.lanes.execution_busy());
    assert_eq!(
        next_work(&mut f),
        Some((
            f.caller,
            Ok(KernelProviderWaitWork::Repark { previous, next })
        ))
    );
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile_demand(demand(&mut f), 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    assert!(repark(&mut f, &mut state, &mut arbiter, next, 0).is_err());
    assert_eq!(f.state().active_resume(), Some(previous));
    assert_eq!(f.state().captured_wait(), Some(next));
    wake.finish_pass(&mut pass, 100, demand(&mut f).retains_work(), false)
        .unwrap();
    let mut pass = wake.begin_pass(110).unwrap().unwrap();
    assert_eq!(
        repark(&mut f, &mut state, &mut arbiter, next, 2).unwrap(),
        (Admission::Parked { wait_id: 72 }, previous)
    );
    assert_eq!(next_work(&mut f), None);
    assert!(!f.lanes.execution_busy());
    assert!(f.lanes.next_resumable().is_none());
    assert_eq!(demand(&mut f), ResumeDemand::Empty);
    wake.finish_pass(&mut pass, 110, demand(&mut f).retains_work(), true)
        .unwrap();
    assert_eq!(wake.next_deadline(), None);
    // The parked NT wait still owns its original deadline and real Event lease.
    assert_eq!(arbiter.next_deadline(now()), Some(100_010));
    assert_eq!(state.event_objects.live_lease_count(), 1);
    assert_eq!(next.observed_at(), previous.observed_at());
}
