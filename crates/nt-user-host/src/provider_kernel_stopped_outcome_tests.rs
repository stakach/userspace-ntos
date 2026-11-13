use super::*;
use crate::provider_kernel_wait::KernelProviderStoppedOutcome as Stop;

#[test]
fn stopped_outcome_requires_a_complete_non_yield_observation() {
    for mask in 0u8..64 {
        let mut state = KernelProviderWaitState::new(42).unwrap();
        assert_eq!(state.stopped_outcome(), Err(STATUS_INVALID_PARAMETER));
        let mut attempt = state.begin_initial().unwrap();
        assert_eq!(state.stopped_outcome(), Err(STATUS_INVALID_PARAMETER));
        let mut observed = facts(42, false);
        observed.completed = mask & 1 != 0;
        observed.callback_suspended = mask & 2 != 0;
        observed.provider_wait_suspended = mask & 4 != 0;
        observed.lpc_wait_suspended = mask & 8 != 0;
        observed.scheduler_yielded = mask & 16 != 0;
        observed.source_work_yielded = mask & 32 != 0;
        state
            .observe(
                &mut attempt,
                observed,
                observed.completed.then_some(0xc0000001),
            )
            .unwrap();
        let expected = match mask {
            0 => Ok(Stop::Walled),
            1 => Ok(Stop::Returned(0xc0000001)),
            2 => Ok(Stop::CallbackSuspended),
            8 => Ok(Stop::LpcWaitSuspended),
            32 => Ok(Stop::SourceWorkYielded),
            _ => Err(STATUS_INVALID_PARAMETER),
        };
        assert_eq!(state.stopped_outcome(), expected, "mask={mask}");
        assert_eq!(state.stopped_outcome(), expected, "read-only repeat");
        assert_eq!(
            state.begin_initial().unwrap_err(),
            PumpProgressError::NotReady
        );
    }
}

#[test]
fn captured_stop_does_not_survive_entry_or_authorize_a_later_observation() {
    let mut f = Fixture::new();
    assert_eq!(
        f.state().stopped_outcome(),
        Ok(Stop::WaitCaptured(f.capture))
    );
    assert_eq!(f.state().captured_wait(), Some(f.capture));
    f.lanes.select(f.capture.key(), 258).unwrap();
    let (_, mut attempt, _) = f.resume().unwrap().into_parts();
    assert_eq!(f.state().stopped_outcome(), Err(STATUS_INVALID_PARAMETER));
    let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
    let state = &mut f.activations.recipient_mut(f.caller).unwrap().state;
    state
        .observe(&mut attempt, facts(reply, false), None)
        .unwrap();
    assert_eq!(state.stopped_outcome(), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        state.retain_provider_wait(*f.capture.request(), Ok(f.capture)),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(state.stopped_outcome(), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(state.active_resume(), Some(f.capture));
}

#[test]
fn rejected_stop_preserves_the_original_status_and_request() {
    let mut state = KernelProviderWaitState::new(42).unwrap();
    let mut attempt = state.begin_initial().unwrap();
    state.observe(&mut attempt, facts(42, false), None).unwrap();
    let request = ProviderWaitRequest::empty();
    assert_eq!(
        state.retain_provider_wait(request, Err(STATUS_INVALID_HANDLE)),
        Err(STATUS_INVALID_HANDLE)
    );
    for _ in 0..2 {
        assert_eq!(state.stopped_outcome(), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            state.rejected_wait(),
            Some((&request, STATUS_INVALID_HANDLE))
        );
        assert!(state.captured_wait().is_none());
    }
}

fn stop_facts(source_work_yielded: bool) -> KernelProviderPumpFacts {
    let mut observed = facts(42, false);
    observed.provider_wait_suspended = false;
    observed.source_work_yielded = source_work_yielded;
    observed
}

/// Issue #379: an exit callout stopped on its own inline source terminal stays an owned,
/// resumable stop. It is resumed once after the terminal is acknowledged and reaches Returned.
#[test]
fn source_work_stop_is_owned_resumed_once_after_the_terminal_and_returns() {
    use crate::provider_kernel_pump::KernelSourceTerminal as Terminal;
    let mut state = KernelProviderWaitState::new(42).unwrap();
    let mut attempt = state.begin_initial().unwrap();
    state.observe(&mut attempt, stop_facts(true), None).unwrap();
    assert_eq!(state.stopped_outcome(), Ok(Stop::SourceWorkYielded));
    assert!(state.captured_wait().is_none());
    assert!(!state.resumed_from_wait());

    assert_eq!(
        state
            .begin_receive_after_source_work(Terminal::Unacknowledged)
            .unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(state.stopped_outcome(), Ok(Stop::SourceWorkYielded));

    let mut receive = state
        .begin_receive_after_source_work(Terminal::Acknowledged)
        .unwrap();
    // The entered receive is no longer a stop; a second entry would replay the callout.
    assert_eq!(state.stopped_outcome(), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        state
            .begin_receive_after_source_work(Terminal::Acknowledged)
            .unwrap_err(),
        PumpProgressError::NotReady
    );
    state
        .observe(&mut receive, facts(42, true), Some(0))
        .unwrap();
    assert_eq!(state.stopped_outcome(), Ok(Stop::Returned(0)));
    for terminal in [Terminal::Unacknowledged, Terminal::Acknowledged, Terminal::Indeterminate] {
        assert!(state.begin_receive_after_source_work(terminal).is_err());
        assert_eq!(state.stopped_outcome(), Ok(Stop::Returned(0)));
    }
}

#[test]
fn walled_stop_is_never_a_source_work_resume() {
    use crate::provider_kernel_pump::KernelSourceTerminal as Terminal;
    let mut state = KernelProviderWaitState::new(42).unwrap();
    let mut attempt = state.begin_initial().unwrap();
    state.observe(&mut attempt, stop_facts(false), None).unwrap();
    assert_eq!(state.stopped_outcome(), Ok(Stop::Walled));
    assert_eq!(
        state
            .begin_receive_after_source_work(Terminal::Acknowledged)
            .unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(state.stopped_outcome(), Ok(Stop::Walled));
}

#[test]
fn indeterminate_source_terminal_keeps_the_stop_owned_and_unentered() {
    use crate::provider_kernel_pump::KernelSourceTerminal as Terminal;
    let mut state = KernelProviderWaitState::new(42).unwrap();
    let mut attempt = state.begin_initial().unwrap();
    state.observe(&mut attempt, stop_facts(true), None).unwrap();
    assert_eq!(
        state
            .begin_receive_after_source_work(Terminal::Indeterminate)
            .unwrap_err(),
        PumpProgressError::SourceTerminalIndeterminate
    );
    assert_eq!(state.stopped_outcome(), Ok(Stop::SourceWorkYielded));
}

#[test]
fn a_wait_resumed_job_reports_its_origin() {
    let mut f = Fixture::new();
    assert!(!f.state().resumed_from_wait());
    f.lanes.select(f.capture.key(), 258).unwrap();
    let _ticket = f.resume().unwrap();
    assert!(f.state().resumed_from_wait());
}
