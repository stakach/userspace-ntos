use super::*;

#[path = "provider_kernel_wait_runtime_tests.rs"]
mod runtime;
#[path = "provider_kernel_wait_publication_tests.rs"]
mod publication;

fn next_work(
    f: &mut Fixture,
) -> Option<(KernelProviderCaller, Result<KernelProviderWaitWork, u32>)> {
    let mut cursor = f.activations.wait_work_cursor();
    let work = f
        .activations
        .next_wait_work(&mut cursor, &f.pm, &f.catalog, &f.lanes);
    assert_eq!(
        f.activations
            .next_wait_work(&mut cursor, &f.pm, &f.catalog, &f.lanes),
        None
    );
    work
}

#[test]
fn initial_work_is_metadata_only_and_remains_available_to_a_later_pass() {
    let (mut f, state) = fixture(true);
    let expected = Some((f.caller, Ok(KernelProviderWaitWork::Initial(f.capture))));
    let bank = &*f.activations.recipient(f.caller).unwrap().bank as *const u64;
    for _ in 0..2 {
        assert_eq!(next_work(&mut f), expected);
        assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(0));
        assert_eq!(f.state().captured_wait(), Some(f.capture));
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
        assert_eq!(state.event_objects.live_lease_count(), 0);
        assert!(state.events.read_state(101));
        assert_eq!(
            &*f.activations.recipient(f.caller).unwrap().bank as *const u64,
            bank
        );
    }
}

#[test]
fn admitted_waiting_selected_and_cancelled_frames_are_not_published_twice() {
    for phase in 0..3 {
        let (mut f, mut state) = fixture(phase == 1);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
        if phase == 2 {
            f.lanes.cancel(f.capture.key(), -1).unwrap();
        }
        let frame = f.lanes.top(f.caller.dispatch.lane()).unwrap().cloned();
        let leases = state.event_objects.live_lease_count();
        assert_eq!(next_work(&mut f), None);
        assert_eq!(
            f.lanes.top(f.caller.dispatch.lane()).unwrap().cloned(),
            frame
        );
        assert_eq!(state.event_objects.live_lease_count(), leases);
        assert_eq!(f.state().captured_wait(), Some(f.capture));
    }
}

#[test]
fn repeated_work_pairs_the_new_capture_with_the_original_active_resume() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let original = f.capture;
    for (id, sequence) in [(72, 2), (71, 3)] {
        let next = next_capture(&mut f, id);
        let expected = Some((
            f.caller,
            Ok(KernelProviderWaitWork::Repark {
                previous: f.capture,
                next,
            }),
        ));
        assert_eq!(next_work(&mut f), expected);
        assert_eq!(f.state().active_resume(), Some(f.capture));
        assert_eq!(f.state().captured_wait(), Some(next));
        state.events.set_existing(101).unwrap();
        repark(&mut f, &mut state, &mut arbiter, next, sequence).unwrap();
        f.capture = next;
        assert_eq!(next_work(&mut f), None);
    }
    assert_ne!(f.capture, original);
}

#[test]
fn stale_authority_is_reported_once_without_retiring_the_original_recipient() {
    for mode in 0..4 {
        let (mut f, _) = fixture(false);
        let lane = f.caller.dispatch.lane();
        let reply = f.caller.binding.reply_object;
        match mode {
            0 => {
                f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
                    .unwrap();
            }
            1 => {
                f.catalog.retire(f.provider, 0).unwrap();
            }
            2 => {
                f.lanes.finish_dispatch(lane, reply).unwrap();
                f.lanes.begin_dispatch(lane, reply).unwrap();
            }
            _ => {
                f.activations.rows[0].caller.binding.reply_object += 1;
            }
        }
        let retained = f.activations.rows[0].caller;
        assert_eq!(
            next_work(&mut f),
            Some((retained, Err(STATUS_INVALID_HANDLE)))
        );
        assert_eq!(f.activations.rows.len(), 1);
        assert_eq!(
            f.activations
                .recipient(retained)
                .unwrap()
                .state
                .captured_wait(),
            Some(f.capture)
        );
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    }
}

#[test]
fn foreign_authority_and_mismatched_admitted_capture_cannot_hide_as_no_work() {
    let (mut f, mut state) = fixture(false);
    let (peer, _) = fixture(false);
    for (pm, catalog) in [(&peer.pm, &f.catalog), (&f.pm, &peer.catalog)] {
        let mut cursor = f.activations.wait_work_cursor();
        assert_eq!(
            f.activations
                .next_wait_work(&mut cursor, pm, catalog, &f.lanes),
            Some((f.caller, Err(STATUS_INVALID_HANDLE)))
        );
    }
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    f.lanes
        .frame_mut(f.caller.dispatch.lane(), f.capture.key())
        .unwrap()
        .unwrap()
        .continuation = peer.capture;
    assert_eq!(
        next_work(&mut f),
        Some((f.caller, Err(STATUS_INVALID_HANDLE)))
    );
    assert_eq!(state.event_objects.live_lease_count(), 1);
    assert_eq!(f.state().captured_wait(), Some(f.capture));
}

#[test]
fn stale_same_id_frame_cannot_substitute_for_the_active_resume_origin() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let original = f.capture;
    for (id, sequence) in [(72, 2), (71, 3)] {
        let next = next_capture(&mut f, id);
        state.events.set_existing(101).unwrap();
        repark(&mut f, &mut state, &mut arbiter, next, sequence).unwrap();
        f.capture = next;
    }
    let next = next_capture(&mut f, 73);
    f.lanes
        .frame_mut(f.caller.dispatch.lane(), f.capture.key())
        .unwrap()
        .unwrap()
        .continuation = original;
    assert_eq!(
        next_work(&mut f),
        Some((f.caller, Err(STATUS_INVALID_HANDLE)))
    );
    assert_eq!(f.state().captured_wait(), Some(next));
    assert_eq!(f.state().active_resume(), Some(f.capture));
    assert_eq!(state.event_objects.live_lease_count(), 0);
}

fn append_waiting_activation(f: &mut Fixture) -> KernelProviderWaitCapture {
    append_waiting_activation_with(f, |_| {})
}

fn append_waiting_activation_with(
    f: &mut Fixture,
    update: impl FnOnce(&mut ProviderWaitRequest),
) -> KernelProviderWaitCapture {
    let native = requestor(&mut f.pm, 0x6000);
    let lane = f.lanes.allocate(binding(2)).unwrap();
    let reply = binding(2).reply_object;
    f.lanes.begin_dispatch(lane, reply).unwrap();
    let mut state = KernelProviderWaitState::new(reply).unwrap();
    let mut attempt = state.begin_initial().unwrap();
    state
        .observe(&mut attempt, facts(reply, false), None)
        .unwrap();
    let caller = f
        .activations
        .capture_with_recipient(
            &mut f.pm,
            &f.catalog,
            &f.lanes,
            f.provider,
            lane,
            native,
            Recipient {
                state,
                bank: Box::new(0x5678),
            },
        )
        .unwrap_or_else(|(status, _)| panic!("capture failed: {status:x}"));
    let mut request = request(caller.owner(), 81);
    update(&mut request);
    let capture = f
        .activations
        .capture_provider_wait(
            caller,
            &f.pm,
            &f.catalog,
            &f.lanes,
            reply,
            f.activations.recipient(caller).unwrap().state.progress(),
            request,
        )
        .unwrap();
    f.activations
        .recipient_mut(caller)
        .unwrap()
        .state
        .retain_provider_wait(request, Ok(capture))
        .unwrap();
    capture
}

#[test]
fn bounded_pass_excludes_later_rows_and_does_not_revisit_failed_rows() {
    let (mut f, _) = fixture(false);
    f.lanes
        .suspend_running(f.caller.dispatch.lane(), f.caller.binding.reply_object, 99)
        .unwrap();
    let mut old = f.activations.wait_work_cursor();
    let second = append_waiting_activation(&mut f);
    assert_eq!(
        f.activations
            .next_wait_work(&mut old, &f.pm, &f.catalog, &f.lanes),
        Some((f.caller, Err(STATUS_INVALID_HANDLE)))
    );
    assert_eq!(
        f.activations
            .next_wait_work(&mut old, &f.pm, &f.catalog, &f.lanes),
        None
    );
    let mut fresh = f.activations.wait_work_cursor();
    assert_eq!(
        f.activations
            .next_wait_work(&mut fresh, &f.pm, &f.catalog, &f.lanes),
        Some((f.caller, Err(STATUS_INVALID_HANDLE)))
    );
    assert_eq!(
        f.activations
            .next_wait_work(&mut fresh, &f.pm, &f.catalog, &f.lanes),
        Some((second.caller(), Ok(KernelProviderWaitWork::Initial(second))))
    );
    assert_eq!(
        f.activations
            .next_wait_work(&mut fresh, &f.pm, &f.catalog, &f.lanes),
        None
    );
    assert_eq!(f.state().captured_wait(), Some(f.capture));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    assert_eq!(references(&f.pm, second.caller().thread()), (1, 1));
}

#[test]
fn a_new_capture_in_a_visited_activation_waits_for_the_next_pass() {
    let (mut f, mut state) = fixture(true);
    let mut cursor = f.activations.wait_work_cursor();
    assert_eq!(
        f.activations
            .next_wait_work(&mut cursor, &f.pm, &f.catalog, &f.lanes),
        Some((f.caller, Ok(KernelProviderWaitWork::Initial(f.capture))))
    );
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let next = next_capture(&mut f, 72);
    assert_eq!(
        f.activations
            .next_wait_work(&mut cursor, &f.pm, &f.catalog, &f.lanes),
        None
    );
    assert_eq!(
        next_work(&mut f),
        Some((
            f.caller,
            Ok(KernelProviderWaitWork::Repark {
                previous: f.capture,
                next,
            })
        ))
    );
}

#[test]
fn rejected_or_uncaptured_waits_report_errors_and_other_pump_stops_are_skipped() {
    for mode in 0..7 {
        let (mut f, _) = fixture(false);
        let reply = f.caller.binding.reply_object;
        let mut state = KernelProviderWaitState::new(reply).unwrap();
        let mut attempt = state.begin_initial().unwrap();
        let mut observed = facts(reply, false);
        observed.provider_wait_suspended = mode < 2;
        observed.callback_suspended = mode == 2;
        observed.lpc_wait_suspended = mode == 3;
        observed.scheduler_yielded = mode == 4;
        observed.completed = mode == 5;
        state
            .observe(&mut attempt, observed, (mode == 5).then_some(7))
            .unwrap();
        if mode == 0 {
            assert_eq!(
                state.retain_provider_wait(*f.capture.request(), Err(0xc000000d)),
                Err(0xc000000d)
            );
        }
        f.activations.recipient_mut(f.caller).unwrap().state = state;
        let expected = match mode {
            0 => Some((f.caller, Err(0xc000000d))),
            1 => Some((f.caller, Err(STATUS_INVALID_HANDLE))),
            _ => None,
        };
        assert_eq!(next_work(&mut f), expected);
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
        assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(0));
        if mode == 0 {
            assert_eq!(
                f.state().rejected_wait(),
                Some((f.capture.request(), 0xc000000d))
            );
        }
    }
}
