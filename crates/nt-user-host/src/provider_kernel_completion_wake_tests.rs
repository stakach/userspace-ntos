use super::*;
use nt_component_suspension::{ResumeDemand, ResumeWake};

fn has_work(f: &Fixture) -> bool {
    f.activations.has_ready_completion() || f.lanes.next_terminal().is_some()
}

#[test]
fn terminal_only_refusal_keeps_retry_until_exact_retirement_and_ack() {
    let mut f = Fixture::new();
    let terminal = pending(&mut f, true);
    let reply = f.caller.binding.reply_object;
    let mut wake = ResumeWake::new(10, 40).unwrap();
    assert!(!f.activations.has_ready_completion());
    assert!(has_work(&f));
    assert!(f.lanes.next_resumable().is_none());
    assert!(!f.lanes.execution_busy());
    let demand = ResumeDemand::observe(f.lanes.execution_busy(), false, || has_work(&f));
    assert_eq!(demand, ResumeDemand::Pending);
    wake.reconcile_demand(demand, 100);

    for (now, next) in [(100, 110), (110, 130)] {
        let mut pass = wake.begin_pass(now).unwrap().unwrap();
        let mut attempt = begin(&mut f, terminal);
        let result = f
            .activations
            .with_terminal_recipient(
                f.caller,
                &f.pm,
                &mut f.lanes,
                terminal,
                &attempt,
                |recipient, _, _| {
                    recipient
                        .state
                        .deliver_terminal_return(terminal, RETURNED + 1)
                },
            )
            .unwrap();
        assert_eq!(result, Err(STATUS_INVALID_PARAMETER));
        f.lanes
            .record_terminal_stage(
                &mut attempt,
                reply,
                TerminalStageOutcome::NoEffects(STATUS_INVALID_PARAMETER),
            )
            .unwrap();
        wake.finish_pass(&mut pass, now, has_work(&f), result.is_ok())
            .unwrap();
        assert_eq!(wake.next_deadline(), Some(next));
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    }

    let mut pass = wake.begin_pass(130).unwrap().unwrap();
    let mut attempt = begin(&mut f, terminal);
    deliver(&mut f, terminal, &attempt).unwrap();
    f.lanes
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    // Local delivery alone does not report successful terminal retirement.
    let refused = f
        .activations
        .finish_terminal_completion(
            f.caller,
            &f.pm,
            &mut f.lanes,
            terminal,
            Err(STATUS_INVALID_HANDLE),
        )
        .unwrap();
    assert!(refused.is_none());
    assert!(has_work(&f));
    assert!(!f.activations.has_ready_completion());
    wake.finish_pass(&mut pass, 130, has_work(&f), refused.is_some())
        .unwrap();
    assert_eq!(wake.next_deadline(), Some(170));

    let mut pass = wake.begin_pass(170).unwrap().unwrap();
    let retired = f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap();
    let (receipt, _) = retired.as_ref().unwrap();
    let receipt = *receipt;
    assert!(f.lanes.next_terminal().is_none());
    assert!(f.activations.has_ready_completion());
    wake.finish_pass(&mut pass, 170, has_work(&f), retired.is_some())
        .unwrap();
    assert_eq!(wake.next_deadline(), Some(180));

    let mut pass = wake.begin_pass(180).unwrap().unwrap();
    let wrong = KernelProviderCompletionReceipt {
        status: RETURNED + 1,
        ..receipt
    };
    let refused = f
        .activations
        .acknowledge_completion_with_recipient(wrong, &mut f.pm);
    assert!(refused.is_err());
    assert!(f.activations.has_ready_completion());
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    wake.finish_pass(&mut pass, 180, has_work(&f), refused.is_ok())
        .unwrap();
    assert_eq!(wake.next_deadline(), Some(190));

    let mut pass = wake.begin_pass(190).unwrap().unwrap();
    let accepted = f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm);
    assert_eq!(accepted.as_ref().unwrap().0, RETURNED);
    assert!(!has_work(&f));
    assert_eq!(references(&f.pm, f.caller.thread()), (0, 0));
    wake.finish_pass(&mut pass, 190, has_work(&f), accepted.is_ok())
        .unwrap();
    assert_eq!(wake.next_deadline(), None);
}
