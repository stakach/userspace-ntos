use super::*;
use nt_component_suspension::{TerminalAttempt, TerminalIdentity, TerminalPhase};

const RETURNED: u32 = 0xc000_0001;

#[path = "provider_kernel_completion_wake_tests.rs"]
mod wake;

fn pending(f: &mut Fixture, observed: bool) -> TerminalIdentity {
    f.lanes.select(f.capture.key(), 258).unwrap();
    let (_, mut attempt, _) = f.resume().unwrap().into_parts();
    let mut result = facts(f.caller.binding.reply_object, true);
    result.completed = observed;
    f.activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .observe(&mut attempt, result, observed.then_some(RETURNED))
        .unwrap();
    f.activations
        .retain_terminal_completion(
            f.caller,
            &f.pm,
            &f.catalog,
            &mut f.lanes,
            f.capture.key(),
            456,
            RETURNED,
        )
        .unwrap()
}

fn begin(f: &mut Fixture, terminal: TerminalIdentity) -> TerminalAttempt {
    f.lanes
        .begin_terminal_stage(
            terminal,
            f.caller.binding.reply_object,
            TerminalStage::LocalDelivery,
        )
        .unwrap()
}

fn deliver(
    f: &mut Fixture,
    terminal: TerminalIdentity,
    attempt: &TerminalAttempt,
) -> Result<(), u32> {
    f.activations.with_terminal_recipient(
        f.caller,
        &f.pm,
        &mut f.lanes,
        terminal,
        attempt,
        |recipient, payload, status| {
            assert_eq!(*payload, 456);
            recipient.state.deliver_terminal_return(terminal, status)?;
            *recipient.bank = status as u64;
            Ok(())
        },
    )?
}

#[test]
fn local_destination_receives_return_not_wait_status_before_exact_retirement_and_ack() {
    let mut f = Fixture::new();
    let bank = &*f.activations.recipient(f.caller).unwrap().bank as *const u64;
    let terminal = pending(&mut f, true);
    let reply = f.caller.binding.reply_object;
    assert!(f.activations.recipient_mut(f.caller).is_err());
    assert!(f.activations.completion(f.caller).is_err());
    let mut attempt = begin(&mut f, terminal);
    assert_eq!(deliver(&mut f, terminal, &attempt), Ok(()));
    assert!(f.state().delivered_terminal_return(terminal, RETURNED));
    assert_eq!(
        *f.activations.recipient(f.caller).unwrap().bank,
        RETURNED as u64
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    assert!(f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .is_err());
    f.lanes
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    assert!(deliver(&mut f, terminal, &attempt).is_err());
    assert!(f
        .activations
        .finish_terminal_completion(
            f.caller,
            &f.pm,
            &mut f.lanes,
            terminal,
            Err(STATUS_INVALID_HANDLE)
        )
        .unwrap()
        .is_none());
    assert!(matches!(
        f.lanes.terminal(terminal, reply).unwrap().phase,
        TerminalPhase::Acknowledged { .. }
    ));
    assert!(f.activations.completion(f.caller).is_err());
    let (receipt, retired) = f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.suspension.completion, 258);
    assert_eq!(receipt.status(), RETURNED);
    assert_eq!(
        &*f.activations.recipient(f.caller).unwrap().bank as *const u64,
        bank
    );
    let wrong = KernelProviderCompletionReceipt {
        status: 258,
        ..receipt
    };
    assert!(f
        .activations
        .acknowledge_completion_with_recipient(wrong, &mut f.pm)
        .is_err());
    assert!(f.state().delivered_terminal_return(terminal, RETURNED));
    let (status, recipient) = f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .unwrap();
    assert_eq!(status, RETURNED);
    assert_eq!(&*recipient.bank as *const u64, bank);
    assert_eq!(references(&f.pm, f.caller.thread()), (0, 0));
}

#[test]
fn foreign_terminal_attempt_caller_and_manager_never_access_the_recipient() {
    let mut f = Fixture::new();
    let terminal = pending(&mut f, true);
    let mut peer = Fixture::new();
    let foreign_terminal = pending(&mut peer, true);
    let foreign_attempt = begin(&mut peer, foreign_terminal);
    let mut attempt = begin(&mut f, terminal);
    assert!(f
        .activations
        .with_terminal_recipient(
            f.caller,
            &peer.pm,
            &mut f.lanes,
            terminal,
            &attempt,
            |_, _, _| panic!("foreign PM entered delivery")
        )
        .is_err());
    assert!(f
        .activations
        .with_terminal_recipient(
            peer.caller,
            &f.pm,
            &mut f.lanes,
            terminal,
            &attempt,
            |_, _, _| panic!("foreign caller entered delivery")
        )
        .is_err());
    assert!(f
        .activations
        .with_terminal_recipient(
            f.caller,
            &f.pm,
            &mut f.lanes,
            foreign_terminal,
            &attempt,
            |_, _, _| panic!("foreign identity entered delivery")
        )
        .is_err());
    assert!(f
        .activations
        .with_terminal_recipient(
            f.caller,
            &f.pm,
            &mut f.lanes,
            terminal,
            &foreign_attempt,
            |_, _, _| panic!("foreign attempt entered delivery")
        )
        .is_err());
    assert!(!f.state().delivered_terminal_return(terminal, RETURNED));
    assert_eq!(*f.activations.recipient(f.caller).unwrap().bank, 0x1234);
    assert_eq!(deliver(&mut f, terminal, &attempt), Ok(()));
    f.lanes
        .record_terminal_stage(
            &mut attempt,
            f.caller.binding.reply_object,
            TerminalStageOutcome::Acknowledged,
        )
        .unwrap();
    assert!(f
        .activations
        .with_terminal_recipient(
            f.caller,
            &f.pm,
            &mut f.lanes,
            terminal,
            &attempt,
            |_, _, _| panic!("consumed attempt entered delivery")
        )
        .is_err());
}

#[test]
fn unobserved_or_wrong_return_is_no_effects_and_never_ready_completion() {
    for observed in [false, true] {
        let mut f = Fixture::new();
        let terminal = pending(&mut f, observed);
        let reply = f.caller.binding.reply_object;
        let mut attempt = begin(&mut f, terminal);
        let wrong = f
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
        assert_eq!(wrong, Err(STATUS_INVALID_PARAMETER));
        assert!(!f.state().delivered_terminal_return(terminal, RETURNED));
        assert!(!f.state().delivered_terminal_return(terminal, RETURNED + 1));
        if !observed {
            assert_eq!(
                deliver(&mut f, terminal, &attempt),
                Err(STATUS_INVALID_PARAMETER)
            );
        }
        f.lanes
            .record_terminal_stage(
                &mut attempt,
                reply,
                TerminalStageOutcome::NoEffects(STATUS_INVALID_PARAMETER),
            )
            .unwrap();
        assert!(deliver(&mut f, terminal, &attempt).is_err());
        assert!(f.activations.completion(f.caller).is_err());
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
        let retry = begin(&mut f, terminal);
        if observed {
            assert_eq!(deliver(&mut f, terminal, &retry), Ok(()));
            assert_eq!(deliver(&mut f, terminal, &retry), Ok(()));
        } else {
            assert_eq!(
                deliver(&mut f, terminal, &retry),
                Err(STATUS_INVALID_PARAMETER)
            );
        }
    }
}

#[test]
fn delivered_local_result_survives_lost_ack_without_reopening_execution() {
    let mut f = Fixture::new();
    let terminal = pending(&mut f, true);
    let attempt = begin(&mut f, terminal);
    deliver(&mut f, terminal, &attempt).unwrap();
    drop(attempt);
    assert!(f.state().delivered_terminal_return(terminal, RETURNED));
    assert_eq!(f.lanes.next_terminal(), None);
    assert!(f
        .lanes
        .begin_terminal_stage(
            terminal,
            f.caller.binding.reply_object,
            TerminalStage::LocalDelivery
        )
        .is_err());
    assert!(f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .is_err());
    assert!(f.activations.completion(f.caller).is_err());
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
}

#[test]
fn exited_caller_and_retired_provider_keep_the_original_local_destination() {
    let mut f = Fixture::new();
    let terminal = pending(&mut f, true);
    f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
        .unwrap();
    f.catalog.retire(f.provider, 0).unwrap();
    let mut attempt = begin(&mut f, terminal);
    deliver(&mut f, terminal, &attempt).unwrap();
    f.lanes
        .record_terminal_stage(
            &mut attempt,
            f.caller.binding.reply_object,
            TerminalStageOutcome::Acknowledged,
        )
        .unwrap();
    let (receipt, _) = f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    let (_, recipient) = f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .unwrap();
    assert!(recipient
        .state
        .delivered_terminal_return(terminal, RETURNED));
    assert_eq!(references(&f.pm, f.caller.thread()), (0, 0));
}
