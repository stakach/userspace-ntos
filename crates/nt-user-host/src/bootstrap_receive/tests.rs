use super::*;

fn ready() -> BootstrapReceiveFacts {
    BootstrapReceiveFacts {
        bootstrap_owned: true,
        invocation_active: false,
        pass_active: false,
        timer_delivery_active: false,
        physical_execution_active: false,
        rearm_pending: false,
    }
}

#[test]
fn pending_checkpoint_work_is_retryable_only_without_other_owners() {
    assert!(!ready().needs_service());
    let pending = BootstrapReceiveFacts {
        rearm_pending: true,
        ..ready()
    };
    assert!(pending.needs_service());
    for gate in 0..5 {
        let mut facts = pending;
        match gate {
            0 => facts.bootstrap_owned = false,
            1 => facts.invocation_active = true,
            2 => facts.pass_active = true,
            3 => facts.timer_delivery_active = true,
            _ => facts.physical_execution_active = true,
        }
        assert!(!facts.needs_service());
    }
}

#[test]
fn target_ack_survives_rearm_failure_and_is_taken_once() {
    let mut owner = BootstrapCoordinator::new(7).unwrap();
    owner.acknowledge(7, false).unwrap();
    owner.invalidate_checkpoint().unwrap();
    let mut facts = ready();
    facts.rearm_pending = true;
    assert!(owner.checkpoint(facts).is_err());
    assert_eq!(owner.completion(), Some(false));
    assert_eq!(owner.take_completion(), Ok(false));
    assert_eq!(
        owner.take_completion(),
        Err(BootstrapReceiveError::CompletionTaken)
    );
    assert_eq!(owner.completion(), None);
    assert!(owner.checkpoint(ready()).is_err());
    assert_eq!(
        owner.acknowledge(7, true),
        Err(BootstrapReceiveError::AlreadyAcknowledged)
    );
}

#[test]
fn wrong_target_does_not_acknowledge_or_invalidate_permission() {
    let mut owner = BootstrapCoordinator::new(7).unwrap();
    let mut permit = owner.checkpoint(ready()).unwrap();
    assert_eq!(
        owner.acknowledge(8, true),
        Err(BootstrapReceiveError::WrongTarget)
    );
    assert_eq!(
        owner.take_completion(),
        Err(BootstrapReceiveError::NotAcknowledged)
    );
    owner.enter_receive(&mut permit).unwrap();
    owner.finish_receive(&mut permit).unwrap();
    assert_eq!(owner.completion(), None);
}

#[test]
fn every_gate_and_transfer_blocks_and_invalidates_old_permission() {
    for gate in 0..6 {
        let mut owner = BootstrapCoordinator::new(7).unwrap();
        let mut stale = owner.checkpoint(ready()).unwrap();
        let mut facts = ready();
        match gate {
            0 => facts.bootstrap_owned = false,
            1 => facts.invocation_active = true,
            2 => facts.pass_active = true,
            3 => facts.timer_delivery_active = true,
            4 => facts.physical_execution_active = true,
            _ => facts.rearm_pending = true,
        }
        assert!(matches!(
            owner.checkpoint(facts),
            Err(BootstrapReceiveError::Blocked)
        ));
        assert_eq!(
            owner.enter_receive(&mut stale),
            Err(BootstrapReceiveError::WrongPermit)
        );
    }
}

#[test]
fn failed_checkpoint_work_and_new_checkpoints_invalidate_stale_permits() {
    let mut owner = BootstrapCoordinator::new(7).unwrap();
    let mut old = owner.checkpoint(ready()).unwrap();
    owner.invalidate_checkpoint().unwrap();
    assert!(owner.enter_receive(&mut old).is_err());
    let mut old = owner.checkpoint(ready()).unwrap();
    let mut current = owner.checkpoint(ready()).unwrap();
    assert!(owner.enter_receive(&mut old).is_err());
    owner.enter_receive(&mut current).unwrap();
}

#[test]
fn uncertain_entered_receive_cannot_replay_or_authorize_another_pass() {
    let mut owner = BootstrapCoordinator::new(7).unwrap();
    let mut permit = owner.checkpoint(ready()).unwrap();
    assert!(owner.finish_receive(&mut permit).is_err());
    owner.enter_receive(&mut permit).unwrap();
    assert!(owner.enter_receive(&mut permit).is_err());
    assert_eq!(
        owner.invalidate_checkpoint(),
        Err(BootstrapReceiveError::ReceiveEntered)
    );
    assert!(matches!(
        owner.checkpoint(ready()),
        Err(BootstrapReceiveError::ReceiveEntered)
    ));
    owner.finish_receive(&mut permit).unwrap();
    assert!(owner.finish_receive(&mut permit).is_err());
    assert!(owner.enter_receive(&mut permit).is_err());
}

#[test]
fn equal_target_does_not_authorize_a_foreign_coordinator() {
    let mut first = BootstrapCoordinator::new(7).unwrap();
    let mut second = BootstrapCoordinator::new(7).unwrap();
    let mut permit = first.checkpoint(ready()).unwrap();
    let _second_permit = second.checkpoint(ready()).unwrap();
    assert!(second.enter_receive(&mut permit).is_err());
    first.enter_receive(&mut permit).unwrap();
    assert!(second.finish_receive(&mut permit).is_err());
    first.finish_receive(&mut permit).unwrap();
}

#[test]
fn repeated_bounded_passes_and_unrelated_arrivals_preserve_target_ownership() {
    let mut owner = BootstrapCoordinator::new(7).unwrap();
    for _ in 0..16 {
        owner.invalidate_checkpoint().unwrap();
        let mut permit = owner.checkpoint(ready()).unwrap();
        owner.enter_receive(&mut permit).unwrap();
        owner.finish_receive(&mut permit).unwrap();
        assert_eq!(owner.completion(), None);
    }
    owner.acknowledge(7, true).unwrap();
    assert_eq!(owner.take_completion(), Ok(true));
}

#[test]
fn target_ack_invalidates_unentered_permit_but_keeps_entered_receive_owned() {
    for entered in [false, true] {
        let mut owner = BootstrapCoordinator::new(7).unwrap();
        let mut permit = owner.checkpoint(ready()).unwrap();
        if entered {
            owner.enter_receive(&mut permit).unwrap();
        }
        owner.acknowledge(7, true).unwrap();
        assert!(owner.enter_receive(&mut permit).is_err());
        if entered {
            assert_eq!(owner.completion(), Some(true));
            assert_eq!(
                owner.take_completion(),
                Err(BootstrapReceiveError::ReceiveEntered)
            );
            owner.finish_receive(&mut permit).unwrap();
        }
        assert_eq!(owner.take_completion(), Ok(true));
    }
}
