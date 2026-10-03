use super::{OriginCommitObservation as Event, OriginCommitPhase as Phase};

#[test]
fn physical_pool_busy_is_no_effect_at_every_local_commit_boundary() {
    for phase in [Phase::CaptureBefore, Phase::PublishCommand, Phase::ReadAck, Phase::RetirePacket] {
        assert_eq!(phase.observe(Event::BusyNoEffect), Some(phase));
    }
}

#[test]
fn acknowledged_origin_commit_never_reenters_origin_on_local_busy() {
    let phase = Phase::CaptureBefore.observe(Event::CapturedBefore).unwrap();
    let phase = phase.observe(Event::CommandPublished).unwrap();
    assert_eq!(phase, Phase::DispatchOrigin);
    assert_eq!(phase.observe(Event::NotEntered), Some(Phase::DispatchOrigin));
    let phase = phase.observe(Event::ReturnedSuccess).unwrap();
    assert_eq!(phase, Phase::ReadAck);
    assert_eq!(phase.observe(Event::BusyNoEffect), Some(Phase::ReadAck));
    assert_eq!(phase.observe(Event::NotEntered), None);
    assert_eq!(phase.observe(Event::CommandPublished), None);
    let phase = phase.observe(Event::AckValidated).unwrap();
    assert_eq!(phase, Phase::RetirePacket);
    assert_eq!(phase.observe(Event::BusyNoEffect), Some(Phase::RetirePacket));
    assert_eq!(phase.observe(Event::ReturnedSuccess), None);
    assert_eq!(phase.observe(Event::PacketRetired), Some(Phase::Complete));
}

#[test]
fn invalid_ack_or_unknown_origin_effect_quarantines_without_replay() {
    assert_eq!(Phase::DispatchOrigin.observe(Event::Uncertain), Some(Phase::Indeterminate));
    assert_eq!(Phase::ReadAck.observe(Event::InvalidAck), Some(Phase::Indeterminate));
    for event in [Event::BusyNoEffect, Event::NotEntered, Event::ReturnedSuccess,
        Event::AckValidated, Event::PacketRetired]
    {
        assert_eq!(Phase::Indeterminate.observe(event), None);
        assert_eq!(Phase::Complete.observe(event), None);
    }
}

#[test]
fn readback_and_retirement_cannot_skip_the_origin_return_receipt() {
    assert_eq!(Phase::CaptureBefore.observe(Event::AckValidated), None);
    assert_eq!(Phase::PublishCommand.observe(Event::ReturnedSuccess), None);
    assert_eq!(Phase::DispatchOrigin.observe(Event::PacketRetired), None);
    assert_eq!(Phase::ReadAck.observe(Event::PacketRetired), None);
}

#[test]
fn retained_command_snapshot_rejects_changed_payload_after_busy_readback() {
    let command = [0x5au8; 48];
    let phase = Phase::DispatchOrigin.observe(Event::ReturnedSuccess).unwrap();
    let phase = phase.observe(Event::BusyNoEffect).unwrap();
    let mut readback = command;
    readback[32] ^= 1;
    let observation = if super::same_terminal_packet(&command, &readback, 8) {
        Event::AckValidated
    } else {
        Event::InvalidAck
    };
    assert_eq!(phase.observe(observation), Some(Phase::Indeterminate));
}
