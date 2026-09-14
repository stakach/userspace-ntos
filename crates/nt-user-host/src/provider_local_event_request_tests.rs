use super::*;

#[test]
fn publish_accepts_only_exact_event_types_and_boolean_states() {
    for event_type in 0..=1 {
        for signaled in 0..=1 {
            assert_eq!(
                LocalEventRequest::decode(PUBLISH, 41, event_type, signaled),
                Ok(LocalEventRequest::Publish {
                    local: 41,
                    event_type: event_type as u32,
                    signaled: signaled != 0
                })
            );
        }
    }
    for invalid in [2, u32::MAX as u64, 1u64 << 32, u64::MAX] {
        assert_eq!(
            LocalEventRequest::decode(PUBLISH, 41, invalid, 0),
            Err(INVALID_PARAMETER)
        );
        assert_eq!(
            LocalEventRequest::decode(PUBLISH, 41, 0, invalid),
            Err(INVALID_PARAMETER)
        );
    }
}

#[test]
fn memory_local_operations_require_zero_unused_scalar_arguments() {
    for (op, expected) in [
        (RETIRE, LocalEventRequest::Retire { local: 41 }),
        (RESET, LocalEventRequest::Reset { local: 41 }),
        (CLEAR, LocalEventRequest::Clear { local: 41 }),
        (READ, LocalEventRequest::Read { local: 41 }),
        (SET, LocalEventRequest::Set { local: 41 }),
        (PULSE, LocalEventRequest::Pulse { local: 41 }),
    ] {
        assert_eq!(LocalEventRequest::decode(op, 41, 0, 0), Ok(expected));
        for (arg2, arg3) in [(1, 0), (0, 1), (1, 1), (u64::MAX, 0), (0, u64::MAX)] {
            assert_eq!(
                LocalEventRequest::decode(op, 41, arg2, arg3),
                Err(INVALID_PARAMETER)
            );
        }
    }
}

#[test]
fn all_supported_operations_reject_zero_local_identity_without_truncating_valid_local() {
    for op in [
        PUBLISH,
        RETIRE,
        ACK_RETIREMENT,
        SET,
        RESET,
        CLEAR,
        PULSE,
        READ,
    ] {
        let (arg2, arg3) = if op == ACK_RETIREMENT { (1, 1) } else { (0, 0) };
        assert_eq!(
            LocalEventRequest::decode(op, 0, arg2, arg3),
            Err(INVALID_PARAMETER)
        );
    }
    assert_eq!(
        LocalEventRequest::decode(READ, u64::MAX, 0, 0),
        Ok(LocalEventRequest::Read { local: u64::MAX })
    );
}

#[test]
fn retirement_ack_preserves_full_legal_slot_and_generation_fields() {
    let max_slot = 1u64 << nt_types::SLOT_BITS;
    let max_generation = (1u64 << nt_types::GEN_BITS) - 1;
    for slot in [1, 2, max_slot] {
        for generation in [1, 2, max_generation] {
            let LocalEventRequest::Ack { local, id } =
                LocalEventRequest::decode(ACK_RETIREMENT, 41, slot, generation).unwrap()
            else {
                panic!("retirement must decode as an exact acknowledgment");
            };
            assert_eq!(local, 41);
            assert_eq!(id.0.slot(), slot - 1);
            assert_eq!(id.0.generation().0 as u64, generation);
            assert!(!id.is_null());
            assert_eq!(EventObjectId::from_wire_parts(slot, generation), Some(id));
        }
    }
}

#[test]
fn retirement_ack_rejects_overwide_or_zero_fields_instead_of_aliasing_an_id() {
    for slot in [0, (1u64 << nt_types::SLOT_BITS) + 1, u64::MAX] {
        assert_eq!(
            LocalEventRequest::decode(ACK_RETIREMENT, 41, slot, 1),
            Err(INVALID_PARAMETER)
        );
        assert_eq!(EventObjectId::from_wire_parts(slot, 1), None);
    }
    for generation in [
        0,
        1u64 << nt_types::GEN_BITS,
        (1u64 << nt_types::GEN_BITS) + 1,
        u32::MAX as u64,
        1u64 << 32,
        u64::MAX,
    ] {
        assert_eq!(
            LocalEventRequest::decode(ACK_RETIREMENT, 41, 1, generation),
            Err(INVALID_PARAMETER)
        );
        assert_eq!(
            LocalEventRequest::decode(ACK_RETIREMENT, 41, 2, generation),
            Err(INVALID_PARAMETER)
        );
        assert_eq!(EventObjectId::from_wire_parts(1, generation), None);
        assert_eq!(EventObjectId::from_wire_parts(2, generation), None);
    }
}

#[test]
fn process_handle_timer_and_unknown_operations_have_no_fake_local_semantics() {
    for op in (0..=64).chain([1u64 << 32, u64::MAX]) {
        if matches!(
            op,
            PUBLISH | RETIRE | ACK_RETIREMENT | SET | RESET | CLEAR | PULSE | READ
        ) {
            continue;
        }
        assert_eq!(LocalEventRequest::decode(op, 41, 0, 0), Err(NOT_SUPPORTED));
        assert_eq!(
            LocalEventRequest::decode(op, 0, u64::MAX, u64::MAX),
            Err(NOT_SUPPORTED)
        );
    }
}

#[test]
fn signaling_requires_live_dispatcher_but_memory_local_operations_do_not() {
    for op in [
        PUBLISH,
        RETIRE,
        ACK_RETIREMENT,
        SET,
        RESET,
        CLEAR,
        PULSE,
        READ,
    ] {
        let (a, b) = if op == ACK_RETIREMENT { (1, 1) } else { (0, 0) };
        let request = LocalEventRequest::decode(op, 41, a, b).unwrap();
        assert_eq!(request.requires_dispatcher(), matches!(op, SET | PULSE));
    }
}
