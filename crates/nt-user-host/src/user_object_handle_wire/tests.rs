use super::*;

#[test]
fn every_request_round_trips() {
    let publish = Publish {
        mode: AccessMode::UserMode,
        attributes: 0x2,
        body: 0x4000_1230,
        object_type: 0x1_4000_0000,
        generation: 0xFFFF_FFFF,
        granted_access: 0x000F_01FF,
    };
    assert_eq!(Publish::decode(publish.encode()), Ok(publish));
    let lookup = Lookup {
        mode: AccessMode::KernelMode,
        handle: 0x8000_0000_0000_0004,
        desired_access: 0x100,
        expected_type: 0,
    };
    assert_eq!(Lookup::decode(lookup.encode()), Ok(lookup));
    let close = Close { mode: AccessMode::UserMode, handle: 0x14 };
    assert_eq!(Close::decode(close.encode()), Ok(close));
    for information in [None, Some((0x2, 0x000F_037F)), Some((0, 0))] {
        let find = Find { process: 0x9000, body: 0, object_type: 0x5000, information };
        assert_eq!(Find::decode(find.encode()), Ok(find));
    }
    let resolved = Resolved {
        body: 0x4000_1230,
        object_type: 0x1_4000_0000,
        generation: 9,
        granted_access: u32::MAX,
        attributes: 3,
    };
    assert_eq!(Resolved::decode(resolved.encode()), Ok(resolved));
}

#[test]
fn malformed_requests_are_refused() {
    let publish = Publish {
        mode: AccessMode::KernelMode,
        attributes: 0x200,
        body: 0x7000,
        object_type: 0x5000,
        generation: 1,
        granted_access: 1,
    }
    .encode();
    for words in [
        [publish[0] | 0x40 << 16, publish[1], publish[2], publish[3]],
        [publish[0] | 1 << 48, publish[1], publish[2], publish[3]],
        [publish[0] | 1 << 9, publish[1], publish[2], publish[3]],
        [publish[0], 0, publish[2], publish[3]],
        [publish[0], publish[1], 0, publish[3]],
        [publish[0], publish[1], publish[2], 1],
        [publish[0], publish[1], 1 << 56, publish[3]],
        [OP_LOOKUP, publish[1], publish[2], publish[3]],
    ] {
        assert_eq!(Publish::decode(words), Err(STATUS_INVALID_PARAMETER));
    }
    assert!(Lookup::decode([OP_LOOKUP, 4, 1 << 32, 0]).is_err());
    assert!(Close::decode([OP_CLOSE, 4, 1, 0]).is_err());
    assert!(Find::decode([OP_FIND | 1 << 16, 0x9000, 0, 0]).is_err(), "filter bits without a filter");
    assert!(Find::decode([OP_FIND | 1 << 8 | 4 << 16, 0x9000, 0, 0]).is_err());
    assert!(Find::decode([OP_FIND, 0, 0, 0]).is_err(), "the target process is not optional");
    assert!(Resolved::decode([0x7000, 1 << 32, 0x5000 | 4 << 56]).is_err());
}

#[test]
fn deltas_round_trip_and_take_their_domain_from_the_caller() {
    let target = UserObjectTarget { domain: 3, object_type: 0x5000, body: 0x7000, generation: 4 };
    for delta in [
        HandleDelta::Acquired { target, count: 1 },
        HandleDelta::Released { target, count: MAX_DELTA },
    ] {
        let words = encode_delta(delta);
        assert_eq!(decode_delta(3, words), Ok(delta));
        assert_eq!(decode_delta(8, words).unwrap().target().domain, 8);
    }
    let words = encode_delta(HandleDelta::Acquired { target, count: 1 });
    assert!(decode_delta(3, [words[0], words[1] & !0xFFFF, words[2]]).is_err());
    assert!(decode_delta(3, [words[0], words[1] | (MAX_DELTA as u64 + 1), words[2]]).is_err());
    assert!(decode_delta(3, [0, words[1], words[2]]).is_err());
}
