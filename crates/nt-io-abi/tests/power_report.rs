use nt_io_abi::power_report::{PowerReportReply, PowerReportRequest};

#[test]
fn acknowledged_previous_state_includes_unspecified_and_is_not_requested_state() {
    for (power_type, maximum) in [(0, 6), (1, 4)] {
        for previous in 0..=maximum {
            assert_eq!(PowerReportReply::decode(4, 0, previous, [0; 2], power_type)
                .unwrap().into_result(), Ok(previous as u32));
        }
    }
    let request = PowerReportRequest::decode(0x1000, 1, 4).unwrap();
    assert_eq!(request.state, 4);
    assert_eq!(PowerReportReply::decode(4, 0, 1, [0; 2], request.power_type)
        .unwrap().into_result(), Ok(1));
}

#[test]
fn request_scalar_types_and_state_sentinels_are_checked() {
    for (power_type, maximum) in [(0, 6), (1, 4)] {
        for state in 0..=maximum {
            let request = PowerReportRequest::decode(1, power_type, state).unwrap();
            assert_eq!(request.device, 1);
            assert_eq!(request.power_type, power_type as u32);
            assert_eq!(request.state, state as u32);
        }
        for state in [maximum + 1, u32::MAX as u64 + 1, u64::MAX] {
            assert!(PowerReportRequest::decode(1, power_type, state).is_err());
        }
    }
    assert!(PowerReportRequest::decode(0, 1, 1).is_err());
    for power_type in [2, u32::MAX as u64 + 1, u64::MAX] {
        assert!(PowerReportRequest::decode(1, power_type, 1).is_err());
    }
}

#[test]
fn rejection_never_fabricates_an_unspecified_success() {
    for status in [0xc000_000du64, 0xc000_0022, 0xc000_00a3] {
        assert_eq!(PowerReportReply::decode(4, status, 0, [0; 2], 1)
            .unwrap().into_result(), Err(status as u32 as i32));
        assert!(PowerReportReply::decode(4, status, 1, [0; 2], 1).is_err());
    }
}

#[test]
fn malformed_or_pending_acknowledgements_never_authorize_a_return_value() {
    for words in [0, 1, 3, 5, u64::MAX] {
        assert!(PowerReportReply::decode(words, 0, 1, [0; 2], 1).is_err());
    }
    for status in [1, 0x103, 0x4000_0000, 0x1_0000_0000, 0xffff_ffff_c000_000d] {
        assert!(PowerReportReply::decode(4, status, 0, [0; 2], 1).is_err());
    }
    for reserved in [[1, 0], [0, 1], [u64::MAX; 2]] {
        assert!(PowerReportReply::decode(4, 0, 1, reserved, 1).is_err());
    }
    for (power_type, previous) in [(0, 7), (1, 5), (2, 1), (1, u32::MAX as u64 + 1)] {
        assert!(PowerReportReply::decode(4, 0, previous, [0; 2], power_type).is_err());
    }
}
