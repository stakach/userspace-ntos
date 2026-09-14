//! `HwStartIO` reports VP_STATUS values, not NTSTATUS completion codes.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoControlCompletion {
    pub nt_status: u32,
    pub information: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoControlProtocolError {
    Pending,
    UnknownStatus(u32),
}

/// Apply NT5 video-port status mapping and its error-information policy. Only success and
/// ERROR_MORE_DATA preserve Information. Pending and unknown miniport statuses are protocol
/// errors, never fabricated terminal completions or release-build compatibility fallbacks.
pub const fn classify_start_io_status(
    status: u32,
    information: u64,
) -> Result<VideoControlCompletion, VideoControlProtocolError> {
    let (nt_status, information) = match status {
        0 => (0, information),
        234 => (0x8000_0005, information),
        8 => (0xc000_009a, 0),
        1 => (0xc000_0002, 0),
        87 => (0xc000_000d, 0),
        122 => (0xc000_0023, 0),
        55 => (0xc000_00c0, 0),
        997 => return Err(VideoControlProtocolError::Pending),
        unknown => return Err(VideoControlProtocolError::UnknownStatus(unknown)),
    };
    Ok(VideoControlCompletion {
        nt_status,
        information,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFORMATION: [u64; 6] = [
        0,
        1,
        u32::MAX as u64,
        0x1_0000_0000,
        0x1234_5678_9abc_def0,
        u64::MAX,
    ];

    #[test]
    fn success_and_more_data_preserve_full_width_information() {
        for (vp_status, nt_status) in [(0, 0), (234, 0x8000_0005)] {
            for information in INFORMATION {
                assert_eq!(
                    classify_start_io_status(vp_status, information),
                    Ok(VideoControlCompletion {
                        nt_status,
                        information
                    })
                );
            }
        }
    }

    #[test]
    fn every_defined_failure_maps_to_nt_status_and_clears_information() {
        for (vp_status, nt_status) in [
            (1, 0xc000_0002),
            (8, 0xc000_009a),
            (55, 0xc000_00c0),
            (87, 0xc000_000d),
            (122, 0xc000_0023),
        ] {
            for information in INFORMATION {
                assert_eq!(
                    classify_start_io_status(vp_status, information),
                    Ok(VideoControlCompletion {
                        nt_status,
                        information: 0
                    })
                );
            }
        }
    }

    #[test]
    fn pending_is_a_protocol_error_for_every_information_value() {
        for information in INFORMATION {
            assert_eq!(
                classify_start_io_status(997, information),
                Err(VideoControlProtocolError::Pending)
            );
        }
    }

    #[test]
    fn undefined_vp_codes_and_native_nt_statuses_are_not_accepted_as_completions() {
        for status in 0..=1024 {
            if matches!(status, 0 | 1 | 8 | 55 | 87 | 122 | 234 | 997) {
                continue;
            }
            assert_eq!(
                classify_start_io_status(status, u64::MAX),
                Err(VideoControlProtocolError::UnknownStatus(status))
            );
        }
        for status in [
            0x8000_0005,
            0xc000_0002,
            0xc000_009a,
            0xc000_000d,
            0xc000_0023,
            0xc000_00c0,
            0xc000_0001,
            u32::MAX,
        ] {
            for information in INFORMATION {
                assert_eq!(
                    classify_start_io_status(status, information),
                    Err(VideoControlProtocolError::UnknownStatus(status))
                );
            }
        }
    }
}
