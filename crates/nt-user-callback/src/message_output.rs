//! Provider-published output ownership for USER Get/Peek message dispatches.

use crate::{
    DISPATCH_MESSAGE_OUTPUT_BYTES, NTUSER_GET_MESSAGE_SSN, NTUSER_PEEK_MESSAGE_SSN, WM_QUIT,
};

/// Whether a completed Get/Peek dispatch returned a message. These USER services return a 32-bit
/// `BOOL`; the generic win32k transport preserves the handler's full RAX so its high half is not
/// part of this ABI result and must not participate in the comparison.
pub const fn message_dispatch_returned_message(ssn: u64, raw_result: u64) -> bool {
    matches!(ssn, NTUSER_GET_MESSAGE_SSN | NTUSER_PEEK_MESSAGE_SSN) && raw_result as u32 == 1
}

/// Number of bytes a completed USER message dispatch authoritatively staged for its caller.
///
/// This is evaluated by the win32k provider after the real handler returns. The executive consumes
/// the published length rather than inferring ownership from the SSN or from a process role. A
/// successful Peek/Get returns one `MSG`; GetMessage also returns `FALSE` for a staged `WM_QUIT`.
pub const fn message_dispatch_output_length(ssn: u64, raw_result: u64, staged_message: u32) -> u32 {
    if message_dispatch_returned_message(ssn, raw_result)
        || (ssn == NTUSER_GET_MESSAGE_SSN && raw_result as u32 == 0 && staged_message == WM_QUIT)
    {
        DISPATCH_MESSAGE_OUTPUT_BYTES
    } else {
        0
    }
}

/// Whether provider-published output ownership agrees with the public Get/Peek return contract.
/// A returned message owns one complete `MSG`. GetMessage `FALSE` can mean either a staged
/// `WM_QUIT` or no output, so the provider's exact published length disambiguates those cases.
pub const fn message_dispatch_output_length_matches_result(
    ssn: u64,
    raw_result: u64,
    output_length: u32,
) -> bool {
    if ssn == NTUSER_GET_MESSAGE_SSN && raw_result as u32 == 0 {
        output_length == 0 || output_length == DISPATCH_MESSAGE_OUTPUT_BYTES
    } else if message_dispatch_returned_message(ssn, raw_result) {
        output_length == DISPATCH_MESSAGE_OUTPUT_BYTES
    } else {
        output_length == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NTUSER_DISPATCH_MESSAGE_SSN;

    #[test]
    fn provider_and_consumer_agree_across_bool_quit_and_error_results() {
        for high_half in [0, 0xfeed_beef_0000_0000] {
            for ssn in [
                NTUSER_GET_MESSAGE_SSN,
                NTUSER_PEEK_MESSAGE_SSN,
                NTUSER_DISPATCH_MESSAGE_SSN,
            ] {
                for low_result in [0, 1, 2, u32::MAX] {
                    for message in [0, 0x0102, WM_QUIT] {
                        let result = high_half | u64::from(low_result);
                        let length = message_dispatch_output_length(ssn, result, message);
                        assert!(message_dispatch_output_length_matches_result(ssn, result, length),
                            "provider publication must be consumable: ssn={ssn:x} result={result:x} message={message:x}");
                        assert_eq!(
                            message_dispatch_returned_message(ssn, result),
                            ssn != NTUSER_DISPATCH_MESSAGE_SSN && low_result == 1
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn false_get_message_preserves_both_exact_publication_outcomes() {
        for result in [0, 0xfeed_beef_0000_0000] {
            assert_eq!(
                message_dispatch_output_length(NTUSER_GET_MESSAGE_SSN, result, 0),
                0
            );
            assert_eq!(
                message_dispatch_output_length(NTUSER_GET_MESSAGE_SSN, result, WM_QUIT),
                DISPATCH_MESSAGE_OUTPUT_BYTES
            );
            assert!(message_dispatch_output_length_matches_result(
                NTUSER_GET_MESSAGE_SSN,
                result,
                0
            ));
            assert!(message_dispatch_output_length_matches_result(
                NTUSER_GET_MESSAGE_SSN,
                result,
                DISPATCH_MESSAGE_OUTPUT_BYTES
            ));
            assert!(!message_dispatch_returned_message(
                NTUSER_GET_MESSAGE_SSN,
                result
            ));
        }
    }

    #[test]
    fn peek_false_and_existing_error_contracts_never_own_a_message() {
        assert_eq!(
            message_dispatch_output_length(NTUSER_PEEK_MESSAGE_SSN, 0, WM_QUIT),
            0
        );
        assert_eq!(
            message_dispatch_output_length(NTUSER_PEEK_MESSAGE_SSN, 1, WM_QUIT),
            DISPATCH_MESSAGE_OUTPUT_BYTES
        );
        for ssn in [NTUSER_GET_MESSAGE_SSN, NTUSER_PEEK_MESSAGE_SSN] {
            for result in [u32::MAX as u64, u64::MAX] {
                assert_eq!(message_dispatch_output_length(ssn, result, WM_QUIT), 0);
                assert!(message_dispatch_output_length_matches_result(
                    ssn, result, 0
                ));
                assert!(!message_dispatch_output_length_matches_result(
                    ssn,
                    result,
                    DISPATCH_MESSAGE_OUTPUT_BYTES
                ));
            }
        }
        assert!(!message_dispatch_output_length_matches_result(
            NTUSER_PEEK_MESSAGE_SSN,
            0,
            DISPATCH_MESSAGE_OUTPUT_BYTES
        ));
    }

    #[test]
    fn true_requires_complete_msg_and_partial_publications_are_always_rejected() {
        for ssn in [NTUSER_GET_MESSAGE_SSN, NTUSER_PEEK_MESSAGE_SSN] {
            for result in [1, 0xfeed_beef_0000_0001] {
                assert!(!message_dispatch_output_length_matches_result(
                    ssn, result, 0
                ));
                assert!(message_dispatch_output_length_matches_result(
                    ssn,
                    result,
                    DISPATCH_MESSAGE_OUTPUT_BYTES
                ));
            }
            for result in [0, 1, u32::MAX as u64] {
                for length in [
                    1,
                    DISPATCH_MESSAGE_OUTPUT_BYTES - 1,
                    DISPATCH_MESSAGE_OUTPUT_BYTES + 1,
                    u32::MAX,
                ] {
                    assert!(!message_dispatch_output_length_matches_result(
                        ssn, result, length
                    ));
                }
            }
        }
    }
}
