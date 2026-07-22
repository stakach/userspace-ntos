//! Pure validation for the `NtRaiseHardError` user-mode contract.

pub const MAXIMUM_HARDERROR_PARAMETERS: u32 = 5;
pub const RESPONSE_RETURN_TO_CALLER: u32 = 0;
pub const OPTION_CANCEL_TRY_CONTINUE: u32 = 8;

pub const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
pub const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;

/// Validate the scalar portion of ReactOS' `NtRaiseHardError` contract before the executive probes
/// the response, parameter array, and any `UNICODE_STRING` entries selected by the mask.
pub fn validate_request(
    number_of_parameters: u32,
    parameters_present: bool,
    valid_response_options: u32,
) -> Result<(), u32> {
    if number_of_parameters > MAXIMUM_HARDERROR_PARAMETERS
        || (parameters_present && number_of_parameters == 0)
    {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    if valid_response_options > OPTION_CANCEL_TRY_CONTINUE {
        return Err(STATUS_INVALID_PARAMETER_4);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_documented_response_option() {
        for option in 0..=OPTION_CANCEL_TRY_CONTINUE {
            assert_eq!(validate_request(0, false, option), Ok(()));
        }
    }

    #[test]
    fn rejects_excess_parameters_and_spurious_array() {
        assert_eq!(
            validate_request(MAXIMUM_HARDERROR_PARAMETERS + 1, true, 1),
            Err(STATUS_INVALID_PARAMETER_2)
        );
        assert_eq!(
            validate_request(0, true, 1),
            Err(STATUS_INVALID_PARAMETER_2)
        );
    }

    #[test]
    fn rejects_unknown_response_option() {
        assert_eq!(
            validate_request(0, false, OPTION_CANCEL_TRY_CONTINUE + 1),
            Err(STATUS_INVALID_PARAMETER_4)
        );
    }
}
