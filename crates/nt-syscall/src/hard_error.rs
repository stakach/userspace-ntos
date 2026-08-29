//! Pure validation for the `NtRaiseHardError` user-mode contract.

pub const MAXIMUM_HARDERROR_PARAMETERS: u32 = 5;
pub const RESPONSE_RETURN_TO_CALLER: u32 = 0;
pub const RESPONSE_CONTINUE: u32 = 10;
pub const OPTION_SHUTDOWN_SYSTEM: u32 = 6;
pub const OPTION_CANCEL_TRY_CONTINUE: u32 = 8;
pub const HARDERROR_OVERRIDE_ERRORMODE: u32 = 0x1000_0000;
pub const FATAL_UNHANDLED_HARD_ERROR: u32 = 0x0000_004c;
pub const HARD_ERROR_MESSAGE_LEN: usize = 112;
pub const LPC_ERROR_EVENT: u16 = 9;

pub const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
pub const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

pub const fn is_error_status(status: u32) -> bool {
    status & 0xc000_0000 == 0xc000_0000
}

pub const fn requires_system_error_handler(ready_for_errors: bool, status: u32) -> bool {
    !ready_for_errors && is_error_status(status)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DefaultHardErrorPort {
    endpoint_handle: u64,
    owner_process: u64,
    ready: bool,
}

impl Default for DefaultHardErrorPort {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultHardErrorPort {
    pub const fn new() -> Self {
        Self {
            endpoint_handle: 0,
            owner_process: 0,
            ready: false,
        }
    }

    pub const fn is_ready(self) -> bool {
        self.ready
    }

    pub const fn registration(self) -> Option<(u64, u64)> {
        if self.ready {
            Some((self.endpoint_handle, self.owner_process))
        } else {
            None
        }
    }

    /// Publish the already-retained broker endpoint. Native registration is one-shot while the
    /// hard-error facility is ready; the executive must release `endpoint_handle` if this fails.
    pub fn register(&mut self, endpoint_handle: u64, owner_process: u64) -> Result<(), ()> {
        if self.endpoint_handle != 0 || endpoint_handle == 0 || owner_process == 0 {
            return Err(());
        }
        self.endpoint_handle = endpoint_handle;
        self.owner_process = owner_process;
        self.ready = true;
        Ok(())
    }

    /// Stop routing new errors during a shutdown hard error while retaining object identity for
    /// orderly executive teardown.
    pub fn disable(&mut self) {
        self.ready = false;
    }
}

/// Encode the native x64 `HARDERROR_MSG`. The LPC broker overwrites the zeroed ClientId and
/// MessageId fields with its trusted request identity while preserving `LPC_ERROR_EVENT`.
pub fn encode_message(
    error_status: u32,
    error_time_100ns: i64,
    valid_response_options: u32,
    unicode_string_parameter_mask: u32,
    number_of_parameters: u32,
    parameters: [u64; MAXIMUM_HARDERROR_PARAMETERS as usize],
) -> Result<[u8; HARD_ERROR_MESSAGE_LEN], u32> {
    validate_request(
        number_of_parameters,
        number_of_parameters != 0,
        valid_response_options,
    )?;
    let mut message = [0u8; HARD_ERROR_MESSAGE_LEN];
    message[0..2].copy_from_slice(&((HARD_ERROR_MESSAGE_LEN - 40) as u16).to_le_bytes());
    message[2..4].copy_from_slice(&(HARD_ERROR_MESSAGE_LEN as u16).to_le_bytes());
    message[4..6].copy_from_slice(&LPC_ERROR_EVENT.to_le_bytes());
    message[40..44].copy_from_slice(&error_status.to_le_bytes());
    message[48..56].copy_from_slice(&error_time_100ns.to_le_bytes());
    message[56..60].copy_from_slice(&valid_response_options.to_le_bytes());
    message[64..68].copy_from_slice(&number_of_parameters.to_le_bytes());
    message[68..72].copy_from_slice(&unicode_string_parameter_mask.to_le_bytes());
    for (index, parameter) in parameters
        .iter()
        .take(number_of_parameters as usize)
        .enumerate()
    {
        let offset = 72 + index * 8;
        message[offset..offset + 8].copy_from_slice(&parameter.to_le_bytes());
    }
    Ok(message)
}

/// Extract and sanitize `HARDERROR_MSG.Response` from an LPC reply. CSRSS may return only the
/// documented `HARDERROR_RESPONSE` values; corrupt or future values become ReturnToCaller.
pub fn response_from_reply(reply: &[u8]) -> Result<u32, u32> {
    if reply.len() != HARD_ERROR_MESSAGE_LEN
        || u16::from_le_bytes(reply[2..4].try_into().unwrap()) as usize != HARD_ERROR_MESSAGE_LEN
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let response = u32::from_le_bytes(reply[60..64].try_into().unwrap());
    Ok(if response <= RESPONSE_CONTINUE {
        response
    } else {
        RESPONSE_RETURN_TO_CALLER
    })
}

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

    #[test]
    fn default_port_registration_is_exact_and_one_shot() {
        let mut port = DefaultHardErrorPort::new();
        assert_eq!(port.registration(), None);
        assert_eq!(port.register(0x4c50, 24), Ok(()));
        assert_eq!(port.registration(), Some((0x4c50, 24)));
        assert_eq!(port.register(0x4c51, 28), Err(()));
        port.disable();
        assert_eq!(port.registration(), None);
        assert_eq!(port.register(0x4c51, 28), Err(()));
    }

    #[test]
    fn only_unhandled_error_severity_requires_the_system_handler() {
        assert!(requires_system_error_handler(false, 0xc000_0005));
        assert!(!requires_system_error_handler(true, 0xc000_0005));
        assert!(!requires_system_error_handler(false, 0x8000_0005));
        assert!(!requires_system_error_handler(false, 0x4000_0005));
    }

    #[test]
    fn native_message_layout_and_response_sanitization() {
        let message = encode_message(
            0xc000_0005,
            0x1122_3344_5566_7788,
            2,
            1,
            2,
            [0xaaaa, 0xbbbb, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(u16::from_le_bytes(message[0..2].try_into().unwrap()), 72);
        assert_eq!(u16::from_le_bytes(message[2..4].try_into().unwrap()), 112);
        assert_eq!(u16::from_le_bytes(message[4..6].try_into().unwrap()), 9);
        assert_eq!(
            u32::from_le_bytes(message[40..44].try_into().unwrap()),
            0xc000_0005
        );
        assert_eq!(
            u64::from_le_bytes(message[72..80].try_into().unwrap()),
            0xaaaa
        );
        assert_eq!(
            u64::from_le_bytes(message[80..88].try_into().unwrap()),
            0xbbbb
        );

        let mut reply = message;
        reply[60..64].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(response_from_reply(&reply), Ok(8));
        reply[60..64].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(response_from_reply(&reply), Ok(RESPONSE_RETURN_TO_CALLER));
        assert_eq!(
            response_from_reply(&reply[..64]),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}
