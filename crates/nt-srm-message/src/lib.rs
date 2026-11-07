//! The native x64 LPC message shape used by `\SeRmCommandPort`.
//!
//! The caller owns user-memory access, port-handle validation, and the actual
//! security policy. This codec only validates the captured message and writes
//! the fields that the current SRM command reply changes.

#![no_std]

use nt_lpc_abi::{msg_type, port_message_total_length, PORT_MESSAGE_HEADER_LEN};

pub const API_OFFSET: usize = PORT_MESSAGE_HEADER_LEN;
pub const RESULT_OFFSET: usize = API_OFFSET + 4;
pub const LUID_OFFSET: usize = RESULT_OFFSET;
pub const REPLY_FIELDS_END: usize = RESULT_OFFSET + 4;

pub const RM_AUDIT_SET_COMMAND: u32 = 1;
pub const RM_CREATE_LOGON_SESSION: u32 = 2;
pub const RM_DELETE_LOGON_SESSION: u32 = 3;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidMessage,
    MessageTooLong,
}

/// A decoded request and the result of the currently supported SRM commands.
/// The native adapter still decides whether to publish the reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestReply {
    pub api_number: u32,
    pub result_status: u32,
    pub luid: Option<u64>,
}

/// Decode the native `PORT_MESSAGE` length pair and SRM payload.
///
/// A valid LPC header can include padding between `DataLength` and
/// `TotalLength`. Like the current executive handler, command fields are read
/// at their fixed offsets within `TotalLength`; an unknown command or missing
/// LUID receives `STATUS_INVALID_PARAMETER` in the reply. A header or API
/// field that cannot be captured is a transport error instead.
pub fn decode_request(bytes: &[u8], max_message: usize) -> Result<RequestReply, RequestError> {
    let header: [u8; 4] = bytes
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RequestError::InvalidMessage)?;
    let total_len = port_message_total_length(header).ok_or(RequestError::InvalidMessage)?;
    if total_len > max_message {
        return Err(RequestError::MessageTooLong);
    }
    let message = bytes
        .get(..total_len)
        .ok_or(RequestError::InvalidMessage)?;
    let api_number = u32::from_le_bytes(
        message
            .get(API_OFFSET..API_OFFSET + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(RequestError::InvalidMessage)?,
    );
    let mut reply = RequestReply {
        api_number,
        result_status: 0,
        luid: None,
    };
    match api_number {
        RM_AUDIT_SET_COMMAND => {}
        RM_CREATE_LOGON_SESSION | RM_DELETE_LOGON_SESSION => {
            if let Some(luid) = message
                .get(LUID_OFFSET..LUID_OFFSET + 8)
                .and_then(|bytes| bytes.try_into().ok())
            {
                reply.luid = Some(u64::from_le_bytes(luid));
            } else {
                reply.result_status = STATUS_INVALID_PARAMETER;
            }
        }
        _ => reply.result_status = STATUS_INVALID_PARAMETER,
    }
    Ok(reply)
}

/// Patch only `PORT_MESSAGE.Type` and the union's `ResultStatus` field.
/// All other reply bytes, including the kernel-authored message identity and
/// length pair, remain owned by the caller.
pub fn write_reply_fields(reply: &mut [u8], result: RequestReply) -> Result<(), RequestError> {
    if reply.len() < REPLY_FIELDS_END {
        return Err(RequestError::InvalidMessage);
    }
    reply[4..6].copy_from_slice(&msg_type::LPC_REPLY.to_le_bytes());
    reply[RESULT_OFFSET..REPLY_FIELDS_END].copy_from_slice(&result.result_status.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(api: u32, payload: &[u8]) -> [u8; 64] {
        let total = API_OFFSET + 4 + payload.len();
        let mut message = [0xa5; 64];
        message[..2].copy_from_slice(&((total - PORT_MESSAGE_HEADER_LEN) as u16).to_le_bytes());
        message[2..4].copy_from_slice(&(total as u16).to_le_bytes());
        message[API_OFFSET..API_OFFSET + 4].copy_from_slice(&api.to_le_bytes());
        message[RESULT_OFFSET..RESULT_OFFSET + payload.len()].copy_from_slice(payload);
        message
    }

    #[test]
    fn decodes_all_three_commands_at_their_native_offsets() {
        let audit = request(RM_AUDIT_SET_COMMAND, &[]);
        assert_eq!(decode_request(&audit[..44], 64), Ok(RequestReply {
            api_number: 1, result_status: 0, luid: None,
        }));
        let luid = 0x1122_3344_5566_7788u64;
        for api in [RM_CREATE_LOGON_SESSION, RM_DELETE_LOGON_SESSION] {
            let message = request(api, &luid.to_le_bytes());
            assert_eq!(decode_request(&message[..52], 64), Ok(RequestReply {
                api_number: api, result_status: 0, luid: Some(luid),
            }));
        }
    }

    #[test]
    fn missing_luid_and_unknown_api_receive_invalid_parameter() {
        let short_luid = request(RM_CREATE_LOGON_SESSION, &[1, 2, 3, 4]);
        assert_eq!(decode_request(&short_luid[..48], 64).unwrap().result_status,
                   STATUS_INVALID_PARAMETER);
        let unknown = request(99, &[]);
        assert_eq!(decode_request(&unknown[..44], 64).unwrap().result_status,
                   STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn rejects_invalid_lpc_lengths_and_incomplete_captures() {
        let message = request(RM_AUDIT_SET_COMMAND, &[]);
        assert_eq!(decode_request(&message[..3], 64), Err(RequestError::InvalidMessage));
        assert_eq!(decode_request(&message[..43], 64), Err(RequestError::InvalidMessage));
        assert_eq!(decode_request(&message[..44], 43), Err(RequestError::MessageTooLong));
        let mut short_total = message;
        short_total[2..4].copy_from_slice(&43u16.to_le_bytes());
        short_total[0..2].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(decode_request(&short_total, 64), Err(RequestError::InvalidMessage));
        let mut short_header = message;
        short_header[2..4].copy_from_slice(&39u16.to_le_bytes());
        assert_eq!(decode_request(&short_header, 64), Err(RequestError::InvalidMessage));
        let mut data_overflow = message;
        data_overflow[0..2].copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(decode_request(&data_overflow, 64), Err(RequestError::InvalidMessage));
    }

    #[test]
    fn reply_patches_only_type_and_result() {
        let mut reply = [0xa5u8; REPLY_FIELDS_END];
        let result = RequestReply { api_number: 99, result_status: STATUS_INVALID_PARAMETER,
                                    luid: None };
        write_reply_fields(&mut reply, result).unwrap();
        assert_eq!(&reply[4..6], &msg_type::LPC_REPLY.to_le_bytes());
        assert_eq!(&reply[RESULT_OFFSET..REPLY_FIELDS_END],
                   &STATUS_INVALID_PARAMETER.to_le_bytes());
        assert!(reply[..4].iter().all(|byte| *byte == 0xa5));
        assert!(reply[6..RESULT_OFFSET].iter().all(|byte| *byte == 0xa5));
        assert_eq!(write_reply_fields(&mut reply[..47], result), Err(RequestError::InvalidMessage));
    }
}
