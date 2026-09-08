//! x64 SECURITY_CLIENT_CONTEXT projection from NT5 `se.h` and ReactOS `xdk/setypes.h`.
//!
//! This is an ABI encoder, not security authority. In particular, ClientToken is a driver-visible
//! address whose canonical ownership and mapping must already be established by the caller.

use crate::GuestAddr;
use bytemuck::{Pod, Zeroable};
use core::mem::{offset_of, size_of};

pub const SECURITY_QUALITY_OF_SERVICE_SIZE: usize = 0x0C;
pub const TOKEN_CONTROL_SIZE: usize = 0x28;
pub const SECURITY_CLIENT_CONTEXT_SIZE: usize = 0x48;
pub const CLIENT_TOKEN_OFFSET: usize = 0x10;
pub const DIRECT_ACCESS_OFFSET: usize = 0x18;
pub const DIRECT_EFFECTIVE_ONLY_OFFSET: usize = 0x19;
pub const SERVER_IS_REMOTE_OFFSET: usize = 0x1A;
pub const TOKEN_CONTROL_OFFSET: usize = 0x1C;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Pod, Zeroable)]
pub struct Luid {
    pub low_part: u32,
    pub high_part: i32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Pod, Zeroable)]
pub struct TokenSource {
    pub source_name: [u8; 8],
    pub source_identifier: Luid,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Pod, Zeroable)]
pub struct TokenControl {
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub modified_id: Luid,
    pub token_source: TokenSource,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Pod, Zeroable)]
pub struct SecurityQualityOfService {
    pub length: u32,
    pub impersonation_level: u32,
    pub context_tracking_mode: u8,
    pub effective_only: u8,
    padding: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Pod, Zeroable)]
pub struct SecurityClientContext {
    pub security_qos: SecurityQualityOfService,
    token_alignment: [u8; 4],
    pub client_token: GuestAddr,
    pub directly_access_client_token: u8,
    pub direct_access_effective_only: u8,
    pub server_is_remote: u8,
    control_alignment: u8,
    pub client_token_control: TokenControl,
    tail_alignment: [u8; 4],
}

const _: () = {
    assert!(size_of::<Luid>() == 8);
    assert!(core::mem::align_of::<Luid>() == 4);
    assert!(size_of::<TokenSource>() == 16);
    assert!(size_of::<TokenControl>() == TOKEN_CONTROL_SIZE);
    assert!(offset_of!(TokenControl, authentication_id) == 8);
    assert!(offset_of!(TokenControl, modified_id) == 16);
    assert!(offset_of!(TokenControl, token_source) == 24);
    assert!(size_of::<SecurityQualityOfService>() == SECURITY_QUALITY_OF_SERVICE_SIZE);
    assert!(size_of::<SecurityClientContext>() == SECURITY_CLIENT_CONTEXT_SIZE);
    assert!(core::mem::align_of::<SecurityClientContext>() == 8);
    assert!(offset_of!(SecurityClientContext, client_token) == CLIENT_TOKEN_OFFSET);
    assert!(
        offset_of!(SecurityClientContext, directly_access_client_token) == DIRECT_ACCESS_OFFSET
    );
    assert!(
        offset_of!(SecurityClientContext, direct_access_effective_only)
            == DIRECT_EFFECTIVE_ONLY_OFFSET
    );
    assert!(offset_of!(SecurityClientContext, server_is_remote) == SERVER_IS_REMOTE_OFFSET);
    assert!(offset_of!(SecurityClientContext, client_token_control) == TOKEN_CONTROL_OFFSET);
};

/// Values already selected by the client-security policy. The optional control record is required
/// only for remote dynamic tracking; absent local/static control bytes are deterministic padding,
/// not a synthesized token-control snapshot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ClientContextFields {
    pub impersonation_level: u32,
    pub dynamic_tracking: bool,
    pub effective_only: bool,
    pub client_token: GuestAddr,
    pub direct_access_effective_only: bool,
    pub server_is_remote: bool,
    pub token_control: Option<TokenControl>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ClientContextEncodingError {
    BufferTooSmall,
    InvalidImpersonationLevel,
    NullToken,
    InvalidControlPresence,
}

/// Encode exactly one complete x64 context, without dereferencing ClientToken. Invalid input or
/// insufficient output leaves every destination byte unchanged; any tail after the record is kept.
pub fn encode_client_context(
    fields: ClientContextFields,
    output: &mut [u8],
) -> Result<(), ClientContextEncodingError> {
    if output.len() < SECURITY_CLIENT_CONTEXT_SIZE {
        return Err(ClientContextEncodingError::BufferTooSmall);
    }
    if fields.impersonation_level > 3 {
        return Err(ClientContextEncodingError::InvalidImpersonationLevel);
    }
    if fields.client_token.is_null() {
        return Err(ClientContextEncodingError::NullToken);
    }
    if fields.token_control.is_some() != (fields.server_is_remote && fields.dynamic_tracking) {
        return Err(ClientContextEncodingError::InvalidControlPresence);
    }
    let record = SecurityClientContext {
        security_qos: SecurityQualityOfService {
            length: SECURITY_QUALITY_OF_SERVICE_SIZE as u32,
            impersonation_level: fields.impersonation_level,
            context_tracking_mode: u8::from(fields.dynamic_tracking),
            effective_only: u8::from(fields.effective_only),
            padding: [0; 2],
        },
        token_alignment: [0; 4],
        client_token: fields.client_token,
        directly_access_client_token: u8::from(fields.dynamic_tracking),
        direct_access_effective_only: u8::from(fields.direct_access_effective_only),
        server_is_remote: u8::from(fields.server_is_remote),
        control_alignment: 0,
        client_token_control: fields.token_control.unwrap_or_default(),
        tail_alignment: [0; 4],
    };
    output[..SECURITY_CLIENT_CONTEXT_SIZE].copy_from_slice(bytemuck::bytes_of(&record));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> ClientContextFields {
        ClientContextFields {
            impersonation_level: 2,
            dynamic_tracking: true,
            effective_only: true,
            client_token: GuestAddr(0x0000_0100_1234_5000),
            direct_access_effective_only: false,
            server_is_remote: false,
            token_control: None,
        }
    }

    #[test]
    fn full_local_record_has_exact_offsets_zero_padding_and_untouched_tail() {
        let mut bytes = [0xA5; 80];
        encode_client_context(fields(), &mut bytes).unwrap();
        assert_eq!(&bytes[0..4], &12u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &2u32.to_le_bytes());
        assert_eq!(&bytes[8..10], &[1, 1]);
        assert_eq!(&bytes[10..16], &[0; 6]);
        assert_eq!(&bytes[16..24], &fields().client_token.0.to_le_bytes());
        assert_eq!(&bytes[24..28], &[1, 0, 0, 0]);
        assert_eq!(&bytes[28..72], &[0; 44]);
        assert_eq!(&bytes[72..], &[0xA5; 8]);
    }

    #[test]
    fn remote_control_includes_entire_source_identifier_past_old_64_byte_limit() {
        let mut input = fields();
        input.server_is_remote = true;
        input.token_control = Some(TokenControl {
            token_id: Luid {
                low_part: 1,
                high_part: -1,
            },
            authentication_id: Luid {
                low_part: 2,
                high_part: -2,
            },
            modified_id: Luid {
                low_part: 3,
                high_part: -3,
            },
            token_source: TokenSource {
                source_name: *b"SOURCE01",
                source_identifier: Luid {
                    low_part: 4,
                    high_part: -4,
                },
            },
        });
        let mut bytes = [0xA5; SECURITY_CLIENT_CONTEXT_SIZE];
        encode_client_context(input, &mut bytes).unwrap();
        assert_eq!(bytes[26], 1);
        assert_eq!(&bytes[28..32], &1u32.to_le_bytes());
        assert_eq!(&bytes[32..36], &(-1i32).to_le_bytes());
        assert_eq!(&bytes[36..40], &2u32.to_le_bytes());
        assert_eq!(&bytes[40..44], &(-2i32).to_le_bytes());
        assert_eq!(&bytes[44..48], &3u32.to_le_bytes());
        assert_eq!(&bytes[48..52], &(-3i32).to_le_bytes());
        assert_eq!(&bytes[52..60], b"SOURCE01");
        assert_eq!(&bytes[60..64], &4u32.to_le_bytes());
        assert_eq!(&bytes[64..68], &(-4i32).to_le_bytes());
        assert_eq!(&bytes[68..72], &[0; 4]);
    }

    #[test]
    fn short_buffers_are_unchanged_including_former_stub_size() {
        for length in 0..SECURITY_CLIENT_CONTEXT_SIZE {
            let mut bytes = [0xA5; SECURITY_CLIENT_CONTEXT_SIZE];
            assert_eq!(
                encode_client_context(fields(), &mut bytes[..length]),
                Err(ClientContextEncodingError::BufferTooSmall)
            );
            assert_eq!(bytes, [0xA5; SECURITY_CLIENT_CONTEXT_SIZE]);
        }
    }

    #[test]
    fn invalid_fields_never_partially_write_output() {
        let mut invalid_level = fields();
        invalid_level.impersonation_level = 4;
        let mut null = fields();
        null.client_token = GuestAddr::NULL;
        let mut missing_control = fields();
        missing_control.server_is_remote = true;
        let mut extra_control = fields();
        extra_control.token_control = Some(TokenControl::default());
        for (input, error) in [
            (
                invalid_level,
                ClientContextEncodingError::InvalidImpersonationLevel,
            ),
            (null, ClientContextEncodingError::NullToken),
            (
                missing_control,
                ClientContextEncodingError::InvalidControlPresence,
            ),
            (
                extra_control,
                ClientContextEncodingError::InvalidControlPresence,
            ),
        ] {
            let mut bytes = [0xA5; SECURITY_CLIENT_CONTEXT_SIZE];
            assert_eq!(encode_client_context(input, &mut bytes), Err(error));
            assert_eq!(bytes, [0xA5; SECURITY_CLIENT_CONTEXT_SIZE]);
        }
    }

    #[test]
    fn static_context_is_not_direct_access_even_when_remote() {
        let mut input = fields();
        input.dynamic_tracking = false;
        input.server_is_remote = true;
        input.direct_access_effective_only = true;
        let mut bytes = [0xA5; SECURITY_CLIENT_CONTEXT_SIZE];
        encode_client_context(input, &mut bytes).unwrap();
        assert_eq!(bytes[8], 0);
        assert_eq!(&bytes[24..28], &[0, 1, 1, 0]);
        assert_eq!(&bytes[28..72], &[0; 44]);
    }
}
