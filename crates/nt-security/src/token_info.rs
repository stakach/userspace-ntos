//! Native byte encoders for token information classes.

use crate::{AccessToken, TokenStatistics};

pub const TOKEN_STATISTICS_LENGTH: usize = 0x38;

/// Result of sizing and optionally writing one native token-information buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TokenInformationEncoding {
    pub required_length: usize,
    pub written: bool,
}

/// A semantic token contained a SID that cannot be represented by the native ABI.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InvalidTokenSid;

/// Encode `TOKEN_OWNER`: an in-buffer pointer followed by the owner SID.
pub fn encode_token_owner(
    token: &AccessToken,
    caller_base: u64,
    output: &mut [u8],
) -> Result<TokenInformationEncoding, InvalidTokenSid> {
    let sid_length = token.owner.native_len().ok_or(InvalidTokenSid)?;
    let required_length = 8 + sid_length;
    let Some(output) = output.get_mut(..required_length) else {
        return Ok(TokenInformationEncoding {
            required_length,
            written: false,
        });
    };

    output.fill(0);
    output[..8].copy_from_slice(&caller_base.wrapping_add(8).to_le_bytes());
    token
        .owner
        .write_native(&mut output[8..])
        .ok_or(InvalidTokenSid)?;
    Ok(TokenInformationEncoding {
        required_length,
        written: true,
    })
}

/// Encode `TOKEN_DEFAULT_DACL`, preserving null and present-empty ACL as distinct states.
pub fn encode_token_default_dacl(
    token: &AccessToken,
    caller_base: u64,
    output: &mut [u8],
) -> TokenInformationEncoding {
    let acl_length = token
        .default_dacl
        .as_ref()
        .map_or(0, |acl| acl.acl_size() as usize);
    let required_length = 8 + acl_length;
    let Some(output) = output.get_mut(..required_length) else {
        return TokenInformationEncoding {
            required_length,
            written: false,
        };
    };

    output.fill(0);
    if let Some(acl) = &token.default_dacl {
        output[..8].copy_from_slice(&caller_base.wrapping_add(8).to_le_bytes());
        output[8..].copy_from_slice(acl.as_bytes());
    }
    TokenInformationEncoding {
        required_length,
        written: true,
    }
}

/// Encode the packed native `TOKEN_STATISTICS` layout.
pub fn encode_token_statistics(
    statistics: TokenStatistics,
    output: &mut [u8],
) -> TokenInformationEncoding {
    let required_length = TOKEN_STATISTICS_LENGTH;
    let Some(output) = output.get_mut(..required_length) else {
        return TokenInformationEncoding {
            required_length,
            written: false,
        };
    };

    output.fill(0);
    write_luid(&mut output[0x00..0x08], statistics.token_id);
    write_luid(&mut output[0x08..0x10], statistics.authentication_id);
    output[0x10..0x18].copy_from_slice(&statistics.expiration_time.to_le_bytes());
    output[0x18..0x1c].copy_from_slice(&(statistics.token_type as u32).to_le_bytes());
    output[0x1c..0x20].copy_from_slice(&(statistics.impersonation_level as u32).to_le_bytes());
    output[0x20..0x24].copy_from_slice(&statistics.dynamic_charged.to_le_bytes());
    output[0x24..0x28].copy_from_slice(&statistics.dynamic_available.to_le_bytes());
    output[0x28..0x2c].copy_from_slice(&statistics.group_count.to_le_bytes());
    output[0x2c..0x30].copy_from_slice(&statistics.privilege_count.to_le_bytes());
    write_luid(&mut output[0x30..0x38], statistics.modified_id);
    TokenInformationEncoding {
        required_length,
        written: true,
    }
}

fn write_luid(output: &mut [u8], luid: crate::Luid) {
    output[..4].copy_from_slice(&luid.low.to_le_bytes());
    output[4..8].copy_from_slice(&luid.high.to_le_bytes());
}
