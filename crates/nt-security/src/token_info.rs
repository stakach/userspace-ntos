//! Native byte encoders for token information classes.

use crate::{AccessToken, TokenGroup, TokenStatistics};

pub const TOKEN_STATISTICS_LENGTH: usize = 0x38;
pub const TOKEN_GROUPS_AND_PRIVILEGES_LENGTH: usize = 0x38;

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

/// Native x64 `SID_AND_ATTRIBUTES`: `{ PSID Sid; DWORD Attributes; }` — 8-byte aligned, so 16.
pub const SID_AND_ATTRIBUTES_LENGTH: usize = 16;

/// Encode `TOKEN_GROUPS` (class 2): `{ DWORD GroupCount; SID_AND_ATTRIBUTES Groups[]; }` with the
/// SID bodies laid out after the array and each `Sid` pointer expressed in the CALLER's address
/// space (`caller_base` + offset), exactly as the kernel's `SeQueryInformationToken` does.
///
/// `caller_base` is the user VA the buffer will be copied to; the pointers are only meaningful
/// there. Returns the required length even when the buffer is too small, so a caller can do the
/// standard "query size, allocate, query again" dance (`GetTokenInformation(.., NULL, 0, &size)` →
/// `STATUS_BUFFER_TOO_SMALL`, which is what `userenv!CheckForGuestsAndAdmins` and
/// `winlogon!AllowAccessOnSession` both require).
pub fn encode_token_groups(
    token: &AccessToken,
    caller_base: u64,
    output: &mut [u8],
) -> Result<TokenInformationEncoding, InvalidTokenSid> {
    encode_token_group_entries(&token.groups, caller_base, output)
}

/// Encode `TOKEN_RESTRICTED_SIDS` (class 11) from the token's restricting SID set.
pub fn encode_token_restricted_sids(
    token: &AccessToken,
    caller_base: u64,
    output: &mut [u8],
) -> Result<TokenInformationEncoding, InvalidTokenSid> {
    encode_token_group_entries(&token.restricted_sids, caller_base, output)
}

/// Encode an arbitrary owned group slice using the same relocatable `TOKEN_GROUPS` layout. This is
/// shared by token queries and `NtAdjustGroupsToken` previous-state output.
pub fn encode_token_group_entries(
    groups: &[TokenGroup],
    caller_base: u64,
    output: &mut [u8],
) -> Result<TokenInformationEncoding, InvalidTokenSid> {
    // A zero-entry query is only the ULONG count. With entries present, x64 aligns the pointer array
    // to offset 8 before the SID bodies.
    let array_offset = if groups.is_empty() { 4 } else { 8 };
    let sid_offset = array_offset + groups.len() * SID_AND_ATTRIBUTES_LENGTH;
    let mut required_length = sid_offset;
    for group in groups {
        required_length += group.sid.native_len().ok_or(InvalidTokenSid)?;
    }
    let Some(output) = output.get_mut(..required_length) else {
        return Ok(TokenInformationEncoding {
            required_length,
            written: false,
        });
    };

    output.fill(0);
    output[..4].copy_from_slice(&(groups.len() as u32).to_le_bytes());
    let mut sid_cursor = sid_offset;
    for (index, group) in groups.iter().enumerate() {
        let entry = array_offset + index * SID_AND_ATTRIBUTES_LENGTH;
        output[entry..entry + 8]
            .copy_from_slice(&caller_base.wrapping_add(sid_cursor as u64).to_le_bytes());
        output[entry + 8..entry + 12].copy_from_slice(&group.native_attributes().to_le_bytes());
        let written = group
            .sid
            .write_native(&mut output[sid_cursor..])
            .ok_or(InvalidTokenSid)?;
        sid_cursor += written;
    }
    Ok(TokenInformationEncoding {
        required_length,
        written: true,
    })
}

/// Encode x64 `TOKEN_GROUPS_AND_PRIVILEGES` (class 13), including the user as the first SID entry.
pub fn encode_token_groups_and_privileges(
    token: &AccessToken,
    caller_base: u64,
    output: &mut [u8],
) -> Result<TokenInformationEncoding, InvalidTokenSid> {
    let sid_count = 1usize
        .checked_add(token.groups.len())
        .ok_or(InvalidTokenSid)?;
    let sid_bodies_length = token
        .user
        .native_len()
        .ok_or(InvalidTokenSid)?
        .checked_add(token.groups.iter().try_fold(0usize, |length, group| {
            length
                .checked_add(group.sid.native_len().ok_or(InvalidTokenSid)?)
                .ok_or(InvalidTokenSid)
        })?)
        .ok_or(InvalidTokenSid)?;
    let sid_length = sid_count
        .checked_mul(SID_AND_ATTRIBUTES_LENGTH)
        .and_then(|length| length.checked_add(sid_bodies_length))
        .ok_or(InvalidTokenSid)?;
    let restricted_bodies_length =
        token
            .restricted_sids
            .iter()
            .try_fold(0usize, |length, group| {
                length
                    .checked_add(group.sid.native_len().ok_or(InvalidTokenSid)?)
                    .ok_or(InvalidTokenSid)
            })?;
    let restricted_sid_length = token
        .restricted_sids
        .len()
        .checked_mul(SID_AND_ATTRIBUTES_LENGTH)
        .and_then(|length| length.checked_add(restricted_bodies_length))
        .ok_or(InvalidTokenSid)?;
    let privilege_length = token
        .privileges
        .len()
        .checked_mul(12)
        .ok_or(InvalidTokenSid)?;
    let required_length = TOKEN_GROUPS_AND_PRIVILEGES_LENGTH
        .checked_add(sid_length)
        .and_then(|length| length.checked_add(restricted_sid_length))
        .and_then(|length| length.checked_add(privilege_length))
        .ok_or(InvalidTokenSid)?;
    let Some(output) = output.get_mut(..required_length) else {
        return Ok(TokenInformationEncoding {
            required_length,
            written: false,
        });
    };

    output.fill(0);
    let sids_offset = TOKEN_GROUPS_AND_PRIVILEGES_LENGTH;
    let restricted_offset = sids_offset + sid_length;
    let privileges_offset = restricted_offset + restricted_sid_length;
    output[0..4].copy_from_slice(&(sid_count as u32).to_le_bytes());
    output[4..8].copy_from_slice(&(sid_length as u32).to_le_bytes());
    output[8..16].copy_from_slice(&caller_base.wrapping_add(sids_offset as u64).to_le_bytes());
    output[16..20].copy_from_slice(&(token.restricted_sids.len() as u32).to_le_bytes());
    output[20..24].copy_from_slice(&(restricted_sid_length as u32).to_le_bytes());
    if !token.restricted_sids.is_empty() {
        output[24..32].copy_from_slice(
            &caller_base
                .wrapping_add(restricted_offset as u64)
                .to_le_bytes(),
        );
    }
    output[32..36].copy_from_slice(&(token.privileges.len() as u32).to_le_bytes());
    output[36..40].copy_from_slice(&(privilege_length as u32).to_le_bytes());
    output[40..48].copy_from_slice(
        &caller_base
            .wrapping_add(privileges_offset as u64)
            .to_le_bytes(),
    );
    write_luid(&mut output[48..56], token.authentication_id);

    let mut sid_cursor = sids_offset + sid_count * SID_AND_ATTRIBUTES_LENGTH;
    write_sid_and_attributes(
        output,
        sids_offset,
        &token.user,
        token.user_attributes,
        caller_base,
        &mut sid_cursor,
    )?;
    for (index, group) in token.groups.iter().enumerate() {
        write_sid_and_attributes(
            output,
            sids_offset + (index + 1) * SID_AND_ATTRIBUTES_LENGTH,
            &group.sid,
            group.native_attributes(),
            caller_base,
            &mut sid_cursor,
        )?;
    }

    let mut restricted_cursor =
        restricted_offset + token.restricted_sids.len() * SID_AND_ATTRIBUTES_LENGTH;
    for (index, group) in token.restricted_sids.iter().enumerate() {
        write_sid_and_attributes(
            output,
            restricted_offset + index * SID_AND_ATTRIBUTES_LENGTH,
            &group.sid,
            group.native_attributes(),
            caller_base,
            &mut restricted_cursor,
        )?;
    }
    for (index, privilege) in token.privileges.iter().enumerate() {
        let entry = privileges_offset + index * 12;
        write_luid(&mut output[entry..entry + 8], privilege.luid);
        output[entry + 8..entry + 12]
            .copy_from_slice(&AccessToken::privilege_attributes(privilege).to_le_bytes());
    }

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

fn write_sid_and_attributes(
    output: &mut [u8],
    entry: usize,
    sid: &crate::Sid,
    attributes: u32,
    caller_base: u64,
    sid_cursor: &mut usize,
) -> Result<(), InvalidTokenSid> {
    output[entry..entry + 8]
        .copy_from_slice(&caller_base.wrapping_add(*sid_cursor as u64).to_le_bytes());
    output[entry + 8..entry + 12].copy_from_slice(&attributes.to_le_bytes());
    let written = sid
        .write_native(&mut output[*sid_cursor..])
        .ok_or(InvalidTokenSid)?;
    *sid_cursor += written;
    Ok(())
}
