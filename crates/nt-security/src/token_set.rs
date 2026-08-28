use crate::{TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID};

pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TokenSetInformationClass {
    Owner,
    PrimaryGroup,
    DefaultDacl,
    SessionId,
    SessionReference,
    AuditPolicy,
    Origin,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TokenSetInformationPlan {
    pub class: TokenSetInformationClass,
    pub fixed_length: usize,
    pub required_access: u32,
    pub requires_tcb: bool,
}

/// Validate the fixed native `NtSetInformationToken` contract before touching a token handle.
/// Variable pointer classes accept trailing bytes, while fixed scalar classes require exact sizes.
pub fn plan_token_information_set(
    information_class: u32,
    information_length: usize,
) -> Result<TokenSetInformationPlan, u32> {
    use TokenSetInformationClass::*;

    let (class, fixed_length, requires_tcb) = match information_class {
        4 if information_length >= 8 => (Owner, 8, false),
        5 if information_length >= 8 => (PrimaryGroup, 8, false),
        6 if information_length >= 8 => (DefaultDacl, 8, false),
        12 if information_length == 4 => (SessionId, 4, true),
        14 if information_length == 4 => (SessionReference, 4, true),
        16 if information_length >= 4 => (AuditPolicy, 4, true),
        17 if information_length == 8 => (Origin, 8, true),
        4 | 5 | 6 | 12 | 14 | 16 | 17 => return Err(STATUS_INFO_LENGTH_MISMATCH),
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    Ok(TokenSetInformationPlan {
        class,
        fixed_length,
        required_access: TOKEN_ADJUST_DEFAULT
            | if class == SessionId {
                TOKEN_ADJUST_SESSIONID
            } else {
                0
            },
        requires_tcb,
    })
}
