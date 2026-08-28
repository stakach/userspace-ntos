//! Pure restricted-token construction policy shared by `NtFilterToken` and kernel callers.

use crate::create_token::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY, SE_GROUP_USE_FOR_DENY_ONLY,
};
use crate::{AccessToken, Luid, Sid, TokenGroup, SE_CHANGE_NOTIFY, STATUS_INVALID_PARAMETER};

/// Remove every privilege except `SeChangeNotifyPrivilege`.
pub const DISABLE_MAX_PRIVILEGE: u32 = 0x0000_0001;
/// Mark the result as exempt from software-restriction-policy checks.
pub const SANDBOX_INERT: u32 = 0x0000_0002;

/// NT5 supports only the two original filter flags. Vista's `LUA_TOKEN` and `WRITE_RESTRICTED`
/// acquire meaning only with the later elevation/integrity token model, so they fail closed here.
pub const TOKEN_FILTER_VALID_FLAGS: u32 = DISABLE_MAX_PRIVILEGE | SANDBOX_INERT;

/// Fully captured inputs to token filtering. Attributes on disabled SIDs and deleted privileges are
/// ignored by the native contract; added restricting SIDs must have zero attributes.
#[derive(Copy, Clone, Debug)]
pub struct TokenFilterRequest<'a> {
    pub flags: u32,
    pub sids_to_disable: &'a [(Sid, u32)],
    pub privileges_to_delete: &'a [(Luid, u32)],
    pub restricted_sids: &'a [(Sid, u32)],
}

/// Build the independent token body produced by `SepPerformTokenFiltering`.
pub fn filter_access_token(
    source: &AccessToken,
    request: TokenFilterRequest<'_>,
) -> Result<AccessToken, u32> {
    if request.flags & !TOKEN_FILTER_VALID_FLAGS != 0
        || request
            .restricted_sids
            .iter()
            .any(|(_, attributes)| *attributes != 0)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let mut filtered = source.clone();

    if request
        .sids_to_disable
        .iter()
        .any(|(sid, _)| *sid == filtered.user)
    {
        filtered.user_attributes &= !(SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT);
        filtered.user_attributes |= SE_GROUP_USE_FOR_DENY_ONLY;
    }
    for group in &mut filtered.groups {
        if request
            .sids_to_disable
            .iter()
            .any(|(sid, _)| *sid == group.sid)
        {
            if filtered.owner == group.sid {
                filtered.owner = filtered.user.clone();
            }
            group.make_deny_only();
        }
    }

    if request.flags & DISABLE_MAX_PRIVILEGE != 0 {
        filtered
            .privileges
            .retain(|privilege| privilege.name == SE_CHANGE_NOTIFY);
    } else {
        filtered.privileges.retain(|privilege| {
            !request
                .privileges_to_delete
                .iter()
                .any(|(luid, _)| *luid == privilege.luid)
        });
    }

    for (sid, _) in request.restricted_sids {
        if filtered
            .restricted_sids
            .iter()
            .any(|existing| existing.sid == *sid)
        {
            continue;
        }
        filtered
            .restricted_sids
            .push(TokenGroup::from_native_attributes(
                sid.clone(),
                SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
            ));
    }
    if request.flags & SANDBOX_INERT != 0 {
        filtered.sandbox_inert = true;
    }
    Ok(filtered)
}
