//! Security Reference Monitor ownership for NT5 job token restrictions.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    Luid, SecurityImpersonationLevel, Sid, TokenFilterRequest, TokenId, TokenStore, TokenType,
    STATUS_ACCESS_DENIED, STATUS_BAD_TOKEN_TYPE, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};

pub const JOB_OBJECT_SECURITY_NO_ADMIN: u32 = 0x0000_0001;
pub const JOB_OBJECT_SECURITY_RESTRICTED_TOKEN: u32 = 0x0000_0002;
pub const JOB_OBJECT_SECURITY_ONLY_TOKEN: u32 = 0x0000_0004;
pub const JOB_OBJECT_SECURITY_FILTER_TOKENS: u32 = 0x0000_0008;
pub const JOB_OBJECT_SECURITY_VALID_FLAGS: u32 = 0x0000_000f;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
pub const JOB_SECURITY_LIMIT_INFORMATION_SIZE: usize = 40;
const TOKEN_GROUPS_HEADER_SIZE: usize = 8;
const SID_AND_ATTRIBUTES_SIZE: usize = 16;
const TOKEN_PRIVILEGES_HEADER_SIZE: usize = 4;
const LUID_AND_ATTRIBUTES_SIZE: usize = 12;

/// Captured, kernel-owned form of the three pointer-bearing job filter arrays.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobTokenFilter {
    pub sids_to_disable: Vec<(Sid, u32)>,
    pub privileges_to_delete: Vec<(Luid, u32)>,
    pub restricted_sids: Vec<(Sid, u32)>,
}

impl JobTokenFilter {
    fn request(&self) -> TokenFilterRequest<'_> {
        TokenFilterRequest {
            flags: 0,
            sids_to_disable: &self.sids_to_disable,
            privileges_to_delete: &self.privileges_to_delete,
            restricted_sids: &self.restricted_sids,
        }
    }

    fn groups_length(groups: &[(Sid, u32)]) -> Option<usize> {
        let entries = groups.len().checked_mul(SID_AND_ATTRIBUTES_SIZE)?;
        groups.iter().try_fold(
            TOKEN_GROUPS_HEADER_SIZE.checked_add(entries)?,
            |length, (sid, _)| length.checked_add(sid.native_len()?),
        )
    }

    fn privileges_length(privileges: &[(Luid, u32)]) -> Option<usize> {
        TOKEN_PRIVILEGES_HEADER_SIZE
            .checked_add(privileges.len().checked_mul(LUID_AND_ATTRIBUTES_SIZE)?)
    }

    pub fn encoded_length(&self) -> Option<usize> {
        let mut length = JOB_SECURITY_LIMIT_INFORMATION_SIZE;
        if !self.sids_to_disable.is_empty() {
            length = length.checked_add(Self::groups_length(&self.sids_to_disable)?)?;
        }
        if !self.privileges_to_delete.is_empty() {
            length = length.checked_add(Self::privileges_length(&self.privileges_to_delete)?)?;
        }
        if !self.restricted_sids.is_empty() {
            length = length.checked_add(Self::groups_length(&self.restricted_sids)?)?;
        }
        Some(length)
    }
}

fn encode_groups(
    groups: &[(Sid, u32)],
    caller_base: u64,
    block_offset: usize,
    output: &mut [u8],
) -> Option<usize> {
    let length = JobTokenFilter::groups_length(groups)?;
    let block = output.get_mut(block_offset..block_offset.checked_add(length)?)?;
    block.fill(0);
    block[..4].copy_from_slice(&u32::try_from(groups.len()).ok()?.to_le_bytes());
    let mut sid_cursor = TOKEN_GROUPS_HEADER_SIZE + groups.len() * SID_AND_ATTRIBUTES_SIZE;
    for (index, (sid, attributes)) in groups.iter().enumerate() {
        let entry = TOKEN_GROUPS_HEADER_SIZE + index * SID_AND_ATTRIBUTES_SIZE;
        let sid_pointer = caller_base
            .checked_add(block_offset as u64)?
            .checked_add(sid_cursor as u64)?;
        block[entry..entry + 8].copy_from_slice(&sid_pointer.to_le_bytes());
        block[entry + 8..entry + 12].copy_from_slice(&attributes.to_le_bytes());
        let written = sid.write_native(&mut block[sid_cursor..])?;
        sid_cursor += written;
    }
    Some(length)
}

fn encode_privileges(
    privileges: &[(Luid, u32)],
    block_offset: usize,
    output: &mut [u8],
) -> Option<usize> {
    let length = JobTokenFilter::privileges_length(privileges)?;
    let block = output.get_mut(block_offset..block_offset.checked_add(length)?)?;
    block.fill(0);
    block[..4].copy_from_slice(&u32::try_from(privileges.len()).ok()?.to_le_bytes());
    for (index, (luid, attributes)) in privileges.iter().enumerate() {
        let entry = TOKEN_PRIVILEGES_HEADER_SIZE + index * LUID_AND_ATTRIBUTES_SIZE;
        block[entry..entry + 4].copy_from_slice(&luid.low.to_le_bytes());
        block[entry + 4..entry + 8].copy_from_slice(&luid.high.to_le_bytes());
        block[entry + 8..entry + 12].copy_from_slice(&attributes.to_le_bytes());
    }
    Some(length)
}

/// Encode the x64 `JOBOBJECT_SECURITY_LIMIT_INFORMATION` query result. Pointer fields always
/// relocate into the caller's buffer; the job token itself remains an internal reference and is
/// never converted into a caller handle by a query.
pub fn encode_job_security_limit_information(
    flags: u32,
    filter: Option<&JobTokenFilter>,
    caller_base: u64,
    output: &mut [u8],
) -> Result<usize, usize> {
    let required = match filter {
        Some(filter) => filter.encoded_length().unwrap_or(usize::MAX),
        None => JOB_SECURITY_LIMIT_INFORMATION_SIZE,
    };
    if output.len() < required {
        return Err(required);
    }
    output[..required].fill(0);
    output[..4].copy_from_slice(&flags.to_le_bytes());
    let Some(filter) = filter else {
        return Ok(JOB_SECURITY_LIMIT_INFORMATION_SIZE);
    };
    let mut cursor = JOB_SECURITY_LIMIT_INFORMATION_SIZE;
    if !filter.sids_to_disable.is_empty() {
        let pointer = caller_base
            .checked_add(u64::try_from(cursor).map_err(|_| usize::MAX)?)
            .ok_or(usize::MAX)?;
        output[16..24].copy_from_slice(&pointer.to_le_bytes());
        cursor += encode_groups(&filter.sids_to_disable, caller_base, cursor, output)
            .ok_or(usize::MAX)?;
    }
    if !filter.privileges_to_delete.is_empty() {
        let pointer = caller_base
            .checked_add(u64::try_from(cursor).map_err(|_| usize::MAX)?)
            .ok_or(usize::MAX)?;
        output[24..32].copy_from_slice(&pointer.to_le_bytes());
        cursor +=
            encode_privileges(&filter.privileges_to_delete, cursor, output).ok_or(usize::MAX)?;
    }
    if !filter.restricted_sids.is_empty() {
        let pointer = caller_base
            .checked_add(u64::try_from(cursor).map_err(|_| usize::MAX)?)
            .ok_or(usize::MAX)?;
        output[32..40].copy_from_slice(&pointer.to_le_bytes());
        cursor += encode_groups(&filter.restricted_sids, caller_base, cursor, output)
            .ok_or(usize::MAX)?;
    }
    Ok(cursor)
}

#[derive(Clone, Debug, Default)]
struct JobTokenPolicy {
    flags: u32,
    only_token: Option<TokenId>,
    filter: Option<JobTokenFilter>,
}

/// Delta needed to undo provider publication when the later Ps commit fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobTokenPolicyUpdate {
    job_id: u32,
    previous_flags: u32,
    installed_only_token: bool,
    installed_filter: bool,
}

/// Provider-owned security material keyed by the opaque Ps JobId.
#[derive(Clone, Debug, Default)]
pub struct JobTokenPolicyStore {
    policies: Vec<Option<JobTokenPolicy>>,
}

impl JobTokenPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(job_id: u32) -> Option<usize> {
        job_id.checked_sub(1).map(|id| id as usize)
    }

    fn policy(&self, job_id: u32) -> Option<&JobTokenPolicy> {
        self.policies.get(Self::slot(job_id)?)?.as_ref()
    }

    /// Publish newly captured material before Ps commits its monotonic flag transaction.
    pub fn install_update(
        &mut self,
        tokens: &mut TokenStore,
        job_id: u32,
        previous_flags: u32,
        next_flags: u32,
        only_token: Option<TokenId>,
        filter: Option<JobTokenFilter>,
    ) -> Result<JobTokenPolicyUpdate, u32> {
        let exclusive = JOB_OBJECT_SECURITY_ONLY_TOKEN | JOB_OBJECT_SECURITY_FILTER_TOKENS;
        let installing_restricted = previous_flags & JOB_OBJECT_SECURITY_RESTRICTED_TOKEN == 0
            && next_flags & JOB_OBJECT_SECURITY_RESTRICTED_TOKEN != 0;
        if next_flags & !JOB_OBJECT_SECURITY_VALID_FLAGS != 0
            || previous_flags & !next_flags != 0
            || next_flags & JOB_OBJECT_SECURITY_ONLY_TOKEN != 0
                && next_flags & JOB_OBJECT_SECURITY_FILTER_TOKENS != 0
            || installing_restricted && previous_flags & exclusive != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let slot = Self::slot(job_id).ok_or(STATUS_INVALID_HANDLE)?;
        let observed_flags = self.policy(job_id).map_or(0, |policy| policy.flags);
        if observed_flags != previous_flags {
            return Err(STATUS_INVALID_PARAMETER);
        }

        let installing_only = previous_flags & JOB_OBJECT_SECURITY_ONLY_TOKEN == 0
            && next_flags & JOB_OBJECT_SECURITY_ONLY_TOKEN != 0;
        let installing_filter = previous_flags & JOB_OBJECT_SECURITY_FILTER_TOKENS == 0
            && next_flags & JOB_OBJECT_SECURITY_FILTER_TOKENS != 0;
        if installing_only != only_token.is_some() || installing_filter != filter.is_some() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let policy_token = only_token.or_else(|| self.policy(job_id)?.only_token);
        if let Some(token_id) = policy_token {
            let token = tokens.get(token_id).ok_or(STATUS_INVALID_HANDLE)?;
            if token.token_type != TokenType::Primary {
                return Err(STATUS_BAD_TOKEN_TYPE);
            }
            if next_flags & JOB_OBJECT_SECURITY_NO_ADMIN != 0 && token.is_administrator() {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }

        if slot >= self.policies.len() {
            self.policies
                .try_reserve(slot + 1 - self.policies.len())
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            self.policies.resize_with(slot + 1, || None);
        }
        if let Some(token_id) = only_token {
            tokens.retain(token_id)?;
        }
        let policy = self.policies[slot].get_or_insert_with(JobTokenPolicy::default);
        policy.flags = next_flags;
        if let Some(token_id) = only_token {
            policy.only_token = Some(token_id);
        }
        if let Some(filter) = filter {
            policy.filter = Some(filter);
        }
        Ok(JobTokenPolicyUpdate {
            job_id,
            previous_flags,
            installed_only_token: installing_only,
            installed_filter: installing_filter,
        })
    }

    /// Undo provider publication after a failed Ps commit.
    pub fn rollback_update(
        &mut self,
        tokens: &mut TokenStore,
        update: JobTokenPolicyUpdate,
    ) -> Result<(), u32> {
        let slot = Self::slot(update.job_id).ok_or(STATUS_INVALID_HANDLE)?;
        let policy = self
            .policies
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let token_to_release = if update.installed_only_token {
            Some(policy.only_token.ok_or(STATUS_INVALID_HANDLE)?)
        } else {
            None
        };
        if let Some(token) = token_to_release {
            tokens.release(token)?;
        }
        let policy = self.policies[slot].as_mut().ok_or(STATUS_INVALID_HANDLE)?;
        if update.installed_filter {
            policy.filter = None;
        }
        if update.installed_only_token {
            policy.only_token = None;
        }
        policy.flags = update.previous_flags;
        if policy.flags == 0 && policy.only_token.is_none() && policy.filter.is_none() {
            self.policies[slot] = None;
        }
        Ok(())
    }

    pub fn flags(&self, job_id: u32) -> u32 {
        self.policy(job_id).map_or(0, |policy| policy.flags)
    }

    pub fn filter(&self, job_id: u32) -> Option<&JobTokenFilter> {
        self.policy(job_id)?.filter.as_ref()
    }

    fn validate_assignment_primary(
        &self,
        job_id: u32,
        tokens: &TokenStore,
        token_id: TokenId,
    ) -> Result<(), u32> {
        let Some(policy) = self.policy(job_id) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let token = tokens.get(token_id).ok_or(STATUS_INVALID_HANDLE)?;
        if policy.flags & JOB_OBJECT_SECURITY_NO_ADMIN != 0 && token.is_administrator() {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(())
    }

    fn validate_impersonation(
        &self,
        job_id: u32,
        tokens: &TokenStore,
        token_id: TokenId,
    ) -> Result<(), u32> {
        self.validate_assignment_primary(job_id, tokens, token_id)?;
        let policy = self.policy(job_id).ok_or(STATUS_INVALID_HANDLE)?;
        let token = tokens.get(token_id).ok_or(STATUS_INVALID_HANDLE)?;
        if policy.flags & JOB_OBJECT_SECURITY_RESTRICTED_TOKEN != 0 && !token.is_restricted() {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(())
    }

    /// Build a process-owned duplicate of the job's forcible primary token.
    pub fn duplicate_only_primary(
        &self,
        tokens: &mut TokenStore,
        job_id: u32,
    ) -> Result<TokenId, u32> {
        let source = self
            .policy(job_id)
            .and_then(|policy| policy.only_token)
            .ok_or(STATUS_INVALID_HANDLE)?;
        tokens.duplicate(
            source,
            TokenType::Primary,
            SecurityImpersonationLevel::Anonymous,
            false,
        )
    }

    /// Validate an existing process token and, for ONLY_TOKEN, build the independent primary token
    /// that must replace it after job assignment succeeds.
    pub fn prepare_primary_replacement(
        &self,
        tokens: &mut TokenStore,
        job_id: u32,
        current: TokenId,
    ) -> Result<Option<TokenId>, u32> {
        let policy = self.policy(job_id).ok_or(STATUS_INVALID_HANDLE)?;
        self.validate_assignment_primary(job_id, tokens, current)?;
        if policy.only_token.is_none() {
            return Ok(None);
        }
        self.duplicate_only_primary(tokens, job_id).map(Some)
    }

    /// Apply the job's impersonation restrictions to one caller-owned token reference. On error
    /// the reference is released; on success ownership of the returned reference stays with the
    /// caller. FILTER_TOKENS creates a new independent filtered token and releases the source.
    pub fn admit_owned_impersonation(
        &self,
        tokens: &mut TokenStore,
        job_id: u32,
        owned_source: TokenId,
    ) -> Result<TokenId, u32> {
        if let Err(status) = self.validate_impersonation(job_id, tokens, owned_source) {
            let _ = tokens.release(owned_source);
            return Err(status);
        }
        let filter = self
            .policy(job_id)
            .and_then(|policy| policy.filter.as_ref());
        let Some(filter) = filter else {
            return Ok(owned_source);
        };
        let filtered = tokens.filter(owned_source, filter.request());
        let _ = tokens.release(owned_source);
        filtered
    }

    /// Validate provider-owned references before another subsystem commits its own teardown. The
    /// executive serializes the subsequent rundown, so this remains stable until `rundown` consumes
    /// the policy.
    pub fn validate_rundown(&self, tokens: &TokenStore, job_id: u32) -> Result<bool, u32> {
        let Some(slot) = Self::slot(job_id) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let Some(policy) = self.policies.get(slot).and_then(Option::as_ref) else {
            return Ok(false);
        };
        if let Some(token) = policy.only_token {
            if tokens
                .reference_count(token)
                .is_none_or(|references| references == 0)
            {
                return Err(STATUS_INVALID_HANDLE);
            }
        }
        Ok(true)
    }

    /// Release the Security Manager's references after the Ps destruction record is accepted.
    pub fn rundown(&mut self, tokens: &mut TokenStore, job_id: u32) -> Result<bool, u32> {
        let Some(slot) = Self::slot(job_id) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let Some(policy) = self.policies.get(slot).and_then(Option::as_ref) else {
            return Ok(false);
        };
        if let Some(token) = policy.only_token {
            tokens.release(token)?;
        }
        self.policies[slot] = None;
        Ok(true)
    }
}
