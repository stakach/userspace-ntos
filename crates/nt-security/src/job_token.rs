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

/// Captured, kernel-owned form of the three pointer-bearing job filter arrays.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobTokenFilter {
    pub sids_to_disable: Vec<(Sid, u32)>,
    pub privileges_to_delete: Vec<(Luid, u32)>,
    pub restricted_sids: Vec<(Sid, u32)>,
}

impl JobTokenFilter {
    pub fn is_empty(&self) -> bool {
        self.sids_to_disable.is_empty()
            && self.privileges_to_delete.is_empty()
            && self.restricted_sids.is_empty()
    }

    fn request(&self) -> TokenFilterRequest<'_> {
        TokenFilterRequest {
            flags: 0,
            sids_to_disable: &self.sids_to_disable,
            privileges_to_delete: &self.privileges_to_delete,
            restricted_sids: &self.restricted_sids,
        }
    }
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
        if next_flags & !JOB_OBJECT_SECURITY_VALID_FLAGS != 0
            || previous_flags & !next_flags != 0
            || next_flags & JOB_OBJECT_SECURITY_RESTRICTED_TOKEN != 0
                && next_flags & (JOB_OBJECT_SECURITY_ONLY_TOKEN | JOB_OBJECT_SECURITY_FILTER_TOKENS)
                    != 0
            || next_flags & JOB_OBJECT_SECURITY_ONLY_TOKEN != 0
                && next_flags & JOB_OBJECT_SECURITY_FILTER_TOKENS != 0
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
        if installing_only != only_token.is_some()
            || installing_filter != filter.is_some()
            || (installing_filter && filter.as_ref().is_some_and(JobTokenFilter::is_empty))
        {
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
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if update.installed_filter {
            policy.filter = None;
        }
        if update.installed_only_token {
            let token = policy.only_token.take().ok_or(STATUS_INVALID_HANDLE)?;
            tokens.release(token)?;
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

    fn validate_token(
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
        if policy.flags & JOB_OBJECT_SECURITY_RESTRICTED_TOKEN != 0 && !token.is_restricted() {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(())
    }

    /// Validate an existing process token and, for ONLY_TOKEN, build the independent primary token
    /// that must replace it after job assignment succeeds.
    pub fn prepare_primary_replacement(
        &self,
        tokens: &mut TokenStore,
        job_id: u32,
        current: TokenId,
    ) -> Result<Option<TokenId>, u32> {
        self.validate_token(job_id, tokens, current)?;
        let policy = self.policy(job_id).ok_or(STATUS_INVALID_HANDLE)?;
        let Some(source) = policy.only_token else {
            return Ok(None);
        };
        tokens
            .duplicate(
                source,
                TokenType::Primary,
                SecurityImpersonationLevel::Anonymous,
                false,
            )
            .map(Some)
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
        if let Err(status) = self.validate_token(job_id, tokens, owned_source) {
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

    /// Release the Security Manager's references after the Ps destruction record is accepted.
    pub fn rundown(&mut self, tokens: &mut TokenStore, job_id: u32) -> Result<bool, u32> {
        let Some(slot) = Self::slot(job_id) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let Some(policy) = self.policies.get_mut(slot).and_then(Option::take) else {
            return Ok(false);
        };
        if let Some(token) = policy.only_token {
            tokens.release(token)?;
        }
        Ok(true)
    }
}
