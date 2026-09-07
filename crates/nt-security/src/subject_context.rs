//! Exact token-reference ownership for captured kernel security subjects.
//!
//! Native adapters supply authenticated process/thread identities. Capture does not authorize an
//! operation: anonymous and lowered impersonation levels remain visible to each policy consumer.

use crate::{AccessToken, SecurityImpersonationLevel, TokenId, TokenStore, TokenType};

const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const STATUS_BAD_TOKEN_TYPE: u32 = 0xc000_00a8;
const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xc000_00a5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubjectClientIdentity {
    pub token: TokenId,
    pub level: SecurityImpersonationLevel,
}

pub struct CapturedClientToken<'a> {
    pub token: &'a AccessToken,
    pub level: SecurityImpersonationLevel,
}

pub struct CapturedSubjectTokens<'a> {
    pub primary: &'a AccessToken,
    pub client: Option<CapturedClientToken<'a>>,
    pub process_audit_id: u64,
}

impl CapturedSubjectTokens<'_> {
    /// `None` denotes the primary subject. A client always carries its captured level alongside
    /// the token; using the token's potentially higher inherent level would elevate authority.
    pub fn effective_token(&self) -> (&AccessToken, Option<SecurityImpersonationLevel>) {
        self.client.as_ref().map_or((self.primary, None), |client| {
            (client.token, Some(client.level))
        })
    }

    /// Kernel SePrivilegeCheck checks the captured client level before even KernelMode or empty-
    /// set bypasses. The immutable store borrow held by this view spans the complete operation.
    pub fn check_privileges(
        &self,
        required: &mut [crate::PrivilegeAdjustment],
        all_necessary: bool,
        mode: crate::ProcessorMode,
    ) -> bool {
        let (token, level) = self.effective_token();
        if level.is_some_and(|level| level < SecurityImpersonationLevel::Impersonation) {
            return false;
        }
        crate::check_token_privileges(token, required, all_necessary, mode)
    }
}

/// Non-cloneable ownership of both captured references. The native context owner must retain this
/// value until explicit release; dropping it is not an implicit release against an unknown store.
#[must_use = "captured token references must be explicitly released"]
#[derive(Debug)]
pub struct CapturedSubjectContext {
    domain: u64,
    primary: TokenId,
    client: Option<SubjectClientIdentity>,
    process_audit_id: u64,
    released: bool,
}

impl CapturedSubjectContext {
    pub fn capture(
        tokens: &mut TokenStore,
        primary: TokenId,
        client: Option<SubjectClientIdentity>,
        process_audit_id: u64,
    ) -> Result<Self, u32> {
        if tokens.get(primary).ok_or(STATUS_INVALID_HANDLE)?.token_type != TokenType::Primary {
            return Err(STATUS_BAD_TOKEN_TYPE);
        }
        if let Some(client) = client {
            let token = tokens.get(client.token).ok_or(STATUS_INVALID_HANDLE)?;
            if token.token_type != TokenType::Impersonation {
                return Err(STATUS_BAD_TOKEN_TYPE);
            }
            if client.level > token.impersonation_level {
                return Err(STATUS_BAD_IMPERSONATION_LEVEL);
            }
        }
        // Validate both increments before retaining either. TokenStore is exclusively borrowed
        // throughout, so the checked reference operations below cannot partially fail.
        for id in core::iter::once(primary).chain(client.map(|client| client.token)) {
            tokens
                .reference_count(id)
                .ok_or(STATUS_INVALID_HANDLE)?
                .checked_add(1)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        }
        let domain = tokens.acquire_subject_domain()?;
        tokens
            .retain(primary)
            .expect("validated primary token reference");
        if let Some(client) = client {
            tokens
                .retain(client.token)
                .expect("validated client token reference");
        }
        Ok(Self {
            domain,
            primary,
            client,
            process_audit_id,
            released: false,
        })
    }

    fn validate(&self, tokens: &TokenStore) -> Result<(), u32> {
        if self.released {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.domain != tokens.subject_domain() {
            return Err(STATUS_INVALID_HANDLE);
        }
        for id in core::iter::once(self.primary).chain(self.client.map(|client| client.token)) {
            if tokens.reference_count(id).unwrap_or(0) == 0 {
                return Err(STATUS_INVALID_HANDLE);
            }
        }
        Ok(())
    }

    /// Hold immutable store access throughout a complete policy operation. This observes the exact
    /// captured tokens even if the process/thread has since installed different token identities.
    pub fn resolve<'a>(&'a self, tokens: &'a TokenStore) -> Result<CapturedSubjectTokens<'a>, u32> {
        self.validate(tokens)?;
        Ok(CapturedSubjectTokens {
            primary: tokens.get(self.primary).ok_or(STATUS_INVALID_HANDLE)?,
            client: match self.client {
                Some(client) => Some(CapturedClientToken {
                    token: tokens.get(client.token).ok_or(STATUS_INVALID_HANDLE)?,
                    level: client.level,
                }),
                None => None,
            },
            process_audit_id: self.process_audit_id,
        })
    }

    pub fn release(&mut self, tokens: &mut TokenStore) -> Result<(), u32> {
        self.validate(tokens)?;
        if let Some(client) = self.client {
            tokens
                .release(client.token)
                .expect("validated captured client reference");
        }
        tokens
            .release(self.primary)
            .expect("validated captured primary reference");
        self.released = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "subject_context_tests.rs"]
mod tests;
