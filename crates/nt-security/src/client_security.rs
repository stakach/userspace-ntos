//! NT client-security context policy and exact token ownership.
//!
//! The integration layer authenticates the source thread and atomically captures its effective
//! token role, level and EffectiveOnly flag. A raw token id is not caller authorization. These
//! owners implement neither thread assignment nor native token-pointer publication.

use crate::{
    plan_client_impersonation, AccessToken, Luid, SecurityContextTrackingMode,
    SecurityImpersonationLevel, SecurityQualityOfService, TokenId, TokenSource, TokenStore,
    TokenType, STATUS_BAD_IMPERSONATION_LEVEL, STATUS_BAD_TOKEN_TYPE, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
};

/// PsReferenceEffectiveToken reports the thread's role, not the token object's stored type.
/// A dynamic client context can install a primary token as an impersonation source.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EffectiveClientTokenSource {
    Primary {
        token: TokenId,
    },
    Impersonating {
        token: TokenId,
        level: SecurityImpersonationLevel,
        effective_only: bool,
    },
}

/// Actual TOKEN_CONTROL fields captured for remote dynamic tracking.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ClientTokenControl {
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub modified_id: Luid,
    pub source: TokenSource,
}

#[derive(Debug)]
struct OwnedToken {
    domain: u64,
    token: TokenId,
    held: bool,
}

impl OwnedToken {
    fn validate<'a>(&self, tokens: &'a TokenStore) -> Result<&'a AccessToken, u32> {
        if !self.held {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.domain == 0 || self.domain != tokens.subject_domain() {
            return Err(STATUS_INVALID_HANDLE);
        }
        tokens.get(self.token).ok_or(STATUS_INVALID_HANDLE)
    }

    fn release(&mut self, tokens: &mut TokenStore) -> Result<(), u32> {
        self.validate(tokens)?;
        tokens.release(self.token)?;
        self.held = false;
        Ok(())
    }
}

/// One owning reference to the context's token. Static tracking owns a duplicate; dynamic tracking
/// owns the original token, not a promise to follow future thread token replacements.
///
/// ```compile_fail
/// use nt_security::ClientSecurityContext;
/// fn duplicate(context: ClientSecurityContext) { let _ = context.clone(); }
/// ```
#[derive(Debug)]
#[must_use = "explicitly release the client context's token reference"]
pub struct ClientSecurityContext {
    owner: OwnedToken,
    qos: SecurityQualityOfService,
    directly_access_client_token: bool,
    direct_access_effective_only: bool,
    server_is_remote: bool,
    control: Option<ClientTokenControl>,
}

impl ClientSecurityContext {
    /// The source identity and thread metadata must come from one authenticated, live capture.
    /// This operation must not race token replacement in the caller's process/thread manager.
    pub fn create(
        tokens: &mut TokenStore,
        source: EffectiveClientTokenSource,
        qos: SecurityQualityOfService,
        server_is_remote: bool,
    ) -> Result<Self, u32> {
        let (token, role, level, effective_only) = match source {
            EffectiveClientTokenSource::Primary { token } => (
                token,
                TokenType::Primary,
                SecurityImpersonationLevel::Anonymous,
                false,
            ),
            EffectiveClientTokenSource::Impersonating {
                token,
                level,
                effective_only,
            } => (token, TokenType::Impersonation, level, effective_only),
        };
        let actual = tokens.get(token).ok_or(STATUS_INVALID_HANDLE)?;
        if role == TokenType::Primary && actual.token_type != TokenType::Primary {
            return Err(STATUS_BAD_TOKEN_TYPE);
        }
        if role == TokenType::Impersonation {
            if actual.token_type == TokenType::Impersonation && level > actual.impersonation_level {
                return Err(STATUS_BAD_IMPERSONATION_LEVEL);
            }
            if server_is_remote && level != SecurityImpersonationLevel::Delegation {
                return Err(STATUS_BAD_IMPERSONATION_LEVEL);
            }
        }
        let plan = plan_client_impersonation(role, level, effective_only, qos)?;
        let directly_access_client_token =
            qos.tracking_mode == SecurityContextTrackingMode::Dynamic;
        let direct_access_effective_only =
            qos.effective_only || (role == TokenType::Impersonation && effective_only);
        let control = if server_is_remote && directly_access_client_token {
            let stats = tokens.statistics(token).ok_or(STATUS_INVALID_HANDLE)?;
            Some(ClientTokenControl {
                token_id: stats.token_id,
                authentication_id: stats.authentication_id,
                modified_id: stats.modified_id,
                source: tokens.source(token).ok_or(STATUS_INVALID_HANDLE)?,
            })
        } else {
            None
        };
        let domain = tokens.acquire_subject_domain()?;
        let token = if plan.static_tracking {
            // SeCopyClientToken duplicates the complete token. EffectiveOnly constrains later
            // impersonation/open, rather than deleting disabled groups or privileges here.
            tokens.duplicate(token, TokenType::Impersonation, plan.level, false)?
        } else {
            tokens.retain(token)?;
            token
        };
        Ok(Self {
            owner: OwnedToken {
                domain,
                token,
                held: true,
            },
            qos,
            directly_access_client_token,
            direct_access_effective_only,
            server_is_remote,
            control,
        })
    }

    pub fn token_id(&self) -> TokenId {
        self.owner.token
    }
    pub fn is_held(&self) -> bool {
        self.owner.held
    }
    pub fn qos(&self) -> SecurityQualityOfService {
        self.qos
    }
    pub fn directly_access_client_token(&self) -> bool {
        self.directly_access_client_token
    }
    pub fn direct_access_effective_only(&self) -> bool {
        self.direct_access_effective_only
    }
    pub fn server_is_remote(&self) -> bool {
        self.server_is_remote
    }
    pub fn token_control(&self) -> Option<ClientTokenControl> {
        self.control
    }
    pub fn token<'a>(&self, tokens: &'a TokenStore) -> Result<&'a AccessToken, u32> {
        self.owner.validate(tokens)
    }
    pub fn release(&mut self, tokens: &mut TokenStore) -> Result<(), u32> {
        self.owner.release(tokens)
    }

    /// Prepare the independent token reference and flags passed to PsImpersonateClient. The
    /// integration layer still must authorize the exact server thread, enforce job policy, and
    /// transactionally install or release this owner; this does not modify a thread.
    pub fn retain_for_impersonation(
        &self,
        tokens: &mut TokenStore,
    ) -> Result<ClientImpersonationReference, u32> {
        self.owner.validate(tokens)?;
        tokens.retain(self.owner.token)?;
        Ok(ClientImpersonationReference {
            owner: OwnedToken {
                domain: self.owner.domain,
                token: self.owner.token,
                held: true,
            },
            level: self.qos.impersonation_level,
            effective_only: if self.directly_access_client_token {
                self.direct_access_effective_only
            } else {
                self.qos.effective_only
            },
        })
    }
}

/// Prepared ownership only, not proof that any thread has been impersonated.
///
/// ```compile_fail
/// use nt_security::ClientImpersonationReference;
/// fn duplicate(owner: ClientImpersonationReference) { let _ = owner.clone(); }
/// ```
#[derive(Debug)]
#[must_use = "retain this owner until thread assignment or explicit release"]
pub struct ClientImpersonationReference {
    owner: OwnedToken,
    level: SecurityImpersonationLevel,
    effective_only: bool,
}

impl ClientImpersonationReference {
    pub fn token_id(&self) -> TokenId {
        self.owner.token
    }
    pub fn is_held(&self) -> bool {
        self.owner.held
    }
    pub fn level(&self) -> SecurityImpersonationLevel {
        self.level
    }
    pub fn effective_only(&self) -> bool {
        self.effective_only
    }
    pub const fn copy_on_open(&self) -> bool {
        true
    }
    pub fn token<'a>(&self, tokens: &'a TokenStore) -> Result<&'a AccessToken, u32> {
        self.owner.validate(tokens)
    }
    pub fn release(&mut self, tokens: &mut TokenStore) -> Result<(), u32> {
        self.owner.release(tokens)
    }
}

#[cfg(test)]
#[path = "client_security/tests.rs"]
mod tests;
