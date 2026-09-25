//! Retained source CREATE subject for cross-domain Mup forwarding.
//!
//! Native adapters must authenticate the source IRP and domain before constructing a key. The
//! local `IO_SECURITY_CONTEXT` address is an equality check, never a portable token or pointer.

use crate::{
    CapturedSubjectContext, CapturedSubjectTokens, SubjectClientIdentity, TokenId, TokenStore,
};
use core::num::NonZeroU64;

const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceCreateSecurityTicket {
    id: NonZeroU64,
    generation: NonZeroU64,
}

impl SourceCreateSecurityTicket {
    pub fn new(id: u64, generation: u64) -> Option<Self> {
        Some(Self {
            id: NonZeroU64::new(id)?,
            generation: NonZeroU64::new(generation)?,
        })
    }

    pub fn id(self) -> u64 {
        self.id.get()
    }
    pub fn generation(self) -> u64 {
        self.generation.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceCreateSecurityKey {
    irp_id: NonZeroU64,
    irp_generation: NonZeroU64,
    domain_id: NonZeroU64,
    domain_cookie: NonZeroU64,
    security_context_address: NonZeroU64,
}

impl SourceCreateSecurityKey {
    pub fn new(
        irp_id: u64,
        irp_generation: u64,
        domain_id: u64,
        domain_cookie: u64,
        security_context_address: u64,
    ) -> Option<Self> {
        Some(Self {
            irp_id: NonZeroU64::new(irp_id)?,
            irp_generation: NonZeroU64::new(irp_generation)?,
            domain_id: NonZeroU64::new(domain_id)?,
            domain_cookie: NonZeroU64::new(domain_cookie)?,
            security_context_address: NonZeroU64::new(security_context_address)?,
        })
    }

    pub fn irp_id(self) -> u64 {
        self.irp_id.get()
    }
    pub fn irp_generation(self) -> u64 {
        self.irp_generation.get()
    }
    pub fn domain_id(self) -> u64 {
        self.domain_id.get()
    }
    pub fn domain_cookie(self) -> u64 {
        self.domain_cookie.get()
    }
    pub fn security_context_address(self) -> u64 {
        self.security_context_address.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceCreateSecurityPhase {
    Captured,
    Pending,
    Indeterminate,
    Terminal,
    Released,
}

/// Owns both token references through the complete provider operation. Dropping this value does
/// not release them; the native I/O owner must observe terminal completion before explicit release.
#[must_use = "source subject must be released after terminal completion"]
pub struct SourceCreateSecurityOwner {
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
    subject: CapturedSubjectContext,
    phase: SourceCreateSecurityPhase,
}

impl SourceCreateSecurityOwner {
    pub fn capture(
        tokens: &mut TokenStore,
        ticket: SourceCreateSecurityTicket,
        key: SourceCreateSecurityKey,
        primary: TokenId,
        client: Option<SubjectClientIdentity>,
        process_audit_id: u64,
    ) -> Result<Self, u32> {
        Ok(Self {
            ticket,
            key,
            subject: CapturedSubjectContext::capture(tokens, primary, client, process_audit_id)?,
            phase: SourceCreateSecurityPhase::Captured,
        })
    }

    pub fn ticket(&self) -> SourceCreateSecurityTicket {
        self.ticket
    }
    pub fn key(&self) -> SourceCreateSecurityKey {
        self.key
    }
    pub fn phase(&self) -> SourceCreateSecurityPhase {
        self.phase
    }

    pub fn resolve<'a>(
        &'a self,
        tokens: &'a TokenStore,
        ticket: SourceCreateSecurityTicket,
        key: SourceCreateSecurityKey,
    ) -> Result<CapturedSubjectTokens<'a>, u32> {
        if self.phase == SourceCreateSecurityPhase::Released
            || ticket != self.ticket
            || key != self.key
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.subject.resolve(tokens)
    }

    pub fn token_ids(
        &self,
        tokens: &TokenStore,
        ticket: SourceCreateSecurityTicket,
        key: SourceCreateSecurityKey,
    ) -> Result<(TokenId, Option<SubjectClientIdentity>), u32> {
        if self.phase == SourceCreateSecurityPhase::Released
            || ticket != self.ticket
            || key != self.key
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.subject.token_ids(tokens)
    }

    pub fn mark_pending(&mut self) {
        if self.phase == SourceCreateSecurityPhase::Captured {
            self.phase = SourceCreateSecurityPhase::Pending;
        }
    }

    pub fn mark_indeterminate(&mut self) {
        if matches!(
            self.phase,
            SourceCreateSecurityPhase::Captured | SourceCreateSecurityPhase::Pending
        ) {
            self.phase = SourceCreateSecurityPhase::Indeterminate;
        }
    }

    /// Call only after a genuine terminal provider result has been observed.
    pub fn mark_terminal(&mut self) {
        if self.phase != SourceCreateSecurityPhase::Released {
            self.phase = SourceCreateSecurityPhase::Terminal;
        }
    }

    pub fn release(&mut self, tokens: &mut TokenStore) -> Result<(), u32> {
        if self.phase != SourceCreateSecurityPhase::Terminal {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.subject.release(tokens)?;
        self.phase = SourceCreateSecurityPhase::Released;
        Ok(())
    }
}

#[cfg(test)]
#[path = "source_create_security_tests.rs"]
mod tests;
