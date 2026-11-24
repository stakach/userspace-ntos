//! One retained device context across synchronous native pump slices.
//!
//! The concrete adapter owns the physical binding, generation check, and bank projection.
//! This type only preserves that exact owner when a pump unwinds or re-enters: a refusal
//! returns the original guard or ticket to its caller. File and video StartDevice pumps use
//! the same transition instead of rebuilding authority from mutable driver state.

/// A native binding whose active stack selector can be removed while its durable row remains.
/// A failed transition must return the very guard or ticket it was given.
pub trait RetainedContextBinding: Sized {
    type Suspended;
    type Error;

    fn suspend(self) -> Result<Self::Suspended, (Self::Error, Self)>;
    fn resume(ticket: Self::Suspended) -> Result<Self, (Self::Error, Self::Suspended)>;
}

/// Move-only owner of either the active stack binding or its exact suspended ticket.
#[must_use = "retain the context until its pump returns or is quarantined"]
pub enum RetainedContextOwner<B: RetainedContextBinding> {
    Active(B),
    Suspended(B::Suspended),
}

impl<B: RetainedContextBinding> RetainedContextOwner<B> {
    pub const fn active(binding: B) -> Self { Self::Active(binding) }

    pub fn active_ref(&self) -> Option<&B> {
        match self {
            Self::Active(binding) => Some(binding),
            Self::Suspended(_) => None,
        }
    }

    /// End the current stack slice, retaining the same durable row for a later resume.
    /// An already suspended owner stays suspended. A refusal returns the original active
    /// owner, so the caller can fence or retry without losing physical authority.
    pub fn suspend(self) -> Result<Self, (B::Error, Self)> {
        match self {
            Self::Active(binding) => B::suspend(binding)
                .map(Self::Suspended)
                .map_err(|(error, binding)| (error, Self::Active(binding))),
            suspended @ Self::Suspended(_) => Ok(suspended),
        }
    }

    /// Rebind the exact ticket before the provider re-enters. A stale generation, foreign
    /// device, or occupied stack returns the same suspended owner; it cannot be replaced by
    /// a fresh lookup or replay of the provider's first request.
    pub fn resume(self) -> Result<Self, (B::Error, Self)> {
        match self {
            Self::Suspended(ticket) => B::resume(ticket)
                .map(Self::Active)
                .map_err(|(error, ticket)| (error, Self::Suspended(ticket))),
            active @ Self::Active(_) => Ok(active),
        }
    }
}
