//! Forward-only construction of executive-lifetime provider capability-bank segments.
use super::BankError;

pub trait ProviderAliasSegmentIo {
    /// Transfer one uniquely reserved empty root slot. Failure transfers nothing.
    fn reserve_slot(&mut self) -> Result<u64, u32>;
    /// Retype exactly one CNode. Failure leaves the reserved slot empty.
    fn retype(&mut self, raw: u64, radix: u32) -> Result<(), u32>;
    /// Mint the guarded copy. Failure leaves the destination slot empty.
    fn mint(&mut self, raw: u64, guarded: u64, guard_bits: u64) -> Result<(), u32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderAliasSegmentSnapshot {
    pub raw: u64,
    pub raw_retyped: bool,
    pub guarded: u64,
    pub guarded_minted: bool,
}

/// This owner intentionally lasts as long as the executive's bank. Partial construction is not
/// rolled back: retries reuse each reserved slot and never revoke a segment containing live leaves.
pub struct ProviderAliasSegment {
    radix: u32,
    held: ProviderAliasSegmentSnapshot,
}

impl ProviderAliasSegment {
    pub const fn new(radix: u32) -> Self {
        Self {
            radix,
            held: ProviderAliasSegmentSnapshot {
                raw: 0,
                raw_retyped: false,
                guarded: 0,
                guarded_minted: false,
            },
        }
    }

    pub fn snapshot(&self) -> ProviderAliasSegmentSnapshot {
        self.held
    }

    pub fn ready(&self) -> Option<u64> {
        self.held.guarded_minted.then_some(self.held.guarded)
    }

    pub fn ensure(&mut self, io: &mut impl ProviderAliasSegmentIo) -> Result<u64, BankError> {
        if self.radix == 0 || self.radix >= 64 {
            return Err(BankError::InvalidRequest);
        }
        if let Some(cap) = self.ready() {
            return Ok(cap);
        }
        if self.held.raw == 0 {
            let raw = io.reserve_slot().map_err(BankError::Backend)?;
            if raw == 0 {
                return Err(BankError::InvalidBackend);
            }
            self.held.raw = raw;
        }
        if !self.held.raw_retyped {
            io.retype(self.held.raw, self.radix)
                .map_err(BankError::Backend)?;
            self.held.raw_retyped = true;
        }
        if self.held.guarded == 0 {
            let guarded = io.reserve_slot().map_err(BankError::Backend)?;
            if guarded == 0 || guarded == self.held.raw {
                return Err(BankError::InvalidBackend);
            }
            self.held.guarded = guarded;
        }
        io.mint(self.held.raw, self.held.guarded, 64 - self.radix as u64)
            .map_err(BankError::Backend)?;
        self.held.guarded_minted = true;
        Ok(self.held.guarded)
    }
}

#[cfg(test)]
#[path = "provider_alias_segment_tests.rs"]
mod tests;
