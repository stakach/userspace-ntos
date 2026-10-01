//! Completion signals prepared before an uncertain cross-component publication.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_STORE_AUTHORITY: AtomicU64 = AtomicU64::new(1);

/// Exact, store-scoped ownership of an unpublished Event completion signal.
/// Dropping a copy does not cancel the transaction; uncertain effects retain it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferredEventSignal {
    authority: u64,
    native: u64,
    serial: u64,
    generation: u64,
    state_sequence: u64,
}

impl DeferredEventSignal {
    pub const fn native_identity(self) -> u64 {
        self.native
    }

    pub const fn state_sequence(self) -> u64 {
        self.state_sequence
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

pub(crate) struct DeferredEventSignals {
    authority: u64,
    next_serial: u64,
    pending: Vec<DeferredEventSignal>,
}

impl Default for DeferredEventSignals {
    fn default() -> Self {
        Self {
            authority: 0,
            next_serial: 1,
            pending: Vec::new(),
        }
    }
}

impl DeferredEventSignals {
    pub(crate) fn contains(&self, native: u64) -> bool {
        self.pending.iter().any(|token| token.native == native)
    }

    pub(crate) fn begin(
        &mut self,
        native: u64,
        generation: u64,
        state_sequence: u64,
    ) -> Result<DeferredEventSignal, ()> {
        let serial = self.next_serial;
        let next = serial.checked_add(1).ok_or(())?;
        self.pending.try_reserve(1).map_err(|_| ())?;
        if self.authority == 0 {
            self.authority = NEXT_STORE_AUTHORITY
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| ())?;
        }
        let token = DeferredEventSignal {
            authority: self.authority,
            native,
            serial,
            generation,
            state_sequence,
        };
        self.pending.push(token);
        self.next_serial = next;
        Ok(token)
    }

    pub(crate) fn retire(&mut self, token: DeferredEventSignal) -> Result<(), ()> {
        if token.authority != self.authority {
            return Err(());
        }
        let index = self
            .pending
            .iter()
            .position(|pending| *pending == token)
            .ok_or(())?;
        self.pending.swap_remove(index);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_serial_does_not_reuse_or_retire_existing_ownership() {
        let mut signals = DeferredEventSignals::default();
        let prior = signals.begin(7, 1, 2).unwrap();
        signals.next_serial = u64::MAX;
        assert_eq!(signals.begin(7, 1, 3), Err(()));
        assert!(signals.contains(7));
        assert_eq!(signals.retire(prior), Ok(()));
        assert!(!signals.contains(7));
    }
}
