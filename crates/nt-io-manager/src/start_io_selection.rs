//! Exact pending-node phase claim around native StartIo queue selection.
//!
//! Completion and cancellation claim the same generation-bearing atomic word. A selection
//! therefore excludes those transitions until the WDM queue effect has a durable owner.

use core::sync::atomic::{AtomicU64, Ordering};

pub struct StartIoSelectionClaim<'a> {
    state: &'a AtomicU64,
    pending: u64,
    selecting: u64,
    effect_committed: bool,
}

impl<'a> StartIoSelectionClaim<'a> {
    /// Only the exact pending generation may enter selection.
    pub fn claim(state: &'a AtomicU64, pending: u64, selecting: u64) -> Option<Self> {
        if pending & !0xff != selecting & !0xff || pending == selecting {
            return None;
        }
        state.compare_exchange(pending, selecting, Ordering::AcqRel, Ordering::Acquire).ok()?;
        Some(Self { state, pending, selecting, effect_committed: false })
    }

    /// After the first physical queue write, rollback would misrepresent the selected packet.
    /// The owner must publish the durable transaction before calling `publish`.
    pub fn effect_committed(&mut self) { self.effect_committed = true; }

    /// Reopen completion/cancellation after the exact selected transaction is durable.
    pub fn publish(self) -> Result<(), Self> {
        if !self.effect_committed { return Err(self); }
        if self.state.compare_exchange(self.selecting, self.pending,
            Ordering::AcqRel, Ordering::Acquire).is_err() { return Err(self); }
        core::mem::forget(self);
        Ok(())
    }
}

impl Drop for StartIoSelectionClaim<'_> {
    fn drop(&mut self) {
        if !self.effect_committed {
            let _ = self.state.compare_exchange(self.selecting, self.pending,
                Ordering::AcqRel, Ordering::Acquire);
        }
    }
}
