//! Exclusive moved-out volume ownership independent of the work using the volume.

use core::sync::atomic::{AtomicU64, Ordering};

/// Refusal to claim the in-memory volume. A refused caller owns no filesystem or release right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeOwnerError { Busy, EpochExhausted }

/// One gate for the mounted volume. Even epochs are available; odd epochs have one owner.
/// The epoch never wraps, so a stale owner cannot release a later claim.
pub struct VolumeOwnerGate { state: AtomicU64 }

impl Default for VolumeOwnerGate {
    fn default() -> Self { Self::new() }
}

impl VolumeOwnerGate {
    pub const fn new() -> Self { Self { state: AtomicU64::new(0) } }

    pub fn is_owned(&self) -> bool { self.state.load(Ordering::Acquire) & 1 != 0 }

    /// Claim before removing the FileSystem from its public slot. The caller must restore the
    /// same filesystem before releasing this token. No IPC may occur between claim and removal.
    pub fn try_claim(&self) -> Result<VolumeOwner<'_>, VolumeOwnerError> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & 1 != 0 { return Err(VolumeOwnerError::Busy); }
            let owned = state.checked_add(1).filter(|epoch| epoch.checked_add(1).is_some())
                .ok_or(VolumeOwnerError::EpochExhausted)?;
            match self.state.compare_exchange_weak(state, owned,
                Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(VolumeOwner { gate: self, epoch: owned }),
                Err(observed) => state = observed,
            }
        }
    }
}

/// The sole move-only release authority for one claimed volume epoch.
/// Dropping or losing it leaves the gate owned, which is required for uncertain effects.
///
/// ```compile_fail
/// use nt_fs::VolumeOwner;
/// fn duplicate(owner: VolumeOwner<'_>) { let _ = owner.clone(); }
/// ```
#[must_use = "retain until the same filesystem is restored or the effect is known"]
pub struct VolumeOwner<'a> { gate: &'a VolumeOwnerGate, epoch: u64 }

impl VolumeOwner<'_> {
    pub fn epoch(&self) -> u64 { self.epoch }

    /// Release after restoring this owner's exact FileSystem to the public slot. A crossed epoch
    /// refuses release and returns the token. There is no release on Drop.
    ///
    /// # Safety
    /// The caller must have restored the same FileSystem instance before invoking this method.
    /// The gate cannot inspect that external slot.
    pub unsafe fn release(self) -> Result<(), Self> {
        let Some(next) = self.epoch.checked_add(1) else { return Err(self); };
        match self.gate.state.compare_exchange(self.epoch, next,
            Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(_) => Err(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crossed_epoch_cannot_release_a_different_owner() {
        let gate = VolumeOwnerGate::new();
        let stale = gate.try_claim().ok().unwrap();
        gate.state.store(stale.epoch() + 2, Ordering::Release);
        assert!(unsafe { stale.release() }.is_err());
        assert!(gate.is_owned());
        assert!(gate.try_claim().is_err());
    }
}
