//! Fail-closed eligibility for copied installed metadata on a native disk route.
//!
//! The Executive owns this fence in the same address space as its metadata cache. It must
//! authenticate the physical disk and classify the canonical SCSI request before invoking the
//! provider. A provider-local atomic would not protect Executive cache hits.

use core::sync::atomic::{AtomicBool, Ordering};

/// A nonempty, checked physical sector interval with an exclusive end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalSectorRange {
    start: u64,
    end: u64,
}

impl PhysicalSectorRange {
    pub fn new(start: u64, sectors: u64) -> Option<Self> {
        if sectors == 0 { return None; }
        Some(Self { start, end: start.checked_add(sectors)? })
    }

    fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Classification of an authenticated SRB after its full CDB and transfer range are checked.
/// Any unsupported opcode, malformed range, or command with an uncertain effect is mutating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PossibleScsiEffect {
    ProvenReadOnly,
    Write { lba: u64, sectors: u32 },
    PossiblyMutating,
}

/// One authoritative eligibility fence for an installed-volume metadata cache.
///
/// `D` is an authenticated physical disk identity; `R` includes mount and relation generation.
/// A same-disk possible mutation permanently disables read-through for this owner, even if its
/// provider later fails, times out, or retains an uncertain effect. The only write exception is
/// an exactly bounded request wholly inside a proven reserve disjoint from the installed range.
/// No method re-enables a poisoned owner; a new route needs a new cache and fence owner.
pub struct InstalledMetadataReadThroughFence<D: Eq, R: Eq> {
    disk: D,
    route: R,
    installed: PhysicalSectorRange,
    reserve: Option<PhysicalSectorRange>,
    poisoned: AtomicBool,
}

impl<D: Eq, R: Eq> InstalledMetadataReadThroughFence<D, R> {
    pub fn new(
        disk: D, route: R, installed: PhysicalSectorRange,
        reserve: Option<PhysicalSectorRange>,
    ) -> Option<Self> {
        if reserve.is_some_and(|reserve| reserve.overlaps(installed)) {
            return None;
        }
        Some(Self { disk, route, installed, reserve, poisoned: AtomicBool::new(false) })
    }

    /// Check the same authenticated disk and exact route generation before a cache hit.
    pub fn eligible(&self, disk: &D, route: &R) -> bool {
        disk == &self.disk && route == &self.route && !self.poisoned.load(Ordering::SeqCst)
    }

    pub fn poisoned(&self) -> bool {
        self.poisoned.load(Ordering::SeqCst)
    }

    /// Called in Executive memory before any provider entry, using a proven physical disk.
    /// The poison is irreversible across terminal failure, cancellation, or uncertain effects.
    pub fn before_effect(&self, disk: &D, effect: PossibleScsiEffect) {
        if disk != &self.disk { return; }
        let harmless = match effect {
            PossibleScsiEffect::ProvenReadOnly => true,
            PossibleScsiEffect::Write { lba, sectors } => {
                PhysicalSectorRange::new(lba, u64::from(sectors))
                    .is_some_and(|range| self.reserve.is_some_and(|reserve| reserve.contains(range))
                        && !range.overlaps(self.installed))
            }
            PossibleScsiEffect::PossiblyMutating => false,
        };
        if !harmless {
            self.poisoned.store(true, Ordering::SeqCst);
        }
    }
}
