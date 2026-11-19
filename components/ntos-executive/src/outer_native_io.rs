//! Native block work that only the outer root service owner may claim.
//!
//! A nested frame (a PnP start wait, a provider pump) never claims a physical command for
//! another owner. When such work is queued it yields to the outer owner instead, as it already
//! did for queued mounted sectors. Background snapshot owners (the lazy checkpoint and the
//! SYSTEM WAL fold) hold the snapshot reserve until their I/O completes, so their queued I/O
//! is outer work of the same kind. If it were not, a foreground registry write in the nested
//! frame would wait on the reserve forever while the reserve's owner waited on the outer loop.

/// One observation of the outer-only native work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OuterNativeIo {
    /// A mounted create, overlay, read or directory sector is claimable.
    pub(crate) sector: bool,
    /// A background snapshot owner can enter its next command or advance a settled recheck.
    pub(crate) background_snapshot: bool,
}

/// One step a nested frame may take for a background snapshot owner holding the reserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackgroundHolderStep {
    /// Nothing: no background work, or foreground work has the slot.
    None,
    /// Settle the background owner's entered command through its terminal.
    Settle,
    /// Enter the background owner's next command in the vacant slot.
    Enter,
}

/// Foreground work has priority over the one physical slot. A foreground command already
/// entered is settled by its own owner, and a queued mounted sector is left for the outer owner
/// so the nested frame's yield still fires (`nested_ready` requires a vacant slot).
pub(crate) const fn background_holder_step(
    slot_occupied: bool,
    occupant_is_background: bool,
    sector_queued: bool,
    background_enterable: bool,
) -> BackgroundHolderStep {
    if slot_occupied {
        if occupant_is_background { BackgroundHolderStep::Settle } else { BackgroundHolderStep::None }
    } else if !sector_queued && background_enterable {
        BackgroundHolderStep::Enter
    } else {
        BackgroundHolderStep::None
    }
}

impl OuterNativeIo {
    /// Work is queued for the outer owner.
    pub(crate) const fn queued(self) -> bool {
        self.sector || self.background_snapshot
    }
}
