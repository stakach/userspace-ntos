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

impl OuterNativeIo {
    /// Work is queued for the outer owner.
    pub(crate) const fn queued(self) -> bool {
        self.sector || self.background_snapshot
    }
}
