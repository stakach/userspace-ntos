//! Exact queued StartIo ownership after a successful WDM device queue insertion.
//!
//! This receipt does not select packets. The native adapter must use the actual WDM queue
//! operation and compare its selected packet with the retained source identity before transfer.

use crate::source_irp_ledger::SourceIrpForwardIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongPacket,
    DuplicateObservation,
}

/// Owns one packet admitted by an actual successful WDM queue insertion. The adapter keeps this
/// alongside the canonical pending node; it must not use receipt order to choose a packet.
#[must_use = "retain the queued packet until exact selection or cancel settlement"]
pub struct QueuedStartIo<O> {
    identity: SourceIrpForwardIdentity,
    owner: Option<O>,
}

impl<O> QueuedStartIo<O> {
    /// Construct only after the WDM insertion commits. `owner` must carry the admitted physical
    /// source pin and matching device projection obligation for this identity.
    pub fn new(identity: SourceIrpForwardIdentity, owner: O) -> Self {
        Self { identity, owner: Some(owner) }
    }

    pub fn identity(&self) -> SourceIrpForwardIdentity { self.identity }

    /// Transfer the owner only for the packet selected by the real WDM queue operation.
    pub fn select(mut self, selected: SourceIrpForwardIdentity) -> Result<O, Self> {
        if selected != self.identity { return Err(self); }
        Ok(self.owner.take().expect("live queued owner"))
    }

    /// The exact cancel routine was selected while the native cancel lock was held. The native
    /// adapter transfers that lock to the callback separately; this receipt retains the packet.
    pub fn begin_cancel(mut self, cancelled: SourceIrpForwardIdentity)
        -> Result<CancelingStartIo<O>, Self>
    {
        if cancelled != self.identity { return Err(self); }
        Ok(CancelingStartIo { identity: self.identity,
            owner: self.owner.take(), callback_returned: false, terminal: false })
    }
}

impl<O> Drop for QueuedStartIo<O> {
    fn drop(&mut self) {
        // Losing a receipt is not permission to unpin a source or retire its device projection.
        if let Some(owner) = self.owner.take() { core::mem::forget(owner); }
    }
}

/// Cancel callbacks may complete their IRP before returning, or return before completion. Both
/// independent exact observations are required before the retained owner can be released.
#[must_use = "retain until both callback return and terminal completion are observed"]
pub struct CancelingStartIo<O> {
    identity: SourceIrpForwardIdentity,
    owner: Option<O>,
    callback_returned: bool,
    terminal: bool,
}

impl<O> CancelingStartIo<O> {
    pub fn identity(&self) -> SourceIrpForwardIdentity { self.identity }

    pub fn callback_returned(&mut self, callback: SourceIrpForwardIdentity) -> Result<(), Error> {
        if callback != self.identity { return Err(Error::WrongPacket); }
        if self.callback_returned { return Err(Error::DuplicateObservation); }
        self.callback_returned = true;
        Ok(())
    }

    /// Only genuine acknowledged terminal completion qualifies. Unknown IPC outcome or an IRP
    /// free request cannot call this method; neither can a mere cancelled bit in the IRP.
    pub fn observe_terminal(&mut self, completed: SourceIrpForwardIdentity) -> Result<(), Error> {
        if completed != self.identity { return Err(Error::WrongPacket); }
        if self.terminal { return Err(Error::DuplicateObservation); }
        self.terminal = true;
        Ok(())
    }

    pub fn finish(mut self) -> Result<O, Self> {
        if !self.callback_returned || !self.terminal { return Err(self); }
        Ok(self.owner.take().expect("live cancelling owner"))
    }
}

impl<O> Drop for CancelingStartIo<O> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() { core::mem::forget(owner); }
    }
}

#[cfg(test)]
#[path = "start_io_queued_tests.rs"]
mod tests;
