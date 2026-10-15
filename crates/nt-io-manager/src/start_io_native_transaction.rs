//! Root-owned committed StartIo reply fence for one exact source/device lifetime.
//!
//! This is not a WDM queue or a callback executor. The native adapter constructs it only after
//! the local WDM queue commit and current receipt publication. A Reply attempt is uncertain as
//! soon as it begins; losing its outcome never authorizes a second queue effect or a second Reply.

use crate::source_irp_ledger::SourceIrpForwardIdentity;
use crate::start_io_current::{
    CompletionObservation, CurrentPhase, CurrentReceipt, CurrentSnapshot, Error as CurrentError,
    LivePacket,
};
use crate::HostedDevicePointerRegistration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartIoTransactionId {
    id: core::num::NonZeroU64,
    generation: core::num::NonZeroU64,
}

impl StartIoTransactionId {
    pub fn new(id: u64, generation: u64) -> Option<Self> {
        Some(Self {
            id: core::num::NonZeroU64::new(id)?,
            generation: core::num::NonZeroU64::new(generation)?,
        })
    }

    pub fn id(self) -> u64 { self.id.get() }
    pub fn generation(self) -> u64 { self.generation.get() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyPhase {
    Committed,
    Uncertain,
    CallbackReturned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongCurrent,
    WrongTransaction,
    WrongPhase,
}

/// A scalar command, never an owner or permission to repeat the committed WDM operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyCommand {
    transaction_id: StartIoTransactionId,
}

impl ReplyCommand {
    pub fn transaction_id(self) -> StartIoTransactionId { self.transaction_id }
}

/// Refusal retains every owner; callers must keep it or return the owners to their ledgers.
#[must_use = "retain both the current receipt and callback image owner on refusal"]
pub struct AdmissionRefusal<D, P, C> {
    pub error: Error,
    current: Option<CurrentReceipt<D, P>>,
    callback: Option<C>,
}

impl<D, P, C> AdmissionRefusal<D, P, C> {
    pub fn into_parts(mut self) -> (Error, CurrentReceipt<D, P>, C) {
        (self.error, self.current.take().expect("refused StartIo receipt"),
            self.callback.take().expect("refused StartIo callback owner"))
    }
}

impl<D, P, C> Drop for AdmissionRefusal<D, P, C> {
    fn drop(&mut self) {
        if let Some(current) = self.current.take() { core::mem::forget(current); }
        if let Some(callback) = self.callback.take() { core::mem::forget(callback); }
    }
}

impl<D, P, C> core::fmt::Debug for AdmissionRefusal<D, P, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdmissionRefusal").field("error", &self.error).finish_non_exhaustive()
    }
}

/// Owns the exact source, projection and callback image across unknown Reply results and nested
/// completion. Explicit terminal observation and callback return are independent conditions.
#[must_use = "retain the committed StartIo owners until exact terminal settlement"]
pub struct CommittedStartIo<D, P, C> {
    current: Option<CurrentReceipt<D, P>>,
    callback: Option<C>,
    identity: SourceIrpForwardIdentity,
    transaction_id: StartIoTransactionId,
    phase: ReplyPhase,
}

impl<D, P, C> CommittedStartIo<D, P, C> {
    pub fn new(
        current: CurrentReceipt<D, P>,
        identity: SourceIrpForwardIdentity,
        transaction_id: StartIoTransactionId,
        callback: C,
    ) -> Result<Self, AdmissionRefusal<D, P, C>> {
        let snapshot = current.snapshot();
        if snapshot.phase != CurrentPhase::Live || snapshot.packet != Some(identity) {
            return Err(AdmissionRefusal { error: Error::WrongCurrent,
                current: Some(current), callback: Some(callback) });
        }
        Ok(Self { current: Some(current), callback: Some(callback), identity,
            transaction_id, phase: ReplyPhase::Committed })
    }

    pub fn phase(&self) -> ReplyPhase { self.phase }

    pub fn current_snapshot(&self) -> CurrentSnapshot {
        self.current.as_ref().expect("unsettled StartIo receipt").snapshot()
    }

    /// Call immediately before the native Reply operation. The outcome is uncertain even when
    /// that operation returns an error, because entry may have occurred before the error.
    pub fn begin_reply(&mut self) -> Result<ReplyCommand, Error> {
        if self.phase != ReplyPhase::Committed { return Err(Error::WrongPhase); }
        self.phase = ReplyPhase::Uncertain;
        Ok(ReplyCommand { transaction_id: self.transaction_id })
    }

    /// Callback return is only an observation of the exact command's invocation, not IRP
    /// completion or permission to release source storage.
    pub fn callback_returned(&mut self, transaction_id: StartIoTransactionId) -> Result<(), Error> {
        if transaction_id != self.transaction_id { return Err(Error::WrongTransaction); }
        if self.phase != ReplyPhase::Uncertain { return Err(Error::WrongPhase); }
        self.phase = ReplyPhase::CallbackReturned;
        Ok(())
    }

    /// Only the native completion path supplies an acknowledged terminal observation. A source
    /// pin returned here still needs an explicit checked ledger release before physical free.
    pub fn observe_completion(
        &mut self,
        registration: HostedDevicePointerRegistration,
        identity: SourceIrpForwardIdentity,
        observation: CompletionObservation,
    ) -> Result<Option<LivePacket<P>>, CurrentError> {
        if identity != self.identity { return Err(CurrentError::WrongPacket); }
        // The callback may still dereference the physical IRP after IoCompleteRequest returns.
        // Keep its source pin until both the exact callback return and terminal completion exist.
        if observation == CompletionObservation::Acknowledged
            && self.phase != ReplyPhase::CallbackReturned
        {
            return Err(CurrentError::WrongPhase);
        }
        self.current.as_mut().expect("unsettled StartIo receipt")
            .observe_completion(registration, identity, observation)
    }

    /// After terminal completion and callback return, transfer the retained device and callback
    /// owners to native cleanup. There is no implicit free or source pin release here.
    pub fn into_completed(mut self) -> Result<(CurrentReceipt<D, P>, C), Self> {
        if self.phase != ReplyPhase::CallbackReturned
            || self.current_snapshot().phase != CurrentPhase::Completed
        { return Err(self); }
        let current = self.current.take().expect("completed StartIo receipt");
        let callback = self.callback.take().expect("completed StartIo callback owner");
        Ok((current, callback))
    }
}

impl<D, P, C> Drop for CommittedStartIo<D, P, C> {
    fn drop(&mut self) {
        // Dropping an unknown or incomplete effect cannot release a callback image or its
        // current packet owner. Deliberately leak them if the native owner loses this value;
        // normal cleanup uses into_completed after both independent observations.
        if let Some(current) = self.current.take() { core::mem::forget(current); }
        if let Some(callback) = self.callback.take() { core::mem::forget(callback); }
    }
}

/// One callback's exact lifetime fence, independent of the device's single CurrentIrp receipt.
/// The per-device receipt transfers its source pin here when Next displaces a live packet, or
/// when terminal completion is observed while this packet remains current. The callback may
/// finish before or after either transfer. Neither observation alone permits source release.
#[must_use = "retain the callback and source pin until both exact observations settle"]
pub struct StartIoCallbackFence<P, C> {
    identity: SourceIrpForwardIdentity,
    transaction_id: StartIoTransactionId,
    phase: ReplyPhase,
    terminal: bool,
    source: Option<LivePacket<P>>,
    callback: Option<C>,
}

impl<P, C> StartIoCallbackFence<P, C> {
    pub fn new(identity: SourceIrpForwardIdentity, transaction_id: StartIoTransactionId,
        callback: C) -> Self
    {
        Self { identity, transaction_id, phase: ReplyPhase::Committed,
            terminal: false, source: None, callback: Some(callback) }
    }

    pub fn identity(&self) -> SourceIrpForwardIdentity { self.identity }
    pub fn phase(&self) -> ReplyPhase { self.phase }
    pub fn terminal_observed(&self) -> bool { self.terminal }
    pub fn source_retained(&self) -> bool { self.source.is_some() }

    pub fn begin_reply(&mut self) -> Result<ReplyCommand, Error> {
        if self.phase != ReplyPhase::Committed { return Err(Error::WrongPhase); }
        self.phase = ReplyPhase::Uncertain;
        Ok(ReplyCommand { transaction_id: self.transaction_id })
    }

    pub fn callback_returned(&mut self, transaction_id: StartIoTransactionId)
        -> Result<(), Error>
    {
        if transaction_id != self.transaction_id { return Err(Error::WrongTransaction); }
        if self.phase != ReplyPhase::Uncertain { return Err(Error::WrongPhase); }
        self.phase = ReplyPhase::CallbackReturned;
        Ok(())
    }

    /// The native adapter supplies this only for a real exact terminal completion. The source
    /// pin stays retained until callback return, even if the WDM current was displaced earlier.
    pub fn observe_terminal(&mut self, identity: SourceIrpForwardIdentity) -> Result<(), Error> {
        if identity != self.identity { return Err(Error::WrongCurrent); }
        if self.terminal { return Err(Error::WrongPhase); }
        self.terminal = true;
        Ok(())
    }

    /// Transfer the old source obligation from the per-device receipt after a successful WDM
    /// update. A refusal returns the original owner; it cannot be dropped or substituted.
    pub fn retain_source(&mut self, packet: LivePacket<P>) -> Result<(), LivePacket<P>> {
        if packet.identity() != self.identity || self.source.is_some() { return Err(packet); }
        self.source = Some(packet);
        Ok(())
    }

    pub fn finish(mut self) -> Result<(LivePacket<P>, C), Self> {
        if self.phase != ReplyPhase::CallbackReturned || !self.terminal
            || self.source.is_none()
        { return Err(self); }
        Ok((self.source.take().expect("settled source pin"),
            self.callback.take().expect("settled callback owner")))
    }
}

impl<P, C> Drop for StartIoCallbackFence<P, C> {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() { core::mem::forget(source); }
        if let Some(callback) = self.callback.take() { core::mem::forget(callback); }
    }
}
