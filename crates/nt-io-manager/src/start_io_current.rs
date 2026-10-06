//! Per-device CurrentIrp provenance, not a queue or a completion implementation.
//!
//! The WDM queue and `start_io` policy remain authoritative for selection and writes. Native
//! admission must validate the live whole registration and retain a real device/projection owner
//! in D; a copied registration or detached DeviceReference alone is not a projection pin. P must
//! own the admitted source allocation while live. Copied SourceIrpForwardIdentity is observation,
//! not a source pin. The adapter holds the relevant locks across admission, WDM commit and receipt
//! publication, and transfers queued/displaced owners to its existing canonical retained owners.
//! The expected packet domain must come from authenticated physical source admission, not from
//! the device projection domain: provider routing can keep those identities separate. This helper
//! compares CurrentIrp to the source component address; a differently addressed native alias still
//! requires an independently admitted mapping identity/translation before using this contract.
//!
//! Completion must be observed here before exact physical free/source-row retirement. Completed
//! retains only scalar packet provenance and the device owner, so it never dereferences freed
//! packet storage or prevents a new allocation generation at the old address from being queued.
//! This standalone contract does not establish any native hook, ACK or retirement fence.

use crate::source_irp_ledger::SourceIrpForwardIdentity;
use crate::start_io::CurrentPacketRelation;
use crate::{HostedDevicePointerRegistration, HostedDomainIdentity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentPhase {
    Empty,
    Live,
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentSnapshot {
    pub device: HostedDevicePointerRegistration,
    pub expected_packet_domain: HostedDomainIdentity,
    pub packet: Option<SourceIrpForwardIdentity>,
    pub phase: CurrentPhase,
}

/// Trusted native adapter observation, never a driver/user-provided proof or a Reply ACK.
/// Acknowledged means genuine terminal completion of this exact source lifetime; callback return,
/// an indeterminate transport, MORE_PROCESSING_REQUIRED and a requested free do not qualify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionObservation {
    Acknowledged,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongDevice,
    WrongCurrent,
    WrongPacket,
    WrongPhase,
    DuplicateCurrent,
}

/// Owner supplied by exact native source admission. Construction does not manufacture a pin.
#[derive(Debug)]
#[must_use = "retain or explicitly transfer the admitted packet owner"]
pub struct LivePacket<P> {
    identity: SourceIrpForwardIdentity,
    owner: P,
}

impl<P> LivePacket<P> {
    pub fn new(identity: SourceIrpForwardIdentity, owner: P) -> Self {
        Self { identity, owner }
    }

    pub fn identity(&self) -> SourceIrpForwardIdentity {
        self.identity
    }

    pub fn into_owner(self) -> P {
        self.owner
    }
}

enum CurrentPacket<P> {
    Live(LivePacket<P>),
    Completed(SourceIrpForwardIdentity),
}

#[must_use = "retain the device lifetime and any current packet obligation"]
pub struct CurrentReceipt<D, P> {
    device: HostedDevicePointerRegistration,
    expected_packet_domain: HostedDomainIdentity,
    _device_owner: D,
    packet: Option<CurrentPacket<P>>,
}

/// Refusal never consumes the incoming packet owner or changes the existing receipt.
#[derive(Debug)]
#[must_use = "retain the returned incoming owner on refusal"]
pub struct UpdateRefusal<P> {
    pub error: Error,
    pub incoming: Option<LivePacket<P>>,
}

/// Prevalidated receipt update, held across the actual WDM commit without reentry.
///
/// `abort` is allowed only before effects or after a proven no-effect refusal. If the native
/// effect is uncertain, retain this intent and both ownership sets; neither dropping/aborting it
/// nor replaying the WDM operation is valid. `commit` is an infallible local publication after
/// successful WDM commit and returns displaced live ownership instead of silently releasing it.
#[must_use = "settle the successful commit or retain the uncertain intent"]
pub struct PreparedUpdate<'a, D, P> {
    receipt: &'a mut CurrentReceipt<D, P>,
    incoming: Option<LivePacket<P>>,
}

impl<D, P> CurrentReceipt<D, P> {
    pub fn new(
        device: HostedDevicePointerRegistration,
        expected_packet_domain: HostedDomainIdentity,
        device_owner: D,
    ) -> Self {
        Self {
            device,
            expected_packet_domain,
            _device_owner: device_owner,
            packet: None,
        }
    }

    pub fn snapshot(&self) -> CurrentSnapshot {
        let (packet, phase) = match &self.packet {
            None => (None, CurrentPhase::Empty),
            Some(CurrentPacket::Live(packet)) => (Some(packet.identity), CurrentPhase::Live),
            Some(CurrentPacket::Completed(identity)) => (Some(*identity), CurrentPhase::Completed),
        };
        CurrentSnapshot {
            device: self.device,
            expected_packet_domain: self.expected_packet_domain,
            packet,
            phase,
        }
    }

    fn validate_device(&self, device: HostedDevicePointerRegistration) -> Result<(), Error> {
        if device != self.device {
            return Err(Error::WrongDevice);
        }
        Ok(())
    }

    fn validate_current(&self, raw_current: u64) -> Result<(), Error> {
        let expected = self
            .snapshot()
            .packet
            .map_or(0, |identity| identity.allocation().component_address);
        if raw_current != expected {
            return Err(Error::WrongCurrent);
        }
        Ok(())
    }

    pub fn classify(
        &self,
        device: HostedDevicePointerRegistration,
        raw_current: u64,
        incoming: &LivePacket<P>,
    ) -> Result<CurrentPacketRelation, Error> {
        self.validate_device(device)?;
        self.validate_current(raw_current)?;
        if incoming.identity.allocation().domain != self.expected_packet_domain {
            return Err(Error::WrongPacket);
        }
        if let Some(retained) = self.snapshot().packet {
            if retained.ticket() == incoming.identity.ticket()
                && retained.allocation() != incoming.identity.allocation()
            {
                return Err(Error::WrongPacket);
            }
        }
        match &self.packet {
            None => Ok(CurrentPacketRelation::Empty),
            Some(CurrentPacket::Live(current)) if current.identity == incoming.identity => {
                Ok(CurrentPacketRelation::LiveSame)
            }
            Some(CurrentPacket::Live(current)) => {
                if current.identity.allocation().component_address
                    == incoming.identity.allocation().component_address
                {
                    return Err(Error::WrongPacket);
                }
                Ok(CurrentPacketRelation::LiveOther)
            }
            Some(CurrentPacket::Completed(identity)) => {
                if *identity == incoming.identity {
                    return Err(Error::WrongPacket);
                }
                if identity.allocation().component_address
                    == incoming.identity.allocation().component_address
                    && (identity.allocation().pool_generation
                        == incoming.identity.allocation().pool_generation
                        || identity.ticket() == incoming.identity.ticket())
                {
                    return Err(Error::WrongPacket);
                }
                Ok(CurrentPacketRelation::Completed)
            }
        }
    }

    /// Observe terminal completion under exact native ownership, before freeing packet storage.
    /// Returning P permits the adapter to release/transfer that source fence under its existing
    /// completion/free protocol; it does not itself perform a native free or free acknowledgement.
    pub fn observe_completion(
        &mut self,
        device: HostedDevicePointerRegistration,
        identity: SourceIrpForwardIdentity,
        observation: CompletionObservation,
    ) -> Result<Option<LivePacket<P>>, Error> {
        self.validate_device(device)?;
        let Some(current) = &self.packet else {
            return Err(Error::WrongPhase);
        };
        let current_identity = match current {
            CurrentPacket::Live(packet) => packet.identity,
            CurrentPacket::Completed(identity) => *identity,
        };
        if current_identity != identity {
            return Err(Error::WrongPacket);
        }
        if matches!(current, CurrentPacket::Completed(_)) {
            return Err(Error::WrongPhase);
        }
        if observation == CompletionObservation::Uncertain {
            return Ok(None);
        }
        let previous = self.packet.replace(CurrentPacket::Completed(identity));
        match previous {
            Some(CurrentPacket::Live(packet)) => Ok(Some(packet)),
            _ => unreachable!("validated live current receipt changed without exclusive access"),
        }
    }

    /// Prepare replacement/clear before the actual successful `start_next`/StartIo WDM commit.
    /// This validates lifetime consistency only; it never selects from or changes the WDM queue.
    pub fn prepare_update(
        &mut self,
        device: HostedDevicePointerRegistration,
        raw_current: u64,
        incoming: Option<LivePacket<P>>,
    ) -> Result<PreparedUpdate<'_, D, P>, UpdateRefusal<P>> {
        let result = (|| {
            self.validate_device(device)?;
            self.validate_current(raw_current)?;
            if let Some(packet) = &incoming {
                match self.classify(device, raw_current, packet)? {
                    CurrentPacketRelation::LiveSame => return Err(Error::DuplicateCurrent),
                    _ => {}
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(PreparedUpdate {
                receipt: self,
                incoming,
            }),
            Err(error) => Err(UpdateRefusal { error, incoming }),
        }
    }
}

impl<D, P> PreparedUpdate<'_, D, P> {
    pub fn abort(self) -> Option<LivePacket<P>> {
        self.incoming
    }

    pub fn commit(self) -> Option<LivePacket<P>> {
        let previous = core::mem::replace(
            &mut self.receipt.packet,
            self.incoming.map(CurrentPacket::Live),
        );
        match previous {
            Some(CurrentPacket::Live(packet)) => Some(packet),
            Some(CurrentPacket::Completed(_)) | None => None,
        }
    }
}
