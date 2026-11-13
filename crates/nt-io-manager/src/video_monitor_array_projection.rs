//! Exact ownership of VideoPort's monitor array returned through an IOCTL pointer.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::source_irp_auxiliary::SourcePoolAllocationIdentity;
use crate::HostedDomainIdentity;

pub const VIDEO_MONITOR_DEVICE_X64_BYTES: usize = 24;
pub const MONITOR_PROJECTION_METADATA_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorProjectionLayout {
    pub monitor_count: usize,
    /// Includes the null PDO terminator, which is the end of the caller-visible array.
    pub visible_bytes: usize,
    pub allocation_bytes: usize,
}

pub fn monitor_projection_layout(count: usize) -> Result<MonitorProjectionLayout, MonitorProjectionError> {
    let visible_bytes = count.checked_add(1)
        .and_then(|entries| entries.checked_mul(VIDEO_MONITOR_DEVICE_X64_BYTES))
        .ok_or(MonitorProjectionError::InvalidArray)?;
    let allocation_bytes = visible_bytes.checked_add(MONITOR_PROJECTION_METADATA_BYTES)
        .ok_or(MonitorProjectionError::InvalidArray)?;
    Ok(MonitorProjectionLayout { monitor_count: count, visible_bytes, allocation_bytes })
}

/// Locate private metadata after the first complete null-PDO entry. Allocator padding does
/// not change the visible array's extent or move its ownership witness.
pub fn projected_monitor_layout(bytes: &[u8]) -> Result<MonitorProjectionLayout, MonitorProjectionError> {
    for (index, entry) in bytes.chunks_exact(VIDEO_MONITOR_DEVICE_X64_BYTES).enumerate() {
        if u64::from_le_bytes(entry[8..16].try_into().unwrap()) == 0 {
            let layout = monitor_projection_layout(index)?;
            return (bytes.len() >= layout.allocation_bytes)
                .then_some(layout).ok_or(MonitorProjectionError::InvalidArray);
        }
    }
    Err(MonitorProjectionError::InvalidArray)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoMonitorDevice {
    pub flag: u32,
    pub pdo: u64,
    pub hw_id: u32,
    pub internal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorProjectionError {
    InvalidIdentity,
    InvalidArray,
    InvalidTransition,
}

/// Exact provider-owned PDO behind an entry in a transferred monitor array. The provider
/// cookie identifies its current address space; the generation identifies this physical child
/// registration even if a later child reuses the same native address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorPdoIdentity {
    provider: HostedDomainIdentity,
    address: u64,
    generation: u64,
}

impl MonitorPdoIdentity {
    pub fn new(
        provider: HostedDomainIdentity,
        address: u64,
        generation: u64,
    ) -> Result<Self, MonitorProjectionError> {
        if provider.domain_id.raw() == 0 || provider.cookie == 0 || address == 0
            || address & 7 != 0 || generation == 0
        {
            return Err(MonitorProjectionError::InvalidIdentity);
        }
        Ok(Self { provider, address, generation })
    }

    pub const fn provider(self) -> HostedDomainIdentity { self.provider }
    pub const fn address(self) -> u64 { self.address }
    pub const fn generation(self) -> u64 { self.generation }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceEffect {
    Acquire,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferencePhase {
    Unacquired,
    Acquiring(u64),
    Acquired,
    Releasing(u64),
    Released,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReferenceEntry {
    pdo: MonitorPdoIdentity,
    phase: ReferencePhase,
}

/// A move-only receipt for one exact native reference or dereference attempt. A rejected receipt
/// leaves the ledger's in-flight effect owned; only its matching completion may advance it.
#[derive(Debug)]
#[must_use = "complete or quarantine the exact PDO reference effect"]
pub struct MonitorPdoReferenceTicket {
    ledger: u64,
    sequence: u64,
    pdo: MonitorPdoIdentity,
    effect: ReferenceEffect,
}

impl MonitorPdoReferenceTicket {
    pub const fn pdo(&self) -> MonitorPdoIdentity { self.pdo }
}

static NEXT_REFERENCE_LEDGER: AtomicU64 = AtomicU64::new(1);

/// Records per-array PDO reference ownership before each native effect. BusRelations owns a
/// separate reference series; aggregate canonical pointer counts never identify this array's
/// references or authorize their release.
#[derive(Debug)]
pub struct MonitorPdoReferenceLedger {
    id: u64,
    next_sequence: u64,
    entries: Vec<ReferenceEntry>,
    caller_handoff: bool,
}

impl MonitorPdoReferenceLedger {
    pub fn new(pdos: &[MonitorPdoIdentity]) -> Result<Self, MonitorProjectionError> {
        let provider = pdos.first().map(|pdo| pdo.provider);
        if pdos.iter().any(|pdo| Some(pdo.provider) != provider
            || pdo.provider.domain_id.raw() == 0 || pdo.provider.cookie == 0
            || pdo.address == 0 || pdo.generation == 0)
            || pdos.iter().enumerate().any(|(index, pdo)| pdos[..index].iter()
                .any(|previous| previous.provider == pdo.provider
                    && previous.address == pdo.address))
        {
            return Err(MonitorProjectionError::InvalidIdentity);
        }
        let id = NEXT_REFERENCE_LEDGER.try_update(
            Ordering::AcqRel, Ordering::Acquire, |next| next.checked_add(1),
        ).map_err(|_| MonitorProjectionError::InvalidTransition)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(pdos.len())
            .map_err(|_| MonitorProjectionError::InvalidArray)?;
        entries.extend(pdos.iter().copied().map(|pdo| ReferenceEntry {
            pdo, phase: ReferencePhase::Unacquired,
        }));
        Ok(Self { id, next_sequence: 1, entries, caller_handoff: false })
    }

    fn ticket(&mut self, index: usize, effect: ReferenceEffect) -> Result<MonitorPdoReferenceTicket, MonitorProjectionError> {
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1)
            .ok_or(MonitorProjectionError::InvalidTransition)?;
        let entry = &mut self.entries[index];
        entry.phase = match effect {
            ReferenceEffect::Acquire => ReferencePhase::Acquiring(sequence),
            ReferenceEffect::Release => ReferencePhase::Releasing(sequence),
        };
        Ok(MonitorPdoReferenceTicket { ledger: self.id, sequence, pdo: entry.pdo, effect })
    }

    pub fn begin_acquire(&mut self) -> Result<Option<MonitorPdoReferenceTicket>, MonitorProjectionError> {
        if self.caller_handoff || self.entries.iter().any(|entry| matches!(entry.phase,
            ReferencePhase::Acquiring(_) | ReferencePhase::Releasing(_)
                | ReferencePhase::Released | ReferencePhase::Uncertain))
        {
            return Err(MonitorProjectionError::InvalidTransition);
        }
        match self.entries.iter().position(|entry| entry.phase == ReferencePhase::Unacquired) {
            Some(index) => self.ticket(index, ReferenceEffect::Acquire).map(Some),
            None => Ok(None),
        }
    }

    fn settle(
        &mut self,
        ticket: MonitorPdoReferenceTicket,
        effect: ReferenceEffect,
        next: ReferencePhase,
    ) -> Result<(), MonitorProjectionError> {
        let entry = self.entries.iter_mut().find(|entry| entry.pdo == ticket.pdo)
            .ok_or(MonitorProjectionError::InvalidIdentity)?;
        let expected = match effect {
            ReferenceEffect::Acquire => ReferencePhase::Acquiring(ticket.sequence),
            ReferenceEffect::Release => ReferencePhase::Releasing(ticket.sequence),
        };
        if ticket.ledger != self.id || ticket.effect != effect || entry.phase != expected
        {
            return Err(MonitorProjectionError::InvalidTransition);
        }
        entry.phase = next;
        Ok(())
    }

    pub fn complete_acquire(&mut self, ticket: MonitorPdoReferenceTicket) -> Result<(), MonitorProjectionError> {
        self.settle(ticket, ReferenceEffect::Acquire, ReferencePhase::Acquired)
    }

    pub fn begin_release(&mut self) -> Result<Option<MonitorPdoReferenceTicket>, MonitorProjectionError> {
        if self.caller_handoff || self.entries.iter().any(|entry| matches!(entry.phase,
            ReferencePhase::Acquiring(_) | ReferencePhase::Releasing(_)
                | ReferencePhase::Uncertain))
        {
            return Err(MonitorProjectionError::InvalidTransition);
        }
        match self.entries.iter().position(|entry| entry.phase == ReferencePhase::Acquired) {
            Some(index) => self.ticket(index, ReferenceEffect::Release).map(Some),
            None => Ok(None),
        }
    }

    pub fn complete_release(&mut self, ticket: MonitorPdoReferenceTicket) -> Result<(), MonitorProjectionError> {
        self.settle(ticket, ReferenceEffect::Release, ReferencePhase::Released)
    }

    pub fn mark_uncertain(&mut self, ticket: MonitorPdoReferenceTicket) -> Result<(), MonitorProjectionError> {
        let effect = ticket.effect;
        self.settle(ticket, effect, ReferencePhase::Uncertain)
    }

    pub fn all_released(&self) -> bool {
        !self.caller_handoff && self.entries.iter().all(|entry| matches!(entry.phase,
            ReferencePhase::Unacquired | ReferencePhase::Released))
    }

    /// The terminal has been published and acknowledged by win32k. The exact canonical
    /// registration counts now belong to the caller, which dereferences each PDO later.
    pub fn handoff_to_caller(&mut self) -> Result<(), MonitorProjectionError> {
        if self.caller_handoff || self.entries.iter().any(|entry| entry.phase != ReferencePhase::Acquired)
        { return Err(MonitorProjectionError::InvalidTransition); }
        self.caller_handoff = true;
        Ok(())
    }

    pub fn caller_handoff(&self) -> bool { self.caller_handoff }
}

/// Only VideoPort transfers counted PDO references with its monitor array. Other
/// providers may return an empty allocated sentinel with no references to ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorSourceReferenceRelease {
    VideoPortAck,
    NoReferences,
}

pub fn classify_monitor_source_release(
    video_port_registered: bool,
    monitor_count: usize,
) -> Result<MonitorSourceReferenceRelease, MonitorProjectionError> {
    match (video_port_registered, monitor_count) {
        (_, 0) => Ok(MonitorSourceReferenceRelease::NoReferences),
        (true, _) => Ok(MonitorSourceReferenceRelease::VideoPortAck),
        (false, _) => Err(MonitorProjectionError::InvalidArray),
    }
}

/// Only a complete, in-bounds entry with a null PDO terminates the array. The
/// allocator may round the allocation capacity beyond that entry.
pub fn decode_monitor_array(bytes: &[u8]) -> Result<Vec<VideoMonitorDevice>, MonitorProjectionError> {
    let mut monitors = Vec::new();
    for entry in bytes.chunks_exact(VIDEO_MONITOR_DEVICE_X64_BYTES) {
        let pdo = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        if pdo == 0 {
            return Ok(monitors);
        }
        monitors.try_reserve(1).map_err(|_| MonitorProjectionError::InvalidArray)?;
        monitors.push(VideoMonitorDevice {
            flag: u32::from_le_bytes(entry[..4].try_into().unwrap()),
            pdo,
            hw_id: u32::from_le_bytes(entry[16..20].try_into().unwrap()),
            internal: entry[20] != 0,
        });
    }
    Err(MonitorProjectionError::InvalidArray)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorArrayAllocation {
    pub domain: HostedDomainIdentity,
    pub allocation: SourcePoolAllocationIdentity,
}

impl MonitorArrayAllocation {
    pub fn new(
        domain: HostedDomainIdentity,
        allocation: SourcePoolAllocationIdentity,
    ) -> Result<Self, MonitorProjectionError> {
        if domain.domain_id.raw() == 0 || domain.cookie == 0
            || allocation.component_address == 0 || allocation.capacity == 0
            || allocation.pool_generation == 0
            || allocation.component_address.checked_add(allocation.capacity).is_none()
        {
            return Err(MonitorProjectionError::InvalidIdentity);
        }
        Ok(Self { domain, allocation })
    }

    pub fn with_allocation(self, allocation: SourcePoolAllocationIdentity) -> Self {
        Self { allocation, ..self }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorArrayProjection {
    source: MonitorArrayAllocation,
    projected: MonitorArrayAllocation,
    published: bool,
    aborted_unpublished: bool,
    dependent_freed: bool,
    provider_effect_quiesced: bool,
    provider_retired: bool,
    effect_uncertain: bool,
}

impl MonitorArrayProjection {
    pub fn new(
        source: MonitorArrayAllocation,
        projected: MonitorArrayAllocation,
    ) -> Result<Self, MonitorProjectionError> {
        if source.domain == projected.domain || source.allocation == projected.allocation {
            return Err(MonitorProjectionError::InvalidIdentity);
        }
        Ok(Self {
            source, projected, published: false, aborted_unpublished: false,
            dependent_freed: false,
            provider_effect_quiesced: false, provider_retired: false, effect_uncertain: false,
        })
    }

    pub fn source(&self) -> MonitorArrayAllocation { self.source }
    pub fn projected(&self) -> MonitorArrayAllocation { self.projected }

    pub fn publish(&mut self) -> Result<(), MonitorProjectionError> {
        if self.published || self.aborted_unpublished || self.effect_uncertain {
            return Err(MonitorProjectionError::InvalidTransition);
        }
        self.published = true;
        Ok(())
    }

    pub fn claim_dependent_free(
        &mut self,
        allocation: MonitorArrayAllocation,
    ) -> Result<(), MonitorProjectionError> {
        if !self.published || self.aborted_unpublished || self.dependent_freed
            || allocation != self.projected {
            return Err(MonitorProjectionError::InvalidIdentity);
        }
        self.dependent_freed = true;
        Ok(())
    }

    pub fn confirm_provider_effect_quiesced(&mut self) -> Result<(), MonitorProjectionError> {
        if self.provider_effect_quiesced || self.effect_uncertain {
            return Err(MonitorProjectionError::InvalidTransition);
        }
        self.provider_effect_quiesced = true;
        Ok(())
    }

    pub fn mark_effect_uncertain(&mut self) { self.effect_uncertain = true; }

    pub fn abort_unpublished(&mut self) -> Result<(), MonitorProjectionError> {
        if self.published || self.aborted_unpublished || self.dependent_freed
            || self.effect_uncertain
        {
            return Err(MonitorProjectionError::InvalidTransition);
        }
        self.aborted_unpublished = true;
        Ok(())
    }

    pub fn provider_retirement_ready(&self) -> bool {
        ((self.published && self.dependent_freed) || self.aborted_unpublished)
            && self.provider_effect_quiesced
            && !self.effect_uncertain && !self.provider_retired
    }

    pub fn confirm_provider_retired(
        &mut self,
        allocation: MonitorArrayAllocation,
    ) -> Result<(), MonitorProjectionError> {
        if !self.provider_retirement_ready() || allocation != self.source {
            return Err(MonitorProjectionError::InvalidIdentity);
        }
        self.provider_retired = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_metadata_follows_null_sentinel_for_any_monitor_count() {
        for count in [0, 1, 2, 17] {
            let layout = monitor_projection_layout(count).unwrap();
            let mut bytes = alloc::vec![0; layout.allocation_bytes + 8];
            for index in 0..count {
                bytes[index * VIDEO_MONITOR_DEVICE_X64_BYTES + 8..index * VIDEO_MONITOR_DEVICE_X64_BYTES + 16]
                    .copy_from_slice(&(index as u64 + 1).to_le_bytes());
            }
            assert_eq!(projected_monitor_layout(&bytes), Ok(layout));
            assert_eq!(decode_monitor_array(&bytes).unwrap().len(), count);
            bytes.truncate(layout.allocation_bytes - 1);
            assert_eq!(projected_monitor_layout(&bytes), Err(MonitorProjectionError::InvalidArray));
        }
    }

    #[test]
    fn source_references_follow_the_completing_provider_contract() {
        assert_eq!(
            classify_monitor_source_release(false, 0),
            Ok(MonitorSourceReferenceRelease::NoReferences),
        );
        assert_eq!(
            classify_monitor_source_release(true, 0),
            Ok(MonitorSourceReferenceRelease::NoReferences),
        );
        assert_eq!(
            classify_monitor_source_release(true, 2),
            Ok(MonitorSourceReferenceRelease::VideoPortAck),
        );
        assert_eq!(
            classify_monitor_source_release(false, 1),
            Err(MonitorProjectionError::InvalidArray),
        );
    }
}
