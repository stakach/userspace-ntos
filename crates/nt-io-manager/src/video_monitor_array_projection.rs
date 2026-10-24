//! Exact ownership of VideoPort's monitor array returned through an IOCTL pointer.

use alloc::vec::Vec;

use crate::source_irp_auxiliary::SourcePoolAllocationIdentity;
use crate::HostedDomainIdentity;

pub const VIDEO_MONITOR_DEVICE_X64_BYTES: usize = 24;

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
