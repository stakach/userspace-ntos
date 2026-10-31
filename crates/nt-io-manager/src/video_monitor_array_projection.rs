//! Exact ownership of VideoPort's monitor array returned through an IOCTL pointer.

use alloc::vec::Vec;

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
        (true, _) => Ok(MonitorSourceReferenceRelease::VideoPortAck),
        (false, 0) => Ok(MonitorSourceReferenceRelease::NoReferences),
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
            Ok(MonitorSourceReferenceRelease::VideoPortAck),
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
