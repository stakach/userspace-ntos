//! Durable one-shot ownership of a provider stack's catalog publication.

use crate::{
    ProviderStackActivationCatalog, ProviderStackActivationError, ProviderStackLaneHandle,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStackLanePublicationPhase {
    Unpublished,
    Publishing,
    Published(ProviderStackLaneHandle),
    Failed(ProviderStackActivationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStackLanePublicationError {
    InvalidPhase,
    Registration(ProviderStackActivationError),
}

/// Retain alongside the physical stack owner before calling register. This receipt never retries
/// failed or interrupted publication and does not unregister on drop. Handles remain scoped to
/// the original catalog lifetime; catalog replacement requires separate lifetime ownership.
///
/// ```compile_fail
/// use nt_provider_wait::ProviderStackLanePublication;
/// fn duplicate(owner: ProviderStackLanePublication) { let _ = owner.clone(); }
/// ```
#[must_use = "retain the exact stack publication receipt"]
pub struct ProviderStackLanePublication {
    phase: ProviderStackLanePublicationPhase,
}

impl Default for ProviderStackLanePublication {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderStackLanePublication {
    pub const fn new() -> Self {
        Self {
            phase: ProviderStackLanePublicationPhase::Unpublished,
        }
    }

    pub const fn phase(&self) -> ProviderStackLanePublicationPhase {
        self.phase
    }

    pub fn register(
        &mut self,
        catalog: &mut ProviderStackActivationCatalog,
        lane_id: u64,
        stack_base: u64,
        stack_bytes: u64,
    ) -> Result<ProviderStackLaneHandle, ProviderStackLanePublicationError> {
        if self.phase != ProviderStackLanePublicationPhase::Unpublished {
            return Err(ProviderStackLanePublicationError::InvalidPhase);
        }
        self.phase = ProviderStackLanePublicationPhase::Publishing;
        match catalog.register_lane(lane_id, stack_base, stack_bytes) {
            Ok(handle) => {
                self.phase = ProviderStackLanePublicationPhase::Published(handle);
                Ok(handle)
            }
            Err(error) => {
                self.phase = ProviderStackLanePublicationPhase::Failed(error);
                Err(ProviderStackLanePublicationError::Registration(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_retains_exact_generation_binding_and_cannot_repeat() {
        let mut catalog = ProviderStackActivationCatalog::new(2, 1).unwrap();
        let mut owner = ProviderStackLanePublication::new();
        assert_eq!(
            owner.phase(),
            ProviderStackLanePublicationPhase::Unpublished
        );
        let handle = owner.register(&mut catalog, 7, 0x1000, 0x2000).unwrap();
        assert_eq!(
            owner.phase(),
            ProviderStackLanePublicationPhase::Published(handle)
        );
        let binding = catalog.binding(handle).unwrap();
        assert_eq!(
            (binding.lane_id, binding.stack_base, binding.stack_bytes),
            (7, 0x1000, 0x2000)
        );
        assert_eq!(
            owner.register(&mut catalog, 8, 0x4000, 0x1000),
            Err(ProviderStackLanePublicationError::InvalidPhase)
        );
        assert_eq!(
            owner.phase(),
            ProviderStackLanePublicationPhase::Published(handle)
        );
    }

    #[test]
    fn duplicate_and_capacity_failures_are_durable_without_retry() {
        let mut catalog = ProviderStackActivationCatalog::new(1, 1).unwrap();
        let first = catalog.register_lane(7, 0x1000, 0x1000).unwrap();
        for (id, base, expected) in [
            (7, 0x3000, ProviderStackActivationError::DuplicateLane),
            (8, 0x1000, ProviderStackActivationError::OverlappingStack),
            (8, 0x3000, ProviderStackActivationError::NoCapacity),
        ] {
            let mut owner = ProviderStackLanePublication::default();
            assert_eq!(
                owner.register(&mut catalog, id, base, 0x1000),
                Err(ProviderStackLanePublicationError::Registration(expected))
            );
            assert_eq!(
                owner.phase(),
                ProviderStackLanePublicationPhase::Failed(expected)
            );
            assert_eq!(
                owner.register(&mut catalog, 9, 0x5000, 0x1000),
                Err(ProviderStackLanePublicationError::InvalidPhase)
            );
            assert_eq!(catalog.binding(first).unwrap().lane_id, 7);
        }
    }

    #[test]
    fn failed_validation_and_entered_publication_cannot_be_replayed() {
        let mut catalog = ProviderStackActivationCatalog::new(1, 1).unwrap();
        let mut owner = ProviderStackLanePublication::new();
        assert_eq!(
            owner.register(&mut catalog, 0, 0x1000, 0x1000),
            Err(ProviderStackLanePublicationError::Registration(
                ProviderStackActivationError::InvalidLane
            ))
        );
        assert_eq!(
            owner.phase(),
            ProviderStackLanePublicationPhase::Failed(ProviderStackActivationError::InvalidLane)
        );
        assert_eq!(
            owner.register(&mut catalog, 7, 0x1000, 0x1000),
            Err(ProviderStackLanePublicationError::InvalidPhase)
        );
        let mut interrupted = ProviderStackLanePublication {
            phase: ProviderStackLanePublicationPhase::Publishing,
        };
        assert_eq!(
            interrupted.register(&mut catalog, 7, 0x1000, 0x1000),
            Err(ProviderStackLanePublicationError::InvalidPhase)
        );
        assert_eq!(
            interrupted.phase(),
            ProviderStackLanePublicationPhase::Publishing
        );
    }

    #[test]
    fn retained_handle_never_aliases_reused_catalog_slot_generation() {
        let mut catalog = ProviderStackActivationCatalog::new(1, 1).unwrap();
        let mut owner = ProviderStackLanePublication::new();
        let old = owner.register(&mut catalog, 7, 0x1000, 0x1000).unwrap();
        catalog.unregister_lane(old).unwrap();
        let replacement = catalog.register_lane(7, 0x1000, 0x1000).unwrap();
        assert_eq!(old.slot(), replacement.slot());
        assert_ne!(old.generation(), replacement.generation());
        assert_eq!(
            catalog.binding(old),
            Err(ProviderStackActivationError::StaleLane)
        );
        assert_eq!(
            owner.phase(),
            ProviderStackLanePublicationPhase::Published(old)
        );
        assert_eq!(
            owner.register(&mut catalog, 7, 0x1000, 0x1000),
            Err(ProviderStackLanePublicationError::InvalidPhase)
        );
    }
}
