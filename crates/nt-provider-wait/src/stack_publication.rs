//! One-shot ownership of a provider stack's catalog publication and retirement.

use crate::{
    ProviderStackActivationCatalog, ProviderStackActivationError, ProviderStackLaneBinding,
    ProviderStackLaneHandle,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStackLanePublicationPhase {
    Unpublished,
    Publishing,
    Published(ProviderStackLaneHandle),
    Failed(ProviderStackActivationError),
    Unregistering(ProviderStackLaneHandle),
    Retired(ProviderStackLaneBinding),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStackLanePublicationError {
    InvalidPhase,
    Registration(ProviderStackActivationError),
    Catalog(ProviderStackActivationError),
    BindingMismatch,
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

    /// Resolve only the retained generation in the original catalog lifetime.
    /// The adapter must independently authenticate that lifetime; table-local handles are not
    /// cross-provider identities. Missing/stale publication is an error, never proof of absence.
    pub fn binding(
        &self,
        catalog: &ProviderStackActivationCatalog,
    ) -> Result<ProviderStackLaneBinding, ProviderStackLanePublicationError> {
        let ProviderStackLanePublicationPhase::Published(handle) = self.phase else {
            return Err(ProviderStackLanePublicationError::InvalidPhase);
        };
        catalog
            .binding(handle)
            .map_err(ProviderStackLanePublicationError::Catalog)
    }

    /// Retire an exact, previously observed binding within the same authenticated catalog.
    /// Catalog refusal is side-effect-free and permits retry after activations drain. Interrupted
    /// mutation remains Unregistering and cannot be replayed. Success retires only the catalog
    /// reference; it does not release a physical stack, capability, or execution fence.
    pub fn retire(
        &mut self,
        catalog: &mut ProviderStackActivationCatalog,
        expected: ProviderStackLaneBinding,
    ) -> Result<ProviderStackLaneBinding, ProviderStackLanePublicationError> {
        let binding = self.binding(catalog)?;
        if binding != expected {
            return Err(ProviderStackLanePublicationError::BindingMismatch);
        }
        self.phase = ProviderStackLanePublicationPhase::Unregistering(binding.handle);
        match catalog.unregister_lane(binding.handle) {
            Ok(()) => {
                self.phase = ProviderStackLanePublicationPhase::Retired(binding);
                Ok(binding)
            }
            Err(error) => {
                self.phase = ProviderStackLanePublicationPhase::Published(binding.handle);
                Err(ProviderStackLanePublicationError::Catalog(error))
            }
        }
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
    fn retirement_checks_every_expected_binding_field_before_mutation() {
        let mut catalog = ProviderStackActivationCatalog::new(2, 1).unwrap();
        let mut owner = ProviderStackLanePublication::new();
        let handle = owner.register(&mut catalog, 7, 0x1000, 0x1000).unwrap();
        let other = catalog.register_lane(8, 0x3000, 0x1000).unwrap();
        let binding = owner.binding(&catalog).unwrap();
        assert_eq!(binding, catalog.binding(handle).unwrap());
        for changed in [
            ProviderStackLaneBinding {
                handle: other,
                ..binding
            },
            ProviderStackLaneBinding {
                lane_id: 9,
                ..binding
            },
            ProviderStackLaneBinding {
                stack_base: 0x2000,
                ..binding
            },
            ProviderStackLaneBinding {
                stack_bytes: 0x2000,
                ..binding
            },
        ] {
            assert_eq!(
                owner.retire(&mut catalog, changed),
                Err(ProviderStackLanePublicationError::BindingMismatch)
            );
            assert_eq!(
                owner.phase(),
                ProviderStackLanePublicationPhase::Published(handle)
            );
            assert_eq!(owner.binding(&catalog), Ok(binding));
        }
    }

    #[test]
    fn active_lane_refusal_retains_publication_then_retirement_succeeds_once() {
        let mut catalog = ProviderStackActivationCatalog::new(1, 2).unwrap();
        let mut owner = ProviderStackLanePublication::new();
        let handle = owner.register(&mut catalog, 7, 0x1000, 0x1000).unwrap();
        let binding = owner.binding(&catalog).unwrap();
        let activation = catalog.begin(handle, 1).unwrap();
        assert_eq!(
            owner.retire(&mut catalog, binding),
            Err(ProviderStackLanePublicationError::Catalog(
                ProviderStackActivationError::LaneActive
            ))
        );
        assert_eq!(
            owner.phase(),
            ProviderStackLanePublicationPhase::Published(handle)
        );
        assert_eq!(owner.binding(&catalog), Ok(binding));
        catalog.finish(activation).unwrap();
        assert_eq!(owner.retire(&mut catalog, binding), Ok(binding));
        assert_eq!(
            owner.phase(),
            ProviderStackLanePublicationPhase::Retired(binding)
        );
        assert_eq!(
            catalog.binding(handle),
            Err(ProviderStackActivationError::StaleLane)
        );
        assert_eq!(
            owner.binding(&catalog),
            Err(ProviderStackLanePublicationError::InvalidPhase)
        );
        assert_eq!(
            owner.retire(&mut catalog, binding),
            Err(ProviderStackLanePublicationError::InvalidPhase)
        );
        assert_eq!(
            owner.register(&mut catalog, 7, 0x1000, 0x1000),
            Err(ProviderStackLanePublicationError::InvalidPhase)
        );
    }

    #[test]
    fn stale_generation_cannot_query_or_retire_replacement_publication() {
        let mut catalog = ProviderStackActivationCatalog::new(1, 1).unwrap();
        let mut owner = ProviderStackLanePublication::new();
        let handle = owner.register(&mut catalog, 7, 0x1000, 0x1000).unwrap();
        let binding = owner.binding(&catalog).unwrap();
        catalog.unregister_lane(handle).unwrap();
        let replacement = catalog.register_lane(7, 0x1000, 0x1000).unwrap();
        let expected = catalog.binding(replacement).unwrap();
        let stale = Err(ProviderStackLanePublicationError::Catalog(
            ProviderStackActivationError::StaleLane,
        ));
        assert_eq!(owner.binding(&catalog), stale);
        assert_eq!(owner.retire(&mut catalog, binding), stale);
        assert_eq!(owner.retire(&mut catalog, expected), stale);
        assert_eq!(
            owner.phase(),
            ProviderStackLanePublicationPhase::Published(handle)
        );
        assert_eq!(catalog.binding(replacement), Ok(expected));
    }

    #[test]
    fn nonpublished_and_entered_retirement_states_refuse_query_or_replay() {
        let mut catalog = ProviderStackActivationCatalog::new(1, 1).unwrap();
        let handle = catalog.register_lane(7, 0x1000, 0x1000).unwrap();
        let binding = catalog.binding(handle).unwrap();
        for phase in [
            ProviderStackLanePublicationPhase::Unpublished,
            ProviderStackLanePublicationPhase::Publishing,
            ProviderStackLanePublicationPhase::Failed(ProviderStackActivationError::NoCapacity),
            ProviderStackLanePublicationPhase::Unregistering(handle),
        ] {
            let mut owner = ProviderStackLanePublication { phase };
            assert_eq!(
                owner.binding(&catalog),
                Err(ProviderStackLanePublicationError::InvalidPhase)
            );
            assert_eq!(
                owner.retire(&mut catalog, binding),
                Err(ProviderStackLanePublicationError::InvalidPhase)
            );
            assert_eq!(owner.phase(), phase);
            assert_eq!(catalog.binding(handle), Ok(binding));
        }
    }

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
