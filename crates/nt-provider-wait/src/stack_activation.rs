use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_STACK_CATALOG: AtomicU64 = AtomicU64::new(1);

/// Exact catalog lifetime, independent of reusable lane handles or memory addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StackCatalogIdentity(u64);

use crate::{
    KernelProviderActivationDescriptor, KernelProviderActivationError, ProviderDomainIdentity,
    ProviderEventBacking, ProviderWaitOwner, ProviderWaitTimeoutKind,
};
use nt_kernel_exec::{IrqlState, PASSIVE_LEVEL};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderStackLaneHandle {
    slot: u32,
    generation: u32,
}

impl ProviderStackLaneHandle {
    pub const fn slot(self) -> u32 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderStackLaneBinding {
    pub handle: ProviderStackLaneHandle,
    pub lane_id: u64,
    pub stack_base: u64,
    pub stack_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderStackEventActivation {
    pub lane: ProviderStackLaneHandle,
    pub lane_id: u64,
    pub dispatch_id: u64,
    pub generation: u64,
}

impl ProviderStackEventActivation {
    pub const fn backing(self) -> ProviderEventBacking {
        ProviderEventBacking::Stack {
            lane_id: self.lane_id,
            lane_generation: self.lane.generation as u64,
            dispatch_id: self.dispatch_id,
            activation_generation: self.generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStackActivationError {
    InvalidCapacity,
    InvalidLane,
    DuplicateLane,
    OverlappingStack,
    NoCapacity,
    IdentityExhausted,
    StaleLane,
    LaneActive,
    InvalidDispatch,
    NoActiveActivation,
    NotTop,
    AddressOutsideLane,
    CrossLaneStorage,
    InvalidIrql,
    InvalidIrqlTransition,
    UnbalancedIrql,
    InvalidKernelDescriptor(KernelProviderActivationError),
    KernelBindingMismatch,
    KernelLaneAlreadyBound,
    KernelDispatchActive,
    StaleKernelDispatch,
}

struct ProviderStackActivationRecord {
    identity: ProviderStackEventActivation,
    irql: IrqlState,
    owner: Option<ProviderWaitOwner>,
}

struct ProviderStackLaneRecord {
    generation: u32,
    live: bool,
    lane_id: u64,
    stack_base: u64,
    stack_bytes: u64,
    activations: Vec<ProviderStackActivationRecord>,
    last_kernel_owner: Option<ProviderWaitOwner>,
}

impl ProviderStackLaneRecord {
    const fn empty() -> Self {
        Self {
            generation: 0,
            live: false,
            lane_id: 0,
            stack_base: 0,
            stack_bytes: 0,
            activations: Vec::new(),
            last_kernel_owner: None,
        }
    }

    fn binding(&self, slot: usize) -> ProviderStackLaneBinding {
        ProviderStackLaneBinding {
            handle: ProviderStackLaneHandle {
                slot: slot as u32,
                generation: self.generation,
            },
            lane_id: self.lane_id,
            stack_base: self.stack_base,
            stack_bytes: self.stack_bytes,
        }
    }
}

/// Generation-fenced stack ownership for a provider's physical execution lanes.
///
/// Activations are LIFO within one physical lane. Independent lanes may finish in any order.
pub struct ProviderStackActivationCatalog {
    identity: StackCatalogIdentity,
    lanes: Vec<ProviderStackLaneRecord>,
    max_lanes: usize,
    max_depth_per_lane: usize,
    next_activation_generation: u64,
}

impl ProviderStackActivationCatalog {
    pub fn new(
        max_lanes: usize,
        max_depth_per_lane: usize,
    ) -> Result<Self, ProviderStackActivationError> {
        Self::new_with_counter(max_lanes, max_depth_per_lane, &NEXT_STACK_CATALOG)
    }

    fn new_with_counter(
        max_lanes: usize,
        max_depth_per_lane: usize,
        counter: &AtomicU64,
    ) -> Result<Self, ProviderStackActivationError> {
        if max_lanes == 0 || max_depth_per_lane == 0 || max_lanes > u32::MAX as usize {
            return Err(ProviderStackActivationError::InvalidCapacity);
        }
        let identity = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next == 0 {
                    None
                } else {
                    next.checked_add(1)
                }
            })
            .map_err(|_| ProviderStackActivationError::IdentityExhausted)?;
        Ok(Self {
            identity: StackCatalogIdentity(identity),
            lanes: Vec::new(),
            max_lanes,
            max_depth_per_lane,
            next_activation_generation: 1,
        })
    }

    pub(crate) const fn identity(&self) -> StackCatalogIdentity {
        self.identity
    }

    pub fn register_lane(
        &mut self,
        lane_id: u64,
        stack_base: u64,
        stack_bytes: u64,
    ) -> Result<ProviderStackLaneHandle, ProviderStackActivationError> {
        let stack_end = stack_base
            .checked_add(stack_bytes)
            .ok_or(ProviderStackActivationError::InvalidLane)?;
        if lane_id == 0 || stack_base == 0 || stack_bytes == 0 || stack_end <= stack_base {
            return Err(ProviderStackActivationError::InvalidLane);
        }
        for lane in self.lanes.iter().filter(|lane| lane.live) {
            if lane.lane_id == lane_id {
                return Err(ProviderStackActivationError::DuplicateLane);
            }
            let lane_end = lane.stack_base + lane.stack_bytes;
            if stack_base < lane_end && lane.stack_base < stack_end {
                return Err(ProviderStackActivationError::OverlappingStack);
            }
        }

        let slot = if let Some(slot) = self.lanes.iter().position(|lane| !lane.live) {
            slot
        } else {
            if self.lanes.len() >= self.max_lanes {
                return Err(ProviderStackActivationError::NoCapacity);
            }
            self.lanes
                .try_reserve(1)
                .map_err(|_| ProviderStackActivationError::NoCapacity)?;
            self.lanes.push(ProviderStackLaneRecord::empty());
            self.lanes.len() - 1
        };
        let generation = self.lanes[slot]
            .generation
            .checked_add(1)
            .ok_or(ProviderStackActivationError::IdentityExhausted)?;
        self.lanes[slot] = ProviderStackLaneRecord {
            generation,
            live: true,
            lane_id,
            stack_base,
            stack_bytes,
            activations: Vec::new(),
            last_kernel_owner: None,
        };
        Ok(self.lanes[slot].binding(slot).handle)
    }

    pub fn unregister_lane(
        &mut self,
        handle: ProviderStackLaneHandle,
    ) -> Result<(), ProviderStackActivationError> {
        let lane = self.lane_mut(handle)?;
        if !lane.activations.is_empty() {
            return Err(ProviderStackActivationError::LaneActive);
        }
        lane.live = false;
        lane.lane_id = 0;
        lane.stack_base = 0;
        lane.stack_bytes = 0;
        Ok(())
    }

    pub fn binding(
        &self,
        handle: ProviderStackLaneHandle,
    ) -> Result<ProviderStackLaneBinding, ProviderStackActivationError> {
        let lane = self.lane(handle)?;
        Ok(lane.binding(handle.slot as usize))
    }

    pub fn resolve(
        &self,
        address: u64,
        bytes: u64,
    ) -> Result<(ProviderStackLaneBinding, u64), ProviderStackActivationError> {
        let end = address
            .checked_add(bytes)
            .ok_or(ProviderStackActivationError::AddressOutsideLane)?;
        if bytes == 0 {
            return Err(ProviderStackActivationError::AddressOutsideLane);
        }
        self.lanes
            .iter()
            .enumerate()
            .find(|(_, lane)| {
                lane.live && address >= lane.stack_base && end <= lane.stack_base + lane.stack_bytes
            })
            .map(|(slot, lane)| (lane.binding(slot), address - lane.stack_base))
            .ok_or(ProviderStackActivationError::AddressOutsideLane)
    }

    pub fn begin_for_stack_pointer(
        &mut self,
        stack_pointer: u64,
        dispatch_id: u64,
    ) -> Result<ProviderStackEventActivation, ProviderStackActivationError> {
        let (binding, _) = self.resolve(stack_pointer, 1)?;
        self.begin(binding.handle, dispatch_id)
    }

    pub fn begin(
        &mut self,
        handle: ProviderStackLaneHandle,
        dispatch_id: u64,
    ) -> Result<ProviderStackEventActivation, ProviderStackActivationError> {
        self.begin_with_owner(handle, dispatch_id, None)
    }

    /// Bind copied root metadata to this activation, never to a guessed local lane ordinal.
    /// A local lane keeps its root binding and epoch fence until explicit unregistration.
    pub fn begin_kernel_for_stack_pointer(
        &mut self,
        stack_pointer: u64,
        expected_provider: ProviderDomainIdentity,
        descriptor: KernelProviderActivationDescriptor,
    ) -> Result<ProviderStackEventActivation, ProviderStackActivationError> {
        let owner = descriptor
            .validate(expected_provider)
            .map_err(ProviderStackActivationError::InvalidKernelDescriptor)?;
        let (binding, _) = self.resolve(stack_pointer, 1)?;
        let lane = self.lane(binding.handle)?;
        if let Some(previous) = lane.last_kernel_owner {
            if !same_kernel_lane(previous, owner) {
                return Err(ProviderStackActivationError::KernelBindingMismatch);
            }
            if owner.dispatch_id <= previous.dispatch_id {
                return Err(ProviderStackActivationError::StaleKernelDispatch);
            }
        }
        for (index, lane) in self.lanes.iter().enumerate().filter(|(_, lane)| lane.live) {
            if index != binding.handle.slot as usize
                && lane
                    .last_kernel_owner
                    .is_some_and(|previous| previous.caller == owner.caller)
            {
                return Err(ProviderStackActivationError::KernelLaneAlreadyBound);
            }
            if lane.activations.iter().any(|record| {
                record
                    .owner
                    .is_some_and(|active| active.caller == owner.caller)
            }) {
                return Err(ProviderStackActivationError::KernelDispatchActive);
            }
        }
        self.begin_with_owner(binding.handle, owner.dispatch_id, Some(owner))
    }

    fn begin_with_owner(
        &mut self,
        handle: ProviderStackLaneHandle,
        dispatch_id: u64,
        owner: Option<ProviderWaitOwner>,
    ) -> Result<ProviderStackEventActivation, ProviderStackActivationError> {
        if dispatch_id == 0 {
            return Err(ProviderStackActivationError::InvalidDispatch);
        }
        let generation = self.next_activation_generation;
        self.next_activation_generation = generation
            .checked_add(1)
            .ok_or(ProviderStackActivationError::IdentityExhausted)?;
        if generation == 0 {
            return Err(ProviderStackActivationError::IdentityExhausted);
        }
        let max_depth = self.max_depth_per_lane;
        let lane = self.lane_mut(handle)?;
        if lane.activations.len() >= max_depth {
            return Err(ProviderStackActivationError::NoCapacity);
        }
        lane.activations
            .try_reserve(1)
            .map_err(|_| ProviderStackActivationError::NoCapacity)?;
        let activation = ProviderStackEventActivation {
            lane: handle,
            lane_id: lane.lane_id,
            dispatch_id,
            generation,
        };
        lane.activations.push(ProviderStackActivationRecord {
            identity: activation,
            irql: IrqlState::new(),
            owner,
        });
        if let Some(owner) = owner {
            lane.last_kernel_owner = Some(owner);
        }
        Ok(activation)
    }

    pub fn active(
        &self,
        handle: ProviderStackLaneHandle,
    ) -> Result<ProviderStackEventActivation, ProviderStackActivationError> {
        self.lane(handle)?
            .activations
            .last()
            .map(|record| record.identity)
            .ok_or(ProviderStackActivationError::NoActiveActivation)
    }

    pub fn current_irql(
        &self,
        activation: ProviderStackEventActivation,
    ) -> Result<u8, ProviderStackActivationError> {
        Ok(self.activation(activation)?.irql.current())
    }

    /// An unbound nested activation cannot borrow the suspended outer caller's authority.
    pub fn owner(
        &self,
        activation: ProviderStackEventActivation,
    ) -> Result<Option<ProviderWaitOwner>, ProviderStackActivationError> {
        Ok(self.activation(activation)?.owner)
    }

    pub fn raise_irql(
        &mut self,
        activation: ProviderStackEventActivation,
        new: u8,
    ) -> Result<u8, ProviderStackActivationError> {
        let record = self.activation_mut(activation)?;
        if new > 15 {
            return Err(ProviderStackActivationError::InvalidIrql);
        }
        record
            .irql
            .try_raise(new)
            .map_err(|_| ProviderStackActivationError::InvalidIrqlTransition)
    }

    pub fn lower_irql(
        &mut self,
        activation: ProviderStackEventActivation,
        new: u8,
    ) -> Result<(), ProviderStackActivationError> {
        let record = self.activation_mut(activation)?;
        if new > 15 {
            return Err(ProviderStackActivationError::InvalidIrql);
        }
        record
            .irql
            .try_lower(new)
            .map_err(|_| ProviderStackActivationError::InvalidIrqlTransition)
    }

    /// Admission depends on the requested timeout form, not current object readiness.
    pub fn can_wait(
        &self,
        activation: ProviderStackEventActivation,
        timeout: ProviderWaitTimeoutKind,
    ) -> Result<bool, ProviderStackActivationError> {
        let irql = &self.activation(activation)?.irql;
        Ok(if timeout == ProviderWaitTimeoutKind::Poll {
            irql.can_poll()
        } else {
            irql.can_wait()
        })
    }

    pub fn classify_event_storage(
        &self,
        current_stack_pointer: u64,
        event_body: u64,
        event_bytes: u64,
    ) -> Result<(ProviderStackEventActivation, u64), ProviderStackActivationError> {
        let (current, _) = self.resolve(current_stack_pointer, 1)?;
        let (storage, offset) = self.resolve(event_body, event_bytes)?;
        if current.handle != storage.handle {
            return Err(ProviderStackActivationError::CrossLaneStorage);
        }
        Ok((self.active(current.handle)?, offset))
    }

    pub fn finish(
        &mut self,
        activation: ProviderStackEventActivation,
    ) -> Result<(), ProviderStackActivationError> {
        if self.activation(activation)?.irql.current() != PASSIVE_LEVEL {
            return Err(ProviderStackActivationError::UnbalancedIrql);
        }
        let lane = self.lane_mut(activation.lane)?;
        lane.activations.pop();
        Ok(())
    }

    fn activation(
        &self,
        activation: ProviderStackEventActivation,
    ) -> Result<&ProviderStackActivationRecord, ProviderStackActivationError> {
        self.lane(activation.lane)?
            .activations
            .last()
            .filter(|record| record.identity == activation)
            .ok_or(ProviderStackActivationError::NotTop)
    }

    fn activation_mut(
        &mut self,
        activation: ProviderStackEventActivation,
    ) -> Result<&mut ProviderStackActivationRecord, ProviderStackActivationError> {
        self.lane_mut(activation.lane)?
            .activations
            .last_mut()
            .filter(|record| record.identity == activation)
            .ok_or(ProviderStackActivationError::NotTop)
    }

    fn lane(
        &self,
        handle: ProviderStackLaneHandle,
    ) -> Result<&ProviderStackLaneRecord, ProviderStackActivationError> {
        self.lanes
            .get(handle.slot as usize)
            .filter(|lane| lane.live && lane.generation == handle.generation)
            .ok_or(ProviderStackActivationError::StaleLane)
    }

    fn lane_mut(
        &mut self,
        handle: ProviderStackLaneHandle,
    ) -> Result<&mut ProviderStackLaneRecord, ProviderStackActivationError> {
        self.lanes
            .get_mut(handle.slot as usize)
            .filter(|lane| lane.live && lane.generation == handle.generation)
            .ok_or(ProviderStackActivationError::StaleLane)
    }
}

fn same_kernel_lane(left: ProviderWaitOwner, right: ProviderWaitOwner) -> bool {
    left.provider_domain == right.provider_domain
        && left.provider_generation == right.provider_generation
        && left.caller == right.caller
}

#[cfg(test)]
#[path = "stack_activation_owner_tests.rs"]
mod owner_tests;

#[cfg(test)]
#[path = "stack_activation_irql_tests.rs"]
mod irql_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_identity_distinguishes_equal_lane_bindings() {
        let mut first = catalog();
        let mut second = catalog();
        let a = first.register_lane(7, 0x1000, 0x1000).unwrap();
        let b = second.register_lane(7, 0x1000, 0x1000).unwrap();
        assert_eq!(first.binding(a), second.binding(b));
        assert_ne!(first.identity(), second.identity());
    }

    #[test]
    fn catalog_identity_survives_move_and_lane_generation_reuse() {
        let mut original = catalog();
        let identity = original.identity();
        let handle = original.register_lane(7, 0x1000, 0x1000).unwrap();
        let mut moved = original;
        assert_eq!(moved.identity(), identity);
        moved.unregister_lane(handle).unwrap();
        let replacement = moved.register_lane(7, 0x1000, 0x1000).unwrap();
        assert_ne!(handle, replacement);
        assert_eq!(moved.identity(), identity);
    }

    #[test]
    fn catalog_identity_exhaustion_never_wraps_or_issues_zero() {
        for value in [0, u64::MAX] {
            let counter = AtomicU64::new(value);
            assert_eq!(
                ProviderStackActivationCatalog::new_with_counter(1, 1, &counter).err(),
                Some(ProviderStackActivationError::IdentityExhausted)
            );
            assert_eq!(counter.load(Ordering::Relaxed), value);
        }
        let counter = AtomicU64::new(u64::MAX - 1);
        let last = ProviderStackActivationCatalog::new_with_counter(1, 1, &counter).unwrap();
        assert_eq!(last.identity(), StackCatalogIdentity(u64::MAX - 1));
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(
            ProviderStackActivationCatalog::new_with_counter(1, 1, &counter).err(),
            Some(ProviderStackActivationError::IdentityExhausted)
        );
    }

    #[test]
    fn invalid_catalog_capacity_does_not_consume_identity() {
        let counter = AtomicU64::new(8);
        for (lanes, depth) in [(0, 1), (1, 0), (u32::MAX as usize + 1, 1)] {
            assert_eq!(
                ProviderStackActivationCatalog::new_with_counter(lanes, depth, &counter).err(),
                Some(ProviderStackActivationError::InvalidCapacity)
            );
            assert_eq!(counter.load(Ordering::Relaxed), 8);
        }
        assert_eq!(
            ProviderStackActivationCatalog::new_with_counter(1, 1, &counter)
                .unwrap()
                .identity(),
            StackCatalogIdentity(8)
        );
    }

    fn catalog() -> ProviderStackActivationCatalog {
        ProviderStackActivationCatalog::new(3, 4).unwrap()
    }

    #[test]
    fn independent_lanes_finish_out_of_global_order() {
        let mut catalog = catalog();
        let first = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
        let second = catalog.register_lane(2, 0x3000, 0x1000).unwrap();
        let a = catalog.begin(first, 10).unwrap();
        let b = catalog.begin(second, 20).unwrap();

        catalog.finish(a).unwrap();
        assert_eq!(catalog.active(second), Ok(b));
        catalog.finish(b).unwrap();
    }

    #[test]
    fn one_lane_remains_strict_lifo() {
        let mut catalog = catalog();
        let lane = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
        let outer = catalog.begin(lane, 10).unwrap();
        let inner = catalog.begin(lane, 11).unwrap();
        assert_eq!(
            catalog.finish(outer),
            Err(ProviderStackActivationError::NotTop)
        );
        catalog.finish(inner).unwrap();
        catalog.finish(outer).unwrap();
    }

    #[test]
    fn event_storage_must_belong_to_current_lane() {
        let mut catalog = catalog();
        let first = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
        catalog.register_lane(2, 0x3000, 0x1000).unwrap();
        catalog.begin(first, 10).unwrap();
        assert_eq!(
            catalog.classify_event_storage(0x1800, 0x3040, 0x40),
            Err(ProviderStackActivationError::CrossLaneStorage)
        );
    }

    #[test]
    fn worker_stack_offset_is_relative_to_its_lane() {
        let mut catalog = catalog();
        let lane = catalog.register_lane(7, 0x9000, 0x2000).unwrap();
        let activation = catalog.begin(lane, 31).unwrap();
        assert_eq!(
            catalog.classify_event_storage(0xa800, 0x9040, 0x40),
            Ok((activation, 0x40))
        );
        assert_eq!(
            activation.backing(),
            ProviderEventBacking::Stack {
                lane_id: 7,
                lane_generation: 1,
                dispatch_id: 31,
                activation_generation: 1,
            }
        );
    }

    #[test]
    fn invalid_and_overlapping_ranges_are_rejected() {
        let mut catalog = catalog();
        assert_eq!(
            catalog.register_lane(1, u64::MAX - 4, 8),
            Err(ProviderStackActivationError::InvalidLane)
        );
        catalog.register_lane(1, 0x1000, 0x1000).unwrap();
        assert_eq!(
            catalog.register_lane(2, 0x1800, 0x1000),
            Err(ProviderStackActivationError::OverlappingStack)
        );
    }

    #[test]
    fn unregister_reuses_a_slot_with_a_fresh_generation() {
        let mut catalog = catalog();
        let old = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
        catalog.unregister_lane(old).unwrap();
        let fresh = catalog.register_lane(2, 0x3000, 0x1000).unwrap();
        assert_eq!(old.slot(), fresh.slot());
        assert_ne!(old.generation(), fresh.generation());
        assert_eq!(
            catalog.begin(old, 2),
            Err(ProviderStackActivationError::StaleLane)
        );
    }

    #[test]
    fn live_activation_fences_lane_release() {
        let mut catalog = catalog();
        let lane = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
        let activation = catalog.begin(lane, 10).unwrap();
        assert_eq!(
            catalog.unregister_lane(lane),
            Err(ProviderStackActivationError::LaneActive)
        );
        catalog.finish(activation).unwrap();
        catalog.unregister_lane(lane).unwrap();
    }
}
