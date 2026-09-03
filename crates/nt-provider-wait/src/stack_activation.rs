use alloc::vec::Vec;

use crate::ProviderEventBacking;

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
}

struct ProviderStackLaneRecord {
    generation: u32,
    live: bool,
    lane_id: u64,
    stack_base: u64,
    stack_bytes: u64,
    activations: Vec<ProviderStackEventActivation>,
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
        if max_lanes == 0 || max_depth_per_lane == 0 || max_lanes > u32::MAX as usize {
            return Err(ProviderStackActivationError::InvalidCapacity);
        }
        Ok(Self {
            lanes: Vec::new(),
            max_lanes,
            max_depth_per_lane,
            next_activation_generation: 1,
        })
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
        lane.activations.push(activation);
        Ok(activation)
    }

    pub fn active(
        &self,
        handle: ProviderStackLaneHandle,
    ) -> Result<ProviderStackEventActivation, ProviderStackActivationError> {
        self.lane(handle)?
            .activations
            .last()
            .copied()
            .ok_or(ProviderStackActivationError::NoActiveActivation)
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
        let lane = self.lane_mut(activation.lane)?;
        if lane.activations.last().copied() != Some(activation) {
            return Err(ProviderStackActivationError::NotTop);
        }
        lane.activations.pop();
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

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
