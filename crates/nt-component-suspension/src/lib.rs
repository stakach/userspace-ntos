//! Cross-kind ownership for a component's retained synchronous Calls.
//!
//! A component may have multiple physical execution lanes. Readiness is independent across lanes,
//! but only the top physical frame of one lane may resume. A resumed dispatch that blocks again can
//! rearm under another typed key while keeping its one native continuation.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionKind {
    ProviderWait,
    LpcRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionKey {
    pub kind: SuspensionKind,
    pub id: u64,
}

impl SuspensionKey {
    pub const fn provider_wait(id: u64) -> Self {
        Self {
            kind: SuspensionKind::ProviderWait,
            id,
        }
    }

    pub const fn lpc_request(id: u64) -> Self {
        Self {
            kind: SuspensionKind::LpcRequest,
            id,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.id != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionOwner {
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub client_pi: u32,
    pub client_generation: u64,
    pub client_tid: u64,
    pub client_badge: u64,
    pub dispatch_id: u64,
}

impl SuspensionOwner {
    pub const fn is_valid(self) -> bool {
        self.provider_domain != 0
            && self.provider_generation != 0
            && self.client_generation != 0
            && self.client_tid != 0
            && self.client_badge != 0
            && self.dispatch_id != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionScope {
    Provider {
        domain: u64,
        generation: u64,
    },
    Process {
        domain: u64,
        provider_generation: u64,
        client_pi: u32,
        client_generation: u64,
    },
    Thread {
        domain: u64,
        provider_generation: u64,
        client_pi: u32,
        client_generation: u64,
        client_tid: u64,
        client_badge: u64,
    },
}

impl SuspensionScope {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Provider { domain, generation } => domain != 0 && generation != 0,
            Self::Process {
                domain,
                provider_generation,
                client_generation,
                ..
            } => domain != 0 && provider_generation != 0 && client_generation != 0,
            Self::Thread {
                domain,
                provider_generation,
                client_generation,
                client_tid,
                client_badge,
                ..
            } => {
                domain != 0
                    && provider_generation != 0
                    && client_generation != 0
                    && client_tid != 0
                    && client_badge != 0
            }
        }
    }

    pub const fn matches(self, owner: SuspensionOwner) -> bool {
        match self {
            Self::Provider { domain, generation } => {
                owner.provider_domain == domain && owner.provider_generation == generation
            }
            Self::Process {
                domain,
                provider_generation,
                client_pi,
                client_generation,
            } => {
                owner.provider_domain == domain
                    && owner.provider_generation == provider_generation
                    && owner.client_pi == client_pi
                    && owner.client_generation == client_generation
            }
            Self::Thread {
                domain,
                provider_generation,
                client_pi,
                client_generation,
                client_tid,
                client_badge,
            } => {
                owner.provider_domain == domain
                    && owner.provider_generation == provider_generation
                    && owner.client_pi == client_pi
                    && owner.client_generation == client_generation
                    && owner.client_tid == client_tid
                    && owner.client_badge == client_badge
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuspensionPhase<R> {
    Waiting,
    Selected { completion: R },
    Resuming { completion: R, cancelled: bool },
    Cancelled { completion: R },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspensionFrame<C, R> {
    pub key: SuspensionKey,
    pub admission_sequence: u64,
    pub owner: SuspensionOwner,
    pub phase: SuspensionPhase<R>,
    pub continuation: C,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspensionResume<R> {
    pub key: SuspensionKey,
    pub completion: R,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedSuspension<C, R> {
    pub key: SuspensionKey,
    pub owner: SuspensionOwner,
    pub completion: R,
    pub cancelled: bool,
    pub continuation: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionError {
    InvalidIdentity,
    DuplicateIdentity,
    Overflow,
    NoCapacity,
    NotFound,
    NotTop,
    InvalidPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneHandle {
    pub index: u32,
    pub generation: u64,
}

impl LaneHandle {
    pub const INVALID: Self = Self {
        index: 0,
        generation: 0,
    };

    pub const fn is_valid(self) -> bool {
        self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneBinding {
    pub executor_id: u64,
    pub receive_endpoint: u64,
    pub reply_object: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneAddressLayout {
    pub base: u64,
    pub stride: u64,
    pub stack_bytes: u64,
    pub ipc_buffer_offset: u64,
    pub capacity: usize,
}

impl LaneAddressLayout {
    pub const fn is_valid(self) -> bool {
        self.base != 0
            && self.stride != 0
            && self.stack_bytes != 0
            && self.stack_bytes <= self.ipc_buffer_offset
            && self.ipc_buffer_offset <= self.stride.saturating_sub(0x1000)
            && self.capacity != 0
    }

    pub fn ipc_buffer_for_stack_pointer(self, stack_pointer: u64) -> Option<u64> {
        if !self.is_valid() || stack_pointer < self.base {
            return None;
        }
        let relative = stack_pointer - self.base;
        let lane = relative / self.stride;
        let lane_offset = relative % self.stride;
        if lane >= self.capacity as u64 || lane_offset >= self.stack_bytes {
            return None;
        }
        self.base
            .checked_add(lane.checked_mul(self.stride)?)?
            .checked_add(self.ipc_buffer_offset)
    }
}

impl LaneBinding {
    pub const fn is_valid(self) -> bool {
        self.executor_id != 0 && self.receive_endpoint != 0 && self.reply_object != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanePhase {
    Idle,
    Running,
    Suspended,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneResume<R> {
    pub lane: LaneHandle,
    pub binding: LaneBinding,
    pub suspension: SuspensionResume<R>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaneError {
    InvalidIdentity,
    DuplicateBinding,
    NoCapacity,
    NotFound,
    StaleGeneration,
    WrongBinding,
    Busy,
    InvalidPhase,
    Suspension(SuspensionError),
}

struct Lane<C, R> {
    binding: LaneBinding,
    phase: LanePhase,
    external_tokens: Vec<u64>,
    suspensions: ComponentSuspensionStack<C, R>,
}

struct LaneSlot<C, R> {
    generation: u64,
    lane: Option<Lane<C, R>>,
}

/// Owns the physical execution lanes for one shared-state component.
///
/// The table serializes component execution while allowing independent lanes to retain physical
/// stacks and reply objects. A suspended lane therefore never prevents a selected top frame on a
/// different lane from resuming.
pub struct ComponentSuspensionLanes<C, R> {
    slots: Vec<LaneSlot<C, R>>,
    max_lanes: usize,
    max_depth_per_lane: usize,
    running: Option<LaneHandle>,
}

pub struct ComponentSuspensionStack<C, R> {
    frames: Vec<SuspensionFrame<C, R>>,
    max_depth: usize,
}

impl<C, R> ComponentSuspensionStack<C, R> {
    pub const fn new(max_depth: usize) -> Self {
        Self {
            frames: Vec::new(),
            max_depth,
        }
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn top(&self) -> Option<&SuspensionFrame<C, R>> {
        self.frames.last()
    }

    pub fn frames(&self) -> &[SuspensionFrame<C, R>] {
        &self.frames
    }

    pub fn get(&self, key: SuspensionKey) -> Option<&SuspensionFrame<C, R>> {
        self.frames.iter().find(|frame| frame.key == key)
    }

    pub fn get_mut(&mut self, key: SuspensionKey) -> Option<&mut SuspensionFrame<C, R>> {
        self.frames.iter_mut().find(|frame| frame.key == key)
    }

    pub fn contains_scope(&self, scope: SuspensionScope) -> bool {
        scope.is_valid() && self.frames.iter().any(|frame| scope.matches(frame.owner))
    }

    pub fn next_cancellable_in_scope(&self, scope: SuspensionScope) -> Option<SuspensionKey> {
        if !scope.is_valid() {
            return None;
        }
        self.frames.iter().find_map(|frame| {
            (scope.matches(frame.owner)
                && matches!(
                    frame.phase,
                    SuspensionPhase::Waiting | SuspensionPhase::Selected { .. }
                ))
            .then_some(frame.key)
        })
    }

    pub fn admit(
        &mut self,
        key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        continuation: C,
    ) -> Result<(), SuspensionError> {
        if !key.is_valid() || admission_sequence == 0 || !owner.is_valid() {
            return Err(SuspensionError::InvalidIdentity);
        }
        if self.frames.iter().any(|frame| {
            frame.key == key
                || (frame.owner.provider_domain == owner.provider_domain
                    && frame.owner.provider_generation == owner.provider_generation
                    && frame.owner.dispatch_id == owner.dispatch_id)
        }) {
            return Err(SuspensionError::DuplicateIdentity);
        }
        if self.frames.len() >= self.max_depth {
            return Err(SuspensionError::Overflow);
        }
        self.frames
            .try_reserve(1)
            .map_err(|_| SuspensionError::NoCapacity)?;
        self.frames.push(SuspensionFrame {
            key,
            admission_sequence,
            owner,
            phase: SuspensionPhase::Waiting,
            continuation,
        });
        Ok(())
    }

    pub fn rollback_admission(&mut self, key: SuspensionKey) -> Result<C, SuspensionError> {
        let frame = self.frames.last().ok_or(SuspensionError::NotFound)?;
        if frame.key != key {
            return Err(SuspensionError::NotTop);
        }
        if !matches!(frame.phase, SuspensionPhase::Waiting) {
            return Err(SuspensionError::InvalidPhase);
        }
        Ok(self.frames.pop().unwrap().continuation)
    }

    pub fn select(&mut self, key: SuspensionKey, completion: R) -> Result<(), SuspensionError> {
        let frame = self
            .frames
            .iter_mut()
            .find(|frame| frame.key == key)
            .ok_or(SuspensionError::NotFound)?;
        if !matches!(frame.phase, SuspensionPhase::Waiting) {
            return Err(SuspensionError::InvalidPhase);
        }
        frame.phase = SuspensionPhase::Selected { completion };
        Ok(())
    }

    pub fn cancel(&mut self, key: SuspensionKey, completion: R) -> Result<(), SuspensionError> {
        let frame = self
            .frames
            .iter_mut()
            .find(|frame| frame.key == key)
            .ok_or(SuspensionError::NotFound)?;
        if !matches!(
            frame.phase,
            SuspensionPhase::Waiting | SuspensionPhase::Selected { .. }
        ) {
            return Err(SuspensionError::InvalidPhase);
        }
        frame.phase = SuspensionPhase::Cancelled { completion };
        Ok(())
    }
}

impl<C, R: Clone> ComponentSuspensionStack<C, R> {
    pub fn top_resume(&self) -> Option<SuspensionResume<R>> {
        let frame = self.frames.last()?;
        match &frame.phase {
            SuspensionPhase::Selected { completion } => Some(SuspensionResume {
                key: frame.key,
                completion: completion.clone(),
                cancelled: false,
            }),
            SuspensionPhase::Cancelled { completion } => Some(SuspensionResume {
                key: frame.key,
                completion: completion.clone(),
                cancelled: true,
            }),
            SuspensionPhase::Waiting | SuspensionPhase::Resuming { .. } => None,
        }
    }

    pub fn begin_resume(
        &mut self,
        key: SuspensionKey,
    ) -> Result<SuspensionResume<R>, SuspensionError> {
        let frame = self.frames.last_mut().ok_or(SuspensionError::NotFound)?;
        if frame.key != key {
            return Err(SuspensionError::NotTop);
        }
        let resume = match &frame.phase {
            SuspensionPhase::Selected { completion } => SuspensionResume {
                key,
                completion: completion.clone(),
                cancelled: false,
            },
            SuspensionPhase::Cancelled { completion } => SuspensionResume {
                key,
                completion: completion.clone(),
                cancelled: true,
            },
            _ => return Err(SuspensionError::InvalidPhase),
        };
        frame.phase = SuspensionPhase::Resuming {
            completion: resume.completion.clone(),
            cancelled: resume.cancelled,
        };
        Ok(resume)
    }

    pub fn rearm(
        &mut self,
        completed_key: SuspensionKey,
        next_key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        continuation: C,
    ) -> Result<(), SuspensionError> {
        if !next_key.is_valid() || admission_sequence == 0 || !owner.is_valid() {
            return Err(SuspensionError::InvalidIdentity);
        }
        if self.frames.iter().any(|frame| frame.key == next_key) {
            return Err(SuspensionError::DuplicateIdentity);
        }
        let frame = self.frames.last_mut().ok_or(SuspensionError::NotFound)?;
        if frame.key != completed_key {
            return Err(SuspensionError::NotTop);
        }
        if !matches!(frame.phase, SuspensionPhase::Resuming { .. }) || frame.owner != owner {
            return Err(SuspensionError::InvalidPhase);
        }
        frame.key = next_key;
        frame.admission_sequence = admission_sequence;
        frame.phase = SuspensionPhase::Waiting;
        frame.continuation = continuation;
        Ok(())
    }

    pub fn complete_dispatch(
        &mut self,
        key: SuspensionKey,
        owner: SuspensionOwner,
    ) -> Result<CompletedSuspension<C, R>, SuspensionError> {
        let frame = self.frames.last().ok_or(SuspensionError::NotFound)?;
        if frame.key != key {
            return Err(SuspensionError::NotTop);
        }
        if frame.owner != owner {
            return Err(SuspensionError::InvalidIdentity);
        }
        let (completion, cancelled) = match &frame.phase {
            SuspensionPhase::Resuming {
                completion,
                cancelled,
            } => (completion.clone(), *cancelled),
            _ => return Err(SuspensionError::InvalidPhase),
        };
        let frame = self.frames.pop().unwrap();
        Ok(CompletedSuspension {
            key: frame.key,
            owner: frame.owner,
            completion,
            cancelled,
            continuation: frame.continuation,
        })
    }

    pub fn abort_resume(
        &mut self,
        key: SuspensionKey,
        owner: SuspensionOwner,
        completion: R,
    ) -> Result<CompletedSuspension<C, R>, SuspensionError> {
        let frame = self.frames.last_mut().ok_or(SuspensionError::NotFound)?;
        if frame.key != key {
            return Err(SuspensionError::NotTop);
        }
        if frame.owner != owner {
            return Err(SuspensionError::InvalidIdentity);
        }
        if !matches!(frame.phase, SuspensionPhase::Resuming { .. }) {
            return Err(SuspensionError::InvalidPhase);
        }
        frame.phase = SuspensionPhase::Resuming {
            completion,
            cancelled: true,
        };
        self.complete_dispatch(key, owner)
    }
}

impl<C, R> ComponentSuspensionLanes<C, R> {
    pub const fn new(max_lanes: usize, max_depth_per_lane: usize) -> Self {
        Self {
            slots: Vec::new(),
            max_lanes,
            max_depth_per_lane,
            running: None,
        }
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.lane.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub const fn running(&self) -> Option<LaneHandle> {
        self.running
    }

    pub fn next_idle(&self) -> Option<(LaneHandle, LaneBinding)> {
        if self.running.is_some() {
            return None;
        }
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let lane = slot.lane.as_ref()?;
            (lane.phase == LanePhase::Idle
                && lane.external_tokens.is_empty()
                && lane.suspensions.is_empty())
            .then_some((
                LaneHandle {
                    index: index as u32,
                    generation: slot.generation,
                },
                lane.binding,
            ))
        })
    }

    /// A fresh root dispatch may add a physical lane only when the component is not executing,
    /// every registered lane is retained, and the configured lane bound has not been reached.
    pub fn needs_idle_lane(&self) -> bool {
        self.running.is_none() && self.next_idle().is_none() && self.len() < self.max_lanes
    }

    pub fn allocate(&mut self, binding: LaneBinding) -> Result<LaneHandle, LaneError> {
        if !binding.is_valid() || self.max_depth_per_lane == 0 {
            return Err(LaneError::InvalidIdentity);
        }
        if self.slots.iter().any(|slot| {
            slot.lane.as_ref().is_some_and(|lane| {
                lane.binding.executor_id == binding.executor_id
                    || lane.binding.receive_endpoint == binding.receive_endpoint
                    || lane.binding.reply_object == binding.reply_object
            })
        }) {
            return Err(LaneError::DuplicateBinding);
        }

        if let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.lane.is_none())
        {
            slot.generation = slot
                .generation
                .checked_add(1)
                .ok_or(LaneError::NoCapacity)?;
            slot.lane = Some(Lane {
                binding,
                phase: LanePhase::Idle,
                external_tokens: Vec::new(),
                suspensions: ComponentSuspensionStack::new(self.max_depth_per_lane),
            });
            return Ok(LaneHandle {
                index: index as u32,
                generation: slot.generation,
            });
        }

        if self.slots.len() >= self.max_lanes || self.slots.len() > u32::MAX as usize {
            return Err(LaneError::NoCapacity);
        }
        self.slots
            .try_reserve(1)
            .map_err(|_| LaneError::NoCapacity)?;
        let handle = LaneHandle {
            index: self.slots.len() as u32,
            generation: 1,
        };
        self.slots.push(LaneSlot {
            generation: handle.generation,
            lane: Some(Lane {
                binding,
                phase: LanePhase::Idle,
                external_tokens: Vec::new(),
                suspensions: ComponentSuspensionStack::new(self.max_depth_per_lane),
            }),
        });
        Ok(handle)
    }

    pub fn release(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
    ) -> Result<LaneBinding, LaneError> {
        self.validate(handle, reply_object)?;
        let slot = &mut self.slots[handle.index as usize];
        let lane = slot.lane.as_ref().ok_or(LaneError::NotFound)?;
        if lane.phase != LanePhase::Idle
            || !lane.external_tokens.is_empty()
            || !lane.suspensions.is_empty()
        {
            return Err(LaneError::Busy);
        }
        Ok(slot.lane.take().unwrap().binding)
    }

    pub fn binding(&self, handle: LaneHandle) -> Result<LaneBinding, LaneError> {
        Ok(self.lane(handle)?.binding)
    }

    pub fn phase(&self, handle: LaneHandle) -> Result<LanePhase, LaneError> {
        Ok(self.lane(handle)?.phase)
    }

    pub fn suspension_count(&self, handle: LaneHandle) -> Result<usize, LaneError> {
        Ok(self.lane(handle)?.suspensions.len())
    }

    pub fn external_depth(&self, handle: LaneHandle) -> Result<usize, LaneError> {
        Ok(self.lane(handle)?.external_tokens.len())
    }

    pub fn external_top(&self, handle: LaneHandle) -> Result<Option<u64>, LaneError> {
        Ok(self.lane(handle)?.external_tokens.last().copied())
    }

    pub fn total_suspensions(&self) -> usize {
        self.slots
            .iter()
            .filter_map(|slot| slot.lane.as_ref())
            .map(|lane| lane.suspensions.len())
            .sum()
    }

    pub fn frames(&self) -> impl Iterator<Item = (LaneHandle, &SuspensionFrame<C, R>)> {
        self.slots.iter().enumerate().flat_map(|(index, slot)| {
            let handle = LaneHandle {
                index: index as u32,
                generation: slot.generation,
            };
            slot.lane.as_ref().into_iter().flat_map(move |lane| {
                lane.suspensions
                    .frames()
                    .iter()
                    .map(move |frame| (handle, frame))
            })
        })
    }

    pub fn top(&self, handle: LaneHandle) -> Result<Option<&SuspensionFrame<C, R>>, LaneError> {
        Ok(self.lane(handle)?.suspensions.top())
    }

    pub fn frame(
        &self,
        handle: LaneHandle,
        key: SuspensionKey,
    ) -> Result<Option<&SuspensionFrame<C, R>>, LaneError> {
        Ok(self.lane(handle)?.suspensions.get(key))
    }

    pub fn frame_mut(
        &mut self,
        handle: LaneHandle,
        key: SuspensionKey,
    ) -> Result<Option<&mut SuspensionFrame<C, R>>, LaneError> {
        Ok(self.lane_mut(handle)?.suspensions.get_mut(key))
    }

    pub fn locate(&self, key: SuspensionKey) -> Option<(LaneHandle, &SuspensionFrame<C, R>)> {
        let handle = self.lane_for_key(key)?;
        self.lane(handle)
            .ok()?
            .suspensions
            .get(key)
            .map(|frame| (handle, frame))
    }

    pub fn begin_dispatch(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
    ) -> Result<(), LaneError> {
        if self.running.is_some() {
            return Err(LaneError::Busy);
        }
        self.validate(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.phase != LanePhase::Idle
            || !lane.external_tokens.is_empty()
            || !lane.suspensions.is_empty()
        {
            return Err(LaneError::InvalidPhase);
        }
        lane.phase = LanePhase::Running;
        self.running = Some(handle);
        Ok(())
    }

    pub fn finish_dispatch(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
    ) -> Result<(), LaneError> {
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if !lane.external_tokens.is_empty() || !lane.suspensions.is_empty() {
            return Err(LaneError::InvalidPhase);
        }
        lane.phase = LanePhase::Idle;
        self.running = None;
        Ok(())
    }

    /// Park a running lane in an external continuation such as a user-mode callback.
    pub fn suspend_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        token: u64,
    ) -> Result<(), LaneError> {
        if token == 0 {
            return Err(LaneError::InvalidIdentity);
        }
        self.validate_running(handle, reply_object)?;
        let max_depth = self.max_depth_per_lane;
        let lane = self.lane_mut(handle)?;
        if lane.external_tokens.len() >= max_depth {
            return Err(LaneError::Suspension(SuspensionError::Overflow));
        }
        lane.external_tokens
            .try_reserve(1)
            .map_err(|_| LaneError::NoCapacity)?;
        lane.external_tokens.push(token);
        lane.phase = LanePhase::Suspended;
        self.running = None;
        Ok(())
    }

    /// Reacquire the execution token for a lane parked by [`Self::suspend_running`].
    pub fn resume_external(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        token: u64,
    ) -> Result<(), LaneError> {
        if self.running.is_some() {
            return Err(LaneError::Busy);
        }
        self.validate(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.phase != LanePhase::Suspended || lane.external_tokens.last().copied() != Some(token)
        {
            return Err(LaneError::InvalidPhase);
        }
        lane.phase = LanePhase::Running;
        self.running = Some(handle);
        Ok(())
    }

    pub fn repark_external(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        token: u64,
    ) -> Result<(), LaneError> {
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.external_tokens.last().copied() != Some(token) {
            return Err(LaneError::InvalidPhase);
        }
        lane.phase = LanePhase::Suspended;
        self.running = None;
        Ok(())
    }

    pub fn complete_external(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        token: u64,
    ) -> Result<(), LaneError> {
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.external_tokens.last().copied() != Some(token) {
            return Err(LaneError::InvalidPhase);
        }
        lane.external_tokens.pop();
        lane.phase = if lane.external_tokens.is_empty() && lane.suspensions.is_empty() {
            LanePhase::Idle
        } else {
            LanePhase::Suspended
        };
        self.running = None;
        Ok(())
    }

    /// Retire the top external continuation while retaining the lane's running token. The caller
    /// must immediately finish, repark, or admit the component work that the callback resumed.
    pub fn retire_external_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        token: u64,
    ) -> Result<(), LaneError> {
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.external_tokens.last().copied() != Some(token) {
            return Err(LaneError::InvalidPhase);
        }
        lane.external_tokens.pop();
        Ok(())
    }

    pub fn replace_external_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        completed_token: u64,
        next_token: u64,
    ) -> Result<(), LaneError> {
        if next_token == 0 {
            return Err(LaneError::InvalidIdentity);
        }
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.external_tokens.last().copied() != Some(completed_token) {
            return Err(LaneError::InvalidPhase);
        }
        *lane.external_tokens.last_mut().unwrap() = next_token;
        lane.phase = LanePhase::Suspended;
        self.running = None;
        Ok(())
    }

    /// Replace the running top external continuation with a typed component suspension.
    ///
    /// A callback return can resume the component directly into a provider or LPC wait. The
    /// callback token and the new wait then describe one continuous physical-lane ownership chain;
    /// exposing an idle or merely-running lane between them would allow unrelated work to enter.
    pub fn transfer_external_to_suspension_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        external_token: u64,
        key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        continuation: C,
    ) -> Result<(), LaneError> {
        if external_token == 0 {
            return Err(LaneError::InvalidIdentity);
        }
        self.validate_running(handle, reply_object)?;
        if self.slots.iter().any(|slot| {
            slot.lane.as_ref().is_some_and(|lane| {
                lane.suspensions.get(key).is_some()
                    || lane.suspensions.frames().iter().any(|frame| {
                        frame.owner.provider_domain == owner.provider_domain
                            && frame.owner.provider_generation == owner.provider_generation
                            && frame.owner.dispatch_id == owner.dispatch_id
                    })
            })
        }) {
            return Err(LaneError::Suspension(SuspensionError::DuplicateIdentity));
        }
        let lane = self.lane_mut(handle)?;
        if lane.external_tokens.last().copied() != Some(external_token) {
            return Err(LaneError::InvalidPhase);
        }
        lane.suspensions
            .admit(key, admission_sequence, owner, continuation)
            .map_err(LaneError::Suspension)?;
        lane.external_tokens.pop();
        lane.phase = LanePhase::Suspended;
        self.running = None;
        Ok(())
    }

    pub fn admit_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        continuation: C,
    ) -> Result<(), LaneError> {
        self.validate_running(handle, reply_object)?;
        if self.slots.iter().any(|slot| {
            slot.lane.as_ref().is_some_and(|lane| {
                lane.suspensions.get(key).is_some()
                    || lane.suspensions.frames().iter().any(|frame| {
                        frame.owner.provider_domain == owner.provider_domain
                            && frame.owner.provider_generation == owner.provider_generation
                            && frame.owner.dispatch_id == owner.dispatch_id
                    })
            })
        }) {
            return Err(LaneError::Suspension(SuspensionError::DuplicateIdentity));
        }
        let lane = self.lane_mut(handle)?;
        lane.suspensions
            .admit(key, admission_sequence, owner, continuation)
            .map_err(LaneError::Suspension)?;
        lane.phase = LanePhase::Suspended;
        self.running = None;
        Ok(())
    }

    pub fn rollback_admission(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        key: SuspensionKey,
    ) -> Result<C, LaneError> {
        if self.running.is_some() {
            return Err(LaneError::Busy);
        }
        self.validate(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.phase != LanePhase::Suspended {
            return Err(LaneError::InvalidPhase);
        }
        let continuation = lane
            .suspensions
            .rollback_admission(key)
            .map_err(LaneError::Suspension)?;
        lane.phase = LanePhase::Running;
        self.running = Some(handle);
        Ok(continuation)
    }

    pub fn select(&mut self, key: SuspensionKey, completion: R) -> Result<(), LaneError> {
        let handle = self
            .lane_for_key(key)
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        self.lane_mut(handle)?
            .suspensions
            .select(key, completion)
            .map_err(LaneError::Suspension)
    }

    pub fn cancel(&mut self, key: SuspensionKey, completion: R) -> Result<(), LaneError> {
        let handle = self
            .lane_for_key(key)
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        self.lane_mut(handle)?
            .suspensions
            .cancel(key, completion)
            .map_err(LaneError::Suspension)
    }

    pub fn contains_scope(&self, scope: SuspensionScope) -> bool {
        self.slots.iter().any(|slot| {
            slot.lane
                .as_ref()
                .is_some_and(|lane| lane.suspensions.contains_scope(scope))
        })
    }

    pub fn next_cancellable_in_scope(
        &self,
        scope: SuspensionScope,
    ) -> Option<(LaneHandle, SuspensionKey)> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let lane = slot.lane.as_ref()?;
            lane.suspensions
                .next_cancellable_in_scope(scope)
                .map(|key| {
                    (
                        LaneHandle {
                            index: index as u32,
                            generation: slot.generation,
                        },
                        key,
                    )
                })
        })
    }

    fn lane(&self, handle: LaneHandle) -> Result<&Lane<C, R>, LaneError> {
        if !handle.is_valid() {
            return Err(LaneError::InvalidIdentity);
        }
        let slot = self
            .slots
            .get(handle.index as usize)
            .ok_or(LaneError::NotFound)?;
        if slot.generation != handle.generation {
            return Err(LaneError::StaleGeneration);
        }
        slot.lane.as_ref().ok_or(LaneError::NotFound)
    }

    fn lane_mut(&mut self, handle: LaneHandle) -> Result<&mut Lane<C, R>, LaneError> {
        if !handle.is_valid() {
            return Err(LaneError::InvalidIdentity);
        }
        let slot = self
            .slots
            .get_mut(handle.index as usize)
            .ok_or(LaneError::NotFound)?;
        if slot.generation != handle.generation {
            return Err(LaneError::StaleGeneration);
        }
        slot.lane.as_mut().ok_or(LaneError::NotFound)
    }

    fn validate(&self, handle: LaneHandle, reply_object: u64) -> Result<(), LaneError> {
        if self.lane(handle)?.binding.reply_object != reply_object || reply_object == 0 {
            return Err(LaneError::WrongBinding);
        }
        Ok(())
    }

    fn validate_running(&self, handle: LaneHandle, reply_object: u64) -> Result<(), LaneError> {
        self.validate(handle, reply_object)?;
        if self.running != Some(handle) || self.lane(handle)?.phase != LanePhase::Running {
            return Err(LaneError::InvalidPhase);
        }
        Ok(())
    }

    fn lane_for_key(&self, key: SuspensionKey) -> Option<LaneHandle> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let lane = slot.lane.as_ref()?;
            lane.suspensions.get(key).map(|_| LaneHandle {
                index: index as u32,
                generation: slot.generation,
            })
        })
    }
}

impl<C, R: Clone> ComponentSuspensionLanes<C, R> {
    pub fn next_resumable(&self) -> Option<LaneResume<R>> {
        if self.running.is_some() {
            return None;
        }
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let lane = slot.lane.as_ref()?;
                if lane.phase != LanePhase::Suspended {
                    return None;
                }
                let suspension = lane.suspensions.top_resume()?;
                let sequence = lane.suspensions.top()?.admission_sequence;
                Some((
                    sequence,
                    LaneResume {
                        lane: LaneHandle {
                            index: index as u32,
                            generation: slot.generation,
                        },
                        binding: lane.binding,
                        suspension,
                    },
                ))
            })
            .min_by_key(|(sequence, _)| *sequence)
            .map(|(_, resume)| resume)
    }

    pub fn begin_resume(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        key: SuspensionKey,
    ) -> Result<SuspensionResume<R>, LaneError> {
        if self.running.is_some() {
            return Err(LaneError::Busy);
        }
        self.validate(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.phase != LanePhase::Suspended {
            return Err(LaneError::InvalidPhase);
        }
        let resume = lane
            .suspensions
            .begin_resume(key)
            .map_err(LaneError::Suspension)?;
        lane.phase = LanePhase::Running;
        self.running = Some(handle);
        Ok(resume)
    }

    pub fn rearm_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        completed_key: SuspensionKey,
        next_key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        continuation: C,
    ) -> Result<(), LaneError> {
        self.validate_running(handle, reply_object)?;
        if self.slots.iter().any(|slot| {
            slot.lane
                .as_ref()
                .is_some_and(|lane| lane.suspensions.get(next_key).is_some())
        }) {
            return Err(LaneError::Suspension(SuspensionError::DuplicateIdentity));
        }
        let lane = self.lane_mut(handle)?;
        lane.suspensions
            .rearm(
                completed_key,
                next_key,
                admission_sequence,
                owner,
                continuation,
            )
            .map_err(LaneError::Suspension)?;
        lane.phase = LanePhase::Suspended;
        self.running = None;
        Ok(())
    }

    pub fn complete_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        key: SuspensionKey,
        owner: SuspensionOwner,
    ) -> Result<CompletedSuspension<C, R>, LaneError> {
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        let completed = lane
            .suspensions
            .complete_dispatch(key, owner)
            .map_err(LaneError::Suspension)?;
        lane.phase = if lane.suspensions.is_empty() && lane.external_tokens.is_empty() {
            LanePhase::Idle
        } else {
            LanePhase::Suspended
        };
        self.running = None;
        Ok(completed)
    }

    pub fn complete_running_and_suspend_external(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        key: SuspensionKey,
        owner: SuspensionOwner,
        token: u64,
    ) -> Result<CompletedSuspension<C, R>, LaneError> {
        if token == 0 {
            return Err(LaneError::InvalidIdentity);
        }
        self.validate_running(handle, reply_object)?;
        let max_depth = self.max_depth_per_lane;
        let lane = self.lane_mut(handle)?;
        if lane.external_tokens.len() >= max_depth {
            return Err(LaneError::Suspension(SuspensionError::Overflow));
        }
        lane.external_tokens
            .try_reserve(1)
            .map_err(|_| LaneError::NoCapacity)?;
        let completed = lane
            .suspensions
            .complete_dispatch(key, owner)
            .map_err(LaneError::Suspension)?;
        lane.external_tokens.push(token);
        lane.phase = LanePhase::Suspended;
        self.running = None;
        Ok(completed)
    }

    pub fn abort_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        key: SuspensionKey,
        owner: SuspensionOwner,
        completion: R,
    ) -> Result<CompletedSuspension<C, R>, LaneError> {
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        let completed = lane
            .suspensions
            .abort_resume(key, owner, completion)
            .map_err(LaneError::Suspension)?;
        lane.phase = if lane.suspensions.is_empty() && lane.external_tokens.is_empty() {
            LanePhase::Idle
        } else {
            LanePhase::Suspended
        };
        self.running = None;
        Ok(completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(dispatch_id: u64) -> SuspensionOwner {
        SuspensionOwner {
            provider_domain: 3,
            provider_generation: 7,
            client_pi: 2,
            client_generation: 11,
            client_tid: 24 + dispatch_id,
            client_badge: 4 + dispatch_id,
            dispatch_id,
        }
    }

    #[test]
    fn buried_provider_selection_waits_for_top_lpc() {
        let mut stack = ComponentSuspensionStack::new(4);
        let provider = SuspensionKey::provider_wait(1);
        let lpc = SuspensionKey::lpc_request(2);
        stack.admit(provider, 1, owner(1), "provider").unwrap();
        stack.admit(lpc, 2, owner(2), "lpc").unwrap();
        stack.select(provider, 0u32).unwrap();
        assert_eq!(stack.top_resume(), None);
        stack.select(lpc, 0u32).unwrap();
        stack.begin_resume(lpc).unwrap();
        stack.complete_dispatch(lpc, owner(2)).unwrap();
        assert_eq!(stack.top_resume().unwrap().key, provider);
    }

    #[test]
    fn buried_lpc_selection_waits_for_top_provider() {
        let mut stack = ComponentSuspensionStack::new(4);
        let lpc = SuspensionKey::lpc_request(1);
        let provider = SuspensionKey::provider_wait(2);
        stack.admit(lpc, 1, owner(1), "lpc").unwrap();
        stack.admit(provider, 2, owner(2), "provider").unwrap();
        stack.select(lpc, 7u32).unwrap();
        assert_eq!(stack.top_resume(), None);
        stack.select(provider, 8u32).unwrap();
        stack.begin_resume(provider).unwrap();
        stack.complete_dispatch(provider, owner(2)).unwrap();
        assert_eq!(stack.top_resume().unwrap().completion, 7);
    }

    #[test]
    fn same_dispatch_rearms_across_kinds_without_growing() {
        let mut stack = ComponentSuspensionStack::new(2);
        let first = SuspensionKey::lpc_request(1);
        let second = SuspensionKey::provider_wait(2);
        stack.admit(first, 1, owner(1), 10u64).unwrap();
        stack.select(first, 0u32).unwrap();
        stack.begin_resume(first).unwrap();
        stack.rearm(first, second, 2, owner(1), 11).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.top().unwrap().continuation, 11);
        assert!(matches!(
            stack.top().unwrap().phase,
            SuspensionPhase::Waiting
        ));
    }

    #[test]
    fn duplicate_key_or_dispatch_owner_is_rejected() {
        let mut stack = ComponentSuspensionStack::<u64, u32>::new(4);
        let key = SuspensionKey::provider_wait(1);
        stack.admit(key, 1, owner(1), 1).unwrap();
        assert_eq!(
            stack.admit(key, 2, owner(2), 2),
            Err(SuspensionError::DuplicateIdentity)
        );
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(2), 2, owner(1), 2),
            Err(SuspensionError::DuplicateIdentity)
        );
    }

    #[test]
    fn select_cancel_and_resume_are_exactly_once() {
        let mut stack = ComponentSuspensionStack::new(2);
        let key = SuspensionKey::lpc_request(1);
        stack.admit(key, 1, owner(1), 9u64).unwrap();
        stack.select(key, 5u32).unwrap();
        assert_eq!(stack.select(key, 5), Err(SuspensionError::InvalidPhase));
        stack.cancel(key, 6).unwrap();
        let resume = stack.begin_resume(key).unwrap();
        assert!(resume.cancelled);
        assert_eq!(resume.completion, 6);
        assert_eq!(stack.begin_resume(key), Err(SuspensionError::InvalidPhase));
        assert_eq!(
            stack.complete_dispatch(key, owner(1)).unwrap().continuation,
            9
        );
        assert!(stack.is_empty());
    }

    #[test]
    fn wrong_owner_cannot_complete_or_rearm() {
        let mut stack = ComponentSuspensionStack::new(2);
        let key = SuspensionKey::provider_wait(1);
        stack.admit(key, 1, owner(1), 1u64).unwrap();
        stack.select(key, 0u32).unwrap();
        stack.begin_resume(key).unwrap();
        assert_eq!(
            stack.complete_dispatch(key, owner(2)),
            Err(SuspensionError::InvalidIdentity)
        );
        assert_eq!(
            stack.rearm(key, SuspensionKey::lpc_request(2), 2, owner(2), 2),
            Err(SuspensionError::InvalidPhase)
        );
    }

    #[test]
    fn buried_cancellation_preserves_lifo_order() {
        let mut stack = ComponentSuspensionStack::new(3);
        let outer = SuspensionKey::provider_wait(1);
        let inner = SuspensionKey::lpc_request(2);
        stack.admit(outer, 1, owner(1), 1u64).unwrap();
        stack.admit(inner, 2, owner(2), 2u64).unwrap();
        stack.cancel(outer, 0xC000_0120u32).unwrap();
        assert_eq!(stack.top_resume(), None);
        stack.select(inner, 0).unwrap();
        stack.begin_resume(inner).unwrap();
        stack.complete_dispatch(inner, owner(2)).unwrap();
        assert!(stack.top_resume().unwrap().cancelled);
    }

    #[test]
    fn teardown_scope_is_generation_exact() {
        let mut stack = ComponentSuspensionStack::<u64, u32>::new(4);
        let key = SuspensionKey::provider_wait(1);
        stack.admit(key, 1, owner(1), 1).unwrap();
        assert!(!stack.contains_scope(SuspensionScope::Process {
            domain: 3,
            provider_generation: 7,
            client_pi: 2,
            client_generation: 10,
        }));
        assert_eq!(
            stack.next_cancellable_in_scope(SuspensionScope::Thread {
                domain: 3,
                provider_generation: 7,
                client_pi: 2,
                client_generation: 11,
                client_tid: 25,
                client_badge: 5,
            }),
            Some(key)
        );
    }

    #[test]
    fn overflow_and_rollback_preserve_owned_state() {
        let mut stack = ComponentSuspensionStack::<u64, u32>::new(1);
        let key = SuspensionKey::provider_wait(1);
        stack.admit(key, 1, owner(1), 77).unwrap();
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(2), 2, owner(2), 88),
            Err(SuspensionError::Overflow)
        );
        assert_eq!(stack.rollback_admission(key).unwrap(), 77);
        assert!(stack.is_empty());
    }

    #[test]
    fn invalid_identity_fails_closed() {
        let mut stack = ComponentSuspensionStack::<u64, u32>::new(2);
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(0), 1, owner(1), 1),
            Err(SuspensionError::InvalidIdentity)
        );
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(1), 0, owner(1), 1),
            Err(SuspensionError::InvalidIdentity)
        );
        let mut invalid = owner(1);
        invalid.provider_generation = 0;
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(1), 1, invalid, 1),
            Err(SuspensionError::InvalidIdentity)
        );
    }

    fn binding(id: u64) -> LaneBinding {
        LaneBinding {
            executor_id: 0x100 + id,
            receive_endpoint: 0x200 + id,
            reply_object: 0x300 + id,
        }
    }

    #[test]
    fn selected_lane_resumes_past_an_unrelated_permanent_waiter() {
        let mut lanes = ComponentSuspensionLanes::new(4, 4);
        let winlogon = lanes.allocate(binding(1)).unwrap();
        let desktop = lanes.allocate(binding(2)).unwrap();
        let lpc = SuspensionKey::lpc_request(1);
        let provider = SuspensionKey::provider_wait(2);

        lanes
            .begin_dispatch(winlogon, binding(1).reply_object)
            .unwrap();
        lanes
            .admit_running(winlogon, binding(1).reply_object, lpc, 1, owner(1), 10u64)
            .unwrap();
        lanes
            .begin_dispatch(desktop, binding(2).reply_object)
            .unwrap();
        lanes
            .admit_running(desktop, binding(2).reply_object, provider, 2, owner(2), 20)
            .unwrap();

        lanes.select(lpc, 0u32).unwrap();
        assert_eq!(lanes.total_suspensions(), 2);
        assert_eq!(lanes.locate(lpc).map(|(lane, _)| lane), Some(winlogon));
        assert_eq!(lanes.frames().count(), 2);
        let ready = lanes.next_resumable().unwrap();
        assert_eq!(ready.lane, winlogon);
        assert_eq!(ready.suspension.key, lpc);
        lanes
            .begin_resume(winlogon, binding(1).reply_object, lpc)
            .unwrap();
        assert_eq!(
            lanes
                .complete_running(winlogon, binding(1).reply_object, lpc, owner(1))
                .unwrap()
                .continuation,
            10
        );
        assert_eq!(lanes.phase(winlogon), Ok(LanePhase::Idle));
        assert_eq!(lanes.phase(desktop), Ok(LanePhase::Suspended));
        assert_eq!(lanes.suspension_count(desktop), Ok(1));
    }

    #[test]
    fn reparked_lane_does_not_mask_a_selected_sibling() {
        let mut lanes = ComponentSuspensionLanes::new(3, 3);
        let first = lanes.allocate(binding(1)).unwrap();
        let sibling = lanes.allocate(binding(2)).unwrap();
        let first_wait = SuspensionKey::lpc_request(1);
        let sibling_wait = SuspensionKey::provider_wait(2);
        let rearmed_wait = SuspensionKey::lpc_request(3);

        lanes.begin_dispatch(first, binding(1).reply_object).unwrap();
        lanes
            .admit_running(first, binding(1).reply_object, first_wait, 1, owner(1), 10u64)
            .unwrap();
        lanes
            .begin_dispatch(sibling, binding(2).reply_object)
            .unwrap();
        lanes
            .admit_running(
                sibling,
                binding(2).reply_object,
                sibling_wait,
                2,
                owner(2),
                20,
            )
            .unwrap();
        lanes.select(first_wait, 7u32).unwrap();
        lanes.select(sibling_wait, 8u32).unwrap();

        let first_resume = lanes.next_resumable().unwrap();
        assert_eq!(first_resume.lane, first);
        lanes
            .begin_resume(first, binding(1).reply_object, first_wait)
            .unwrap();
        lanes
            .rearm_running(
                first,
                binding(1).reply_object,
                first_wait,
                rearmed_wait,
                3,
                owner(1),
                30,
            )
            .unwrap();

        assert_eq!(lanes.phase(first), Ok(LanePhase::Suspended));
        assert_eq!(lanes.top(first).unwrap().unwrap().key, rearmed_wait);
        let sibling_resume = lanes.next_resumable().unwrap();
        assert_eq!(sibling_resume.lane, sibling);
        assert_eq!(sibling_resume.suspension.key, sibling_wait);
    }

    #[test]
    fn selected_outer_frame_still_waits_for_its_same_lane_top() {
        let mut lanes = ComponentSuspensionLanes::new(2, 4);
        let lane = lanes.allocate(binding(1)).unwrap();
        let outer = SuspensionKey::lpc_request(1);
        let inner = SuspensionKey::provider_wait(2);

        lanes.begin_dispatch(lane, binding(1).reply_object).unwrap();
        lanes
            .admit_running(lane, binding(1).reply_object, outer, 1, owner(1), 10u64)
            .unwrap();
        lanes.select(outer, 7u32).unwrap();
        lanes
            .begin_resume(lane, binding(1).reply_object, outer)
            .unwrap();
        lanes
            .admit_running(lane, binding(1).reply_object, inner, 2, owner(2), 20)
            .unwrap();

        assert_eq!(lanes.next_resumable(), None);
        lanes.select(inner, 8).unwrap();
        assert_eq!(lanes.next_resumable().unwrap().suspension.key, inner);
    }

    #[test]
    fn running_token_serializes_shared_component_state() {
        let mut lanes = ComponentSuspensionLanes::<u64, u32>::new(2, 2);
        let first = lanes.allocate(binding(1)).unwrap();
        let second = lanes.allocate(binding(2)).unwrap();
        lanes
            .begin_dispatch(first, binding(1).reply_object)
            .unwrap();
        assert_eq!(
            lanes.begin_dispatch(second, binding(2).reply_object),
            Err(LaneError::Busy)
        );
        lanes
            .finish_dispatch(first, binding(1).reply_object)
            .unwrap();
        lanes
            .begin_dispatch(second, binding(2).reply_object)
            .unwrap();
        assert_eq!(lanes.running(), Some(second));
    }

    #[test]
    fn physical_growth_is_requested_only_when_all_existing_lanes_are_retained() {
        let mut lanes = ComponentSuspensionLanes::<u64, u32>::new(3, 2);
        let first = lanes.allocate(binding(1)).unwrap();
        let second = lanes.allocate(binding(2)).unwrap();
        assert!(!lanes.needs_idle_lane());

        lanes.begin_dispatch(first, binding(1).reply_object).unwrap();
        assert!(!lanes.needs_idle_lane());
        lanes
            .admit_running(
                first,
                binding(1).reply_object,
                SuspensionKey::lpc_request(1),
                1,
                owner(1),
                10u64,
            )
            .unwrap();
        assert!(!lanes.needs_idle_lane());
        lanes.begin_dispatch(second, binding(2).reply_object).unwrap();
        lanes
            .admit_running(
                second,
                binding(2).reply_object,
                SuspensionKey::provider_wait(2),
                2,
                owner(2),
                20,
            )
            .unwrap();
        assert!(lanes.needs_idle_lane());

        lanes.allocate(binding(3)).unwrap();
        assert!(!lanes.needs_idle_lane());
    }

    #[test]
    fn external_callback_parking_hands_the_token_to_an_idle_lane() {
        let mut lanes = ComponentSuspensionLanes::<u64, u32>::new(2, 3);
        let first = lanes.allocate(binding(1)).unwrap();
        let second = lanes.allocate(binding(2)).unwrap();
        assert_eq!(lanes.next_idle().map(|(lane, _)| lane), Some(first));
        lanes
            .begin_dispatch(first, binding(1).reply_object)
            .unwrap();
        assert_eq!(lanes.next_idle(), None);
        assert_eq!(
            lanes.suspend_running(first, binding(1).reply_object, 0),
            Err(LaneError::InvalidIdentity)
        );
        lanes
            .suspend_running(first, binding(1).reply_object, 0xA)
            .unwrap();
        assert_eq!(lanes.external_depth(first), Ok(1));
        assert_eq!(lanes.external_top(first), Ok(Some(0xA)));
        assert_eq!(lanes.next_idle().map(|(lane, _)| lane), Some(second));
        lanes
            .begin_dispatch(second, binding(2).reply_object)
            .unwrap();
        lanes
            .finish_dispatch(second, binding(2).reply_object)
            .unwrap();
        assert_eq!(
            lanes.resume_external(first, binding(1).reply_object, 0xB),
            Err(LaneError::InvalidPhase)
        );
        lanes
            .resume_external(first, binding(1).reply_object, 0xA)
            .unwrap();
        lanes
            .suspend_running(first, binding(1).reply_object, 0xB)
            .unwrap();
        assert_eq!(lanes.external_depth(first), Ok(2));
        assert_eq!(
            lanes.resume_external(first, binding(1).reply_object, 0xA),
            Err(LaneError::InvalidPhase)
        );
        lanes
            .resume_external(first, binding(1).reply_object, 0xB)
            .unwrap();
        lanes
            .complete_external(first, binding(1).reply_object, 0xB)
            .unwrap();
        assert_eq!(lanes.phase(first), Ok(LanePhase::Suspended));
        assert_eq!(lanes.external_top(first), Ok(Some(0xA)));
        lanes
            .resume_external(first, binding(1).reply_object, 0xA)
            .unwrap();
        lanes
            .repark_external(first, binding(1).reply_object, 0xA)
            .unwrap();
        lanes
            .resume_external(first, binding(1).reply_object, 0xA)
            .unwrap();
        lanes
            .complete_external(first, binding(1).reply_object, 0xA)
            .unwrap();
        assert_eq!(lanes.phase(first), Ok(LanePhase::Idle));
    }

    #[test]
    fn component_completion_preserves_an_outer_callback_suspension() {
        let mut lanes = ComponentSuspensionLanes::new(1, 3);
        let lane = lanes.allocate(binding(1)).unwrap();
        let outer = SuspensionKey::provider_wait(1);

        lanes.begin_dispatch(lane, binding(1).reply_object).unwrap();
        lanes
            .admit_running(lane, binding(1).reply_object, outer, 1, owner(1), 10u64)
            .unwrap();
        lanes.select(outer, 7u32).unwrap();
        lanes
            .begin_resume(lane, binding(1).reply_object, outer)
            .unwrap();
        lanes
            .suspend_running(lane, binding(1).reply_object, 0xCA11_BACC)
            .unwrap();
        assert_eq!(lanes.suspension_count(lane), Ok(1));
        assert_eq!(lanes.external_depth(lane), Ok(1));

        lanes
            .resume_external(lane, binding(1).reply_object, 0xCA11_BACC)
            .unwrap();
        assert_eq!(
            lanes
                .complete_running_and_suspend_external(
                    lane,
                    binding(1).reply_object,
                    outer,
                    owner(1),
                    0xBEEF,
                )
                .unwrap()
                .continuation,
            10
        );
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
        assert_eq!(lanes.external_top(lane), Ok(Some(0xBEEF)));
        assert_eq!(lanes.next_idle(), None);

        lanes
            .resume_external(lane, binding(1).reply_object, 0xBEEF)
            .unwrap();
        lanes
            .replace_external_running(lane, binding(1).reply_object, 0xBEEF, 0xF00D)
            .unwrap();
        lanes
            .resume_external(lane, binding(1).reply_object, 0xF00D)
            .unwrap();
        lanes
            .complete_external(lane, binding(1).reply_object, 0xF00D)
            .unwrap();
        assert_eq!(lanes.external_top(lane), Ok(Some(0xCA11_BACC)));
        lanes
            .resume_external(lane, binding(1).reply_object, 0xCA11_BACC)
            .unwrap();
        lanes
            .retire_external_running(lane, binding(1).reply_object, 0xCA11_BACC)
            .unwrap();
        lanes
            .finish_dispatch(lane, binding(1).reply_object)
            .unwrap();
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    }

    #[test]
    fn callback_return_transfers_directly_to_a_provider_wait() {
        let mut lanes = ComponentSuspensionLanes::new(1, 3);
        let lane = lanes.allocate(binding(1)).unwrap();
        let wait = SuspensionKey::provider_wait(0x77);

        lanes.begin_dispatch(lane, binding(1).reply_object).unwrap();
        lanes
            .suspend_running(lane, binding(1).reply_object, 0xCA11_BACC)
            .unwrap();
        lanes
            .resume_external(lane, binding(1).reply_object, 0xCA11_BACC)
            .unwrap();
        lanes
            .transfer_external_to_suspension_running(
                lane,
                binding(1).reply_object,
                0xCA11_BACC,
                wait,
                1,
                owner(1),
                42u64,
            )
            .unwrap();

        assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
        assert_eq!(lanes.external_depth(lane), Ok(0));
        assert_eq!(lanes.suspension_count(lane), Ok(1));
        assert_eq!(lanes.next_idle(), None);
        lanes.select(wait, 7u32).unwrap();
        lanes
            .begin_resume(lane, binding(1).reply_object, wait)
            .unwrap();
        let completed = lanes
            .complete_running(lane, binding(1).reply_object, wait, owner(1))
            .unwrap();
        assert_eq!(completed.continuation, 42);
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    }

    #[test]
    fn wrong_reply_object_and_stale_generation_fail_closed() {
        let mut lanes = ComponentSuspensionLanes::<u64, u32>::new(1, 2);
        let first = lanes.allocate(binding(1)).unwrap();
        assert_eq!(
            lanes.begin_dispatch(first, binding(2).reply_object),
            Err(LaneError::WrongBinding)
        );
        lanes
            .begin_dispatch(first, binding(1).reply_object)
            .unwrap();
        lanes
            .finish_dispatch(first, binding(1).reply_object)
            .unwrap();
        lanes.release(first, binding(1).reply_object).unwrap();

        let second = lanes.allocate(binding(2)).unwrap();
        assert_eq!(second.index, first.index);
        assert_ne!(second.generation, first.generation);
        assert_eq!(lanes.binding(first), Err(LaneError::StaleGeneration));
    }

    #[test]
    fn duplicate_bindings_keys_and_capacity_are_rejected() {
        let mut lanes = ComponentSuspensionLanes::<u64, u32>::new(2, 2);
        let first = lanes.allocate(binding(1)).unwrap();
        let mut duplicate = binding(2);
        duplicate.reply_object = binding(1).reply_object;
        assert_eq!(lanes.allocate(duplicate), Err(LaneError::DuplicateBinding));
        let second = lanes.allocate(binding(2)).unwrap();
        assert_eq!(lanes.allocate(binding(3)), Err(LaneError::NoCapacity));

        let key = SuspensionKey::lpc_request(1);
        lanes
            .begin_dispatch(first, binding(1).reply_object)
            .unwrap();
        lanes
            .admit_running(first, binding(1).reply_object, key, 1, owner(1), 10u64)
            .unwrap();
        lanes
            .begin_dispatch(second, binding(2).reply_object)
            .unwrap();
        assert_eq!(
            lanes.admit_running(second, binding(2).reply_object, key, 2, owner(2), 20),
            Err(LaneError::Suspension(SuspensionError::DuplicateIdentity))
        );
        assert_eq!(
            lanes.admit_running(
                second,
                binding(2).reply_object,
                SuspensionKey::provider_wait(2),
                2,
                owner(1),
                20,
            ),
            Err(LaneError::Suspension(SuspensionError::DuplicateIdentity))
        );
    }

    #[test]
    fn rearm_and_scope_teardown_remain_lane_exact() {
        let mut lanes = ComponentSuspensionLanes::new(2, 2);
        let lane = lanes.allocate(binding(1)).unwrap();
        let lpc = SuspensionKey::lpc_request(1);
        let provider = SuspensionKey::provider_wait(2);
        lanes.begin_dispatch(lane, binding(1).reply_object).unwrap();
        lanes
            .admit_running(lane, binding(1).reply_object, lpc, 1, owner(1), 10u64)
            .unwrap();
        lanes.select(lpc, 0u32).unwrap();
        lanes
            .begin_resume(lane, binding(1).reply_object, lpc)
            .unwrap();
        lanes
            .rearm_running(
                lane,
                binding(1).reply_object,
                lpc,
                provider,
                2,
                owner(1),
                11,
            )
            .unwrap();

        let scope = SuspensionScope::Thread {
            domain: 3,
            provider_generation: 7,
            client_pi: 2,
            client_generation: 11,
            client_tid: 25,
            client_badge: 5,
        };
        assert!(lanes.contains_scope(scope));
        assert_eq!(
            lanes.next_cancellable_in_scope(scope),
            Some((lane, provider))
        );
        lanes.cancel(provider, 0xC000_0120).unwrap();
        assert!(lanes.next_resumable().unwrap().suspension.cancelled);
    }

    #[test]
    fn lane_address_layout_resolves_only_owned_stack_ranges() {
        let layout = LaneAddressLayout {
            base: 0x1000_0000,
            stride: 0x40_000,
            stack_bytes: 0x20_000,
            ipc_buffer_offset: 0x20_000,
            capacity: 3,
        };
        assert!(layout.is_valid());
        assert_eq!(
            layout.ipc_buffer_for_stack_pointer(0x1000_0000),
            Some(0x1002_0000)
        );
        assert_eq!(
            layout.ipc_buffer_for_stack_pointer(0x1004_1234),
            Some(0x1006_0000)
        );
        assert_eq!(layout.ipc_buffer_for_stack_pointer(0x1002_0000), None);
        assert_eq!(layout.ipc_buffer_for_stack_pointer(0x100c_0000), None);
        assert_eq!(layout.ipc_buffer_for_stack_pointer(0x0fff_ffff), None);
    }
}
