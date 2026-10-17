//! Checked authority for a component-owned, physically contiguous RAM run.
//!
//! Native cap retype, physical-address queries and maps are effects performed by the executive.
//! This receipt prevents publication before every frame and mapping has been proved. An uncertain
//! effect remains retained: its caps and virtual aperture cannot be recycled by this contract.

const PAGE: u64 = 4096;
const RETYPE_FAN_OUT: u64 = 256;
const MAX_CHILD_BYTES: u64 = 64 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContiguousRamLayout {
    base: u64,
    frames: u64,
    child_bytes: u64,
}

impl ContiguousRamLayout {
    /// Smallest independently owned Untyped capable of holding the rounded frame run.
    pub fn minimum_child_bytes(bytes: u64) -> Option<u64> {
        let rounded = bytes.checked_add(PAGE - 1)? & !(PAGE - 1);
        if rounded == 0 || rounded > MAX_CHILD_BYTES { return None; }
        Some(rounded.checked_next_power_of_two()?.max(PAGE))
    }

    /// `child_bytes` is an independently retained child Untyped, not component pool capacity.
    pub fn for_request(bytes: u64, base: u64, child_bytes: u64) -> Option<Self> {
        if base & (PAGE - 1) != 0 || child_bytes < PAGE || child_bytes > MAX_CHILD_BYTES
            || !child_bytes.is_power_of_two() || child_bytes < Self::minimum_child_bytes(bytes)?
        { return None; }
        let frames = bytes.checked_add(PAGE - 1)? / PAGE;
        let rounded = frames.checked_mul(PAGE)?;
        if rounded > child_bytes || base.checked_add(rounded).is_none() { return None; }
        Some(Self { base, frames, child_bytes })
    }

    pub const fn base(self) -> u64 { self.base }
    pub const fn frames(self) -> u64 { self.frames }
    pub const fn child_bytes(self) -> u64 { self.child_bytes }
    pub fn end(self) -> u64 { self.base + self.frames * PAGE }
    pub fn batch_count(self) -> u64 { self.frames.div_ceil(RETYPE_FAN_OUT) }
    pub fn batch(self, index: u64) -> Option<(u64, u32)> {
        let start = index.checked_mul(RETYPE_FAN_OUT)?;
        (start < self.frames).then(|| (start, (self.frames - start).min(RETYPE_FAN_OUT) as u32))
    }

    /// Reject any address range occupied by the component's code, pool, stack, worker lanes,
    /// executive instance windows, or another retained contiguous run.
    pub fn avoids(self, occupied: &[(u64, u64)]) -> bool {
        occupied.iter().all(|&(start, end)|
            start <= end && (self.end() <= start || self.base >= end))
    }
}

/// A proved, published physical run in one provider VSpace. The executive constructs this only
/// after frame identity and mapping publication; numeric addresses alone cannot grant access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContiguousRamPublishedMapping {
    owner: ContiguousRamOwner,
    virtual_start: u64,
    physical_start: u64,
    length: u64,
    cache: u32,
}

impl ContiguousRamPublishedMapping {
    pub fn new(owner: ContiguousRamOwner, virtual_start: u64, physical_start: u64,
        length: u64, cache: u32) -> Option<Self> {
        if owner.generation == 0 || owner.domain == 0 || length == 0
            || virtual_start & (PAGE - 1) != 0 || physical_start & (PAGE - 1) != 0
            || virtual_start.checked_add(length).is_none()
            || physical_start.checked_add(length).is_none() { return None; }
        Some(Self { owner, virtual_start, physical_start, length, cache })
    }

    pub fn physical_address(self, owner: ContiguousRamOwner, address: u64) -> Option<u64> {
        if owner != self.owner { return None; }
        let offset = address.checked_sub(self.virtual_start)?;
        (offset < self.length).then(|| self.physical_start + offset)
    }

    pub fn contains_physical(self, owner: ContiguousRamOwner, physical: u64,
        length: u64, cache: u32) -> bool {
        owner == self.owner && cache == self.cache && length != 0
            && physical.checked_sub(self.physical_start)
                .and_then(|offset| offset.checked_add(length))
                .is_some_and(|end| end <= self.length)
    }

    pub fn virtual_address(self, owner: ContiguousRamOwner, physical: u64,
        length: u64, cache: u32) -> Option<u64> {
        if !self.contains_physical(owner, physical, length, cache) { return None; }
        Some(self.virtual_start + (physical - self.physical_start))
    }
}

/// A separate page-table projection of a provider's owned frames into a registered consumer.
/// Native code retains every copied frame cap until this projection has been torn down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContiguousRamProjectedMapping {
    producer: ContiguousRamOwner,
    consumer: ContiguousRamOwner,
    virtual_start: u64,
    physical_start: u64,
    length: u64,
    cache: u32,
    live: bool,
}

impl ContiguousRamProjectedMapping {
    pub fn new(source: ContiguousRamPublishedMapping, producer: ContiguousRamOwner,
        consumer: ContiguousRamOwner, virtual_start: u64, physical_start: u64,
        length: u64, cache: u32) -> Option<Self> {
        if producer == consumer || consumer.generation == 0 || consumer.domain == 0
            || (virtual_start & (PAGE - 1)) != (physical_start & (PAGE - 1))
            || virtual_start.checked_add(length).is_none()
            || !source.contains_physical(producer, physical_start, length, cache) {
            return None;
        }
        Some(Self { producer, consumer, virtual_start, physical_start, length, cache, live: true })
    }

    pub fn virtual_address(self, consumer: ContiguousRamOwner, physical: u64,
        length: u64, cache: u32) -> Option<u64> {
        if !self.live || consumer != self.consumer || cache != self.cache || length == 0 {
            return None;
        }
        let offset = physical.checked_sub(self.physical_start)?;
        (offset.checked_add(length)? <= self.length).then(|| self.virtual_start + offset)
    }

    pub fn retire(&mut self, consumer: ContiguousRamOwner) -> Result<(), ContiguousRamError> {
        if consumer != self.consumer { return Err(ContiguousRamError::WrongOwner); }
        self.live = false;
        Ok(())
    }

    /// A caller's MmUnmapIoSpace releases only the exact projection returned for that MAP.
    pub fn retire_exact(&mut self, consumer: ContiguousRamOwner, virtual_start: u64,
        length: u64) -> Result<(), ContiguousRamError> {
        if consumer != self.consumer { return Err(ContiguousRamError::WrongOwner); }
        if !self.live || virtual_start != self.virtual_start || length != self.length {
            return Err(ContiguousRamError::Unproved);
        }
        self.live = false;
        Ok(())
    }

    pub fn producer(self) -> ContiguousRamOwner { self.producer }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContiguousRamOwner {
    pub instance: usize,
    pub generation: u64,
    pub domain: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContiguousRamError {
    WrongOwner,
    WrongFrame,
    WrongCap,
    WrongPhysicalRun,
    OutsideNtRange,
    Unproved,
    UncertainEffect,
    NoTicket,
    NoCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContiguousRamRequest {
    pub length: u64,
    pub low: u64,
    pub high: u64,
    pub boundary: u64,
    pub cache: u32,
}

#[derive(Clone, Copy)]
struct Pending {
    owner: ContiguousRamOwner,
    caller_badge: u64,
    token: u64,
    length: u64,
    low: u64,
    high: u64,
}

/// PREPARE stores only request metadata. COMMIT removes it before native effects, so a lost
/// reply can never cause an allocation replay. Old tickets cannot become live after expiry.
pub struct ContiguousRamPrepareTable {
    next_token: u64,
    pending: [Option<Pending>; 16],
}

impl Default for ContiguousRamPrepareTable {
    fn default() -> Self { Self::new() }
}

impl ContiguousRamPrepareTable {
    pub const fn new() -> Self { Self { next_token: 0, pending: [None; 16] } }

    pub fn prepare(&mut self, owner: ContiguousRamOwner, caller_badge: u64,
        length: u64, low: u64, high: u64) -> Result<u64, ContiguousRamError> {
        if owner.generation == 0 || owner.domain == 0 || caller_badge == 0
            || length == 0 || low > high || length.checked_add(PAGE - 1).is_none() {
            return Err(ContiguousRamError::Unproved);
        }
        // One live request per exact caller; replacement expires its previous ticket without
        // touching native resources. Different callers may prepare concurrently.
        let index = self.pending.iter().position(|slot| slot.is_some_and(|row|
            row.owner == owner && row.caller_badge == caller_badge))
            .or_else(|| self.pending.iter().position(Option::is_none))
            .ok_or(ContiguousRamError::NoCapacity)?;
        let token = self.next_token.checked_add(1).ok_or(ContiguousRamError::NoCapacity)?;
        self.next_token = token;
        self.pending[index] = Some(Pending { owner, caller_badge, token, length, low, high });
        Ok(token)
    }

    pub fn expire(&mut self, owner: ContiguousRamOwner, caller_badge: u64, token: u64)
        -> Result<(), ContiguousRamError> {
        let index = self.find(owner, caller_badge, token)?;
        self.pending[index] = None;
        Ok(())
    }

    pub fn retire_owner(&mut self, owner: ContiguousRamOwner) {
        for slot in &mut self.pending {
            if slot.is_some_and(|row| row.owner == owner) { *slot = None; }
        }
    }

    pub fn commit(&mut self, owner: ContiguousRamOwner, caller_badge: u64, token: u64,
        boundary: u64, cache: u32) -> Result<ContiguousRamRequest, ContiguousRamError> {
        let index = self.find(owner, caller_badge, token)?;
        // Consume even invalid COMMIT arguments: caller must PREPARE a fresh ticket.
        let pending = self.pending[index].take().ok_or(ContiguousRamError::NoTicket)?;
        if boundary != 0 && (!boundary.is_power_of_two() || boundary < PAGE) {
            return Err(ContiguousRamError::OutsideNtRange);
        }
        Ok(ContiguousRamRequest {
            length: pending.length, low: pending.low, high: pending.high, boundary, cache,
        })
    }

    fn find(&self, owner: ContiguousRamOwner, caller_badge: u64, token: u64)
        -> Result<usize, ContiguousRamError> {
        self.pending.iter().position(|slot| slot.is_some_and(|row|
            row.owner == owner && row.caller_badge == caller_badge && row.token == token))
            .ok_or(ContiguousRamError::NoTicket)
    }
}

/// Resource identity supplied by the executive after a fresh reservation, or retained from a
/// confirmed clean prior allocation. A child and its empty CSpace slots are reusable only at
/// their exact frame capacity. Mapped pages or an uncertain native effect are never handed to
/// another generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContiguousRamLeaseSource {
    Fresh,
    SlotsOnly { cap_base: u64, capacity_frames: u64 },
    Reuse { child: u64, cap_base: u64, capacity_frames: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContiguousRamLease {
    pub slot: usize,
    pub source: ContiguousRamLeaseSource,
}

#[derive(Clone, Copy)]
enum LeaseState {
    Empty,
    Active { owner: ContiguousRamOwner, source: ContiguousRamLeaseSource,
        requested_frames: u64 },
    Available { child: u64, cap_base: u64, capacity_frames: u64 },
    Quarantined,
}

/// At most eight owned child Untypeds and root CSpace runs exist, regardless of the number of
/// definite failures or provider-generation changes. Native cleanup confirms a lease is empty
/// before calling `confirm_clean`; only then may another generation reserve it.
pub struct ContiguousRamLeaseBank { slots: [LeaseState; 8] }

impl Default for ContiguousRamLeaseBank {
    fn default() -> Self { Self::new() }
}

impl ContiguousRamLeaseBank {
    pub const fn new() -> Self { Self { slots: [LeaseState::Empty; 8] } }

    pub fn reserve(&mut self, owner: ContiguousRamOwner, capacity_frames: u64)
        -> Result<ContiguousRamLease, ContiguousRamError> {
        if owner.generation == 0 || owner.domain == 0 { return Err(ContiguousRamError::WrongOwner); }
        if capacity_frames == 0 || capacity_frames > MAX_CHILD_BYTES / PAGE
            || !capacity_frames.is_power_of_two() { return Err(ContiguousRamError::Unproved); }
        // Consume reusable resources before carving another child from the boot Untyped.
        let index = self.slots.iter().position(|state| matches!(state,
            LeaseState::Available { child, cap_base, capacity_frames: available }
                if *child != 0 && *cap_base != 0 && *available == capacity_frames))
            .or_else(|| self.slots.iter().position(|state| matches!(state,
                LeaseState::Available { child: 0, cap_base, capacity_frames: available }
                    if *cap_base != 0 && *available == capacity_frames)))
            .or_else(|| self.slots.iter().position(|state| matches!(state, LeaseState::Empty)))
            .ok_or(ContiguousRamError::NoCapacity)?;
        let source = match self.slots[index] {
            LeaseState::Available { child, cap_base, capacity_frames }
                if child != 0 && cap_base != 0 =>
                ContiguousRamLeaseSource::Reuse { child, cap_base, capacity_frames },
            LeaseState::Available { child: 0, cap_base, capacity_frames } if cap_base != 0 =>
                ContiguousRamLeaseSource::SlotsOnly { cap_base, capacity_frames },
            _ => ContiguousRamLeaseSource::Fresh,
        };
        self.slots[index] = LeaseState::Active { owner, source,
            requested_frames: capacity_frames };
        Ok(ContiguousRamLease { slot: index, source })
    }

    pub fn attach_resources(&mut self, owner: ContiguousRamOwner, slot: usize,
        child: u64, cap_base: u64, capacity_frames: u64) -> Result<(), ContiguousRamError> {
        if child == 0 || cap_base == 0 || capacity_frames == 0
            || capacity_frames > MAX_CHILD_BYTES / PAGE || !capacity_frames.is_power_of_two() {
            return Err(ContiguousRamError::Unproved);
        }
        match self.slots.get(slot).copied() {
            Some(LeaseState::Active { owner: exact, source, requested_frames }) if exact == owner
                && requested_frames == capacity_frames
                && (source == ContiguousRamLeaseSource::Fresh || source
                    == ContiguousRamLeaseSource::SlotsOnly { cap_base, capacity_frames }) => {
                self.slots[slot] = LeaseState::Active { owner,
                    source: ContiguousRamLeaseSource::Reuse { child, cap_base, capacity_frames },
                    requested_frames };
                Ok(())
            }
            _ => Err(ContiguousRamError::WrongOwner),
        }
    }

    /// Retain a contiguous root CSpace run even when carving a child Untyped fails with a
    /// confirmed no-effect label. Future attempts reuse these exact empty slots.
    pub fn attach_frame_slots(&mut self, owner: ContiguousRamOwner, slot: usize,
        cap_base: u64, capacity_frames: u64) -> Result<(), ContiguousRamError> {
        if cap_base == 0 || capacity_frames == 0 || capacity_frames > MAX_CHILD_BYTES / PAGE
            || !capacity_frames.is_power_of_two() {
            return Err(ContiguousRamError::Unproved);
        }
        match self.slots.get(slot).copied() {
            Some(LeaseState::Active { owner: exact,
                source: ContiguousRamLeaseSource::Fresh, requested_frames })
                if exact == owner && requested_frames == capacity_frames => {
                self.slots[slot] = LeaseState::Active { owner,
                    source: ContiguousRamLeaseSource::SlotsOnly { cap_base, capacity_frames },
                    requested_frames };
                Ok(())
            }
            _ => Err(ContiguousRamError::WrongOwner),
        }
    }

    pub fn confirm_clean(&mut self, owner: ContiguousRamOwner, slot: usize)
        -> Result<(), ContiguousRamError> {
        match self.slots.get(slot).copied() {
            Some(LeaseState::Active { owner: exact, source, .. }) if exact == owner => {
                self.slots[slot] = match source {
                    ContiguousRamLeaseSource::Reuse { child, cap_base, capacity_frames } =>
                        LeaseState::Available { child, cap_base, capacity_frames },
                    ContiguousRamLeaseSource::SlotsOnly { cap_base, capacity_frames } =>
                        LeaseState::Available { child: 0, cap_base, capacity_frames },
                    ContiguousRamLeaseSource::Fresh => LeaseState::Empty,
                };
                Ok(())
            }
            _ => Err(ContiguousRamError::WrongOwner),
        }
    }

    pub fn quarantine(&mut self, owner: ContiguousRamOwner, slot: usize)
        -> Result<(), ContiguousRamError> {
        match self.slots.get(slot).copied() {
            Some(LeaseState::Active { owner: exact, .. }) if exact == owner => {
                self.slots[slot] = LeaseState::Quarantined;
                Ok(())
            }
            _ => Err(ContiguousRamError::WrongOwner),
        }
    }

    pub fn owned_child_count(&self) -> usize {
        self.slots.iter().filter(|state| match state {
            LeaseState::Available { child, .. } => *child != 0,
            LeaseState::Active { source: ContiguousRamLeaseSource::Reuse { child, .. }, .. } =>
                *child != 0,
            _ => false,
        }).count()
    }
}

/// Sequential receipt avoids a 9,216-entry shadow allocation. Native code retains the cap run;
/// each frame cap is accepted only with a checked `X86Page::GetAddress` result.
pub struct ContiguousRamReceipt {
    owner: ContiguousRamOwner,
    layout: ContiguousRamLayout,
    child: u64,
    cap_base: u64,
    next_frame: u64,
    first_physical: Option<u64>,
    next_physical: u64,
    next_map: u64,
    map_in_flight: bool,
    uncertain: bool,
    published: bool,
}

impl ContiguousRamReceipt {
    pub fn new(owner: ContiguousRamOwner, layout: ContiguousRamLayout, child: u64) -> Option<Self> {
        if owner.generation == 0 || owner.domain == 0 || child == 0 { return None; }
        Some(Self {
            owner, layout, child, cap_base: 0, next_frame: 0,
            first_physical: None, next_physical: 0, next_map: 0,
            map_in_flight: false, uncertain: false, published: false,
        })
    }

    pub fn child(&self, owner: ContiguousRamOwner) -> Result<u64, ContiguousRamError> {
        self.check_owner(owner)?;
        Ok(self.child)
    }

    fn check_owner(&self, owner: ContiguousRamOwner) -> Result<(), ContiguousRamError> {
        if self.owner != owner { Err(ContiguousRamError::WrongOwner) }
        else if self.uncertain { Err(ContiguousRamError::UncertainEffect) }
        else { Ok(()) }
    }

    pub fn record_frame(&mut self, owner: ContiguousRamOwner, index: u64, cap: u64, physical: u64)
        -> Result<(), ContiguousRamError>
    {
        self.check_owner(owner)?;
        if index != self.next_frame || index >= self.layout.frames || self.published {
            return Err(ContiguousRamError::WrongFrame);
        }
        if cap == 0 || (index != 0 && self.cap_base.checked_add(index) != Some(cap)) {
            return Err(ContiguousRamError::WrongCap);
        }
        if physical & (PAGE - 1) != 0 ||
            (index != 0 && physical != self.next_physical) {
            return Err(ContiguousRamError::WrongPhysicalRun);
        }
        let next = physical.checked_add(PAGE).ok_or(ContiguousRamError::WrongPhysicalRun)?;
        if index == 0 { self.first_physical = Some(physical); self.cap_base = cap; }
        self.next_physical = next;
        self.next_frame += 1;
        Ok(())
    }

    pub fn begin_map(&mut self, owner: ContiguousRamOwner, index: u64)
        -> Result<(), ContiguousRamError>
    {
        self.check_owner(owner)?;
        if self.next_frame != self.layout.frames || index != self.next_map
            || self.map_in_flight || index >= self.layout.frames {
            return Err(ContiguousRamError::Unproved);
        }
        self.map_in_flight = true;
        Ok(())
    }

    /// An error may mean the native map happened despite a lost acknowledgement. Quarantine the
    /// entire run until an explicit teardown establishes which mappings and caps remain.
    pub fn record_map_result(&mut self, owner: ContiguousRamOwner, index: u64, result: Result<(), ()>)
        -> Result<(), ContiguousRamError>
    {
        self.check_owner(owner)?;
        if !self.map_in_flight || index != self.next_map {
            return Err(ContiguousRamError::Unproved);
        }
        if result.is_err() {
            self.uncertain = true;
            return Err(ContiguousRamError::UncertainEffect);
        }
        self.map_in_flight = false;
        self.next_map += 1;
        Ok(())
    }

    pub fn publish(&mut self, owner: ContiguousRamOwner, low: u64, high: u64, boundary: u64)
        -> Result<u64, ContiguousRamError>
    {
        self.check_owner(owner)?;
        if self.next_frame != self.layout.frames || self.next_map != self.layout.frames
            || self.map_in_flight || self.published {
            return Err(ContiguousRamError::Unproved);
        }
        let first = self.first_physical.ok_or(ContiguousRamError::Unproved)?;
        let last = self.next_physical - 1;
        if low > high || first < low || last > high ||
            boundary != 0 && (!boundary.is_power_of_two() || boundary < PAGE
                || first / boundary != last / boundary) {
            return Err(ContiguousRamError::OutsideNtRange);
        }
        self.published = true;
        Ok(self.layout.base)
    }

    pub fn can_release(&self, owner: ContiguousRamOwner) -> bool {
        self.owner == owner && !self.uncertain && !self.map_in_flight && self.next_map == 0
            && !self.published
    }
}
