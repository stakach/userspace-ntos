//! Exact Reply slot ownership and exclusive replacement leases.
//!
//! This table owns slot state. The native root's current Reply selector remains outside it:
//! `0` means no active Reply, including while a hosted Call retains its own capability.
//! Numeric caps and slot indices are never authority without their exact generations.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_TABLE_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootReplyIdentity {
    table_generation: u64,
    slot: usize,
    slot_generation: u64,
    cap: u64,
}

impl RootReplyIdentity {
    pub const fn cap(self) -> u64 {
        self.cap
    }
    pub const fn slot(self) -> usize {
        self.slot
    }
}

/// A selector only: the table retains both Replies until exact cancellation or commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootReplyReplacementLease {
    active: RootReplyIdentity,
    replacement: RootReplyIdentity,
    reservation_generation: u64,
    retirement_generation: u64,
}

/// Pre-effect ownership of one future root Reply slot. A native cap must be bound to this
/// exact reservation before its retype is entered.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "retain this spare reservation through native allocation and retype"]
pub struct RootReplySpareLease {
    table_generation: u64,
    slot: usize,
    slot_generation: u64,
}

impl RootReplyReplacementLease {
    pub const fn active(self) -> RootReplyIdentity {
        self.active
    }
    pub const fn replacement(self) -> RootReplyIdentity {
        self.replacement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootReplySlotState {
    Vacant,
    Free,
    Reserved,
    SparePrepared,
    Used,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootReplyRetypeOutcome {
    Acknowledged,
    NoEffects,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootReplyReplacementError {
    Uninitialized,
    InvalidCap,
    DuplicateCap,
    NoCapacity,
    NoFreeReply,
    StaleIdentity,
    StaleLease,
    NotFree,
    NotUsed,
    ReservedReply,
    UnboundSpare,
    QuarantinedReply,
    ActiveReply,
}

#[derive(Clone, Copy)]
enum SlotState {
    Vacant,
    Free,
    Reserved { generation: u64 },
    SparePrepared { generation: u64 },
    Used,
    Quarantined,
}

struct Slot {
    cap: u64,
    generation: u64,
    state: SlotState,
}

/// Pure source of truth for native Reply pool slots. The current root selector and native cap
/// effects are separate contracts; every native mutation must use one of these transitions.
pub struct RootReplySlotTable {
    generation: u64,
    next_generation: u64,
    slots: Vec<Slot>,
}

impl RootReplySlotTable {
    /// Empty static storage before native bootstrap. It reports zero records and cannot admit
    /// a Reply until `new` installs a generation-bearing table.
    pub const fn uninitialized() -> Self {
        Self {
            generation: 0,
            next_generation: 1,
            slots: Vec::new(),
        }
    }

    pub fn new(initial_capacity: usize) -> Result<Self, RootReplyReplacementError> {
        let generation = NEXT_TABLE_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                next.checked_add(1)
            })
            .map_err(|_| RootReplyReplacementError::NoCapacity)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(initial_capacity)
            .map_err(|_| RootReplyReplacementError::NoCapacity)?;
        Ok(Self {
            generation,
            next_generation: 1,
            slots,
        })
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }
    pub const fn is_initialized(&self) -> bool {
        self.generation != 0
    }
    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }
    pub fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| !matches!(slot.state, SlotState::Vacant))
            .count()
    }
    pub fn used_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot.state, SlotState::Used | SlotState::Quarantined)
                || (matches!(slot.state, SlotState::SparePrepared { .. }) && slot.cap != 0))
            .count()
    }

    pub fn slot_state(&self, index: usize) -> Option<RootReplySlotState> {
        self.slots.get(index).map(|slot| match slot.state {
            SlotState::Vacant => RootReplySlotState::Vacant,
            SlotState::Free => RootReplySlotState::Free,
            SlotState::Reserved { .. } => RootReplySlotState::Reserved,
            SlotState::SparePrepared { .. } => RootReplySlotState::SparePrepared,
            SlotState::Used => RootReplySlotState::Used,
            SlotState::Quarantined => RootReplySlotState::Quarantined,
        })
    }

    pub fn state(
        &self,
        identity: RootReplyIdentity,
    ) -> Result<RootReplySlotState, RootReplyReplacementError> {
        let slot = self.exact(identity)?;
        Ok(match slot.state {
            SlotState::Vacant => RootReplySlotState::Vacant,
            SlotState::Free => RootReplySlotState::Free,
            SlotState::Reserved { .. } => RootReplySlotState::Reserved,
            SlotState::SparePrepared { .. } => RootReplySlotState::SparePrepared,
            SlotState::Used => RootReplySlotState::Used,
            SlotState::Quarantined => RootReplySlotState::Quarantined,
        })
    }

    pub fn find_cap(&self, cap: u64) -> Option<RootReplyIdentity> {
        if cap == 0 {
            return None;
        }
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            (slot.cap == cap && !matches!(slot.state, SlotState::Vacant))
                .then(|| self.identity_at(index))
        })
    }

    pub fn at(&self, index: usize) -> Option<RootReplyIdentity> {
        let slot = self.slots.get(index)?;
        (slot.cap != 0 && !matches!(slot.state, SlotState::Vacant))
            .then(|| self.identity_at(index))
    }

    /// The caller can exclude a free cap that is still owned by shared ingress. This observation
    /// does not reserve the slot; use `reserve` before entering an effect.
    pub fn find_free(&self, mut eligible: impl FnMut(u64) -> bool) -> Option<RootReplyIdentity> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            (matches!(slot.state, SlotState::Free) && eligible(slot.cap))
                .then(|| self.identity_at(index))
        })
    }

    /// Establish the pure spare-allocation boundary before any native cap is allocated.
    pub fn prepare_spare(&mut self) -> Result<RootReplySpareLease, RootReplyReplacementError> {
        if self.generation == 0 {
            return Err(RootReplyReplacementError::Uninitialized);
        }
        let next = self.next_generation.checked_add(1)
            .ok_or(RootReplyReplacementError::NoCapacity)?;
        let index = if let Some(index) = self.slots.iter()
            .position(|slot| matches!(slot.state, SlotState::Vacant)) {
            index
        } else {
            self.slots.try_reserve(1)
                .map_err(|_| RootReplyReplacementError::NoCapacity)?;
            self.slots.push(Slot { cap: 0, generation: 0, state: SlotState::Vacant });
            self.slots.len() - 1
        };
        let generation = self.next_generation;
        self.slots[index] = Slot {
            cap: 0,
            generation,
            state: SlotState::SparePrepared { generation },
        };
        self.next_generation = next;
        Ok(RootReplySpareLease {
            table_generation: self.generation,
            slot: index,
            slot_generation: generation,
        })
    }

    /// Record the allocated root CSpace slot before entering native retype. The native slot
    /// allocator owns the allocation itself; this table excludes it from other Reply claims.
    pub fn bind_spare(
        &mut self,
        lease: &RootReplySpareLease,
        cap: u64,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        self.exact_spare(lease)?;
        if cap == 0 { return Err(RootReplyReplacementError::InvalidCap); }
        if self.find_cap(cap).is_some() {
            return Err(RootReplyReplacementError::DuplicateCap);
        }
        if self.slots[lease.slot].cap != 0 {
            return Err(RootReplyReplacementError::StaleLease);
        }
        self.slots[lease.slot].cap = cap;
        Ok(self.identity_at(lease.slot))
    }

    /// Acknowledged native retype has created one Reply in the previously bound cap. This
    /// transition cannot allocate or consume a new generation after the native effect.
    pub fn publish_spare(
        &mut self,
        lease: RootReplySpareLease,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        self.exact_spare(&lease)?;
        if self.slots[lease.slot].cap == 0 {
            return Err(RootReplyReplacementError::UnboundSpare);
        }
        self.slots[lease.slot].state = SlotState::Free;
        Ok(self.identity_at(lease.slot))
    }

    /// An unexpected native result leaves the bound cap unusable until independent proof of
    /// its physical state. It cannot re-enter the free pool or be cleared by a numeric cap.
    pub fn quarantine_spare(
        &mut self,
        lease: RootReplySpareLease,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        self.exact_spare(&lease)?;
        if self.slots[lease.slot].cap == 0 {
            return Err(RootReplyReplacementError::UnboundSpare);
        }
        self.slots[lease.slot].state = SlotState::Quarantined;
        Ok(self.identity_at(lease.slot))
    }

    /// Cancel only after a certified no-effect retype. The root allocator may then recycle
    /// the allocated but empty CSpace slot; a stale lease cannot erase a reused Reply slot.
    pub fn cancel_spare_no_effects(
        &mut self,
        lease: RootReplySpareLease,
    ) -> Result<(), RootReplyReplacementError> {
        self.exact_spare(&lease)?;
        let slot = &mut self.slots[lease.slot];
        slot.cap = 0;
        slot.state = SlotState::Vacant;
        Ok(())
    }

    /// Register a genuinely fresh cap after native allocation and retype acknowledge.
    pub fn insert_free(
        &mut self,
        cap: u64,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        self.insert(cap, SlotState::Free)
    }

    /// Register an independently owned Reply already bound to an admitted Call.
    pub fn insert_used(
        &mut self,
        cap: u64,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        self.insert(cap, SlotState::Used)
    }

    fn insert(
        &mut self,
        cap: u64,
        state: SlotState,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        if self.generation == 0 {
            return Err(RootReplyReplacementError::Uninitialized);
        }
        if cap == 0 {
            return Err(RootReplyReplacementError::InvalidCap);
        }
        if self.find_cap(cap).is_some() {
            return Err(RootReplyReplacementError::DuplicateCap);
        }
        let next = self
            .next_generation
            .checked_add(1)
            .ok_or(RootReplyReplacementError::NoCapacity)?;
        let index = if let Some(index) = self
            .slots
            .iter()
            .position(|slot| matches!(slot.state, SlotState::Vacant))
        {
            index
        } else {
            self.slots
                .try_reserve(1)
                .map_err(|_| RootReplyReplacementError::NoCapacity)?;
            self.slots.push(Slot {
                cap: 0,
                generation: 0,
                state: SlotState::Vacant,
            });
            self.slots.len() - 1
        };
        self.slots[index] = Slot {
            cap,
            generation: self.next_generation,
            state,
        };
        self.next_generation = next;
        Ok(self.identity_at(index))
    }

    /// Claim a particular free replacement before entering the native pump. The native caller
    /// verifies `active` against the root's exact current Reply owner and main-slot selector.
    pub fn reserve(
        &mut self,
        active: RootReplyIdentity,
        replacement: RootReplyIdentity,
    ) -> Result<RootReplyReplacementLease, RootReplyReplacementError> {
        if !matches!(self.exact(active)?.state, SlotState::Used) {
            return Err(RootReplyReplacementError::NotUsed);
        }
        if !matches!(self.exact(replacement)?.state, SlotState::Free) {
            return Err(RootReplyReplacementError::NotFree);
        }
        // Reserve the old slot's next incarnation now as well. Native deletion may follow
        // this lease, so retirement publication must never fail for generation exhaustion.
        let next = self
            .next_generation
            .checked_add(2)
            .ok_or(RootReplyReplacementError::NoCapacity)?;
        let lease = RootReplyReplacementLease {
            active,
            replacement,
            reservation_generation: self.next_generation,
            retirement_generation: self.next_generation + 1,
        };
        self.slots[replacement.slot].state = SlotState::Reserved {
            generation: self.next_generation,
        };
        self.next_generation = next;
        Ok(lease)
    }

    /// Select and reserve in one pure transition. The eligibility callback can check whether
    /// shared ingress still claims a nominally free cap.
    pub fn reserve_first(
        &mut self,
        active: RootReplyIdentity,
        eligible: impl FnMut(u64) -> bool,
    ) -> Result<RootReplyReplacementLease, RootReplyReplacementError> {
        if !matches!(self.exact(active)?.state, SlotState::Used) {
            return Err(RootReplyReplacementError::NotUsed);
        }
        let replacement = self
            .find_free(eligible)
            .ok_or(RootReplyReplacementError::NoFreeReply)?;
        self.reserve(active, replacement)
    }

    /// Release only this reservation after a certified no-effect outcome.
    pub fn cancel_no_effects(
        &mut self,
        lease: RootReplyReplacementLease,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        self.exact_lease(lease)?;
        self.slots[lease.replacement.slot].state = SlotState::Free;
        Ok(lease.replacement)
    }

    /// Publish only the replacement slot's ownership. The root's main selector is updated by
    /// native code after it revalidates the exact active owner; the original stays `Used` here.
    pub fn commit(
        &mut self,
        lease: RootReplyReplacementLease,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        self.exact_lease(lease)?;
        if !matches!(self.exact(lease.active)?.state, SlotState::Used) {
            return Err(RootReplyReplacementError::NotUsed);
        }
        self.slots[lease.replacement.slot].state = SlotState::Used;
        Ok(lease.replacement)
    }

    /// The root has acknowledged deletion of the old private Reply. Publish the new used
    /// replacement and the old free slot together, before changing the native main selector.
    pub fn commit_retiring_active(
        &mut self,
        lease: RootReplyReplacementLease,
        retype: RootReplyRetypeOutcome,
    ) -> Result<(RootReplyIdentity, Option<RootReplyIdentity>), RootReplyReplacementError> {
        self.exact_lease(lease)?;
        if !matches!(self.exact(lease.active)?.state, SlotState::Used) {
            return Err(RootReplyReplacementError::NotUsed);
        }
        self.slots[lease.replacement.slot].state = SlotState::Used;
        let active = &mut self.slots[lease.active.slot];
        match retype {
            RootReplyRetypeOutcome::Acknowledged => {
                active.generation = lease.retirement_generation;
                active.state = SlotState::Free;
            }
            RootReplyRetypeOutcome::NoEffects => {
                active.generation = lease.retirement_generation;
                active.cap = 0;
                active.state = SlotState::Vacant;
            }
            RootReplyRetypeOutcome::Uncertain => {
                active.state = SlotState::Quarantined;
            }
        }
        Ok((
            lease.replacement,
            (retype == RootReplyRetypeOutcome::Acknowledged)
                .then(|| self.identity_at(lease.active.slot)),
        ))
    }

    /// An acknowledged Reply retirement/retype makes a non-main used slot reusable. A host with
    /// main=0 passes `None`; the caller must supply the actual current main identity otherwise.
    pub fn retire_used(
        &mut self,
        identity: RootReplyIdentity,
        current_main: Option<RootReplyIdentity>,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        if current_main == Some(identity) {
            return Err(RootReplyReplacementError::ActiveReply);
        }
        if !matches!(self.exact(identity)?.state, SlotState::Used) {
            return Err(RootReplyReplacementError::NotUsed);
        }
        self.make_free(identity)
    }

    /// The legacy root may keep a free Reply cap in its main receive slot. Releasing that
    /// already-free slot is idempotent; releasing a used main Reply still requires retirement.
    pub fn mark_free(
        &mut self,
        identity: RootReplyIdentity,
        current_main: Option<RootReplyIdentity>,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        match self.exact(identity)?.state {
            SlotState::Free => Ok(identity),
            SlotState::Used => self.retire_used(identity, current_main),
            SlotState::Reserved { .. } => Err(RootReplyReplacementError::ReservedReply),
            SlotState::SparePrepared { .. } => Err(RootReplyReplacementError::ReservedReply),
            SlotState::Quarantined => Err(RootReplyReplacementError::QuarantinedReply),
            SlotState::Vacant => Err(RootReplyReplacementError::StaleIdentity),
        }
    }

    /// Bind a free Reply to an admitted Call outside the root replacement path.
    pub fn mark_used(
        &mut self,
        identity: RootReplyIdentity,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        if !matches!(self.exact(identity)?.state, SlotState::Free) {
            return Err(RootReplyReplacementError::NotFree);
        }
        self.slots[identity.slot].state = SlotState::Used;
        Ok(identity)
    }

    /// The native root has independently observed its old main Reply free and has inserted
    /// a distinct, admitted hosted Call as `new_main`. Retire the old slot before the root
    /// publishes the new selector. This explicit rotation avoids pretending that the new
    /// Reply was already the current main while checking the old one.
    pub fn replace_main_after_free_observation(
        &mut self,
        old_main: RootReplyIdentity,
        new_main: RootReplyIdentity,
    ) -> Result<(), RootReplyReplacementError> {
        if old_main == new_main {
            return Err(RootReplyReplacementError::DuplicateCap);
        }
        if !matches!(self.exact(new_main)?.state, SlotState::Used) {
            return Err(RootReplyReplacementError::NotUsed);
        }
        match self.exact(old_main)?.state {
            SlotState::Free => Ok(()),
            SlotState::Used => self.make_free(old_main).map(|_| ()),
            SlotState::Reserved { .. } => Err(RootReplyReplacementError::ReservedReply),
            SlotState::SparePrepared { .. } => Err(RootReplyReplacementError::ReservedReply),
            SlotState::Quarantined => Err(RootReplyReplacementError::QuarantinedReply),
            SlotState::Vacant => Err(RootReplyReplacementError::StaleIdentity),
        }
    }

    /// Remove a cap transferred to another authoritative pool. Neither a current main Reply
    /// nor a reserved cap may be cleared; the old identity then becomes permanently stale.
    pub fn clear(
        &mut self,
        identity: RootReplyIdentity,
        current_main: Option<RootReplyIdentity>,
    ) -> Result<(), RootReplyReplacementError> {
        if current_main == Some(identity) {
            return Err(RootReplyReplacementError::ActiveReply);
        }
        let state = self.exact(identity)?.state;
        if matches!(state, SlotState::Reserved { .. }) {
            return Err(RootReplyReplacementError::ReservedReply);
        }
        if matches!(state, SlotState::SparePrepared { .. }) {
            return Err(RootReplyReplacementError::ReservedReply);
        }
        if matches!(state, SlotState::Quarantined) {
            return Err(RootReplyReplacementError::QuarantinedReply);
        }
        self.slots[identity.slot].cap = 0;
        self.slots[identity.slot].state = SlotState::Vacant;
        Ok(())
    }

    fn make_free(
        &mut self,
        identity: RootReplyIdentity,
    ) -> Result<RootReplyIdentity, RootReplyReplacementError> {
        let next = self
            .next_generation
            .checked_add(1)
            .ok_or(RootReplyReplacementError::NoCapacity)?;
        let slot = &mut self.slots[identity.slot];
        slot.generation = self.next_generation;
        slot.state = SlotState::Free;
        self.next_generation = next;
        Ok(self.identity_at(identity.slot))
    }

    fn identity_at(&self, index: usize) -> RootReplyIdentity {
        let slot = &self.slots[index];
        RootReplyIdentity {
            table_generation: self.generation,
            slot: index,
            slot_generation: slot.generation,
            cap: slot.cap,
        }
    }

    fn exact(&self, identity: RootReplyIdentity) -> Result<&Slot, RootReplyReplacementError> {
        let slot = self
            .slots
            .get(identity.slot)
            .ok_or(RootReplyReplacementError::StaleIdentity)?;
        if identity.table_generation != self.generation
            || identity.slot_generation != slot.generation
            || identity.cap != slot.cap
            || matches!(slot.state, SlotState::Vacant)
        {
            return Err(RootReplyReplacementError::StaleIdentity);
        }
        Ok(slot)
    }

    fn exact_lease(
        &self,
        lease: RootReplyReplacementLease,
    ) -> Result<(), RootReplyReplacementError> {
        let slot = self
            .exact(lease.replacement)
            .map_err(|_| RootReplyReplacementError::StaleLease)?;
        if !matches!(slot.state, SlotState::Reserved { generation }
            if generation == lease.reservation_generation)
        {
            return Err(RootReplyReplacementError::StaleLease);
        }
        Ok(())
    }

    fn exact_spare(&self, lease: &RootReplySpareLease)
        -> Result<(), RootReplyReplacementError>
    {
        let slot = self.slots.get(lease.slot)
            .ok_or(RootReplyReplacementError::StaleLease)?;
        if lease.table_generation != self.generation
            || slot.generation != lease.slot_generation
            || !matches!(slot.state, SlotState::SparePrepared { generation }
                if generation == lease.slot_generation)
        {
            return Err(RootReplyReplacementError::StaleLease);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "root_reply_replacement/tests.rs"]
mod tests;
