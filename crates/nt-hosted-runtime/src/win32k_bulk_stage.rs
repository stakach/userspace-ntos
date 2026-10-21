//! Checked layouts and generation-bound ownership for isolated win32k bulk arguments.

const PAGE_BYTES: u64 = 4096;

use nt_user_callback::DispatchReturnReceipt;

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value.checked_add(alignment - 1).map(|value| value & !(alignment - 1))
}

/// A bitmap and its description in one shared provider argument lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32kBulkLayout {
    pub bits_offset: u64,
    pub info_offset: u64,
    pub bytes: u64,
}

impl Win32kBulkLayout {
    pub fn flat(bytes: u64) -> Option<Self> {
        (bytes != 0).then_some(Self { bits_offset: 0, info_offset: 0, bytes })
    }

    pub fn dib(initial_bits: u64, info_bytes: u64) -> Option<Self> {
        if info_bytes == 0 { return None; }
        let info_offset = align_up(initial_bits, 8)?;
        let bytes = align_up(info_offset.checked_add(info_bytes)?, 8)?;
        Some(Self { bits_offset: 0, info_offset, bytes })
    }

    fn mapped_bytes(self) -> Option<u64> {
        if self.bytes == 0 || self.bits_offset >= self.bytes || self.info_offset >= self.bytes {
            return None;
        }
        align_up(self.bytes, PAGE_BYTES)
    }
}

/// An exact physical provider, requestor generation, and staging request identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32kBulkOwner {
    provider_domain: u64,
    provider_generation: u64,
    requester_index: u32,
    requester_generation: u64,
    dispatch_id: u64,
}

impl Win32kBulkOwner {
    pub fn new(provider_domain: u64, provider_generation: u64, requester_index: u32, requester_generation: u64, dispatch_id: u64) -> Option<Self> {
        (provider_domain != 0 && provider_generation != 0 && requester_generation != 0 && dispatch_id != 0).then_some(Self {
            provider_domain, provider_generation, requester_index, requester_generation, dispatch_id,
        })
    }

    pub const fn matches_requester(self, index: u32, generation: u64) -> bool {
        self.requester_index == index && self.requester_generation == generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32kBulkStageError {
    InvalidArena,
    InvalidLayout,
    WrongProvider,
    NoCapacity,
    StaleLease,
    WrongOwner,
    InvalidTransition,
}

/// Evidence from mapping a reserved lease into the executive and provider VSpaces.
/// `NoEffect` is valid only before the first mapping syscall could have changed either VSpace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32kBulkMapFailure { NoEffect, Indeterminate }

/// The physical provider lane and native dispatch, independent of the staging request nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32kBulkDispatchIdentity {
    lane_index: u32,
    lane_generation: u64,
    dispatch_id: u64,
    ssn: u64,
}

impl Win32kBulkDispatchIdentity {
    pub const fn new(lane_index: u32, lane_generation: u64, dispatch_id: u64, ssn: u64) -> Option<Self> {
        if lane_generation == 0 || dispatch_id == 0 || ssn == 0 {
            None
        } else {
            Some(Self { lane_index, lane_generation, dispatch_id, ssn })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32kBulkLeaseState { Reserved, MappingUncertain, Entered, Uncertain, Completed }

/// Copying this ticket does not duplicate the claim; the ledger is authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32kBulkLease {
    generation: u64,
    owner: Win32kBulkOwner,
    base: u64,
    mapped_bytes: u64,
    layout: Win32kBulkLayout,
}

impl Win32kBulkLease {
    pub const fn base(self) -> u64 { self.base }
    pub const fn mapped_bytes(self) -> u64 { self.mapped_bytes }
    pub const fn layout(self) -> Win32kBulkLayout { self.layout }
    pub const fn owner(self) -> Win32kBulkOwner { self.owner }
    pub fn bits_pointer(self) -> Option<u64> { self.base.checked_add(self.layout.bits_offset) }
    pub fn info_pointer(self) -> Option<u64> { self.base.checked_add(self.layout.info_offset) }
}

#[derive(Clone, Copy)]
struct Row {
    lease: Win32kBulkLease,
    state: Win32kBulkLeaseState,
    retained_dispatch: Option<Win32kBulkDispatchIdentity>,
}

/// Virtual extent owner. Native code demand maps both aliases before copy-in, retains the backing
/// for the session, and clears bytes before reuse. A transport reply does not prove provider
/// completion or permit virtual extent reuse.
pub struct Win32kBulkStages<const N: usize> {
    base: u64,
    bytes: u64,
    provider_domain: u64,
    provider_generation: u64,
    next_generation: u64,
    rows: [Option<Row>; N],
}

impl<const N: usize> Win32kBulkStages<N> {
    pub fn new(base: u64, bytes: u64, provider_domain: u64, provider_generation: u64) -> Result<Self, Win32kBulkStageError> {
        if base == 0 || base % PAGE_BYTES != 0 || bytes == 0 || bytes % PAGE_BYTES != 0
            || base.checked_add(bytes).is_none() || provider_domain == 0 || provider_generation == 0 || N == 0
        {
            return Err(Win32kBulkStageError::InvalidArena);
        }
        Ok(Self { base, bytes, provider_domain, provider_generation, next_generation: 1, rows: [None; N] })
    }

    pub fn reserve(&mut self, owner: Win32kBulkOwner, layout: Win32kBulkLayout) -> Result<Win32kBulkLease, Win32kBulkStageError> {
        if owner.provider_domain != self.provider_domain || owner.provider_generation != self.provider_generation {
            return Err(Win32kBulkStageError::WrongProvider);
        }
        let span = layout.mapped_bytes().ok_or(Win32kBulkStageError::InvalidLayout)?;
        let slot = self.rows.iter().position(Option::is_none).ok_or(Win32kBulkStageError::NoCapacity)?;
        let mut offset = 0u64;
        loop {
            let end = offset.checked_add(span).ok_or(Win32kBulkStageError::NoCapacity)?;
            if end > self.bytes { return Err(Win32kBulkStageError::NoCapacity); }
            let overlap = self.rows.iter().flatten().find(|row| {
                let start = row.lease.base - self.base;
                let occupied_end = start + row.lease.mapped_bytes;
                offset < occupied_end && start < end
            });
            if let Some(row) = overlap {
                offset = row.lease.base - self.base + row.lease.mapped_bytes;
                continue;
            }
            let generation = self.next_generation;
            self.next_generation = generation.checked_add(1).ok_or(Win32kBulkStageError::NoCapacity)?;
            let lease = Win32kBulkLease { generation, owner, base: self.base + offset, mapped_bytes: span, layout };
            self.rows[slot] = Some(Row {
                lease,
                state: Win32kBulkLeaseState::Reserved,
                retained_dispatch: None,
            });
            return Ok(lease);
        }
    }

    fn row_mut(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner) -> Result<&mut Row, Win32kBulkStageError> {
        if lease.owner != owner { return Err(Win32kBulkStageError::WrongOwner); }
        self.rows.iter_mut().flatten().find(|row| row.lease == lease).ok_or(Win32kBulkStageError::StaleLease)
    }

    pub fn state(&self, lease: Win32kBulkLease) -> Option<Win32kBulkLeaseState> {
        self.rows.iter().flatten().find(|row| row.lease == lease).map(|row| row.state)
    }

    /// Resolve an already bound native completion to its exact lease. No numeric dispatch ID
    /// alone authorizes release; the caller still supplies its authenticated owner and receipt.
    pub fn retained_for_dispatch(&self, dispatch: Win32kBulkDispatchIdentity)
        -> Result<Option<Win32kBulkLease>, Win32kBulkStageError>
    {
        let mut found = None;
        for row in self.rows.iter().flatten() {
            if row.retained_dispatch == Some(dispatch) {
                if found.is_some() { return Err(Win32kBulkStageError::InvalidTransition); }
                found = Some(row.lease);
            }
        }
        Ok(found)
    }

    /// Close a failed mapping admission according to its physical effect evidence. A definitive
    /// pre-map refusal releases the virtual claim; uncertain partial effects retain it. A
    /// provider return cannot resolve mapping uncertainty because no provider call was entered.
    pub fn reject_mapping(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner,
        failure: Win32kBulkMapFailure) -> Result<(), Win32kBulkStageError>
    {
        match failure {
            Win32kBulkMapFailure::NoEffect => self.cancel(lease, owner),
            Win32kBulkMapFailure::Indeterminate => {
                let row = self.row_mut(lease, owner)?;
                if row.state != Win32kBulkLeaseState::Reserved {
                    return Err(Win32kBulkStageError::InvalidTransition);
                }
                row.state = Win32kBulkLeaseState::MappingUncertain;
                Ok(())
            }
        }
    }

    /// Record the claim before native entry, including when its result may become uncertain.
    pub fn enter(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner) -> Result<(), Win32kBulkStageError> {
        let row = self.row_mut(lease, owner)?;
        if row.state != Win32kBulkLeaseState::Reserved { return Err(Win32kBulkStageError::InvalidTransition); }
        row.state = Win32kBulkLeaseState::Entered;
        Ok(())
    }

    pub fn mark_uncertain(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner) -> Result<(), Win32kBulkStageError> {
        let row = self.row_mut(lease, owner)?;
        if row.state != Win32kBulkLeaseState::Entered { return Err(Win32kBulkStageError::InvalidTransition); }
        row.state = Win32kBulkLeaseState::Uncertain;
        Ok(())
    }

    /// Bind a parked call to the exact physical lane and native dispatch. Reparking preserves
    /// this binding; a different dispatch cannot inherit its still-live provider argument bytes.
    pub fn retain_for_dispatch(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner,
        dispatch: Win32kBulkDispatchIdentity) -> Result<(), Win32kBulkStageError>
    {
        if self.rows.iter().flatten().any(|row| {
            row.lease != lease && row.retained_dispatch == Some(dispatch)
        }) {
            return Err(Win32kBulkStageError::InvalidTransition);
        }
        let row = self.row_mut(lease, owner)?;
        if !matches!(row.state, Win32kBulkLeaseState::Entered | Win32kBulkLeaseState::Uncertain)
            || row.retained_dispatch.is_some_and(|bound| bound != dispatch)
        {
            return Err(Win32kBulkStageError::InvalidTransition);
        }
        row.retained_dispatch = Some(dispatch);
        row.state = Win32kBulkLeaseState::Uncertain;
        Ok(())
    }

    /// Retire only after the already owned native lane supplies a matching handler-return
    /// receipt. The native adapter must also authenticate that lane's generation and requester.
    pub fn complete_retained_dispatch(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner,
        dispatch: Win32kBulkDispatchIdentity, receipt: DispatchReturnReceipt, result: u64,
        completed: bool) -> Result<(), Win32kBulkStageError>
    {
        let row = self.row_mut(lease, owner)?;
        if row.state != Win32kBulkLeaseState::Uncertain
            || row.retained_dispatch != Some(dispatch)
            || receipt.authenticate(dispatch.dispatch_id, dispatch.ssn, result, completed)
                .ok().and_then(|returned| returned.handler_value()) != Some(result)
        {
            return Err(Win32kBulkStageError::InvalidTransition);
        }
        row.state = Win32kBulkLeaseState::Completed;
        self.retire(lease, owner)
    }

    /// Call only with definitive completion from the exact native invocation.
    pub fn complete(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner) -> Result<(), Win32kBulkStageError> {
        let row = self.row_mut(lease, owner)?;
        if !matches!(row.state, Win32kBulkLeaseState::Entered | Win32kBulkLeaseState::Uncertain)
            || row.retained_dispatch.is_some() {
            return Err(Win32kBulkStageError::InvalidTransition);
        }
        row.state = Win32kBulkLeaseState::Completed;
        Ok(())
    }

    fn release(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner, expected: Win32kBulkLeaseState) -> Result<(), Win32kBulkStageError> {
        if self.row_mut(lease, owner)?.state != expected { return Err(Win32kBulkStageError::InvalidTransition); }
        let slot = self.rows.iter().position(|row| row.is_some_and(|row| row.lease == lease))
            .ok_or(Win32kBulkStageError::StaleLease)?;
        self.rows[slot] = None;
        Ok(())
    }

    /// Release a virtual claim before native entry. Session-owned backing pages remain mapped;
    /// the next claimant must clear the bytes it will expose to the provider.
    pub fn cancel(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner) -> Result<(), Win32kBulkStageError> {
        self.release(lease, owner, Win32kBulkLeaseState::Reserved)
    }

    /// Release a virtual claim after definitive native completion. Session-owned backing pages
    /// remain mapped and may be reused only after the next claimant clears touched bytes.
    pub fn retire(&mut self, lease: Win32kBulkLease, owner: Win32kBulkOwner) -> Result<(), Win32kBulkStageError> {
        self.release(lease, owner, Win32kBulkLeaseState::Completed)
    }

    pub fn is_drained(&self) -> bool { self.rows.iter().all(Option::is_none) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BASE: u64 = 0x1_0000_0000;

    fn owner(lane: u32, dispatch: u64) -> Win32kBulkOwner {
        Win32kBulkOwner::new(11, 7, lane, 3, dispatch).unwrap()
    }

    #[test]
    fn released_winlogon_splash_bitmap_fits_a_checked_owned_lease() {
        let layout = Win32kBulkLayout::dib(14_745_600, 40).expect("valid splash DIB");
        assert_eq!(layout.info_offset, 14_745_600);
        assert_eq!(layout.bytes, 14_745_640);
        let mut stages = Win32kBulkStages::<2>::new(TEST_BASE, 64 * 1024 * 1024, 11, 7).unwrap();
        let lease = stages.reserve(owner(0, 1), layout).unwrap();
        assert_eq!(lease.info_pointer(), Some(lease.base() + 14_745_600));
        assert!(lease.mapped_bytes() >= layout.bytes);
    }

    #[test]
    fn overflow_cannot_wrap_the_staged_extent() {
        assert!(Win32kBulkLayout::dib(u64::MAX, 40).is_none());
        assert!(Win32kBulkLayout::dib(4, 0).is_none());
        assert!(Win32kBulkLayout::flat(0).is_none());
        assert_eq!(Win32kBulkLayout::flat(17).unwrap().bytes, 17);
    }

    #[test]
    fn overlapping_native_calls_get_disjoint_extents() {
        let mut stages = Win32kBulkStages::<6>::new(TEST_BASE, 64 * 1024 * 1024, 11, 7).unwrap();
        let layout = Win32kBulkLayout::dib(14_745_600, 40).unwrap();
        let first = stages.reserve(owner(0, 1), layout).unwrap();
        stages.enter(first, owner(0, 1)).unwrap();
        let second = stages.reserve(owner(1, 2), layout).unwrap();
        assert!(first.base() + first.mapped_bytes() <= second.base());
        let third = stages.reserve(owner(2, 3), layout).unwrap();
        assert!(second.base() + second.mapped_bytes() <= third.base());
        let fourth = stages.reserve(owner(3, 4), layout).unwrap();
        assert!(third.base() + third.mapped_bytes() <= fourth.base());
        assert_eq!(stages.reserve(owner(4, 5), layout), Err(Win32kBulkStageError::NoCapacity));
        assert_eq!(stages.retire(first, owner(0, 1)), Err(Win32kBulkStageError::InvalidTransition));
    }

    #[test]
    fn uncertain_effects_and_stale_generations_retain_their_extent() {
        let mut stages = Win32kBulkStages::<1>::new(TEST_BASE, 4096, 11, 7).unwrap();
        let layout = Win32kBulkLayout::dib(1024, 40).unwrap();
        let first = stages.reserve(owner(0, 1), layout).unwrap();
        stages.enter(first, owner(0, 1)).unwrap();
        stages.mark_uncertain(first, owner(0, 1)).unwrap();
        assert_eq!(stages.cancel(first, owner(0, 1)), Err(Win32kBulkStageError::InvalidTransition));
        assert_eq!(stages.retire(first, owner(0, 1)), Err(Win32kBulkStageError::InvalidTransition));
        assert_eq!(stages.reserve(owner(1, 2), layout), Err(Win32kBulkStageError::NoCapacity));
        assert_eq!(stages.complete(first, owner(1, 2)), Err(Win32kBulkStageError::WrongOwner));
        stages.complete(first, owner(0, 1)).unwrap();
        stages.retire(first, owner(0, 1)).unwrap();
        let second = stages.reserve(owner(1, 2), layout).unwrap();
        assert_eq!(first.base(), second.base());
        assert_ne!(first, second);
        assert_eq!(stages.enter(first, owner(0, 1)), Err(Win32kBulkStageError::StaleLease));
    }

    #[test]
    fn wrong_provider_and_malformed_layout_are_rejected() {
        let mut stages = Win32kBulkStages::<1>::new(TEST_BASE, 4096, 11, 7).unwrap();
        let layout = Win32kBulkLayout::dib(32, 40).unwrap();
        let old = Win32kBulkOwner::new(11, 6, 0, 3, 1).unwrap();
        assert_eq!(stages.reserve(old, layout), Err(Win32kBulkStageError::WrongProvider));
        let other_physical_domain = Win32kBulkOwner::new(12, 7, 0, 3, 1).unwrap();
        assert_eq!(stages.reserve(other_physical_domain, layout), Err(Win32kBulkStageError::WrongProvider));
        assert_eq!(stages.reserve(owner(0, 1), Win32kBulkLayout { bits_offset: 0, info_offset: u64::MAX, bytes: 8 }), Err(Win32kBulkStageError::InvalidLayout));
        assert!(stages.is_drained());
    }

    #[test]
    fn failed_map_admission_distinguishes_no_effect_from_uncertain_partial_map() {
        let mut stages = Win32kBulkStages::<1>::new(TEST_BASE, 4096, 11, 7).unwrap();
        let layout = Win32kBulkLayout::flat(64).unwrap();
        let first_owner = owner(0, 1);
        let first = stages.reserve(first_owner, layout).unwrap();

        // A failure before any native map must release the reserved row; the same address can
        // satisfy the next request without waiting for a provider that was never entered.
        stages.reject_mapping(first, first_owner, Win32kBulkMapFailure::NoEffect).unwrap();
        assert!(stages.is_drained());
        let second_owner = owner(0, 2);
        let second = stages.reserve(second_owner, layout).unwrap();
        assert_eq!(second.base(), first.base());
        assert_ne!(second, first);

        // Once either VSpace may have changed, the exact row and address stay fenced. A later
        // request cannot overwrite bytes that the partially mapped provider might still read.
        stages.reject_mapping(second, second_owner, Win32kBulkMapFailure::Indeterminate).unwrap();
        assert!(!stages.is_drained());
        assert_eq!(stages.reserve(owner(0, 3), layout), Err(Win32kBulkStageError::NoCapacity));
        assert_eq!(stages.cancel(second, second_owner), Err(Win32kBulkStageError::InvalidTransition));
        assert_eq!(stages.complete(second, second_owner), Err(Win32kBulkStageError::InvalidTransition));
    }

    #[test]
    fn suspended_dispatch_keeps_each_lease_until_its_exact_handler_return() {
        use nt_user_callback::DispatchReturnReceipt;

        let mut stages = Win32kBulkStages::<2>::new(TEST_BASE, 3 * PAGE_BYTES, 11, 7).unwrap();
        let layout = Win32kBulkLayout::flat(32).unwrap();
        let owner_a = owner(0, 1); // The owner's dispatch_id is the staging request nonce.
        let owner_b = owner(1, 2);
        let lease_a = stages.reserve(owner_a, layout).unwrap();
        let lease_b = stages.reserve(owner_b, layout).unwrap();
        assert_ne!(lease_a.base(), lease_b.base());
        stages.enter(lease_a, owner_a).unwrap();
        stages.enter(lease_b, owner_b).unwrap();

        // These IDs come from the native Win32k dispatch and its physical lane. Reparking the
        // same dispatch through a callback and then a provider wait must retain one ticket.
        let dispatch_a = Win32kBulkDispatchIdentity::new(3, 41, 101, 0x1082).unwrap();
        let dispatch_b = Win32kBulkDispatchIdentity::new(4, 52, 202, 0x10a0).unwrap();
        stages.retain_for_dispatch(lease_a, owner_a, dispatch_a).unwrap();
        stages.retain_for_dispatch(lease_b, owner_b, dispatch_b).unwrap();
        stages.retain_for_dispatch(lease_a, owner_a, dispatch_a).unwrap();
        assert_eq!(stages.retain_for_dispatch(lease_b, owner_b, dispatch_a),
            Err(Win32kBulkStageError::InvalidTransition));
        assert_eq!(stages.retained_for_dispatch(dispatch_a), Ok(Some(lease_a)));
        assert_eq!(stages.state(lease_a), Some(Win32kBulkLeaseState::Uncertain));

        let exact_a = DispatchReturnReceipt::handler_returned(101, 0x1082, 7);
        let wrong_id = DispatchReturnReceipt::handler_returned(202, 0x1082, 7);
        let stale_lane = Win32kBulkDispatchIdentity::new(3, 40, 101, 0x1082).unwrap();
        let stale_requester = Win32kBulkOwner::new(11, 7, 0, 4, 1).unwrap();
        assert!(stages.complete_retained_dispatch(
            lease_a, stale_requester, dispatch_a, exact_a, 7, true,
        ).is_err());
        assert!(stages.complete_retained_dispatch(
            lease_a, owner_a, stale_lane, exact_a, 7, true,
        ).is_err());
        assert!(stages.complete_retained_dispatch(
            lease_a, owner_a, dispatch_a, wrong_id, 7, true,
        ).is_err());
        assert!(stages.complete_retained_dispatch(
            lease_a, owner_a, dispatch_a, exact_a, 7, false,
        ).is_err());
        assert!(stages.complete_retained_dispatch(
            lease_a, owner_a, dispatch_a,
            DispatchReturnReceipt::refused(101, 0x1082, 7), 7, true,
        ).is_err());
        assert_eq!(stages.state(lease_a), Some(Win32kBulkLeaseState::Uncertain));

        let exact_b = DispatchReturnReceipt::handler_returned(202, 0x10a0, 9);
        stages.complete_retained_dispatch(lease_b, owner_b, dispatch_b, exact_b, 9, true).unwrap();
        assert_eq!(stages.state(lease_b), None);
        assert_eq!(stages.state(lease_a), Some(Win32kBulkLeaseState::Uncertain));
        let next = stages.reserve(owner(2, 3), layout).unwrap();
        assert_eq!(next.base(), lease_b.base());

        stages.complete_retained_dispatch(lease_a, owner_a, dispatch_a, exact_a, 7, true).unwrap();
        assert_eq!(stages.state(lease_a), None);
        assert!(stages.complete_retained_dispatch(
            lease_a, owner_a, dispatch_a, exact_a, 7, true,
        ).is_err());
    }

    #[test]
    fn mapping_uncertainty_cannot_be_resolved_by_a_provider_return() {
        use nt_user_callback::DispatchReturnReceipt;

        let mut stages = Win32kBulkStages::<1>::new(TEST_BASE, PAGE_BYTES, 11, 7).unwrap();
        let lease_owner = owner(0, 1);
        let lease = stages.reserve(lease_owner, Win32kBulkLayout::flat(32).unwrap()).unwrap();
        stages.reject_mapping(lease, lease_owner, Win32kBulkMapFailure::Indeterminate).unwrap();
        let dispatch = Win32kBulkDispatchIdentity::new(3, 41, 101, 0x1082).unwrap();
        let receipt = DispatchReturnReceipt::handler_returned(101, 0x1082, 7);
        assert!(stages.complete_retained_dispatch(
            lease, lease_owner, dispatch, receipt, 7, true,
        ).is_err());
        assert_eq!(stages.state(lease), Some(Win32kBulkLeaseState::MappingUncertain));
    }
}
