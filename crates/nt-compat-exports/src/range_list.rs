//! NT closed-interval range-list policy used by PCI resource arbitration.
//!
//! The native adapter owns the guest `RTL_RANGE_LIST` links and allocations;
//! this module decides interval semantics without depending on guest memory.

use alloc::vec::Vec;

pub const ADD_IF_CONFLICT: u32 = 1;
pub const ADD_SHARED: u32 = 2;
pub const SHARED_OK: u32 = 1;
pub const NULL_CONFLICT_OK: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: u64,
    pub end: u64,
    pub owner: u64,
    pub user_data: u64,
    pub attributes: u8,
    pub shared: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeListError {
    InvalidParameter,
    Conflict,
    NotFound,
    InsufficientResources,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeList {
    ranges: Vec<Range>,
}

impl RangeList {
    pub const fn new() -> Self { Self { ranges: Vec::new() } }

    pub fn ranges(&self) -> &[Range] { &self.ranges }

    pub fn add(&mut self, mut range: Range, flags: u32) -> Result<(), RangeListError> {
        if range.start > range.end { return Err(RangeListError::InvalidParameter); }
        let shared = flags & ADD_SHARED != 0;
        if flags & ADD_IF_CONFLICT == 0 && self.ranges.iter().any(|existing| {
            range.start <= existing.end && existing.start <= range.end
                && !(shared && existing.shared)
        }) {
            return Err(RangeListError::Conflict);
        }
        self.ranges.try_reserve(1).map_err(|_| RangeListError::InsufficientResources)?;
        range.shared = shared;
        // ReactOS inserts a same-start entry after its peers.
        let position = self.ranges.partition_point(|existing| existing.start <= range.start);
        self.ranges.insert(position, range);
        Ok(())
    }

    pub fn delete_owner(&mut self, owner: u64) -> usize {
        let before = self.ranges.len();
        self.ranges.retain(|range| range.owner != owner);
        before - self.ranges.len()
    }

    pub fn clear(&mut self) { self.ranges.clear(); }

    /// Copy every source entry into an already initialized list. Entries are
    /// inserted by start so subsequent searches retain the sorted invariant.
    /// Capacity is reserved before mutation, so allocation failure is atomic.
    pub fn append_from(&mut self, source: &Self) -> Result<(), RangeListError> {
        self.ranges.try_reserve(source.ranges.len())
            .map_err(|_| RangeListError::InsufficientResources)?;
        for &range in &source.ranges {
            self.add(range, ADD_IF_CONFLICT | if range.shared { ADD_SHARED } else { 0 })?;
        }
        Ok(())
    }

    pub fn invert_into(&self, destination: &mut Self) -> Result<(), RangeListError> {
        destination.append_from(&self.invert()?)
    }

    pub fn find(
        &self, minimum: u64, maximum: u64, length: u64, alignment: u64,
        flags: u32, available_attributes: u8, mut ignore_conflict: impl FnMut(&Range) -> bool,
    ) -> Result<u64, RangeListError> {
        if length == 0 || alignment == 0 { return Err(RangeListError::InvalidParameter); }
        let width = length - 1;
        if width > maximum { return Err(RangeListError::NotFound); }
        let mut candidate = (maximum - width) & !(alignment - 1);
        loop {
            if candidate < minimum { return Err(RangeListError::NotFound); }
            let end = candidate + width;
            let mut lowest_conflict = None::<u64>;
            for range in &self.ranges {
                if range.start > end { break; }
                if range.end < candidate
                    || (flags & SHARED_OK != 0 && range.shared)
                    || available_attributes & range.attributes != 0
                    || (flags & NULL_CONFLICT_OK != 0 && range.owner == 0)
                    || ignore_conflict(range)
                { continue; }
                lowest_conflict = Some(lowest_conflict.map_or(range.start, |old| old.min(range.start)));
            }
            let Some(conflict) = lowest_conflict else { return Ok(candidate); };
            if conflict == 0 || width >= conflict { return Err(RangeListError::NotFound); }
            candidate = (conflict - 1 - width) & !(alignment - 1);
        }
    }

    pub fn invert(&self) -> Result<Self, RangeListError> {
        let mut result = Self::new();
        let mut gap = 0u64;
        for range in &self.ranges {
            if range.start > gap {
                result.add(Range { start: gap, end: range.start - 1, owner: 0,
                    user_data: 0, attributes: 0, shared: false }, 0)?;
            }
            if range.end == u64::MAX { return Ok(result); }
            gap = gap.max(range.end + 1);
        }
        result.add(Range { start: gap, end: u64::MAX, owner: 0,
            user_data: 0, attributes: 0, shared: false }, 0)?;
        Ok(result)
    }
}
