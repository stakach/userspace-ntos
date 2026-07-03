//! Generation-protected record store (spec §9).
//!
//! A [`GenStore`] is a slot-map keyed by a generation-protected id: the id packs
//! a 24-bit generation and a 40-bit slot index. Removing a record bumps its
//! slot's generation, so any id that still refers to the old occupant no longer
//! resolves — stale ids are rejected. There is no `unsafe` here.

use alloc::vec::Vec;
use core::marker::PhantomData;

use nt_io_abi::{DeviceId, DriverId, FileId, IoRequestId, IrpId, IO_ID_GEN_BITS};

const GEN_MASK: u32 = (1u32 << IO_ID_GEN_BITS) - 1;

/// The next generation (wraps within [`IO_ID_GEN_BITS`], never zero so a
/// null/zero id stays reserved).
#[inline]
fn next_gen(g: u32) -> u32 {
    let n = g.wrapping_add(1) & GEN_MASK;
    if n == 0 {
        1
    } else {
        n
    }
}

/// A generation-protected I/O id: constructible from `(generation, slot)` and
/// decomposable back. Implemented for the `nt-io-abi` id newtypes.
pub trait IoId: Copy + Eq {
    fn from_parts(generation: u32, slot: u64) -> Self;
    fn parts(self) -> (u32, u64);
}

macro_rules! impl_io_id {
    ($($t:ty),* $(,)?) => {
        $(
            impl IoId for $t {
                #[inline]
                fn from_parts(generation: u32, slot: u64) -> Self {
                    <$t>::new(generation, slot)
                }
                #[inline]
                fn parts(self) -> (u32, u64) {
                    (self.generation(), self.slot())
                }
            }
        )*
    };
}

impl_io_id!(DriverId, DeviceId, FileId, IrpId, IoRequestId);

struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

/// A slot-map of `T` keyed by a generation-protected id `I`.
pub struct GenStore<I, T> {
    slots: Vec<Slot<T>>,
    _marker: PhantomData<fn() -> I>,
}

impl<I: IoId, T> Default for GenStore<I, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: IoId, T> GenStore<I, T> {
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Insert a record, returning its fresh id (reuses a freed slot if any).
    pub fn insert(&mut self, value: T) -> I {
        if let Some(idx) = self.slots.iter().position(|s| s.value.is_none()) {
            // The slot's generation was already bumped when it was freed.
            self.slots[idx].value = Some(value);
            I::from_parts(self.slots[idx].generation, idx as u64)
        } else {
            let idx = self.slots.len();
            self.slots.push(Slot {
                generation: 1,
                value: Some(value),
            });
            I::from_parts(1, idx as u64)
        }
    }

    /// Resolve a live record by id. A stale or unknown id yields `None`.
    pub fn get(&self, id: I) -> Option<&T> {
        let (gen, slot) = id.parts();
        let s = self.slots.get(slot as usize)?;
        if s.generation == gen {
            s.value.as_ref()
        } else {
            None
        }
    }

    /// Mutable variant of [`get`](Self::get).
    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        let (gen, slot) = id.parts();
        let s = self.slots.get_mut(slot as usize)?;
        if s.generation == gen {
            s.value.as_mut()
        } else {
            None
        }
    }

    /// Remove a record by id (bumping its slot's generation). Returns the record,
    /// or `None` for a stale/unknown id.
    pub fn remove(&mut self, id: I) -> Option<T> {
        let (gen, slot) = id.parts();
        let s = self.slots.get_mut(slot as usize)?;
        if s.generation != gen {
            return None;
        }
        let v = s.value.take();
        if v.is_some() {
            s.generation = next_gen(s.generation);
        }
        v
    }

    /// True if `id` resolves to a live record.
    pub fn contains(&self, id: I) -> bool {
        self.get(id).is_some()
    }

    /// Number of live records.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.value.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate live `(id, &record)` pairs (for scans, e.g. driver-fault cleanup).
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> {
        self.slots.iter().enumerate().filter_map(|(idx, s)| {
            s.value
                .as_ref()
                .map(|v| (I::from_parts(s.generation, idx as u64), v))
        })
    }

    /// Collect the ids of all live records (owned, for mutate-while-scanning).
    pub fn ids(&self) -> Vec<I> {
        self.iter().map(|(id, _)| id).collect()
    }
}
