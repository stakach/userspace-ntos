//! Retained two-query metadata work for routed data-section creation.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::data_section::STATUS_IO_DEVICE_ERROR;
use crate::routed_section_metadata::decode_standard_query;
use crate::{CompletedFileQuery, RoutedSectionMetadata, SectionMountId};

static NEXT_STORE: AtomicU64 = AtomicU64::new(1);
const STATUS_PENDING: u32 = 0x0000_0103;
pub const FILE_STANDARD_INFORMATION_CLASS: u32 = 5;
pub const FILE_INTERNAL_INFORMATION_CLASS: u32 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingSectionMetadataId {
    store: u64,
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy)]
enum Phase<K> {
    StandardReserved,
    StandardSubmitted(K),
    StandardCopying(K, usize),
    StandardTerminal(K, u32),
    InternalReserved,
    InternalSubmitted(K),
    InternalCopying(K, usize),
    InternalTerminal(K, u32),
    Ready(RoutedSectionMetadata),
    Failed(u32),
}

impl<K: Copy> Phase<K> {
    fn key(self) -> Option<K> {
        match self {
            Self::StandardSubmitted(key)
            | Self::StandardCopying(key, _)
            | Self::StandardTerminal(key, _)
            | Self::InternalSubmitted(key)
            | Self::InternalCopying(key, _)
            | Self::InternalTerminal(key, _) => Some(key),
            _ => None,
        }
    }
}

struct Work<R, K> {
    generation: u64,
    mount: SectionMountId,
    owner: R,
    phase: Phase<K>,
    standard: [u8; 24],
    internal: [u8; 8],
}

pub struct PendingSectionMetadataQueries<R, K> {
    store: u64,
    next_generation: u64,
    rows: Vec<Option<Work<R, K>>>,
}

impl<R, K: Copy + Eq> PendingSectionMetadataQueries<R, K> {
    pub const fn new() -> Self {
        Self {
            store: 0,
            next_generation: 0,
            rows: Vec::new(),
        }
    }

    pub fn reserve(
        &mut self,
        mount: SectionMountId,
        owner: R,
    ) -> Result<PendingSectionMetadataId, R> {
        let Some(generation) = self.next_generation.checked_add(1) else {
            return Err(owner);
        };
        let slot = self.rows.iter().position(Option::is_none);
        if slot.is_none() && self.rows.try_reserve(1).is_err() {
            return Err(owner);
        }
        if self.store == 0 {
            let Ok(store) =
                NEXT_STORE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
            else {
                return Err(owner);
            };
            self.store = store;
        }
        self.next_generation = generation;
        let row = Work {
            generation,
            mount,
            owner,
            phase: Phase::StandardReserved,
            standard: [0; 24],
            internal: [0; 8],
        };
        let slot = if let Some(slot) = slot {
            self.rows[slot] = Some(row);
            slot
        } else {
            self.rows.push(Some(row));
            self.rows.len() - 1
        };
        Ok(PendingSectionMetadataId {
            store: self.store,
            slot,
            generation,
        })
    }

    fn row(&self, id: PendingSectionMetadataId) -> Option<&Work<R, K>> {
        if id.store != self.store {
            return None;
        }
        self.rows
            .get(id.slot)?
            .as_ref()
            .filter(|row| row.generation == id.generation)
    }

    fn row_mut(&mut self, id: PendingSectionMetadataId) -> Option<&mut Work<R, K>> {
        if id.store != self.store {
            return None;
        }
        self.rows
            .get_mut(id.slot)?
            .as_mut()
            .filter(|row| row.generation == id.generation)
    }

    pub fn next_query(&self, id: PendingSectionMetadataId) -> Option<u32> {
        match self.row(id)?.phase {
            Phase::StandardReserved => Some(FILE_STANDARD_INFORMATION_CLASS),
            Phase::InternalReserved => Some(FILE_INTERNAL_INFORMATION_CLASS),
            _ => None,
        }
    }

    /// Only the initial, pre-dispatch reservation is cancelable without provider reconciliation.
    pub fn cancel_reserved(&mut self, id: PendingSectionMetadataId) -> Option<R> {
        if !matches!(self.row(id)?.phase, Phase::StandardReserved) {
            return None;
        }
        Some(self.rows[id.slot].take()?.owner)
    }

    pub fn bind_pending(&mut self, id: PendingSectionMetadataId, key: K) -> bool {
        if self
            .rows
            .iter()
            .flatten()
            .any(|row| row.phase.key() == Some(key))
        {
            return false;
        }
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        row.phase = match row.phase {
            Phase::StandardReserved => Phase::StandardSubmitted(key),
            Phase::InternalReserved => Phase::InternalSubmitted(key),
            _ => return false,
        };
        true
    }

    /// Inline completions have no retained IRP and therefore require no backend ACK.
    pub fn complete_inline(
        &mut self,
        id: PendingSectionMetadataId,
        result: CompletedFileQuery<'_>,
    ) -> bool {
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        match row.phase {
            Phase::StandardReserved => {
                row.phase = match result.exact(24) {
                    Ok(bytes) => {
                        row.standard.copy_from_slice(bytes);
                        Self::after_standard(row)
                    }
                    Err(status) => Phase::Failed(status),
                };
            }
            Phase::InternalReserved => {
                row.phase = match result.exact(8) {
                    Ok(bytes) => {
                        row.internal.copy_from_slice(bytes);
                        Self::finish(row)
                    }
                    Err(status) => Phase::Failed(status),
                };
            }
            _ => return false,
        }
        true
    }

    /// A terminal result is not publishable until its exact output has been copied and ACKed.
    pub fn terminal(
        &mut self,
        id: PendingSectionMetadataId,
        key: K,
        status: u32,
        information: u64,
    ) -> bool {
        if status == STATUS_PENDING {
            return false;
        }
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        let (length, standard) = match row.phase {
            Phase::StandardSubmitted(bound) if bound == key => (24, true),
            Phase::InternalSubmitted(bound) if bound == key => (8, false),
            _ => return false,
        };
        let result = if status != 0 {
            status
        } else if information != length {
            STATUS_IO_DEVICE_ERROR
        } else {
            0
        };
        row.phase = match (standard, result) {
            (true, 0) => Phase::StandardCopying(key, 0),
            (false, 0) => Phase::InternalCopying(key, 0),
            (true, status) => Phase::StandardTerminal(key, status),
            (false, status) => Phase::InternalTerminal(key, status),
        };
        true
    }

    pub fn append(
        &mut self,
        id: PendingSectionMetadataId,
        key: K,
        offset: usize,
        bytes: &[u8],
    ) -> bool {
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        let (copied, standard) = match row.phase {
            Phase::StandardCopying(bound, copied) if bound == key => (copied, true),
            Phase::InternalCopying(bound, copied) if bound == key => (copied, false),
            _ => return false,
        };
        let output: &mut [u8] = if standard {
            &mut row.standard
        } else {
            &mut row.internal
        };
        if bytes.is_empty() || offset != copied || bytes.len() > output.len() - copied {
            return false;
        }
        output[copied..copied + bytes.len()].copy_from_slice(bytes);
        let copied = copied + bytes.len();
        row.phase = match (standard, copied == output.len()) {
            (true, true) => Phase::StandardTerminal(key, 0),
            (false, true) => Phase::InternalTerminal(key, 0),
            (true, false) => Phase::StandardCopying(key, copied),
            (false, false) => Phase::InternalCopying(key, copied),
        };
        true
    }

    /// Call only after the canonical I/O manager confirms this IRP's ACK.
    pub fn acknowledge_backend(&mut self, id: PendingSectionMetadataId, key: K) -> bool {
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        row.phase = match row.phase {
            Phase::StandardTerminal(bound, 0) if bound == key => Self::after_standard(row),
            Phase::StandardTerminal(bound, status) if bound == key => Phase::Failed(status),
            Phase::InternalTerminal(bound, 0) if bound == key => Self::finish(row),
            Phase::InternalTerminal(bound, status) if bound == key => Phase::Failed(status),
            _ => return false,
        };
        true
    }

    fn finish(row: &Work<R, K>) -> Phase<K> {
        let standard = CompletedFileQuery {
            status: 0,
            information: 24,
            output: &row.standard,
        };
        let internal = CompletedFileQuery {
            status: 0,
            information: 8,
            output: &row.internal,
        };
        match RoutedSectionMetadata::from_queries(row.mount, standard, internal) {
            Ok(metadata) => Phase::Ready(metadata),
            Err(status) => Phase::Failed(status),
        }
    }

    fn after_standard(row: &Work<R, K>) -> Phase<K> {
        let standard = CompletedFileQuery {
            status: 0,
            information: 24,
            output: &row.standard,
        };
        match decode_standard_query(standard) {
            Ok(_) => Phase::InternalReserved,
            Err(status) => Phase::Failed(status),
        }
    }

    pub fn take_terminal(
        &mut self,
        id: PendingSectionMetadataId,
    ) -> Option<(R, Result<RoutedSectionMetadata, u32>)> {
        let result = match self.row(id)?.phase {
            Phase::Ready(metadata) => Ok(metadata),
            Phase::Failed(status) => Err(status),
            _ => return None,
        };
        Some((self.rows[id.slot].take()?.owner, result))
    }
}

impl<R, K: Copy + Eq> Default for PendingSectionMetadataQueries<R, K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "pending_section_metadata_tests.rs"]
mod tests;
