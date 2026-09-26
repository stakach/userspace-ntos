//! Retained source identity for a canonical File opened through a layered volume.

use alloc::vec::Vec;

use crate::{
    FatShortName, FileMetadata, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_NAME_INVALID,
};

/// Matches the executive's captured native File-name limit without folding or truncating UTF-16.
pub const LAYERED_OPEN_NAME_CAP: usize = 1024;

/// The source selected by CREATE. Later operations must not repeat namespace lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayeredOpenSource {
    Installed {
        first_cluster: u32,
        metadata: FileMetadata,
        alternate_name: FatShortName,
    },
    Overlay {
        file_id: u64,
    },
}

/// A borrowed view of the CREATE-selected source and exact opened name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayeredOpenRecord<'a> {
    pub source: LayeredOpenSource,
    pub name: &'a [u16],
}

/// Driver-owned context returned by CREATE and retained in the canonical File.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayeredOpenContextId(u64);

impl LayeredOpenContextId {
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

#[derive(Clone, Copy)]
struct OpenEntry {
    canonical_file_id: u64,
    source: LayeredOpenSource,
    name_len: u16,
    name: [u16; LAYERED_OPEN_NAME_CAP],
}

#[derive(Clone, Copy)]
struct OpenSlot {
    generation: u32,
    entry: Option<OpenEntry>,
}

impl OpenSlot {
    const fn empty() -> Self {
        Self {
            generation: 1,
            entry: None,
        }
    }
}

/// Bounded driver-owned open descriptions. Exhausted generations retire a slot rather than alias
/// a context that may still be retained by a stale IRP.
pub struct LayeredOpenTable<const SLOTS: usize> {
    slots: Vec<OpenSlot>,
}

impl<const SLOTS: usize> LayeredOpenTable<SLOTS> {
    pub const fn new() -> Self {
        assert!(SLOTS > 0 && SLOTS < u32::MAX as usize);
        Self { slots: Vec::new() }
    }

    pub fn insert(
        &mut self,
        canonical_file_id: u64,
        source: LayeredOpenSource,
        volume_relative_name: &[u16],
    ) -> Result<LayeredOpenContextId, u32> {
        if volume_relative_name.len() > LAYERED_OPEN_NAME_CAP {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let index = match self
            .slots
            .iter()
            .position(|slot| slot.entry.is_none() && slot.generation != u32::MAX)
        {
            Some(index) => index,
            None if self.slots.len() < SLOTS => {
                self.slots
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                self.slots.push(OpenSlot::empty());
                self.slots.len() - 1
            }
            None => return Err(STATUS_INSUFFICIENT_RESOURCES),
        };
        let slot = &mut self.slots[index];
        let mut name = [0; LAYERED_OPEN_NAME_CAP];
        name[..volume_relative_name.len()].copy_from_slice(volume_relative_name);
        slot.entry = Some(OpenEntry {
            canonical_file_id,
            source,
            name_len: volume_relative_name.len() as u16,
            name,
        });
        Ok(LayeredOpenContextId(
            (u64::from(slot.generation) << 32) | (index as u64 + 1),
        ))
    }

    pub fn get(
        &self,
        context: LayeredOpenContextId,
        canonical_file_id: u64,
    ) -> Result<LayeredOpenRecord<'_>, u32> {
        let entry = self
            .slot(context, canonical_file_id)?
            .entry
            .as_ref()
            .expect("validated occupied slot");
        Ok(LayeredOpenRecord {
            source: entry.source,
            name: &entry.name[..entry.name_len as usize],
        })
    }

    pub fn release(
        &mut self,
        context: LayeredOpenContextId,
        canonical_file_id: u64,
    ) -> Result<LayeredOpenSource, u32> {
        let slot = self.slot_mut(context, canonical_file_id)?;
        let source = slot.entry.take().expect("validated occupied slot").source;
        slot.generation += 1;
        Ok(source)
    }

    fn slot(
        &self,
        context: LayeredOpenContextId,
        canonical_file_id: u64,
    ) -> Result<&OpenSlot, u32> {
        let index = (context.0 as u32)
            .checked_sub(1)
            .ok_or(STATUS_INVALID_HANDLE)? as usize;
        self.slots
            .get(index)
            .filter(|slot| {
                slot.generation == (context.0 >> 32) as u32
                    && slot
                        .entry
                        .is_some_and(|entry| entry.canonical_file_id == canonical_file_id)
            })
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn slot_mut(
        &mut self,
        context: LayeredOpenContextId,
        canonical_file_id: u64,
    ) -> Result<&mut OpenSlot, u32> {
        let index = (context.0 as u32)
            .checked_sub(1)
            .ok_or(STATUS_INVALID_HANDLE)? as usize;
        self.slots
            .get_mut(index)
            .filter(|slot| {
                slot.generation == (context.0 >> 32) as u32
                    && slot
                        .entry
                        .is_some_and(|entry| entry.canonical_file_id == canonical_file_id)
            })
            .ok_or(STATUS_INVALID_HANDLE)
    }
}

impl<const SLOTS: usize> Default for LayeredOpenTable<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed() -> LayeredOpenSource {
        LayeredOpenSource::Installed {
            first_cluster: 42,
            metadata: FileMetadata {
                file_id: 137,
                end_of_file: 4096,
                ..FileMetadata::default()
            },
            alternate_name: FatShortName::EMPTY,
        }
    }

    #[test]
    fn source_selection_is_retained_across_lookup() {
        let mut table = LayeredOpenTable::<2>::new();
        let name: alloc::vec::Vec<u16> = "reactos\\Fonts\\Arial.ttf".encode_utf16().collect();
        let fat = table.insert(10, installed(), &name).unwrap();
        let overlay = table
            .insert(
                11,
                LayeredOpenSource::Overlay { file_id: 99 },
                &[b'x' as u16],
            )
            .unwrap();
        assert_eq!(table.get(fat, 10).unwrap().source, installed());
        assert_eq!(table.get(fat, 10).unwrap().name, name.as_slice());
        assert_eq!(
            table.get(overlay, 11),
            Ok(LayeredOpenRecord {
                source: LayeredOpenSource::Overlay { file_id: 99 },
                name: &[b'x' as u16]
            })
        );
    }

    #[test]
    fn lazy_table_retains_generation_fence_after_reuse() {
        let mut table = LayeredOpenTable::<1>::new();
        assert!(table.slots.is_empty());
        let first = table.insert(7, installed(), &[b'a' as u16]).unwrap();
        assert_eq!(table.slots.len(), 1);
        assert_eq!(table.release(first, 7), Ok(installed()));
        let second = table.insert(7, installed(), &[b'b' as u16]).unwrap();
        assert_ne!(first, second);
        assert_eq!(table.get(first, 7), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.get(second, 7).unwrap().name, &[b'b' as u16]);
    }

    #[test]
    fn stale_and_cross_file_contexts_cannot_resolve_or_release() {
        let mut table = LayeredOpenTable::<1>::new();
        let first = table.insert(10, installed(), &[b'a' as u16]).unwrap();
        assert_eq!(table.get(first, 11), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.release(first, 11), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.release(first, 10), Ok(installed()));
        assert_eq!(table.get(first, 10), Err(STATUS_INVALID_HANDLE));
        let second = table
            .insert(
                11,
                LayeredOpenSource::Overlay { file_id: 99 },
                &[b'b' as u16],
            )
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(table.get(first, 10), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.get(second, 10), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            table.get(second, 11),
            Ok(LayeredOpenRecord {
                source: LayeredOpenSource::Overlay { file_id: 99 },
                name: &[b'b' as u16]
            })
        );
        assert_eq!(
            table.release(second, 11),
            Ok(LayeredOpenSource::Overlay { file_id: 99 })
        );
        assert_eq!(table.release(second, 11), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn full_table_rejects_open_without_disturbing_existing_source() {
        let mut table = LayeredOpenTable::<1>::new();
        let first = table.insert(10, installed(), &[b'a' as u16]).unwrap();
        assert_eq!(
            table.insert(
                11,
                LayeredOpenSource::Overlay { file_id: 99 },
                &[b'b' as u16]
            ),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(table.get(first, 10).unwrap().source, installed());
    }

    #[test]
    fn captured_name_survives_caller_mutation_and_slot_reuse() {
        let mut table = LayeredOpenTable::<1>::new();
        let mut name = alloc::vec![b'A' as u16, b'.' as u16, b'T' as u16];
        let first = table.insert(10, installed(), &name).unwrap();
        name[0] = b'B' as u16;
        assert_eq!(
            table.get(first, 10).unwrap().name,
            &[b'A' as u16, b'.' as u16, b'T' as u16]
        );
        table.release(first, 10).unwrap();
        let second = table.insert(11, installed(), &name).unwrap();
        assert_eq!(table.get(first, 10), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.get(second, 11).unwrap().name, name.as_slice());
    }

    #[test]
    fn oversized_name_does_not_allocate_or_mutate_a_slot() {
        let mut table = LayeredOpenTable::<1>::new();
        let long_name = [b'x' as u16; LAYERED_OPEN_NAME_CAP + 1];
        assert_eq!(
            table.insert(10, installed(), &long_name),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        let opened = table.insert(10, installed(), &[b'a' as u16]).unwrap();
        assert_eq!(table.get(opened, 10).unwrap().name, &[b'a' as u16]);
    }
}
