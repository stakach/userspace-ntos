//! Read-only FAT FILE_OBJECT opens, sharing, and exact retained-reference lifetime.

use super::{
    duplicate_body_reference, open_generation, open_id, open_slot, same_fat_file,
    DIRECTORY_OPEN_PATH_CAP, MAX_FAT_OPEN_SLOTS,
};
use crate::{
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_OBJECT_NAME_INVALID,
    STATUS_QUOTA_EXCEEDED, STATUS_SHARING_VIOLATION,
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnlyFileOpen {
    pub first_cluster: u32,
    pub size: u32,
    pub current_offset: u64,
    pub create_options: u32,
    mode_state: crate::FileModeState,
    pub metadata: crate::FileMetadata,
    pub alternate_name: crate::FatShortName,
    /// `FILE_OBJECT::Event` state shared by every duplicated process handle.
    signaled: bool,
    share: crate::FileShareAccess,
    path_len: u16,
    path: [u8; DIRECTORY_OPEN_PATH_CAP],
}

impl ReadOnlyFileOpen {
    pub const fn mode_state(&self) -> crate::FileModeState {
        self.mode_state
    }

    pub fn set_mode(&mut self, requested: u32) -> Result<crate::FileModeState, u32> {
        let next = self
            .mode_state
            .transition(requested)
            .map_err(|status| status.raw() as u32)?;
        self.mode_state = next;
        Ok(next)
    }

    pub fn volume_relative_path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }
}

#[derive(Clone, Copy)]
struct ReadOnlyFileOpenSlot {
    occupied: bool,
    generation: u32,
    handle_references: u16,
    references: u16,
    open: ReadOnlyFileOpen,
}

impl ReadOnlyFileOpenSlot {
    const fn empty() -> Self {
        Self {
            occupied: false,
            generation: 0,
            handle_references: 0,
            references: 0,
            open: ReadOnlyFileOpen {
                first_cluster: 0,
                size: 0,
                current_offset: 0,
                create_options: 0,
                mode_state: crate::FileModeState::from_create_options(0),
                metadata: crate::FileMetadata {
                    creation_time: 0,
                    last_access_time: 0,
                    last_write_time: 0,
                    change_time: 0,
                    allocation_size: 0,
                    end_of_file: 0,
                    valid_data_length: 0,
                    file_id: 0,
                    attributes: 0,
                    reparse_tag: 0,
                    number_of_links: 0,
                    delete_pending: false,
                    is_directory: false,
                },
                alternate_name: crate::FatShortName::EMPTY,
                signaled: false,
                share: crate::FileShareAccess::none(),
                path_len: 0,
                path: [0; DIRECTORY_OPEN_PATH_CAP],
            },
        }
    }

    fn vacate(&mut self) {
        let generation = self.generation + 1;
        *self = Self::empty();
        self.generation = generation;
    }
}

/// Slots grow lazily within the existing 16-bit slot identity space. Explicit `SLOTS` selects
/// a smaller caller-owned budget; the default does not reserve all addressable slots up front.
pub struct ReadOnlyFileOpenTable<const SLOTS: usize = MAX_FAT_OPEN_SLOTS> {
    slots: Vec<ReadOnlyFileOpenSlot>,
}

/// Copied accounting for diagnostics; observing it never retains or reclaims an open body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnlyFileOpenUsage {
    pub allocated_slots: usize,
    pub slot_limit: usize,
    pub occupied_bodies: usize,
    pub io_only_bodies: usize,
    pub total_handle_refs: usize,
    pub generation_exhausted_slots: usize,
}

impl<const SLOTS: usize> ReadOnlyFileOpenTable<SLOTS> {
    pub const fn new() -> Self {
        assert!(SLOTS > 0);
        assert!(SLOTS <= MAX_FAT_OPEN_SLOTS);
        Self { slots: Vec::new() }
    }

    pub fn usage(&self) -> ReadOnlyFileOpenUsage {
        let mut usage = ReadOnlyFileOpenUsage {
            allocated_slots: self.slots.len(),
            slot_limit: SLOTS,
            occupied_bodies: 0,
            io_only_bodies: 0,
            total_handle_refs: 0,
            generation_exhausted_slots: 0,
        };
        for slot in &self.slots {
            if slot.occupied {
                usage.occupied_bodies += 1;
                usage.io_only_bodies += usize::from(slot.handle_references == 0);
                usage.total_handle_refs += usize::from(slot.handle_references);
            } else if slot.generation > u16::MAX as u32 {
                usage.generation_exhausted_slots += 1;
            }
        }
        usage
    }

    pub fn create(
        &mut self,
        first_cluster: u32,
        size: u32,
        volume_relative_path: &[u8],
        desired_access: u32,
        share_access: u32,
        create_options: u32,
        metadata: crate::FileMetadata,
        alternate_name: crate::FatShortName,
    ) -> Result<u32, u32> {
        if volume_relative_path.len() > DIRECTORY_OPEN_PATH_CAP {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let requested = crate::FileShareAccess::new(desired_access, share_access);
        self.check_share_access(volume_relative_path, metadata, requested)?;
        let index = match self
            .slots
            .iter()
            .position(|slot| !slot.occupied && slot.generation <= u16::MAX as u32)
        {
            Some(index) => index,
            None if self.slots.len() < SLOTS => {
                self.slots
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                self.slots.push(ReadOnlyFileOpenSlot::empty());
                self.slots.len() - 1
            }
            None => return Err(STATUS_INSUFFICIENT_RESOURCES),
        };
        let slot = &mut self.slots[index];
        let mut path = [0; DIRECTORY_OPEN_PATH_CAP];
        path[..volume_relative_path.len()].copy_from_slice(volume_relative_path);
        *slot = ReadOnlyFileOpenSlot {
            occupied: true,
            generation: slot.generation,
            handle_references: 1,
            references: 1,
            open: ReadOnlyFileOpen {
                first_cluster,
                size,
                current_offset: 0,
                create_options,
                mode_state: crate::FileModeState::from_create_options(create_options),
                metadata,
                alternate_name,
                signaled: true,
                share: requested,
                path_len: volume_relative_path.len() as u16,
                path,
            },
        };
        Ok(open_id(index, slot.generation))
    }

    pub fn check_share(
        &self,
        volume_relative_path: &[u8],
        metadata: crate::FileMetadata,
        desired_access: u32,
        share_access: u32,
    ) -> Result<(), u32> {
        self.check_share_access(
            volume_relative_path,
            metadata,
            crate::FileShareAccess::new(desired_access, share_access),
        )
    }

    fn check_share_access(
        &self,
        volume_relative_path: &[u8],
        metadata: crate::FileMetadata,
        requested: crate::FileShareAccess,
    ) -> Result<(), u32> {
        if self
            .slots
            .iter()
            .filter(|slot| slot.occupied && slot.handle_references != 0)
            .all(|slot| {
                !same_fat_file(
                    &slot.open.metadata,
                    slot.open.volume_relative_path(),
                    &metadata,
                    volume_relative_path,
                ) || requested.compatible_with(slot.open.share)
            })
        {
            Ok(())
        } else {
            Err(STATUS_SHARING_VIOLATION)
        }
    }

    pub fn get(&self, id: u32) -> Result<&ReadOnlyFileOpen, u32> {
        self.slots
            .get(open_slot(id))
            .filter(|slot| slot.occupied && slot.generation == open_generation(id))
            .map(|slot| &slot.open)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn get_mut(&mut self, id: u32) -> Result<&mut ReadOnlyFileOpen, u32> {
        self.slots
            .get_mut(open_slot(id))
            .filter(|slot| slot.occupied && slot.generation == open_generation(id))
            .map(|slot| &mut slot.open)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn retain(&mut self, id: u32) -> Result<(), u32> {
        let slot = self
            .slots
            .get_mut(open_slot(id))
            .filter(|slot| {
                slot.occupied
                    && slot.generation == open_generation(id)
                    && slot.handle_references != 0
            })
            .ok_or(STATUS_INVALID_HANDLE)?;
        let references = slot
            .references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        let handle_references = slot
            .handle_references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        slot.references = references;
        slot.handle_references = handle_references;
        Ok(())
    }

    /// Duplicate an I/O reference already held by an admitted operation.
    pub fn retain_referenced_io(&mut self, id: u32) -> Result<(), u32> {
        let slot = self
            .slots
            .get_mut(open_slot(id))
            .filter(|slot| slot.occupied && slot.generation == open_generation(id))
            .ok_or(STATUS_INVALID_HANDLE)?;
        slot.references = duplicate_body_reference(slot.references, slot.handle_references)?;
        Ok(())
    }

    pub fn retain_io(&mut self, id: u32) -> Result<(), u32> {
        let slot = self
            .slots
            .get_mut(open_slot(id))
            .filter(|slot| {
                slot.occupied
                    && slot.generation == open_generation(id)
                    && slot.handle_references != 0
            })
            .ok_or(STATUS_INVALID_HANDLE)?;
        slot.references = slot
            .references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        Ok(())
    }

    pub fn set_signaled(&mut self, id: u32, signaled: bool) -> Result<(), u32> {
        self.get_mut(id)?.signaled = signaled;
        Ok(())
    }

    pub fn is_signaled(&self, id: u32) -> Result<bool, u32> {
        self.get(id).map(|open| open.signaled)
    }

    /// Whether releasing one process handle will issue this FILE_OBJECT's cleanup/close.
    pub fn is_final_reference(&self, id: u32) -> Result<bool, u32> {
        self.slots
            .get(open_slot(id))
            .filter(|slot| {
                slot.occupied
                    && slot.generation == open_generation(id)
                    && slot.handle_references != 0
            })
            .map(|slot| slot.handle_references == 1)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn release(&mut self, id: u32) -> Result<(), u32> {
        let slot = self
            .slots
            .get_mut(open_slot(id))
            .filter(|slot| slot.occupied && slot.generation == open_generation(id))
            .ok_or(STATUS_INVALID_HANDLE)?;
        if slot.handle_references == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        slot.handle_references -= 1;
        slot.references -= 1;
        if slot.references == 0 {
            slot.vacate();
        }
        Ok(())
    }

    pub fn release_io(&mut self, id: u32) -> Result<(), u32> {
        let slot = self
            .slots
            .get_mut(open_slot(id))
            .filter(|slot| slot.occupied && slot.generation == open_generation(id))
            .ok_or(STATUS_INVALID_HANDLE)?;
        if slot.references == slot.handle_references {
            return Err(STATUS_INVALID_HANDLE);
        }
        slot.references -= 1;
        if slot.references == 0 {
            slot.vacate();
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        for slot in &mut self.slots {
            if slot.occupied {
                slot.vacate();
            }
        }
    }
}

impl<const SLOTS: usize> Default for ReadOnlyFileOpenTable<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{DirectoryOpenSlot, DirectoryOpenTable};
    extern crate std;

    fn fat_short_name(name: &str) -> crate::FatShortName {
        crate::FatShortName::from_units(&name.encode_utf16().collect::<std::vec::Vec<_>>()).unwrap()
    }

    fn pressure_open<const SLOTS: usize>(
        table: &mut ReadOnlyFileOpenTable<SLOTS>,
    ) -> Result<u32, u32> {
        table.create(
            41,
            64,
            b"retained-image",
            crate::FILE_READ_DATA,
            crate::FILE_SHARE_READ,
            0,
            crate::FileMetadata::default(),
            crate::FatShortName::EMPTY,
        )
    }

    #[test]
    fn readonly_usage_observes_retention_and_exact_cleanup_without_mutation() {
        let mut table = ReadOnlyFileOpenTable::<2>::new();
        let empty = ReadOnlyFileOpenUsage {
            allocated_slots: 0,
            slot_limit: 2,
            occupied_bodies: 0,
            io_only_bodies: 0,
            total_handle_refs: 0,
            generation_exhausted_slots: 0,
        };
        assert_eq!(table.usage(), empty);
        let id = pressure_open(&mut table).unwrap();
        table.retain(id).unwrap();
        table.retain_io(id).unwrap();
        let opened = ReadOnlyFileOpenUsage {
            allocated_slots: 1,
            occupied_bodies: 1,
            total_handle_refs: 2,
            ..empty
        };
        assert_eq!(table.usage(), opened);
        table.release(id).unwrap();
        table.release(id).unwrap();
        let retained = ReadOnlyFileOpenUsage {
            total_handle_refs: 0,
            io_only_bodies: 1,
            ..opened
        };
        assert_eq!(table.usage(), retained);
        assert_eq!(table.usage(), retained);
        assert!(table.get(id).is_ok());
        table.release_io(id).unwrap();
        assert_eq!(
            table.usage(),
            ReadOnlyFileOpenUsage {
                allocated_slots: 1,
                ..empty
            }
        );
        let reused = pressure_open(&mut table).unwrap();
        assert_ne!(id, reused);
        assert_eq!(table.get(id), Err(STATUS_INVALID_HANDLE));
        table.release(reused).unwrap();
    }

    #[test]
    fn readonly_usage_counts_exhausted_generations_only_after_final_release() {
        let mut table = ReadOnlyFileOpenTable::<1>::new();
        table.slots.push(ReadOnlyFileOpenSlot::empty());
        table.slots[0].generation = u16::MAX as u32;
        let id = pressure_open(&mut table).unwrap();
        table.retain_io(id).unwrap();
        table.release(id).unwrap();
        assert_eq!(table.usage().generation_exhausted_slots, 0);
        assert_eq!(table.usage().io_only_bodies, 1);
        table.release_io(id).unwrap();
        assert_eq!(
            table.usage(),
            ReadOnlyFileOpenUsage {
                allocated_slots: 1,
                slot_limit: 1,
                occupied_bodies: 0,
                io_only_bodies: 0,
                total_handle_refs: 0,
                generation_exhausted_slots: 1,
            }
        );
        assert_eq!(
            pressure_open(&mut table),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
    }

    #[test]
    fn default_readonly_table_preserves_sixty_four_closed_handle_io_owners() {
        let mut table: ReadOnlyFileOpenTable = ReadOnlyFileOpenTable::new();
        assert!(
            table.slots.is_empty(),
            "identity-space budget must not preallocate the arena"
        );
        let mut retained = alloc::vec::Vec::new();
        for _ in 0..64 {
            let id = pressure_open(&mut table).unwrap();
            table.retain_io(id).unwrap();
            table.release(id).unwrap();
            retained.push(id);
        }
        let next = pressure_open(&mut table)
            .expect("retained sources do not impose a 64-body native limit");
        assert_eq!(open_slot(next), 64);
        let first = retained[0];
        for id in retained {
            assert_eq!(table.get(id).unwrap().first_cluster, 41);
            assert_eq!(table.retain_io(id), Err(STATUS_INVALID_HANDLE));
            table.release_io(id).unwrap();
            assert_eq!(table.get(id), Err(STATUS_INVALID_HANDLE));
        }
        assert!(table.get(next).is_ok());
        table.release(next).unwrap();
        let reused = pressure_open(&mut table).unwrap();
        assert_eq!(open_slot(reused), open_slot(first));
        assert_ne!(reused, first);
        assert_eq!(table.get(first), Err(STATUS_INVALID_HANDLE));
        table.release(reused).unwrap();
    }

    #[test]
    fn explicit_readonly_budget_refuses_without_reclaiming_live_io_owners() {
        let mut table = ReadOnlyFileOpenTable::<64>::new();
        let mut retained = alloc::vec::Vec::new();
        for _ in 0..64 {
            let id = pressure_open(&mut table).unwrap();
            table.retain_io(id).unwrap();
            table.release(id).unwrap();
            retained.push(id);
        }
        assert_eq!(
            pressure_open(&mut table),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        for id in &retained {
            assert!(table.get(*id).is_ok());
        }
        let old = retained.remove(0);
        table.release_io(old).unwrap();
        let reused = pressure_open(&mut table).unwrap();
        assert_ne!(reused, old);
        assert_eq!(table.get(old), Err(STATUS_INVALID_HANDLE));
        table.release(reused).unwrap();
        for id in retained {
            table.release_io(id).unwrap();
        }
    }

    #[test]
    fn readonly_file_referenced_io_survives_probe_handle_close() {
        let mut table = ReadOnlyFileOpenTable::<1>::new();
        let create = |table: &mut ReadOnlyFileOpenTable<1>| {
            table
                .create(
                    41,
                    64,
                    b"file",
                    crate::FILE_READ_DATA,
                    0,
                    0,
                    crate::FileMetadata::default(),
                    crate::FatShortName::EMPTY,
                )
                .unwrap()
        };
        let object = create(&mut table);
        table.retain_io(object).unwrap();
        table.release(object).unwrap();
        assert_eq!(table.retain_io(object), Err(STATUS_INVALID_HANDLE));
        table.retain_referenced_io(object).unwrap();
        table.release_io(object).unwrap();
        assert!(table.get(object).is_ok());
        table.release_io(object).unwrap();
        assert_eq!(
            table.retain_referenced_io(object),
            Err(STATUS_INVALID_HANDLE)
        );
        let reused = create(&mut table);
        assert_ne!(reused, object);
        assert_eq!(
            table.retain_referenced_io(reused),
            Err(STATUS_INVALID_HANDLE)
        );
        table.retain_io(reused).unwrap();
        assert_eq!(
            table.retain_referenced_io(object),
            Err(STATUS_INVALID_HANDLE)
        );
        table.release_io(reused).unwrap();
        table.release(reused).unwrap();
    }

    #[test]
    fn readonly_file_open_references_share_position() {
        const EMPTY: ReadOnlyFileOpenTable<2> = ReadOnlyFileOpenTable::new();
        let mut table = EMPTY;
        assert!(table.slots.is_empty());
        let alternate_name = fat_short_name("NTDLL.DLL");
        let shared = table
            .create(
                41,
                64,
                b"reactos\\system32\\ntdll.dll",
                0,
                0,
                0x20,
                crate::FileMetadata::default(),
                alternate_name,
            )
            .unwrap();
        let independent = table
            .create(
                41,
                64,
                b"reactos\\system32\\ntdll.dll",
                0,
                0,
                0x10,
                crate::FileMetadata::default(),
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_eq!(table.slots.len(), 2);
        assert_eq!(
            table.create(
                77,
                1,
                b"reactos\\other",
                0,
                0,
                0,
                crate::FileMetadata::default(),
                crate::FatShortName::EMPTY,
            ),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        table.retain(shared).unwrap();
        assert_eq!(table.is_final_reference(shared), Ok(false));
        assert_eq!(table.is_signaled(shared), Ok(true));
        table.set_signaled(shared, false).unwrap();
        table.get_mut(shared).unwrap().current_offset = 17;
        assert_eq!(table.get(shared).unwrap().current_offset, 17);
        assert_eq!(
            table.get(shared).unwrap().alternate_name.units(),
            alternate_name.units()
        );
        assert_eq!(
            table.get(shared).unwrap().volume_relative_path(),
            b"reactos\\system32\\ntdll.dll"
        );
        assert_eq!(table.get(independent).unwrap().current_offset, 0);
        table.release(shared).unwrap();
        assert_eq!(table.is_final_reference(shared), Ok(true));
        assert_eq!(table.is_signaled(shared), Ok(false));
        table.set_signaled(shared, true).unwrap();
        assert_eq!(table.get(shared).unwrap().first_cluster, 41);
        assert_eq!(table.get(shared).unwrap().create_options, 0x20);
        table.release(shared).unwrap();
        assert_eq!(table.get(shared), Err(STATUS_INVALID_HANDLE));
        let reused = table
            .create(
                99,
                128,
                b"reactos\\x",
                0,
                0,
                0,
                crate::FileMetadata::default(),
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_ne!(reused, shared);
        assert_eq!(table.get(shared), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.retain(shared), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.release(shared), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.get(reused).unwrap().first_cluster, 99);
    }

    #[test]
    fn readonly_file_io_reference_survives_last_handle_cleanup() {
        let mut table = ReadOnlyFileOpenTable::<2>::new();
        let metadata = crate::FileMetadata {
            end_of_file: 64,
            file_id: 41,
            ..crate::FileMetadata::default()
        };
        let options = crate::FILE_SYNCHRONOUS_IO_NONALERT;
        let object = table
            .create(
                41,
                64,
                b"reactos\\system32\\ntdll.dll",
                crate::FILE_READ_DATA,
                0,
                options,
                metadata,
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_eq!(
            table.check_share(
                b"reactos\\system32\\ntdll.dll",
                metadata,
                crate::FILE_READ_DATA,
                0
            ),
            Err(STATUS_SHARING_VIOLATION)
        );
        table.retain_io(object).unwrap();
        table.get_mut(object).unwrap().current_offset = 17;
        table.release(object).unwrap();
        assert_eq!(table.is_final_reference(object), Err(STATUS_INVALID_HANDLE));
        let body = table.get(object).unwrap();
        assert_eq!(body.metadata, metadata);
        assert_eq!(body.first_cluster, 41);
        assert_eq!(body.size, 64);
        assert_eq!(body.current_offset, 17);
        assert_eq!(body.create_options, options);
        let reopened = table
            .create(
                41,
                64,
                b"reactos\\system32\\ntdll.dll",
                crate::FILE_READ_DATA,
                0,
                options,
                metadata,
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_eq!(table.get(reopened).unwrap().current_offset, 0);
        assert_eq!(table.set_signaled(object, true), Ok(()));
        table.release_io(object).unwrap();
        assert_eq!(table.get(object), Err(STATUS_INVALID_HANDLE));
        table.release(reopened).unwrap();
        let reused = table
            .create(
                41,
                64,
                b"reactos\\system32\\ntdll.dll",
                crate::FILE_READ_DATA,
                0,
                options,
                metadata,
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_ne!(reused, object);
        assert_eq!(table.retain_io(object), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.release_io(object), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.get_mut(object), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.get(reused).unwrap().current_offset, 0);
    }

    #[test]
    fn readonly_file_open_table_clear_reuses_fixed_storage() {
        let mut table = ReadOnlyFileOpenTable::<2>::new();
        let first = table
            .create(
                41,
                64,
                b"reactos\\a",
                0,
                0,
                0,
                crate::FileMetadata::default(),
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        table.retain(first).unwrap();
        table
            .create(
                42,
                128,
                b"reactos\\b",
                0,
                0,
                0,
                crate::FileMetadata::default(),
                crate::FatShortName::EMPTY,
            )
            .unwrap();

        table.clear();

        assert_eq!(table.get(first), Err(STATUS_INVALID_HANDLE));
        let reused = table
            .create(
                99,
                1,
                b"",
                0,
                0,
                0,
                crate::FileMetadata::default(),
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_ne!(reused, first);
        assert_eq!(table.get(first), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.release(first), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.get(reused).unwrap().first_cluster, 99);
        let second = table
            .create(
                100,
                2,
                b"reactos",
                0,
                0,
                0,
                crate::FileMetadata::default(),
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_eq!(open_slot(second), 1);
        assert_ne!(second, 1);
    }

    #[test]
    fn fat_open_generations_retire_instead_of_wrapping() {
        let metadata = crate::FileMetadata::default();
        let mut directories = DirectoryOpenTable::<1>::new();
        directories.slots.push(DirectoryOpenSlot::empty());
        directories.slots[0].generation = u16::MAX as u32;
        let directory = directories
            .create(
                41,
                b"reactos",
                0,
                0,
                0,
                metadata,
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        directories.release(directory).unwrap();
        assert_eq!(directories.get(directory), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            directories.create(42, b"other", 0, 0, 0, metadata, crate::FatShortName::EMPTY),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );

        let mut files = ReadOnlyFileOpenTable::<1>::new();
        files.slots.push(ReadOnlyFileOpenSlot::empty());
        files.slots[0].generation = u16::MAX as u32;
        let file = files
            .create(
                41,
                64,
                b"reactos\\a",
                0,
                0,
                0,
                metadata,
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        files.retain_io(file).unwrap();
        files.release(file).unwrap();
        assert_eq!(files.get(file).unwrap().first_cluster, 41);
        files.release_io(file).unwrap();
        assert_eq!(files.get(file), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            files.create(
                42,
                64,
                b"reactos\\b",
                0,
                0,
                0,
                metadata,
                crate::FatShortName::EMPTY
            ),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
    }

    #[test]
    fn fat_open_tables_enforce_stable_identity_share_claims_until_final_release() {
        let directory_metadata = crate::FileMetadata {
            file_id: 0xD1,
            is_directory: true,
            ..crate::FileMetadata::default()
        };
        let mut directories = DirectoryOpenTable::<3>::new();
        let directory = directories
            .create(
                41,
                b"reactos\\system32",
                crate::FILE_READ_DATA,
                crate::FILE_SHARE_READ,
                0,
                directory_metadata,
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_eq!(
            directories.create(
                41,
                b"REACTOS\\SYSTEM32",
                crate::FILE_WRITE_DATA,
                crate::FILE_SHARE_READ | crate::FILE_SHARE_WRITE,
                0,
                directory_metadata,
                crate::FatShortName::EMPTY,
            ),
            Err(STATUS_SHARING_VIOLATION)
        );
        directories.retain(directory).unwrap();
        directories.release(directory).unwrap();
        assert_eq!(
            directories.check_share(
                b"reactos\\system32",
                directory_metadata,
                crate::FILE_WRITE_DATA,
                crate::FILE_SHARE_READ | crate::FILE_SHARE_WRITE,
            ),
            Err(STATUS_SHARING_VIOLATION)
        );
        directories.release(directory).unwrap();
        assert_eq!(
            directories.check_share(
                b"reactos\\system32",
                directory_metadata,
                crate::FILE_WRITE_DATA,
                crate::FILE_SHARE_WRITE,
            ),
            Ok(())
        );

        let file_metadata = crate::FileMetadata {
            file_id: 0xF1,
            end_of_file: 64,
            ..crate::FileMetadata::default()
        };
        let mut files = ReadOnlyFileOpenTable::<2>::new();
        let file = files
            .create(
                51,
                64,
                b"reactos\\system32\\ntdll.dll",
                crate::FILE_READ_DATA,
                crate::FILE_SHARE_READ,
                0,
                file_metadata,
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_eq!(
            files.check_share(
                b"reactos\\system32\\ntdll.dll",
                file_metadata,
                crate::FILE_WRITE_DATA,
                crate::FILE_SHARE_READ | crate::FILE_SHARE_WRITE,
            ),
            Err(STATUS_SHARING_VIOLATION)
        );
        files.release(file).unwrap();
        let reopened = files
            .create(
                51,
                64,
                b"reactos\\system32\\ntdll.dll",
                crate::FILE_WRITE_DATA,
                crate::FILE_SHARE_WRITE,
                0,
                file_metadata,
                crate::FatShortName::EMPTY,
            )
            .unwrap();
        assert_ne!(reopened, file);
        assert_eq!(files.get(file), Err(STATUS_INVALID_HANDLE));
    }
}
