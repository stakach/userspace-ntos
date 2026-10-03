//! Loop-owned hosted executable cache and process-instance attachments.
//!
//! Bootstrap entries are durable leaf-keyed cache entries. Native process snapshots instead own
//! exact-generation private bytes until mechanism retirement and all scoped readers drain.
//! Boxed parsed descriptors remain stable across cache growth and other entries' retirement.
#![allow(clippy::all)]

use alloc::{boxed::Box, vec::Vec};

use crate::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostedLoadedImageRegistrationError {
    InvalidPi,
    InvalidLeaf,
    InvalidPoolVa,
    DuplicatePi,
    AllocationFailure,
    NotFound,
    StaleIdentity,
    StillAttached,
    LiveReaders,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostedImageReader {
    authority: u64,
    serial: u64,
    target: nt_exe_image::SpawnTarget,
}

#[derive(Clone, Copy)]
struct HostedLoadedImageAttachment {
    cache_index: usize,
    generation: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct HostedLoadedImage {
    leaf: [u8; nt_exe_image::MAX_EXE_LEAF],
    leaf_len: usize,
    pool_va: u64,
}

impl HostedLoadedImage {
    pub(crate) fn leaf(&self) -> &[u8] {
        &self.leaf[..self.leaf_len]
    }

    pub(crate) fn pool_va(&self) -> u64 {
        self.pool_va
    }
}

struct HostedLoadedImageCacheEntry {
    image: HostedLoadedImage,
    pe: nt_pe_loader::PeFile<'static>,
    /// Exact snapshots own their immutable bytes independently of the Section's retained File.
    owned_bytes: Option<Vec<u8>>,
    owner: Option<nt_exe_image::SpawnTarget>,
}

fn try_box_entry(
    entry: HostedLoadedImageCacheEntry,
) -> Result<Box<HostedLoadedImageCacheEntry>, HostedLoadedImageRegistrationError> {
    let layout = core::alloc::Layout::new::<HostedLoadedImageCacheEntry>();
    // Stable Rust has no fallible Box constructor. This exact nonzero layout is allocated once;
    // ownership transfers to Box only after allocation succeeds and the entry is initialized.
    let pointer = unsafe { alloc::alloc::alloc(layout) }.cast::<HostedLoadedImageCacheEntry>();
    if pointer.is_null() {
        HOSTED_LOADED_IMAGE_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Err(HostedLoadedImageRegistrationError::AllocationFailure);
    }
    unsafe {
        pointer.write(entry);
        Ok(Box::from_raw(pointer))
    }
}

pub(crate) struct HostedLoadedImageTable {
    attachments: Vec<Option<HostedLoadedImageAttachment>>,
    cache: Vec<Box<HostedLoadedImageCacheEntry>>,
    readers: Vec<HostedImageReader>,
    authority: u64,
    next_reader: u64,
}

impl HostedLoadedImageTable {
    pub(crate) const fn new() -> Self {
        Self {
            attachments: Vec::new(),
            cache: Vec::new(),
            readers: Vec::new(),
            authority: 0,
            next_reader: 1,
        }
    }

    pub(crate) fn reset(&mut self, slots: usize) -> bool {
        if !self.readers.is_empty() || self.cache.iter().any(|entry| entry.owner.is_some()) {
            return false;
        }
        if self.authority == 0 {
            let Ok(authority) = HOSTED_LOADED_IMAGE_AUTHORITIES.fetch_update(
                Ordering::Relaxed, Ordering::Relaxed, |value| value.checked_add(1),
            ) else { return false; };
            self.authority = authority;
        }
        self.attachments.clear();
        self.cache.clear();
        if self.attachments.try_reserve(slots).is_err()
            || self.cache.try_reserve(slots).is_err()
        {
            HOSTED_LOADED_IMAGE_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        while self.attachments.len() < slots {
            self.attachments.push(None);
        }
        true
    }

    pub(crate) fn register_if_loaded(
        &mut self,
        image: nt_exe_image::HostedProcessImageRef<'_>,
        pe: Option<nt_pe_loader::PeFile<'static>>,
        pool_va: u64,
    ) -> Result<(), HostedLoadedImageRegistrationError> {
        let Some(pe) = pe else {
            return Ok(());
        };
        if image.pi >= MAX_PI || image.pi >= self.attachments.len() {
            return Err(HostedLoadedImageRegistrationError::InvalidPi);
        }
        let Some(leaf) = nt_exe_image::canonical_exe_leaf(image.leaf) else {
            return Err(HostedLoadedImageRegistrationError::InvalidLeaf);
        };
        if leaf.len() != image.leaf.len()
            || image.leaf.len() > nt_exe_image::MAX_EXE_LEAF
            || !leaf.eq_ignore_ascii_case(image.leaf)
        {
            return Err(HostedLoadedImageRegistrationError::InvalidLeaf);
        }
        if pool_va == 0 {
            return Err(HostedLoadedImageRegistrationError::InvalidPoolVa);
        }
        if self.attachments[image.pi].is_some() {
            return Err(HostedLoadedImageRegistrationError::DuplicatePi);
        }

        let cache_index = match self
            .cache
            .iter()
            .position(|entry| entry.owned_bytes.is_none() && entry.image.leaf().eq_ignore_ascii_case(image.leaf))
        {
            Some(index) => index,
            None => {
                if self.cache.try_reserve(1).is_err() {
                    HOSTED_LOADED_IMAGE_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
                    return Err(HostedLoadedImageRegistrationError::AllocationFailure);
                }
                let mut stored_leaf = [0u8; nt_exe_image::MAX_EXE_LEAF];
                stored_leaf[..image.leaf.len()].copy_from_slice(image.leaf);
                let index = self.cache.len();
                let entry = try_box_entry(HostedLoadedImageCacheEntry {
                    image: HostedLoadedImage {
                        leaf: stored_leaf,
                        leaf_len: image.leaf.len(),
                        pool_va,
                    },
                    pe,
                    owned_bytes: None,
                    owner: None,
                })?;
                self.cache.push(entry);
                index
            }
        };
        self.attachments[image.pi] = Some(HostedLoadedImageAttachment {
            cache_index,
            generation: image.generation,
        });
        Ok(())
    }

    pub(crate) fn register_exact_loaded(
        &mut self,
        image: nt_exe_image::HostedProcessImageRef<'_>,
        bytes: Vec<u8>,
    ) -> Result<(), HostedLoadedImageRegistrationError> {
        if image.pi >= MAX_PI || image.pi >= self.attachments.len() {
            return Err(HostedLoadedImageRegistrationError::InvalidPi);
        }
        if self.attachments[image.pi].is_some() {
            return Err(HostedLoadedImageRegistrationError::DuplicatePi);
        }
        if image.leaf.is_empty() || image.leaf.len() > nt_exe_image::MAX_EXE_LEAF {
            return Err(HostedLoadedImageRegistrationError::InvalidLeaf);
        }
        self.cache.try_reserve(1).map_err(|_| HostedLoadedImageRegistrationError::AllocationFailure)?;
        let pool_va = bytes.as_ptr() as u64;
        // The cache owns this Vec and never mutates its allocation. Parsed references are used
        // only while the durable table remains live, exactly as its existing resident PE cache.
        let resident = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), bytes.len()) };
        let pe = nt_pe_loader::PeFile::parse(resident)
            .map_err(|_| HostedLoadedImageRegistrationError::InvalidPoolVa)?;
        let mut leaf = [0; nt_exe_image::MAX_EXE_LEAF];
        leaf[..image.leaf.len()].copy_from_slice(image.leaf);
        let index = self.cache.len();
        let entry = try_box_entry(HostedLoadedImageCacheEntry {
            image: HostedLoadedImage { leaf, leaf_len: image.leaf.len(), pool_va },
            pe, owned_bytes: Some(bytes),
            owner: Some(nt_exe_image::SpawnTarget::from_image(image)),
        })?;
        self.cache.push(entry);
        self.attachments[image.pi] = Some(HostedLoadedImageAttachment {
            cache_index: index, generation: image.generation,
        });
        Ok(())
    }

    fn attachment_for_pi(&self, pi: usize) -> Option<HostedLoadedImageAttachment> {
        self.attachments.get(pi).and_then(|entry| *entry)
    }

    pub(crate) fn get_by_pi(&self, pi: usize) -> Option<HostedLoadedImage> {
        let attachment = self.attachment_for_pi(pi)?;
        self.cache
            .get(attachment.cache_index)
            .map(|entry| entry.image)
    }

    pub(crate) unsafe fn pe_by_pi<'a>(
        &'a self,
        pi: usize,
    ) -> Option<&'a nt_pe_loader::PeFile<'static>> {
        let attachment = self.attachment_for_pi(pi)?;
        self.cache.get(attachment.cache_index).map(|entry| &entry.pe)
    }

    pub(crate) unsafe fn pe_and_pool_by_leaf<'a>(
        &'a self,
        leaf: &[u8],
    ) -> Option<(&'a nt_pe_loader::PeFile<'static>, u64)> {
        let entry = self
            .cache
            .iter()
            .find(|entry| entry.owned_bytes.is_none() && entry.image.leaf().eq_ignore_ascii_case(leaf))?;
        Some((&entry.pe, entry.image.pool_va()))
    }

    pub(crate) unsafe fn pe_and_pool_for_image<'a>(
        &'a self,
        hosted: nt_exe_image::HostedProcessImageRef<'_>,
    ) -> Option<(&'a nt_pe_loader::PeFile<'static>, u64)> {
        let attachment = self.attachment_for_pi(hosted.pi)?;
        if attachment.generation != hosted.generation {
            return None;
        }
        let entry = self.cache.get(attachment.cache_index)?;
        if !entry.image.leaf().eq_ignore_ascii_case(hosted.leaf) {
            return None;
        }
        Some((&entry.pe, entry.image.pool_va()))
    }

    pub(crate) fn matches_target(&self, target: nt_exe_image::SpawnTarget) -> bool {
        self.attachment_for_pi(target.pi)
            .is_some_and(|attachment| attachment.generation == target.generation)
    }

    pub(crate) fn retire_exact(
        &mut self,
        target: nt_exe_image::SpawnTarget,
    ) -> Result<(), HostedLoadedImageRegistrationError> {
        let attachment = self
            .attachments
            .get_mut(target.pi)
            .ok_or(HostedLoadedImageRegistrationError::InvalidPi)?;
        let current = attachment.ok_or(HostedLoadedImageRegistrationError::NotFound)?;
        if current.generation != target.generation {
            return Err(HostedLoadedImageRegistrationError::StaleIdentity);
        }
        *attachment = None;
        Ok(())
    }

    pub(crate) fn acquire_snapshot_reader(
        &mut self,
        target: nt_exe_image::SpawnTarget,
    ) -> Result<HostedImageReader, HostedLoadedImageRegistrationError> {
        if !self.matches_target(target) || self.authority == 0 {
            return Err(HostedLoadedImageRegistrationError::StaleIdentity);
        }
        let next = self.next_reader.checked_add(1)
            .ok_or(HostedLoadedImageRegistrationError::AllocationFailure)?;
        self.readers.try_reserve(1)
            .map_err(|_| HostedLoadedImageRegistrationError::AllocationFailure)?;
        let reader = HostedImageReader { authority: self.authority, serial: self.next_reader, target };
        self.next_reader = next;
        self.readers.push(reader);
        Ok(reader)
    }

    pub(crate) fn release_snapshot_reader(
        &mut self,
        reader: HostedImageReader,
    ) -> Result<(), HostedLoadedImageRegistrationError> {
        if reader.authority != self.authority {
            return Err(HostedLoadedImageRegistrationError::StaleIdentity);
        }
        let index = self.readers.iter().position(|entry| *entry == reader)
            .ok_or(HostedLoadedImageRegistrationError::StaleIdentity)?;
        self.readers.swap_remove(index);
        Ok(())
    }

    /// Transfer private backing only after both mechanism retirement and parsed readers have
    /// drained. The caller supplies the mechanism acknowledgement; this table fences readers.
    pub(crate) fn retire_exact_snapshot(
        &mut self,
        target: nt_exe_image::SpawnTarget,
    ) -> Result<Vec<u8>, HostedLoadedImageRegistrationError> {
        let index = self.cache.iter().position(|entry| entry.owner == Some(target))
            .ok_or(HostedLoadedImageRegistrationError::NotFound)?;
        if self.matches_target(target) {
            return Err(HostedLoadedImageRegistrationError::StillAttached);
        }
        if self.readers.iter().any(|reader| reader.target == target) {
            return Err(HostedLoadedImageRegistrationError::LiveReaders);
        }
        let entry = self.cache.swap_remove(index);
        for attachment in self.attachments.iter_mut().flatten() {
            if attachment.cache_index == self.cache.len() {
                attachment.cache_index = index;
            }
        }
        let HostedLoadedImageCacheEntry { pe, owned_bytes, .. } = *entry;
        // Remove every retained parsed reference before transferring the allocation for Drop.
        core::mem::drop(pe);
        Ok(owned_bytes.expect("private snapshot owns its exact byte allocation"))
    }

    pub(crate) fn store_stats(&self) -> (usize, usize, usize, usize, u64) {
        (
            self.attachments.len(),
            self.attachments.capacity(),
            self.cache.len(),
            self.cache.capacity(),
            HOSTED_LOADED_IMAGE_ALLOCATION_FAILURES.load(Ordering::Relaxed),
        )
    }
}

static HOSTED_LOADED_IMAGE_ALLOCATION_FAILURES: AtomicU64 = AtomicU64::new(0);
static HOSTED_LOADED_IMAGE_AUTHORITIES: AtomicU64 = AtomicU64::new(1);

/// A raw table pointer avoids retaining a mutable table borrow across provider IPC/callbacks.
pub(crate) struct HostedImageReadScope {
    table: *mut HostedLoadedImageTable,
    reader: HostedImageReader,
}

impl HostedImageReadScope {
    pub(crate) unsafe fn capture(
        table: *mut HostedLoadedImageTable,
        target: nt_exe_image::SpawnTarget,
    ) -> Result<Self, HostedLoadedImageRegistrationError> {
        let reader = unsafe { (&mut *table).acquire_snapshot_reader(target)? };
        Ok(Self { table, reader })
    }
}

impl Drop for HostedImageReadScope {
    fn drop(&mut self) {
        unsafe { (&mut *self.table).release_snapshot_reader(self.reader) }
            .expect("exact hosted image reader scope must release once");
    }
}
