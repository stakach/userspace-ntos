//! Loop-owned hosted executable cache and process-instance attachments.
//!
//! Parsed PE files and their resident pool bytes are durable executable cache entries keyed by
//! canonical leaf. Active process indices hold only generation-tagged attachments to that cache,
//! so terminating one process can release its PI without reloading the executable or exposing an
//! old attachment after PI reuse.
#![allow(clippy::all)]

use alloc::vec::Vec;

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
}

pub(crate) struct HostedLoadedImageTable {
    attachments: Vec<Option<HostedLoadedImageAttachment>>,
    cache: Vec<HostedLoadedImageCacheEntry>,
}

impl HostedLoadedImageTable {
    pub(crate) const fn new() -> Self {
        Self {
            attachments: Vec::new(),
            cache: Vec::new(),
        }
    }

    pub(crate) fn reset(&mut self, slots: usize) -> bool {
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
            .position(|entry| entry.image.leaf().eq_ignore_ascii_case(image.leaf))
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
                self.cache.push(HostedLoadedImageCacheEntry {
                    image: HostedLoadedImage {
                        leaf: stored_leaf,
                        leaf_len: image.leaf.len(),
                        pool_va,
                    },
                    pe,
                });
                index
            }
        };
        self.attachments[image.pi] = Some(HostedLoadedImageAttachment {
            cache_index,
            generation: image.generation,
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
            .find(|entry| entry.image.leaf().eq_ignore_ascii_case(leaf))?;
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
