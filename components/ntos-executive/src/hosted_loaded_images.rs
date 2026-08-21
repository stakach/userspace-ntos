//! Loop-owned loaded hosted executable image registry.
//!
//! The SEC_IMAGE service loop owns this table. Parsed PE objects and their resident pool bytes are
//! keyed by hosted process index, so syscall handlers consume one dynamic lookup boundary instead of
//! bootstrap-specific image locals.
#![allow(clippy::all)]

use alloc::vec::Vec;

use crate::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostedLoadedImageRegistrationError {
    InvalidPi,
    InvalidLeaf,
    InvalidPoolVa,
    DuplicatePi,
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

pub(crate) struct HostedLoadedImageTable {
    entries: Vec<Option<HostedLoadedImage>>,
    pes: Vec<Option<nt_pe_loader::PeFile<'static>>>,
}

impl HostedLoadedImageTable {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            pes: Vec::new(),
        }
    }

    pub(crate) fn reset(&mut self, slots: usize) -> bool {
        self.entries.clear();
        self.pes.clear();
        if self.entries.try_reserve(slots).is_err() || self.pes.try_reserve(slots).is_err() {
            HOSTED_LOADED_IMAGE_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        while self.entries.len() < slots {
            self.entries.push(None);
        }
        while self.pes.len() < slots {
            self.pes.push(None);
        }
        true
    }

    pub(crate) fn register_if_loaded(
        &mut self,
        image: nt_exe_image::HostedProcessImageRef<'_>,
        pe: Option<nt_pe_loader::PeFile<'static>>,
        pool_va: u64,
    ) -> Result<(), HostedLoadedImageRegistrationError> {
        if pe.is_none() {
            return Ok(());
        }
        if image.pi >= MAX_PI || image.pi >= self.entries.len() || image.pi >= self.pes.len() {
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
        if self.entries[image.pi].is_some() || self.pes[image.pi].is_some() {
            return Err(HostedLoadedImageRegistrationError::DuplicatePi);
        }

        let mut stored_leaf = [0u8; nt_exe_image::MAX_EXE_LEAF];
        stored_leaf[..image.leaf.len()].copy_from_slice(image.leaf);
        self.pes[image.pi] = pe;
        self.entries[image.pi] = Some(HostedLoadedImage {
            leaf: stored_leaf,
            leaf_len: image.leaf.len(),
            pool_va,
        });
        Ok(())
    }

    pub(crate) fn get_by_pi(&self, pi: usize) -> Option<HostedLoadedImage> {
        self.entries.get(pi).and_then(|entry| *entry)
    }

    pub(crate) unsafe fn pe_by_pi<'a>(
        &'a self,
        pi: usize,
    ) -> Option<&'a nt_pe_loader::PeFile<'static>> {
        self.get_by_pi(pi)?;
        self.pes.get(pi)?.as_ref()
    }

    pub(crate) unsafe fn pe_and_pool_by_leaf<'a>(
        &'a self,
        leaf: &[u8],
    ) -> Option<(&'a nt_pe_loader::PeFile<'static>, u64)> {
        let (pi, entry) = self.entries.iter().enumerate().find_map(|(pi, entry)| {
            let entry = entry.as_ref()?;
            entry
                .leaf()
                .eq_ignore_ascii_case(leaf)
                .then_some((pi, entry))
        })?;
        let pe = self.pes.get(pi)?.as_ref()?;
        Some((pe, entry.pool_va()))
    }

    pub(crate) unsafe fn pe_and_pool_for_image<'a>(
        &'a self,
        hosted: nt_exe_image::HostedProcessImageRef<'_>,
    ) -> Option<(&'a nt_pe_loader::PeFile<'static>, u64)> {
        let entry = self.get_by_pi(hosted.pi)?;
        if !entry.leaf().eq_ignore_ascii_case(hosted.leaf) {
            return None;
        }
        let pe = self.pes.get(hosted.pi)?.as_ref()?;
        Some((pe, entry.pool_va()))
    }

    pub(crate) fn store_stats(&self) -> (usize, usize, usize, usize, u64) {
        (
            self.entries.len(),
            self.entries.capacity(),
            self.pes.len(),
            self.pes.capacity(),
            HOSTED_LOADED_IMAGE_ALLOCATION_FAILURES.load(Ordering::Relaxed),
        )
    }
}

static HOSTED_LOADED_IMAGE_ALLOCATION_FAILURES: AtomicU64 = AtomicU64::new(0);
