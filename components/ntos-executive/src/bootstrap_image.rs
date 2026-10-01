//! Persistent installed-file ownership for the initial hosted image bootstrap.

pub(crate) struct InstalledImage {
    source_va: u64,
    length: u32,
}

impl InstalledImage {
    pub(crate) fn source_va(&self) -> u64 {
        self.source_va
    }

    pub(crate) fn bytes(&self) -> &'static [u8] {
        // The filesystem pool retains its mapped frames for the executive lifetime;
        // spawned image fault sources therefore outlive this bootstrap descriptor.
        unsafe { core::slice::from_raw_parts(self.source_va as *const u8, self.length as usize) }
    }
}

pub(crate) unsafe fn load_installed(path: &[u8]) -> Option<InstalledImage> {
    let fs = crate::fs_loader::exec_fs()?;
    let (source_va, length) = crate::fs_loader::load_file_to_pool(&fs, path)?;
    Some(InstalledImage { source_va, length })
}
