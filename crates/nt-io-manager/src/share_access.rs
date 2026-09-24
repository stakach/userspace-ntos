//! Raw NT I/O Manager share-access accounting for hosted file objects.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileShareState {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub shared_read: bool,
    pub shared_write: bool,
    pub shared_delete: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareAccessCounters {
    pub open_count: u32,
    pub readers: u32,
    pub writers: u32,
    pub deleters: u32,
    pub shared_read: u32,
    pub shared_write: u32,
    pub shared_delete: u32,
}

impl ShareAccessCounters {
    pub fn check(
        &mut self,
        desired_access: u32,
        desired_share_access: u32,
        file: &mut FileShareState,
        update: bool,
        has_extension: bool,
    ) -> Result<(), u32> {
        file.set_access(desired_access);
        if has_extension || !file.has_access() {
            return Ok(());
        }
        let shared_read = desired_share_access & 1 != 0;
        let shared_write = desired_share_access & 2 != 0;
        let shared_delete = desired_share_access & 4 != 0;
        if (file.read && self.shared_read < self.open_count)
            || (file.write && self.shared_write < self.open_count)
            || (file.delete && self.shared_delete < self.open_count)
            || (self.readers != 0 && !shared_read)
            || (self.writers != 0 && !shared_write)
            || (self.deleters != 0 && !shared_delete)
        {
            return Err(0xc000_0043); // STATUS_SHARING_VIOLATION
        }
        file.shared_read = shared_read;
        file.shared_write = shared_write;
        file.shared_delete = shared_delete;
        if update {
            self.update(file, false);
        }
        Ok(())
    }

    pub fn set(
        &mut self,
        desired_access: u32,
        desired_share_access: u32,
        file: &mut FileShareState,
        has_extension: bool,
    ) {
        file.set_access(desired_access);
        if !file.has_access() {
            if !has_extension {
                *self = Self::default();
            }
            return;
        }
        file.shared_read = desired_share_access & 1 != 0;
        file.shared_write = desired_share_access & 2 != 0;
        file.shared_delete = desired_share_access & 4 != 0;
        if !has_extension {
            *self = Self::default();
            self.update(file, false);
        }
    }

    pub fn update(&mut self, file: &FileShareState, has_extension: bool) {
        if has_extension || !file.has_access() {
            return;
        }
        self.open_count = self.open_count.wrapping_add(1);
        self.readers = self.readers.wrapping_add(u32::from(file.read));
        self.writers = self.writers.wrapping_add(u32::from(file.write));
        self.deleters = self.deleters.wrapping_add(u32::from(file.delete));
        self.shared_read = self.shared_read.wrapping_add(u32::from(file.shared_read));
        self.shared_write = self.shared_write.wrapping_add(u32::from(file.shared_write));
        self.shared_delete = self
            .shared_delete
            .wrapping_add(u32::from(file.shared_delete));
    }

    pub fn remove(&mut self, file: &FileShareState, has_extension: bool) {
        if has_extension || !file.has_access() {
            return;
        }
        self.open_count = self.open_count.wrapping_sub(1);
        self.readers = self.readers.wrapping_sub(u32::from(file.read));
        self.writers = self.writers.wrapping_sub(u32::from(file.write));
        self.deleters = self.deleters.wrapping_sub(u32::from(file.delete));
        self.shared_read = self.shared_read.wrapping_sub(u32::from(file.shared_read));
        self.shared_write = self.shared_write.wrapping_sub(u32::from(file.shared_write));
        self.shared_delete = self
            .shared_delete
            .wrapping_sub(u32::from(file.shared_delete));
    }
}

impl FileShareState {
    fn set_access(&mut self, desired_access: u32) {
        self.read = desired_access & (0x1 | 0x20) != 0;
        self.write = desired_access & (0x2 | 0x4) != 0;
        self.delete = desired_access & 0x10000 != 0;
    }

    fn has_access(&self) -> bool {
        self.read || self.write || self.delete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_access_conflicts_and_no_access_opens() {
        let mut counters = ShareAccessCounters::default();
        let mut first = FileShareState::default();
        assert_eq!(counters.check(1, 1, &mut first, true, false), Ok(()));
        assert_eq!(counters.open_count, 1);
        let mut denied = FileShareState::default();
        assert_eq!(
            counters.check(2, 3, &mut denied, true, false),
            Err(0xc000_0043)
        );
        assert!(denied.write);
        assert_eq!(counters.open_count, 1);
        let mut metadata = FileShareState::default();
        assert_eq!(counters.check(0x80, 0, &mut metadata, true, false), Ok(()));
        assert_eq!(counters.open_count, 1);
        counters.remove(&first, false);
        assert_eq!(counters, ShareAccessCounters::default());
    }

    #[test]
    fn check_without_update_then_update_and_remove() {
        let mut counters = ShareAccessCounters::default();
        let mut file = FileShareState::default();
        assert_eq!(counters.check(0x20, 7, &mut file, false, false), Ok(()));
        assert_eq!(counters.open_count, 0);
        counters.update(&file, false);
        assert_eq!(counters.open_count, 1);
        assert_eq!(counters.readers, 1);
        counters.remove(&file, false);
        assert_eq!(counters, ShareAccessCounters::default());
    }

    #[test]
    fn extension_skips_share_accounting() {
        let mut counters = ShareAccessCounters::default();
        let mut file = FileShareState::default();
        assert_eq!(counters.check(1, 0, &mut file, true, true), Ok(()));
        assert!(file.read);
        assert_eq!(counters.open_count, 0);
        counters.set(2, 0, &mut file, true);
        assert_eq!(counters.open_count, 0);
    }

    #[test]
    fn set_initializes_counters_and_delete_share_is_enforced() {
        let mut counters = ShareAccessCounters {
            open_count: 12,
            ..ShareAccessCounters::default()
        };
        let mut first = FileShareState::default();
        counters.set(0x10000, 1, &mut first, false);
        assert_eq!(counters.open_count, 1);
        assert_eq!(counters.deleters, 1);
        assert_eq!(counters.shared_delete, 0);

        let mut second = FileShareState::default();
        assert_eq!(
            counters.check(0x10000, 7, &mut second, true, false),
            Err(0xc000_0043)
        );
        assert_eq!(counters.open_count, 1);
        counters.remove(&first, false);
        assert_eq!(counters, ShareAccessCounters::default());

        counters.set(0, 0, &mut first, false);
        assert_eq!(counters, ShareAccessCounters::default());
    }
}
