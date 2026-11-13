//! Pure resident-source catalog for boot driver preload.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub va: u64,
    pub len: u32,
    pub pin: PoolPin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolPin {
    pub epoch: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub cluster: u32,
    pub len: u32,
    pub modified: u64,
    pub file_id: u64,
}

struct Entry {
    path: Vec<u8>,
    file: FileIdentity,
    source: Source,
}

pub struct Catalog {
    generation: u64,
    pool_base: u64,
    pool_epoch: u64,
    capacity: u64,
    bytes: u64,
    entries: Vec<Entry>,
    complete: bool,
    receipt: Option<PreloadReceipt>,
}

impl Catalog {
    pub fn new(generation: u64, pool_base: u64, pool_epoch: u64, capacity: u64) -> Option<Self> {
        (generation != 0 && pool_base != 0 && pool_epoch != 0 && capacity != 0).then(|| Self {
            generation,
            pool_base,
            pool_epoch,
            capacity,
            bytes: 0,
            entries: Vec::new(),
            complete: false,
            receipt: None,
        })
    }

    pub fn get(&self, generation: u64, path: &[u8], pool_epoch: u64, watermark: u64) -> Option<Source> {
        if generation != self.generation {
            return None;
        }
        self.get_pinned(path, pool_epoch, watermark)
    }

    /// Look up source bytes already resident in this boot image. CM generation can advance for
    /// unrelated registry writes after preload; the live service policy chooses the path, while
    /// the pool epoch and pin prove these exact source bytes have not been recycled.
    pub fn get_pinned(&self, path: &[u8], pool_epoch: u64, watermark: u64) -> Option<Source> {
        if pool_epoch != self.pool_epoch {
            return None;
        }
        self.entries.iter().find(|entry| entry.path.eq_ignore_ascii_case(path))
            .and_then(|entry| {
                let source = entry.source;
                (source.pin.epoch == pool_epoch
                    && source.pin.end <= watermark
                    && source.pin.end <= self.capacity
                    && source.va == self.pool_base.checked_add(source.pin.start)?
                    && source.pin.end.checked_sub(source.pin.start)?
                        == ((source.len as u64).checked_add(0xfff)? & !0xfff))
                    .then_some(source)
            })
    }

    /// Reserve all accounting before invoking a reader that may enter native AHCI.
    pub fn stage(
        &mut self,
        generation: u64,
        path: &[u8],
        file: FileIdentity,
        watermark: u64,
        mut read: impl FnMut() -> Option<(Source, u64)>,
    ) -> Option<Source> {
        if generation != self.generation || path.is_empty() || file.len == 0 {
            return None;
        }
        if let Some(entry) = self.entries.iter().find(|entry| entry.path.eq_ignore_ascii_case(path)) {
            return (entry.file == file)
                .then(|| self.get(generation, path, self.pool_epoch, watermark)).flatten();
        }
        let rounded = (file.len as u64).checked_add(0xfff)? & !0xfff;
        let next = self.bytes.checked_add(rounded)?;
        if rounded > self.capacity.checked_sub(watermark)? {
            return None;
        }
        self.entries.try_reserve(1).ok()?;
        let mut owned_path = Vec::new();
        owned_path.try_reserve_exact(path.len()).ok()?;
        owned_path.extend_from_slice(path);
        let (source, after) = read()?;
        if source.len != file.len
            || source.pin.epoch != self.pool_epoch
            || source.pin.end > self.capacity
            || source.pin.end > after
            || source.pin.start < watermark
            || source.pin.end.checked_sub(source.pin.start) != Some(rounded)
            || self.pool_base.checked_add(source.pin.start) != Some(source.va)
        {
            return None;
        }
        self.entries.push(Entry { path: owned_path, file, source });
        self.bytes = next;
        Some(source)
    }

    /// Build a new generation without rereading an unchanged source whose pool pin is still
    /// valid. The caller publishes this catalog only after its full selected closure succeeds.
    pub fn stage_from_prior(
        &mut self,
        prior: Option<&Catalog>,
        generation: u64,
        path: &[u8],
        file: FileIdentity,
        watermark: u64,
        read: impl FnMut() -> Option<(Source, u64)>,
    ) -> Option<Source> {
        if generation != self.generation || path.is_empty() || file.len == 0 {
            return None;
        }
        if self.entries.iter().any(|entry| entry.path.eq_ignore_ascii_case(path)) {
            return self.stage(generation, path, file, watermark, read);
        }
        if let Some(prior) = prior {
            if prior.pool_base == self.pool_base
                && prior.pool_epoch == self.pool_epoch
                && prior.capacity == self.capacity
                && prior.entries.iter().any(|entry| {
                    entry.path.eq_ignore_ascii_case(path) && entry.file == file
                })
            {
                if let Some(source) = prior.get(prior.generation, path, self.pool_epoch, watermark) {
                    let rounded = (file.len as u64).checked_add(0xfff)? & !0xfff;
                    let next = self.bytes.checked_add(rounded)?;
                    if next > self.capacity {
                        return None;
                    }
                    self.entries.try_reserve(1).ok()?;
                    let mut owned_path = Vec::new();
                    owned_path.try_reserve_exact(path.len()).ok()?;
                    owned_path.extend_from_slice(path);
                    self.entries.push(Entry { path: owned_path, file, source });
                    self.bytes = next;
                    return Some(source);
                }
            }
        }
        self.stage(generation, path, file, watermark, read)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn generation(&self) -> u64 { self.generation }

    pub fn pool_epoch(&self) -> u64 { self.pool_epoch }

    pub fn complete(&self) -> bool { self.complete }

    pub fn receipt(&self) -> Option<PreloadReceipt> { self.receipt }

    pub fn complete_with_receipt(&mut self, receipt: PreloadReceipt) {
        self.complete = true;
        self.receipt = Some(receipt);
    }

}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreloadReceipt {
    pub generation: u64,
    pub pool_epoch: u64,
    pub watermark: u64,
    pub services: usize,
    pub bytes: u64,
}


#[cfg(test)]
mod tests {
    use super::*;

    const FILE: FileIdentity = FileIdentity { cluster: 8, len: 0x801, modified: 9, file_id: 10 };
    const SOURCE: Source = Source {
        va: 0x2000,
        len: FILE.len,
        pin: PoolPin { epoch: 1, start: 0x1000, end: 0x2000 },
    };

    #[test]
    fn exact_generation_and_path_only() {
        let mut sources = Catalog::new(17, 0x1000, 1, 0x3000).unwrap();
        assert_eq!(sources.stage(17, b"windows\\drivers\\one.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))), Some(SOURCE));
        assert_eq!(sources.get(17, b"WINDOWS\\DRIVERS\\ONE.SYS", 1, 0x2000), Some(SOURCE));
        assert_eq!(sources.get(18, b"windows\\drivers\\one.sys", 1, 0x2000), None);
        assert_eq!(sources.get(17, b"windows\\drivers\\other.sys", 1, 0x2000), None);
        assert_eq!(sources.get(17, b"windows/drivers/one.sys", 1, 0x2000), None);
        assert_eq!(sources.bytes(), 0x1000);
    }

    #[test]
    fn duplicate_does_not_read_or_charge_twice() {
        let mut sources = Catalog::new(1, 0x1000, 1, 0x3000).unwrap();
        assert_eq!(sources.stage(1, b"a.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))), Some(SOURCE));
        assert_eq!(sources.stage(1, b"A.SYS", FILE, 0x2000, || panic!("duplicate read")), Some(SOURCE));
        assert_eq!(sources.stage(1, b"a.sys", FileIdentity { len: 0x802, ..FILE }, 0x2000, || panic!("identity changed")), None);
        assert_eq!(sources.bytes(), 0x1000);
    }

    #[test]
    fn capacity_refuses_before_read() {
        let mut sources = Catalog::new(1, 0x1000, 1, 0x2000).unwrap();
        let large = FileIdentity { len: 0x1001, ..FILE };
        assert_eq!(sources.stage(1, b"large.sys", large, 0x1000, || panic!("capacity exceeded")), None);
        assert_eq!(sources.bytes(), 0);
    }

    #[test]
    fn stale_pool_identity_or_reused_watermark_cannot_serve_source() {
        let mut sources = Catalog::new(1, 0x1000, 1, 0x3000).unwrap();
        sources.stage(1, b"a.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))).unwrap();
        assert_eq!(sources.get(1, b"a.sys", 2, 0x2000), None);
        assert_eq!(sources.get(1, b"a.sys", 1, 0x1000), None);
    }

    #[test]
    fn resident_source_survives_registry_generation_changes_but_not_pool_reuse() {
        let mut sources = Catalog::new(1, 0x1000, 1, 0x3000).unwrap();
        sources.stage(1, b"mouclass.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))).unwrap();
        // Registry mutations may advance the CM generation while the boot image and its
        // already pinned source bytes stay the same. Launch policy is checked separately.
        assert_eq!(sources.get(23, b"mouclass.sys", 1, 0x2000), None);
        assert_eq!(sources.get_pinned(b"mouclass.sys", 1, 0x2000), Some(SOURCE));
        assert_eq!(sources.get_pinned(b"mouclass.sys", 2, 0x2000), None);
        assert_eq!(sources.get_pinned(b"mouclass.sys", 1, 0x1000), None);
    }

    #[test]
    fn refreshed_catalog_reuses_only_exact_pinned_file_identity_without_reading() {
        let mut prior = Catalog::new(17, 0x1000, 1, 0x5000).unwrap();
        prior.stage(17, b"Windows\\System32\\drivers\\disk.sys", FILE, 0x1000,
            || Some((SOURCE, 0x2000))).unwrap();
        let mut candidate = Catalog::new(18, 0x1000, 1, 0x5000).unwrap();
        let source = candidate.stage_from_prior(
            Some(&prior), 18, b"windows\\system32\\DRIVERS\\DISK.SYS", FILE, 0x2000,
            || panic!("unchanged pinned source must not be read again"),
        );
        assert_eq!(source, Some(SOURCE));
        assert_eq!(candidate.get(18, b"windows\\system32\\drivers\\disk.sys", 1, 0x2000), Some(SOURCE));
        assert_eq!(candidate.get(17, b"windows\\system32\\drivers\\disk.sys", 1, 0x2000), None);
        assert_eq!(candidate.bytes(), 0x1000);
        assert_eq!(prior.get(17, b"windows\\system32\\drivers\\disk.sys", 1, 0x2000), Some(SOURCE));
    }

    #[test]
    fn changed_file_identity_gets_a_new_pin_in_candidate() {
        let mut prior = Catalog::new(17, 0x1000, 1, 0x5000).unwrap();
        prior.stage(17, b"disk.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))).unwrap();
        let changed = FileIdentity { modified: FILE.modified + 1, ..FILE };
        let replacement = Source {
            va: 0x3000,
            len: changed.len,
            pin: PoolPin { epoch: 1, start: 0x2000, end: 0x3000 },
        };
        let mut candidate = Catalog::new(18, 0x1000, 1, 0x5000).unwrap();
        assert_eq!(candidate.stage_from_prior(Some(&prior), 18, b"disk.sys", changed, 0x2000,
            || Some((replacement, 0x3000))), Some(replacement));
        assert_eq!(candidate.get(18, b"disk.sys", 1, 0x3000), Some(replacement));
        assert_eq!(prior.get(17, b"disk.sys", 1, 0x3000), Some(SOURCE));
    }

    #[test]
    fn refresh_never_reuses_prior_source_from_another_pool_epoch() {
        let mut prior = Catalog::new(17, 0x1000, 1, 0x5000).unwrap();
        prior.stage(17, b"disk.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))).unwrap();
        let replacement = Source {
            va: 0x3000,
            len: FILE.len,
            pin: PoolPin { epoch: 2, start: 0x2000, end: 0x3000 },
        };
        let mut candidate = Catalog::new(18, 0x1000, 2, 0x5000).unwrap();
        let mut reads = 0;
        assert_eq!(candidate.stage_from_prior(Some(&prior), 18, b"disk.sys", FILE, 0x2000,
            || { reads += 1; Some((replacement, 0x3000)) }), Some(replacement));
        assert_eq!(reads, 1);
        assert_eq!(candidate.get(18, b"disk.sys", 2, 0x3000), Some(replacement));
    }

    #[test]
    fn failed_refresh_candidate_leaves_published_catalog_intact() {
        let mut published = Catalog::new(17, 0x1000, 1, 0x5000).unwrap();
        published.stage(17, b"disk.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))).unwrap();
        published.complete = true;
        let receipt = PreloadReceipt {
            generation: 17, pool_epoch: 1, watermark: 0x2000, services: 1, bytes: 0x1000,
        };
        published.receipt = Some(receipt);
        let changed = FileIdentity { modified: FILE.modified + 1, ..FILE };
        let mut candidate = Catalog::new(18, 0x1000, 1, 0x5000).unwrap();
        assert_eq!(candidate.stage_from_prior(Some(&published), 18, b"disk.sys", changed, 0x2000,
            || None), None);
        assert!(candidate.entries.is_empty());
        assert!(!candidate.complete);
        assert_eq!(candidate.receipt, None);
        assert_eq!(published.receipt, Some(receipt));
        assert_eq!(published.get(17, b"disk.sys", 1, 0x2000), Some(SOURCE));
    }
}
