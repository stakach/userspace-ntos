//! Bounded copies of installed-volume metadata sectors under an explicit mutation fence.

#[derive(Clone, Copy)]
struct Entry<K> {
    identity: K,
    sector: u32,
    bytes: [u8; 512],
}

/// Keeps exact completed sector bytes outside a provider's reusable DMA buffer.
///
/// `K` must identify the physical mount generation. The provider route must either be part of
/// `K` or be authenticated and phase-fenced by the caller before every lookup and publication.
/// Callers may publish only a successful, exact 512-byte read after the provider terminal and
/// acknowledgement have been authenticated. Failed or uncertain reads must retain their owner
/// and must never call `publish`. Callers must invalidate before any possible installed-layer
/// mutation and before transferring write authority to another provider. Snapshot/WAL sectors
/// and writable file data do not belong in this cache.
pub struct InstalledMetadataSectorCache<K: Copy + Eq, const N: usize> {
    // Oldest to newest. Every slot before `len` is occupied.
    entries: [Option<Entry<K>>; N],
    len: usize,
}

impl<K: Copy + Eq, const N: usize> InstalledMetadataSectorCache<K, N> {
    pub const fn new() -> Self {
        Self { entries: [const { None }; N], len: 0 }
    }

    /// Drop all bytes before mount replacement or any possible installed-layer mutation.
    pub fn invalidate(&mut self) {
        for entry in &mut self.entries[..self.len] {
            *entry = None;
        }
        self.len = 0;
    }

    /// Whether a new sector would require an eviction. A miss here may still be a first read;
    /// capacity alone cannot distinguish a cold sector from one previously evicted.
    pub fn is_full(&self) -> bool { N != 0 && self.len == N }

    /// Return only a copied sector from the caller-authenticated mounted route.
    pub fn lookup(&mut self, identity: K, sector: u32) -> Option<&[u8; 512]> {
        let index = self.entries[..self.len].iter().position(|entry| {
            entry.as_ref().is_some_and(|entry| entry.identity == identity && entry.sector == sector)
        })?;
        self.promote(index);
        self.entries[self.len - 1].as_ref().map(|entry| &entry.bytes)
    }

    /// Return a copied sector; fetch exactly once on a miss. The caller's fetch closure must
    /// return success only after exact physical completion and owner retirement. An error or
    /// uncertain result is never published. The caller must fence every possible write first.
    pub fn read_or_fetch<E>(
        &mut self, identity: K, sector: u32,
        fetch: impl FnOnce(u32, &mut [u8; 512]) -> Result<(), E>,
    ) -> Result<[u8; 512], E> {
        if let Some(bytes) = self.lookup(identity, sector) {
            return Ok(*bytes);
        }
        let mut bytes = [0; 512];
        fetch(sector, &mut bytes)?;
        self.publish(identity, sector, &bytes);
        Ok(bytes)
    }

    /// Publish a copied sector after its exact authenticated completion and acknowledgement.
    /// Returns true only when a different sector was evicted to make room.
    pub fn publish(&mut self, identity: K, sector: u32, bytes: &[u8; 512]) -> bool {
        if N == 0 { return false; }
        if let Some(index) = self.entries[..self.len].iter().position(|entry| {
            entry.as_ref().is_some_and(|entry| entry.identity == identity && entry.sector == sector)
        }) {
            self.promote(index);
            self.entries[self.len - 1].as_mut().unwrap().bytes.copy_from_slice(bytes);
            return false;
        }
        let evicted = self.len == N;
        if evicted {
            for index in 0..self.len - 1 {
                self.entries[index] = self.entries[index + 1].take();
            }
        } else {
            self.len += 1;
        }
        self.entries[self.len - 1] = Some(Entry { identity, sector, bytes: *bytes });
        evicted
    }

    fn promote(&mut self, index: usize) {
        let entry = self.entries[index].take().expect("occupied metadata cache slot");
        for slot in index..self.len - 1 {
            self.entries[slot] = self.entries[slot + 1].take();
        }
        self.entries[self.len - 1] = Some(entry);
    }
}

impl<K: Copy + Eq, const N: usize> Default for InstalledMetadataSectorCache<K, N> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copied_metadata_requires_the_exact_mount_and_provider_generation() {
        let mut cache = InstalledMetadataSectorCache::<(u64, u64), 2>::new();
        let mut provider_bytes = [0x5a; 512];
        assert!(!cache.publish((7, 11), 42, &provider_bytes));
        provider_bytes.fill(0);

        assert_eq!(cache.lookup((7, 11), 42), Some(&[0x5a; 512]));
        assert_eq!(cache.lookup((8, 11), 42), None);
        assert_eq!(cache.lookup((7, 12), 42), None);
        assert_eq!(cache.lookup((7, 11), 43), None);
        cache.invalidate();
        assert_eq!(cache.lookup((7, 11), 42), None);
    }
}
