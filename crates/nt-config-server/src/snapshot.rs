use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotChunk {
    pub(crate) written: usize,
    pub(crate) needed: usize,
    pub(crate) token: u64,
}

struct TokenSequence {
    next: u64,
}

impl TokenSequence {
    const fn new() -> Self {
        Self { next: 1 }
    }

    fn take(&mut self) -> Option<u64> {
        let token = self.next;
        if token == 0 {
            return None;
        }
        self.next = token.checked_add(1).unwrap_or(0);
        Some(token)
    }
}

struct Snapshot<K> {
    token: u64,
    key: K,
    value: Vec<u8>,
    offset: usize,
}

fn copy_chunk(value: &[u8], offset: usize, capacity: usize, out: &mut [u8]) -> usize {
    let written = core::cmp::min(value.len() - offset, core::cmp::min(capacity, out.len()));
    out[..written].copy_from_slice(&value[offset..offset + written]);
    written
}

/// A single-flight immutable transfer. Beginning a new transfer retires the previous snapshot.
pub(crate) struct SnapshotBank<K> {
    snapshot: Option<Snapshot<K>>,
    tokens: TokenSequence,
}

impl<K> SnapshotBank<K> {
    pub(crate) const fn new() -> Self {
        Self {
            snapshot: None,
            tokens: TokenSequence::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.snapshot = None;
    }

    pub(crate) fn begin(
        &mut self,
        key: K,
        value: Vec<u8>,
        capacity: usize,
        out: &mut [u8],
    ) -> Option<SnapshotChunk> {
        self.clear();
        let needed = value.len();
        let written = copy_chunk(&value, 0, capacity, out);
        if written == needed {
            return Some(SnapshotChunk {
                written,
                needed,
                token: 0,
            });
        }
        let token = self.tokens.take()?;
        self.snapshot = Some(Snapshot {
            token,
            key,
            value,
            offset: written,
        });
        Some(SnapshotChunk {
            written,
            needed,
            token,
        })
    }

    pub(crate) fn pull(
        &mut self,
        token: u64,
        offset: usize,
        capacity: usize,
        out: &mut [u8],
        key_matches: impl FnOnce(&K) -> bool,
    ) -> Option<SnapshotChunk> {
        let snapshot = self.snapshot.as_mut()?;
        if token == 0
            || snapshot.token != token
            || snapshot.offset != offset
            || !key_matches(&snapshot.key)
        {
            return None;
        }
        let needed = snapshot.value.len();
        let written = copy_chunk(&snapshot.value, snapshot.offset, capacity, out);
        snapshot.offset += written;
        if snapshot.offset == needed {
            self.snapshot = None;
        }
        Some(SnapshotChunk {
            written,
            needed,
            token,
        })
    }

    pub(crate) fn abort(&mut self, token: u64, key_matches: impl FnOnce(&K) -> bool) -> bool {
        let matches = self.snapshot.as_ref().is_some_and(|snapshot| {
            token != 0 && snapshot.token == token && key_matches(&snapshot.key)
        });
        if matches {
            self.snapshot = None;
        }
        matches
    }
}

/// An immutable transfer pool for protocols that permit concurrent readers.
pub(crate) struct SnapshotPool<K> {
    snapshots: Vec<Snapshot<K>>,
    tokens: TokenSequence,
}

impl<K> SnapshotPool<K> {
    pub(crate) const fn new() -> Self {
        Self {
            snapshots: Vec::new(),
            tokens: TokenSequence::new(),
        }
    }

    pub(crate) fn begin(
        &mut self,
        key: K,
        value: Vec<u8>,
        capacity: usize,
        out: &mut [u8],
    ) -> Option<SnapshotChunk> {
        let needed = value.len();
        let written = copy_chunk(&value, 0, capacity, out);
        if written == needed {
            return Some(SnapshotChunk {
                written,
                needed,
                token: 0,
            });
        }
        self.snapshots.try_reserve(1).ok()?;
        let token = self.tokens.take()?;
        self.snapshots.push(Snapshot {
            token,
            key,
            value,
            offset: written,
        });
        Some(SnapshotChunk {
            written,
            needed,
            token,
        })
    }

    pub(crate) fn pull(
        &mut self,
        token: u64,
        offset: usize,
        capacity: usize,
        out: &mut [u8],
        key_matches: impl Fn(&K) -> bool,
    ) -> Option<SnapshotChunk> {
        let index = self.snapshots.iter().position(|snapshot| {
            token != 0
                && snapshot.token == token
                && snapshot.offset == offset
                && key_matches(&snapshot.key)
        })?;
        let snapshot = &mut self.snapshots[index];
        let needed = snapshot.value.len();
        let written = copy_chunk(&snapshot.value, snapshot.offset, capacity, out);
        snapshot.offset += written;
        if snapshot.offset == needed {
            self.snapshots.swap_remove(index);
        }
        Some(SnapshotChunk {
            written,
            needed,
            token,
        })
    }

    pub(crate) fn abort(&mut self, token: u64, key_matches: impl Fn(&K) -> bool) -> bool {
        let Some(index) = self.snapshots.iter().position(|snapshot| {
            token != 0 && snapshot.token == token && key_matches(&snapshot.key)
        }) else {
            return false;
        };
        self.snapshots.swap_remove(index);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{SnapshotBank, SnapshotPool};
    use alloc::vec;

    #[test]
    fn single_flight_transfer_is_ordered_and_retires_on_completion() {
        let mut bank = SnapshotBank::new();
        let mut first = [0; 2];
        let begin = bank
            .begin("first", vec![1, 2, 3, 4], 2, &mut first)
            .unwrap();
        assert_eq!(first, [1, 2]);
        assert_ne!(begin.token, 0);
        assert!(bank
            .pull(begin.token, 1, 2, &mut [0; 2], |key| *key == "first")
            .is_none());

        let mut tail = [0; 2];
        let pull = bank
            .pull(begin.token, 2, 2, &mut tail, |key| *key == "first")
            .unwrap();
        assert_eq!(tail, [3, 4]);
        assert_eq!(pull.needed, 4);
        assert!(bank
            .pull(begin.token, 4, 1, &mut [0; 1], |_| true)
            .is_none());
    }

    #[test]
    fn a_new_single_flight_transfer_invalidates_the_old_token() {
        let mut bank = SnapshotBank::new();
        let first = bank.begin(1, vec![1, 2], 1, &mut [0; 1]).unwrap();
        let second = bank.begin(2, vec![3, 4], 1, &mut [0; 1]).unwrap();
        assert_ne!(first.token, second.token);
        assert!(bank
            .pull(first.token, 1, 1, &mut [0; 1], |_| true)
            .is_none());
        assert!(bank.abort(second.token, |key| *key == 2));
        assert!(!bank.abort(second.token, |_| true));
    }

    #[test]
    fn pool_keeps_independent_snapshots_live() {
        let mut pool = SnapshotPool::new();
        let first = pool.begin(1, vec![1, 2], 1, &mut [0; 1]).unwrap();
        let second = pool.begin(2, vec![3, 4], 1, &mut [0; 1]).unwrap();
        let mut tail = [0];
        assert!(pool
            .pull(second.token, 1, 1, &mut tail, |key| *key == 2)
            .is_some());
        assert_eq!(tail, [4]);
        assert!(pool.abort(first.token, |key| *key == 1));
    }
}
