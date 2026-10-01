//! Acceptance arithmetic for an isolated native source-IRP probe, not I/O routing policy.

/// Terminal, origin commit, canonical commit, and retirement counts, in that order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub ioctl: [u64; 4],
    pub read: [u64; 4],
    pub write: [u64; 4],
    pub methods: [u64; 4],
}

impl Snapshot {
    /// Refuse counter rollback instead of interpreting it as successful progress.
    pub fn delta_since(self, before: Self) -> Option<Self> {
        fn subtract(after: [u64; 4], before: [u64; 4]) -> Option<[u64; 4]> {
            Some([
                after[0].checked_sub(before[0])?,
                after[1].checked_sub(before[1])?,
                after[2].checked_sub(before[2])?,
                after[3].checked_sub(before[3])?,
            ])
        }
        Some(Self {
            ioctl: subtract(self.ioctl, before.ioctl)?,
            read: subtract(self.read, before.read)?,
            write: subtract(self.write, before.write)?,
            methods: subtract(self.methods, before.methods)?,
        })
    }

    /// Two execution modes, each with READ, WRITE, and all four IOCTL methods.
    /// Exact equality also refuses unrelated traffic in the isolated probe interval.
    pub fn proves_twelve_operations(self) -> bool {
        self.ioctl == [8; 4]
            && self.read == [2; 4]
            && self.write == [2; 4]
            && self.methods == [2; 4]
    }
}
