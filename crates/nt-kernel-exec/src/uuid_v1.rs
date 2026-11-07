//! Root-owned UUID v1 allocation when no globally unique hardware node is known.

/// Informational NTSTATUS returned by ExUuidCreate without a globally unique node.
pub const RPC_NT_UUID_LOCAL_ONLY: i32 = 0x4002_0056;
const UUID_EPOCH_FROM_NT_100NS: u64 = 5_748_192_000_000_000;
const MAX_TIMESTAMP: u64 = (1u64 << 60) - 1;
const LOCAL_NODE: [u8; 6] = [0x01, b'n', b'o', b'n', b'i', b'c'];

/// One instance belongs to the kernel's service pump, shared by all driver callers.
pub struct UuidV1Generator {
    last_nt_time: Option<u64>,
    last_timestamp: Option<u64>,
    clock_sequence: u16,
}

impl UuidV1Generator {
    pub const fn new(clock_sequence: u16) -> Self {
        Self {
            last_nt_time: None,
            last_timestamp: None,
            clock_sequence: clock_sequence & 0x3fff,
        }
    }

    /// Returns the in-memory x64 GUID bytes, or `None` if the v1 timestamp is exhausted.
    pub fn next(&mut self, nt_time_100ns: u64) -> Option<[u8; 16]> {
        let mut timestamp = nt_time_100ns.checked_add(UUID_EPOCH_FROM_NT_100NS)?;
        if self.last_nt_time.is_some_and(|last| nt_time_100ns < last) {
            self.clock_sequence = self.clock_sequence.wrapping_add(1) & 0x3fff;
        }
        if let Some(last) = self.last_timestamp {
            if timestamp <= last {
                timestamp = last.checked_add(1)?;
            }
        }
        if timestamp > MAX_TIMESTAMP {
            return None;
        }
        self.last_nt_time = Some(nt_time_100ns);
        self.last_timestamp = Some(timestamp);

        let mut uuid = [0u8; 16];
        uuid[0..4].copy_from_slice(&(timestamp as u32).to_le_bytes());
        uuid[4..6].copy_from_slice(&((timestamp >> 32) as u16).to_le_bytes());
        uuid[6..8].copy_from_slice(&(((timestamp >> 48) as u16 & 0x0fff) | 0x1000).to_le_bytes());
        uuid[8] = 0x80 | ((self.clock_sequence >> 8) as u8 & 0x3f);
        uuid[9] = self.clock_sequence as u8;
        uuid[10..16].copy_from_slice(&LOCAL_NODE);
        Some(uuid)
    }
}
