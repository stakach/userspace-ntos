//! Replayable acquisition of the sole SYSTEM mutation upload. Receipt ACK transfers ownership
//! to the caller; it never aborts or consumes the upload. Registrations live for the CM authority.

pub const MAX_SLOTS: usize = 256;

pub mod operation {
    pub const QUERY: u16 = 1;
    pub const BEGIN: u16 = 2;
    pub const ACKNOWLEDGE: u16 = 3;
}

pub mod disposition {
    pub const AUTHORITY: u16 = 1;
    pub const OUTCOME: u16 = 2;
    pub const ACKNOWLEDGED: u16 = 3;
    pub const ALREADY_ACKNOWLEDGED: u16 = 4;
}

/// QUERY registers a nonzero requester and slot count, with all other identity/input fields zero.
/// BEGIN names the exact granted slot/next attempt and captures generation/length, with token zero.
/// ACK retains that request identity and echoes the successful token (zero for a failed outcome);
/// slot count, expected generation and semantic length are zero. ACK cannot retire an unexecuted
/// BEGIN. The requester must first resolve any uncertain acquisition to learn its outcome.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Request {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub mount: u16,
    pub slot_count: u32,
    pub semantic_journal_len: u32,
    pub server_nonce: u64,
    pub requester_nonce: u64,
    pub request_slot: u64,
    pub request_generation: u64,
    pub expected_generation: u64,
    pub mutation_token: u64,
}

/// Outer success means this fixed envelope is valid. OUTCOME carries the cached acquisition
/// status and exact inputs; only successful acquisition has a nonzero mutation token. QUERY
/// echoes the grant and requester plus new authority. ACK zeroes all acquisition/outcome fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Reply {
    pub abi_size: u16,
    pub abi_version: u16,
    pub disposition: u16,
    pub mount: u16,
    pub outcome_status: i32,
    pub slot_count: u32,
    pub server_nonce: u64,
    pub requester_nonce: u64,
    pub request_slot: u64,
    pub request_generation: u64,
    pub expected_generation: u64,
    pub mutation_token: u64,
    pub semantic_journal_len: u32,
    pub reserved: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_envelopes_have_no_padding_and_roundtrip_unaligned() {
        assert_eq!(core::mem::size_of::<Request>(), 64);
        assert_eq!(core::mem::size_of::<Reply>(), 72);
        assert_eq!(core::mem::offset_of!(Request, server_nonce), 16);
        assert_eq!(core::mem::offset_of!(Request, mutation_token), 56);
        assert_eq!(core::mem::offset_of!(Reply, semantic_journal_len), 64);
        assert_eq!(core::mem::offset_of!(Reply, reserved), 68);
        let request = Request {
            abi_size: 64,
            mutation_token: u64::MAX,
            ..Request::default()
        };
        let reply = Reply {
            abi_size: 72,
            outcome_status: -1,
            ..Reply::default()
        };
        let mut bytes = [0u8; 73];
        bytes[1..65].copy_from_slice(request.as_bytes());
        assert_eq!(Request::from_bytes(&bytes[1..65]), Some(request));
        assert!(Request::from_bytes(&bytes[..63]).is_none());
        bytes[1..].copy_from_slice(reply.as_bytes());
        assert_eq!(Reply::from_bytes(&bytes[1..]), Some(reply));
        assert!(Reply::from_bytes(&bytes[..71]).is_none());
        assert_eq!(crate::opcode::CM_OP_SYSTEM_HIVE_MUTATION_BEGIN, 0x2161);
    }
}
