//! The hosted THREADINFO provisioning against a model of the pinned LiberNT win32k queue code.
//!
//! Offsets in the model are read from pinned win32k.sys (source revision 8e478a22; RVA = VMA -
//! 0x10000):
//! - `CreateThreadInfo` RVA 0x23a18 initializes the heads at +0xB0, +0x150, +0x190, the
//!   sixteen hook heads +0x1C8..+0x2C8, +0x300 and +0x310, and sets `pcti = pti + 0x2C8`.
//! - `MsqWakeQueue` RVA 0x84010 ORs the bits into `pcti->fsWakeBits` (+6) and
//!   `pcti->fsChangeBits` (+4), then increments `nCntsQBits[]` at +0x2DC (key), +0x2E0/+0x2E4
//!   (mouse), +0x2E8 (post), +0x2EC (send), +0x2F0 (hotkey), +0x2F4 (event).
//! - `ClearMsgBitsMask` RVA 0x84110 decrements the same counter and clears the bit from both
//!   words only when the counter reaches zero.

use crate::win32k_threadinfo::{self, ThreadInfoMemory};
use alloc::vec;
use alloc::vec::Vec;

const PTI: u64 = 0x0000_0100_3114_a000;
const THREADINFO_BYTES: usize = 0x340;
const PCTI: u64 = 0x70;
const CTI: u64 = 0x2C8;
const CHANGE_BITS: u64 = 4;
const WAKE_BITS: u64 = 6;
const QS_POSTMESSAGE: u16 = 0x08;
const QS_SENDMESSAGE: u16 = 0x40;
const POST_COUNT: u64 = 0x2E8;
const SEND_COUNT: u64 = 0x2EC;

struct ThreadInfo {
    bytes: Vec<u8>,
}

impl ThreadInfo {
    fn offset(address: u64) -> usize {
        usize::try_from(address - PTI).unwrap()
    }

    fn u16_at(&self, address: u64) -> u16 {
        let at = Self::offset(address);
        u16::from_le_bytes(self.bytes[at..at + 2].try_into().unwrap())
    }

    fn set_u16(&mut self, address: u64, value: u16) {
        let at = Self::offset(address);
        self.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn u32_at(&self, address: u64) -> u32 {
        let at = Self::offset(address);
        u32::from_le_bytes(self.bytes[at..at + 4].try_into().unwrap())
    }

    fn set_u32(&mut self, address: u64, value: u32) {
        let at = Self::offset(address);
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Pinned `CreateThreadInfo`'s list heads and embedded `pcti`.
    fn created() -> Self {
        let mut info = Self { bytes: vec![0; THREADINFO_BYTES] };
        let mut heads = vec![0xB0, 0x150, 0x190, 0x300, 0x310];
        heads.extend((0x1C8..0x2C8).step_by(0x10));
        for head in heads {
            info.write_u64(PTI + head, PTI + head);
            info.write_u64(PTI + head + 8, PTI + head);
        }
        info.write_u64(PTI + PCTI, PTI + CTI);
        info
    }

    fn pcti(&self) -> u64 {
        self.read_u64(PTI + PCTI)
    }

    fn change_bits(&self) -> u16 {
        self.u16_at(self.pcti() + CHANGE_BITS)
    }

    fn wake_bits(&self) -> u16 {
        self.u16_at(self.pcti() + WAKE_BITS)
    }

    /// `MsqWakeQueue` for one counted queue bit.
    fn wake(&mut self, bit: u16, count: u64) {
        let pcti = self.pcti();
        self.set_u16(pcti + WAKE_BITS, self.u16_at(pcti + WAKE_BITS) | bit);
        self.set_u16(pcti + CHANGE_BITS, self.u16_at(pcti + CHANGE_BITS) | bit);
        self.set_u32(PTI + count, self.u32_at(PTI + count).wrapping_add(1));
    }

    /// `ClearMsgBitsMask` for one counted queue bit.
    fn clear(&mut self, bit: u16, count: u64) {
        let remaining = self.u32_at(PTI + count).wrapping_sub(1);
        self.set_u32(PTI + count, remaining);
        if remaining == 0 {
            let pcti = self.pcti();
            self.set_u16(pcti + WAKE_BITS, self.u16_at(pcti + WAKE_BITS) & !bit);
            self.set_u16(pcti + CHANGE_BITS, self.u16_at(pcti + CHANGE_BITS) & !bit);
        }
    }
}

impl ThreadInfoMemory for ThreadInfo {
    fn read_u64(&self, address: u64) -> u64 {
        let at = Self::offset(address);
        u64::from_le_bytes(self.bytes[at..at + 8].try_into().unwrap())
    }

    fn write_u64(&mut self, address: u64, value: u64) {
        let at = Self::offset(address);
        self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
}

#[test]
fn seeding_a_created_threadinfo_changes_no_field() {
    let created = ThreadInfo::created();
    let mut hosted = ThreadInfo::created();
    win32k_threadinfo::seed_list_heads(&mut hosted, PTI);
    let changed: Vec<usize> = (0..THREADINFO_BYTES)
        .filter(|&at| created.bytes[at] != hosted.bytes[at])
        .collect();
    assert!(changed.is_empty(), "hosted seeding rewrote THREADINFO bytes at {changed:#x?}");
}

#[test]
fn a_dispatched_sent_message_clears_the_queue_bit_on_a_hosted_threadinfo() {
    // Boot 44834608861: winlogon peeks with PM_QS_SENDMESSAGE and waits on QS_SENDMESSAGE.
    // Its CLIENTTHREADINFO kept fsChangeBits = fsWakeBits = 0x58 for about 1M polls.
    let mut info = ThreadInfo::created();
    win32k_threadinfo::seed_list_heads(&mut info, PTI);
    info.wake(QS_SENDMESSAGE, SEND_COUNT);
    info.clear(QS_SENDMESSAGE, SEND_COUNT);
    info.wake(QS_POSTMESSAGE, POST_COUNT);
    info.clear(QS_POSTMESSAGE, POST_COUNT);
    assert_eq!(info.change_bits(), 0);
    assert_eq!(info.wake_bits(), 0);
}

#[test]
fn placeholder_threadinfo_gets_every_head_and_the_embedded_cti() {
    let mut info = ThreadInfo { bytes: vec![0; THREADINFO_BYTES] };
    win32k_threadinfo::seed_list_heads(&mut info, PTI);
    for head in [0xB0, 0x150, 0x190, 0x300, 0x310] {
        assert_eq!(info.read_u64(PTI + head), PTI + head, "head +{head:#x}");
        assert_eq!(info.read_u64(PTI + head + 8), PTI + head, "head +{head:#x}");
    }
    assert_eq!(win32k_threadinfo::EMBEDDED_CLIENT_THREAD_INFO, CTI);
}

#[cfg(test)]
mod pinned_image {
    extern crate std;

    use std::fs;
    use std::path::PathBuf;

    const SOURCE_REVISION: &str = "source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d";

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn raw_offset(bytes: &[u8], rva: u64) -> usize {
        let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        assert_eq!(&bytes[pe..pe + 4], b"PE\0\0");
        let count = u16::from_le_bytes(bytes[pe + 6..pe + 8].try_into().unwrap()) as usize;
        let optional = u16::from_le_bytes(bytes[pe + 20..pe + 22].try_into().unwrap()) as usize;
        for index in 0..count {
            let section = pe + 24 + optional + index * 40;
            let base = u32::from_le_bytes(bytes[section + 12..section + 16].try_into().unwrap()) as u64;
            let size = u32::from_le_bytes(bytes[section + 8..section + 12].try_into().unwrap()) as u64;
            if (base..base + size).contains(&rva) {
                let raw = u32::from_le_bytes(bytes[section + 20..section + 24].try_into().unwrap());
                return raw as usize + (rva - base) as usize;
            }
        }
        panic!("RVA 0x{rva:x} is outside pinned win32k.sys");
    }

    /// `lea reg, [base + disp32]` at `rva`, returning the displacement.
    fn lea_displacement(bytes: &[u8], rva: u64, prefix: [u8; 3]) -> u64 {
        let at = raw_offset(bytes, rva);
        assert_eq!(bytes[at..at + 3], prefix, "LEA at RVA 0x{rva:x}");
        u64::from(u32::from_le_bytes(bytes[at + 3..at + 7].try_into().unwrap()))
    }

    /// The pinned release may be absent on CI. When cached locally, read the THREADINFO offsets
    /// from the instructions that use them, so the hosted layout cannot drift from the binary.
    #[test]
    fn hosted_offsets_match_pinned_create_thread_info() {
        if let Ok(manifest) = fs::read_to_string(root().join("rust-micro/vendor/libernt/manifest.txt")) {
            assert!(manifest.lines().any(|line| line == SOURCE_REVISION));
        }
        let image = root().join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
        let Ok(bytes) = fs::read(image) else {
            return;
        };
        const LEA_RAX_RBX: [u8; 3] = [0x48, 0x8d, 0x83];
        use crate::win32k_threadinfo::*;
        assert_eq!(lea_displacement(&bytes, 0x23a9f, LEA_RAX_RBX), EMBEDDED_CLIENT_THREAD_INFO);
        assert_eq!(lea_displacement(&bytes, 0x23abc, LEA_RAX_RBX), WINDOW_LIST_HEAD);
        assert_eq!(lea_displacement(&bytes, 0x23ad1, LEA_RAX_RBX), W32_CALLBACK_LIST_HEAD);
        assert_eq!(lea_displacement(&bytes, 0x23ae6, LEA_RAX_RBX), POSTED_MESSAGES_LIST_HEAD);
        assert_eq!(lea_displacement(&bytes, 0x23afb, LEA_RAX_RBX), SENT_MESSAGES_LIST_HEAD);
        assert_eq!(lea_displacement(&bytes, 0x23b10, LEA_RAX_RBX), PTI_LINK);
        // MsqCleanupThreadMsgs: lea r15, [rsi + PostedMessagesListHead].
        assert_eq!(lea_displacement(&bytes, 0x886e2, [0x4c, 0x8d, 0xbe]), POSTED_MESSAGES_LIST_HEAD);
    }
}
