//! Hosted provisioning of the pinned LiberNT win32k `THREADINFO`.
//!
//! The host fills in a THREADINFO's `LIST_ENTRY` heads when a thread reaches window-manager code
//! without the real `CreateThreadInfo` having run (the dispatch and desktop threads). It runs on
//! every client THREADINFO too, so a head offset that misses the pinned layout overwrites a live
//! field. Only fields that are not yet a valid list head are written.
//!
//! Offsets are those pinned win32k.sys (source revision 8e478a22) `CreateThreadInfo` uses at
//! RVA 0x23a9f..0x23b10. Its `nCntsQBits[]` queue counters sit at +0x2DC..+0x2FC, between the
//! embedded CLIENTTHREADINFO and `WindowListHead`.

/// `THREADINFO.SentMessagesListHead`.
pub const SENT_MESSAGES_LIST_HEAD: u64 = 0xB0;
/// `THREADINFO.PtiLink`, membership in `DESKTOP.PtiList`.
pub const PTI_LINK: u64 = 0x150;
/// `THREADINFO.PostedMessagesListHead`.
pub const POSTED_MESSAGES_LIST_HEAD: u64 = 0x190;
/// `THREADINFO.WindowListHead`.
pub const WINDOW_LIST_HEAD: u64 = 0x300;
/// `THREADINFO.W32CallbackListHead`.
pub const W32_CALLBACK_LIST_HEAD: u64 = 0x310;
/// `THREADINFO.cti`, the CLIENTTHREADINFO `pcti` names while the thread has no desktop.
pub const EMBEDDED_CLIENT_THREAD_INFO: u64 = 0x2C8;

/// The heads the host seeds on a THREADINFO.
pub const HOSTED_LIST_HEADS: [u64; 5] = [
    SENT_MESSAGES_LIST_HEAD,
    PTI_LINK,
    POSTED_MESSAGES_LIST_HEAD,
    WINDOW_LIST_HEAD,
    W32_CALLBACK_LIST_HEAD,
];

/// Access to the server memory that holds a THREADINFO.
pub trait ThreadInfoMemory {
    fn read_u64(&self, address: u64) -> u64;
    fn write_u64(&mut self, address: u64, value: u64);
}

/// Make `head` an empty `LIST_ENTRY` unless both links are already set.
pub fn ensure_list_head(memory: &mut impl ThreadInfoMemory, head: u64) {
    if memory.read_u64(head) == 0 || memory.read_u64(head + 8) == 0 {
        memory.write_u64(head, head);
        memory.write_u64(head + 8, head);
    }
}

/// Seed every hosted list head of the THREADINFO at `pti`.
pub fn seed_list_heads(memory: &mut impl ThreadInfoMemory, pti: u64) {
    for offset in HOSTED_LIST_HEADS {
        ensure_list_head(memory, pti + offset);
    }
}
