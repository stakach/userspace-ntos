//! Preserve an outer receive while deferred work invokes capabilities on the same root TCB.

use crate::IPC_BUFFER;
use core::sync::atomic::Ordering;

// seL4_IPCBuffer: tag, 120 message words, userData, three cap/badge words and receive CNode/index/
// depth. This is the ABI extent in rust-micro/src/ipc_buffer.rs, not the whole backing page.
const BUFFER_WORDS: usize = 128;

pub(crate) struct SavedMessageBuffer {
    base: *mut u64,
    words: [u64; BUFFER_WORDS],
}

impl SavedMessageBuffer {
    pub(crate) unsafe fn capture() -> Self {
        let base = IPC_BUFFER.load(Ordering::Relaxed) as *mut u64;
        assert!(!base.is_null(), "deferred IPC has no root message buffer");
        let mut words = [0; BUFFER_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            *word = core::ptr::read_volatile(base.add(index));
        }
        Self { base, words }
    }
}

impl Drop for SavedMessageBuffer {
    fn drop(&mut self) {
        // The root TCB and its IPC mapping outlive the entire service loop. Nested snapshots
        // restore in stack order; deferred capability replies are consumed before this restore.
        for (index, word) in self.words.iter().enumerate() {
            unsafe { core::ptr::write_volatile(self.base.add(index), *word) };
        }
    }
}
