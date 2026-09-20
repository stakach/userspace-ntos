//! Preserve an outer receive while deferred work invokes capabilities on the same root TCB.

use crate::IPC_BUFFER;
use core::sync::atomic::Ordering;
use nt_component_suspension::{IpcBufferSnapshot, ReceivedMessage};

pub(crate) struct SavedMessageBuffer {
    base: *mut u64,
    snapshot: IpcBufferSnapshot,
}

impl SavedMessageBuffer {
    pub(crate) unsafe fn capture() -> Self {
        let base = IPC_BUFFER.load(Ordering::Relaxed) as *mut u64;
        assert!(!base.is_null(), "deferred IPC has no root message buffer");
        let snapshot =
            IpcBufferSnapshot::capture(|index| core::ptr::read_volatile(base.add(index)));
        Self { base, snapshot }
    }
}

impl Drop for SavedMessageBuffer {
    fn drop(&mut self) {
        // The root TCB and its IPC mapping outlive the entire service loop. Nested snapshots
        // restore in stack order; deferred capability replies are consumed before this restore.
        self.snapshot.restore(|index, word| unsafe {
            core::ptr::write_volatile(self.base.add(index), word)
        });
    }
}

pub(crate) unsafe fn capture_received(
    badge: u64,
    info: u64,
    registers: [u64; 4],
) -> ReceivedMessage {
    let base = IPC_BUFFER.load(Ordering::Relaxed) as *const u64;
    assert!(!base.is_null(), "receive has no root message buffer");
    ReceivedMessage::new(
        badge,
        info,
        registers,
        IpcBufferSnapshot::capture(|index| core::ptr::read_volatile(base.add(index))),
    )
}

/// Materialize a retained receive for legacy handlers that still read the root IPC bank.
/// Fast MRs remain in ReceivedMessage::registers; this restores the exact original buffer.
pub(crate) unsafe fn restore_received(message: &ReceivedMessage) {
    let base = IPC_BUFFER.load(Ordering::Relaxed) as *mut u64;
    assert!(!base.is_null(), "received message has no root IPC buffer");
    message.restore_buffer(|index, word| core::ptr::write_volatile(base.add(index), word));
}
