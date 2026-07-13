//! `KEVENT` dispatcher objects as a raw-memory primitive (`KeInitializeEvent` / `KeSetEvent` /
//! `KeResetEvent` / `KeClearEvent` / `KePulseEvent` / `KeReadStateEvent`).
//!
//! A real NT `KEVENT` is a `DISPATCHER_HEADER` whose signalled state lives *inline* in the object
//! memory (`Header.SignalState`), so `Ke*Event` operate directly on the caller's `KEVENT` storage —
//! there is no side table. This module lays out and manipulates that inline state at the real x64
//! `DISPATCHER_HEADER` offsets.
//!
//! It is the allocation-free sibling of the [`EventStore`](crate::EventStore): the `EventStore` keys
//! event state by pointer in a `Vec` for the Driver Host (where a heap exists and a driver's `KEVENT`
//! is opaque storage the runtime never lays out); this primitive instead lays out a *concrete*
//! `KEVENT` for callers that are allocation-free and hand the object pointer to other code that will
//! read/deref it as a real dispatcher object. The win32k host is exactly that case — its bump heap is
//! spent by the time win32k runs, and `ObReferenceObjectByHandle(..., ExEventObjectType, &Object)`
//! must hand back a pointer to a genuine `KEVENT` (win32k stores it in `gpPowerRequestCalloutEvent`
//! and may later `KeSetEvent` it). Mirrors the pattern of [`init_general_lookaside`](crate::init_general_lookaside)
//! and [`session_section`](crate::session_section). Real semantics reference:
//! `references/nt5/base/ntos/ke/eventobj.c` (`KeInitializeEvent`/`KeSetEvent`/`KeResetEvent`).

pub use crate::event::EventKind;

/// x64 `KEVENT` / `DISPATCHER_HEADER` field offsets.
pub mod kevent_layout {
    /// `UCHAR Type` — `EventNotificationObject` (0) or `EventSynchronizationObject` (1).
    pub const TYPE: usize = 0x00;
    /// `UCHAR Size` — the object size in `ULONG`s (`sizeof(KEVENT) / 4` == 6).
    pub const SIZE: usize = 0x02;
    /// `LONG SignalState` — the inline signalled state (non-zero == signalled).
    pub const SIGNAL_STATE: usize = 0x04;
    /// `LIST_ENTRY WaitListHead` — the waiter list (`Flink`@0x08, `Blink`@0x10). Empty == self-linked.
    pub const WAIT_LIST_HEAD: usize = 0x08;
    /// Total `KEVENT` size in bytes.
    pub const SIZE_OF: usize = 0x18;
}

/// `DISPATCHER_HEADER.Type` for a notification (manual-reset) event — `EventNotificationObject`.
pub const EVENT_NOTIFICATION_OBJECT: u8 = 0;
/// `DISPATCHER_HEADER.Type` for a synchronization (auto-reset) event — `EventSynchronizationObject`.
pub const EVENT_SYNCHRONIZATION_OBJECT: u8 = 1;
/// `KEVENT.Header.Size` (object size in `ULONG`s).
const KEVENT_SIZE_IN_DWORDS: u8 = (kevent_layout::SIZE_OF / 4) as u8;

fn type_byte(kind: EventKind) -> u8 {
    match kind {
        EventKind::Notification => EVENT_NOTIFICATION_OBJECT,
        EventKind::Synchronization => EVENT_SYNCHRONIZATION_OBJECT,
    }
}

/// `KeInitializeEvent(Event, Type, State)` — lay out a real `KEVENT` at `ev`: stamp the
/// dispatcher-header `Type`/`Size`, set the initial `SignalState`, and self-link the (empty)
/// `WaitListHead`.
///
/// # Safety
/// `ev` must point to at least [`kevent_layout::SIZE_OF`] writable bytes.
pub unsafe fn init_kevent(ev: *mut u8, kind: EventKind, signaled: bool) {
    use kevent_layout as o;
    core::ptr::write_unaligned(ev.add(o::TYPE), type_byte(kind));
    core::ptr::write_unaligned(ev.add(o::SIZE), KEVENT_SIZE_IN_DWORDS);
    core::ptr::write_unaligned(ev.add(o::SIGNAL_STATE) as *mut i32, if signaled { 1 } else { 0 });
    // Empty waiter list: Flink = Blink = &WaitListHead.
    let head = ev.add(o::WAIT_LIST_HEAD) as u64;
    core::ptr::write_unaligned(ev.add(o::WAIT_LIST_HEAD) as *mut u64, head);
    core::ptr::write_unaligned(ev.add(o::WAIT_LIST_HEAD + 8) as *mut u64, head);
}

/// The event's `Type` (dispatcher-object kind).
///
/// # Safety
/// `ev` must be a valid `KEVENT` (see [`init_kevent`]).
pub unsafe fn kevent_kind(ev: *const u8) -> EventKind {
    if core::ptr::read_unaligned(ev.add(kevent_layout::TYPE)) == EVENT_SYNCHRONIZATION_OBJECT {
        EventKind::Synchronization
    } else {
        EventKind::Notification
    }
}

/// `KeReadStateEvent` — the current signalled state.
///
/// # Safety
/// `ev` must be a valid `KEVENT`.
pub unsafe fn kevent_read_state(ev: *const u8) -> bool {
    core::ptr::read_unaligned(ev.add(kevent_layout::SIGNAL_STATE) as *const i32) != 0
}

/// `KeSetEvent` — signal the event, returning the previous state.
///
/// # Safety
/// `ev` must be a valid `KEVENT`.
pub unsafe fn kevent_set(ev: *mut u8) -> bool {
    let prev = kevent_read_state(ev);
    core::ptr::write_unaligned(ev.add(kevent_layout::SIGNAL_STATE) as *mut i32, 1);
    prev
}

/// `KeResetEvent` — clear the event, returning the previous state.
///
/// # Safety
/// `ev` must be a valid `KEVENT`.
pub unsafe fn kevent_reset(ev: *mut u8) -> bool {
    let prev = kevent_read_state(ev);
    core::ptr::write_unaligned(ev.add(kevent_layout::SIGNAL_STATE) as *mut i32, 0);
    prev
}

/// `KeClearEvent` — clear the event (no return value; the cheap `KeResetEvent`).
///
/// # Safety
/// `ev` must be a valid `KEVENT`.
pub unsafe fn kevent_clear(ev: *mut u8) {
    core::ptr::write_unaligned(ev.add(kevent_layout::SIGNAL_STATE) as *mut i32, 0);
}

/// `KePulseEvent` — momentarily signal (release waiters), then reset. With no modelled waiter list
/// the observable net effect on the inline state is a clear; the previous state is returned.
///
/// # Safety
/// `ev` must be a valid `KEVENT`.
pub unsafe fn kevent_pulse(ev: *mut u8) -> bool {
    let prev = kevent_read_state(ev);
    core::ptr::write_unaligned(ev.add(kevent_layout::SIGNAL_STATE) as *mut i32, 0);
    prev
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::kevent_layout as o;
    use super::*;

    #[test]
    fn initializes_a_real_dispatcher_header() {
        let mut buf = [0xAAu8; o::SIZE_OF];
        let ev = buf.as_mut_ptr();
        unsafe {
            init_kevent(ev, EventKind::Synchronization, false);
            assert_eq!(core::ptr::read_unaligned(ev.add(o::TYPE)), EVENT_SYNCHRONIZATION_OBJECT);
            assert_eq!(core::ptr::read_unaligned(ev.add(o::SIZE)), 6);
            assert!(!kevent_read_state(ev));
            assert_eq!(kevent_kind(ev), EventKind::Synchronization);
            // Empty waiter list is self-linked.
            let head = ev.add(o::WAIT_LIST_HEAD) as u64;
            assert_eq!(core::ptr::read_unaligned(ev.add(o::WAIT_LIST_HEAD) as *const u64), head);
            assert_eq!(core::ptr::read_unaligned(ev.add(o::WAIT_LIST_HEAD + 8) as *const u64), head);
        }
    }

    #[test]
    fn notification_type_byte_and_initial_signalled() {
        let mut buf = [0u8; o::SIZE_OF];
        let ev = buf.as_mut_ptr();
        unsafe {
            init_kevent(ev, EventKind::Notification, true);
            assert_eq!(core::ptr::read_unaligned(ev.add(o::TYPE)), EVENT_NOTIFICATION_OBJECT);
            assert_eq!(kevent_kind(ev), EventKind::Notification);
            assert!(kevent_read_state(ev));
        }
    }

    #[test]
    fn set_reset_clear_return_previous_state() {
        let mut buf = [0u8; o::SIZE_OF];
        let ev = buf.as_mut_ptr();
        unsafe {
            init_kevent(ev, EventKind::Notification, false);
            assert!(!kevent_set(ev)); // was clear
            assert!(kevent_read_state(ev));
            assert!(kevent_set(ev)); // was set (idempotent signal)
            assert!(kevent_reset(ev)); // was set
            assert!(!kevent_read_state(ev));
            assert!(!kevent_reset(ev)); // was clear
            kevent_set(ev);
            kevent_clear(ev);
            assert!(!kevent_read_state(ev));
        }
    }

    #[test]
    fn pulse_clears_and_returns_previous() {
        let mut buf = [0u8; o::SIZE_OF];
        let ev = buf.as_mut_ptr();
        unsafe {
            init_kevent(ev, EventKind::Synchronization, true);
            assert!(kevent_pulse(ev)); // was signalled
            assert!(!kevent_read_state(ev)); // pulse leaves it clear
            assert!(!kevent_pulse(ev)); // was clear
        }
    }
}
