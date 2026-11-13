//! A pending File request references its completion Event (as `IopReferenceEvent` does in NT):
//! the Event cannot retire while the I/O is pending, completion signals exactly that Event, and
//! a request that carries only a bare Event index is never signalled, because the index may
//! name a later object once its slot is reused.

use nt_io_manager::{CompletionEvent, FileTransferEvent, PendingFileIo};
use nt_kernel_exec::{
    EventKind, EventLeaseKind, EventObjectId, EventObjectOwner, EventObjectRegistry, EventStore,
    RetiredEventObject,
};
use nt_object_manager::slot_ledger::{SlotLedger, SlotRef};

/// The executive's rules in miniature: a namespace slot is freed only by the registry's
/// retirement, and the next Event may then take the same index.
#[derive(Default)]
struct Events {
    slots: SlotLedger,
    registry: EventObjectRegistry,
    state: EventStore,
}

impl Events {
    fn create(&mut self) -> (SlotRef, EventObjectId) {
        let slot = self.slots.allocate().unwrap();
        let native = slot.index() as u64 + 1;
        assert!(self.state.try_initialize(native, EventKind::Notification, false));
        let id = self.registry.create(EventObjectOwner::new(7, 1), native).unwrap();
        self.registry.retain_handle(id).unwrap();
        (slot, id)
    }

    fn retire(&mut self, slot: SlotRef, retired: Option<RetiredEventObject>) -> bool {
        let Some(retired) = retired else { return false };
        assert!(self.state.remove_existing(retired.native_identity));
        self.slots.release(slot, 0).unwrap();
        true
    }

    /// `NtClose` of the last handle to a non-permanent Event.
    fn close_last_handle(&mut self, slot: SlotRef, id: EventObjectId) -> bool {
        assert_eq!(self.registry.release_handle(id), Ok(None));
        let retired = self.registry.request_delete(id).unwrap();
        self.retire(slot, retired)
    }

    fn begin_io(&mut self, id: EventObjectId) -> FileTransferEvent {
        let lease = self.registry.acquire_wait(id, EventLeaseKind::Operation).unwrap();
        let native_identity = self.registry.snapshot(id).unwrap().native_identity;
        FileTransferEvent { id, lease, native_identity }
    }

    /// What I/O completion does with a request's Event.
    fn complete(&mut self, slot: SlotRef, pending: &PendingFileIo) -> Option<u64> {
        let CompletionEvent::Leased(event) = pending.completion_event() else {
            return None;
        };
        let native = event.resolve(&self.registry)?;
        self.state.set_existing(native)?;
        let retired = self
            .registry
            .release_wait(event.lease, EventLeaseKind::Operation)
            .unwrap();
        self.retire(slot, retired);
        Some(native)
    }

    fn signaled(&self, native: u64) -> bool {
        self.state.query_existing(native).unwrap().1
    }
}

fn pending(event_obj_idx: u64, transfer_event: Option<FileTransferEvent>) -> PendingFileIo {
    PendingFileIo { event_obj_idx, transfer_event, ..PendingFileIo::default() }
}

#[test]
fn an_event_with_pending_io_does_not_retire_when_its_last_handle_closes() {
    let mut events = Events::default();
    let (slot, id) = events.create();
    let lease = events.begin_io(id);

    assert!(!events.close_last_handle(slot, id), "pending I/O still references the Event");
    assert_eq!(lease.resolve(&events.registry), Some(lease.native_identity));
    assert!(events.slots.is_current(slot));

    // No later Event can be given the index while the request is pending.
    for _ in 0..200 {
        let (other_slot, other) = events.create();
        assert_ne!(other_slot.index(), slot.index());
        assert!(events.close_last_handle(other_slot, other));
    }
}

#[test]
fn completion_after_handle_close_signals_the_original_event_then_releases_it() {
    let mut events = Events::default();
    let (slot, id) = events.create();
    let lease = events.begin_io(id);
    let request = pending(lease.native_identity, Some(lease));
    assert!(!events.close_last_handle(slot, id));

    // The signal is observable until the completion's own reference is released.
    let native = lease.native_identity;
    let CompletionEvent::Leased(event) = request.completion_event() else {
        panic!("a leased request names its Event");
    };
    assert_eq!(event.resolve(&events.registry), Some(native));
    assert_eq!(events.state.set_existing(native), Some(false));
    assert!(events.signaled(native));

    let retired = events.registry.release_wait(event.lease, EventLeaseKind::Operation).unwrap();
    assert!(events.retire(slot, retired), "the completion held the final reference");
    assert!(!events.slots.is_current(slot));
    assert_eq!(lease.resolve(&events.registry), None, "a released lease names nothing");
}

#[test]
fn a_request_holding_only_a_bare_index_never_signals_the_slots_next_occupant() {
    let mut events = Events::default();
    let (slot, id) = events.create();
    let stale_index = events.registry.snapshot(id).unwrap().native_identity;
    let request = pending(stale_index, None);

    // Nothing references the Event, so closing the handle retires it and frees the slot.
    assert!(events.close_last_handle(slot, id));
    let (victim_slot, victim) = events.create();
    assert_eq!(victim_slot.index(), slot.index(), "the freed index is reused");
    let victim_native = events.registry.snapshot(victim).unwrap().native_identity;
    assert_eq!(victim_native, stale_index);

    assert_eq!(request.completion_event(), CompletionEvent::Unleased(stale_index));
    assert_eq!(events.complete(victim_slot, &request), None);
    assert!(!events.signaled(victim_native), "an unrelated Event was signalled");
}

#[test]
fn a_lease_that_was_already_released_cannot_reach_a_reused_slot() {
    let mut events = Events::default();
    let (slot, id) = events.create();
    let lease = events.begin_io(id);
    let request = pending(lease.native_identity, Some(lease));
    assert!(!events.close_last_handle(slot, id));
    assert_eq!(events.complete(slot, &request), Some(lease.native_identity));

    let (victim_slot, victim) = events.create();
    assert_eq!(victim_slot.index(), slot.index());
    let victim_native = events.registry.snapshot(victim).unwrap().native_identity;

    // A second delivery of the same completion finds its lease gone.
    assert_eq!(events.complete(victim_slot, &request), None);
    assert!(!events.signaled(victim_native));
}

#[test]
fn a_request_without_an_event_or_with_a_mismatched_lease_has_no_leased_target() {
    let mut events = Events::default();
    let (_, id) = events.create();
    let lease = events.begin_io(id);

    assert_eq!(pending(u64::MAX, None).completion_event(), CompletionEvent::None);
    // A detached consumer keeps its lease for release but signals nothing.
    assert_eq!(pending(u64::MAX, Some(lease)).completion_event(), CompletionEvent::None);
    assert_eq!(
        pending(lease.native_identity + 1, Some(lease)).completion_event(),
        CompletionEvent::Unleased(lease.native_identity + 1)
    );
}
