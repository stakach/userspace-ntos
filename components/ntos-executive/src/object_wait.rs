//! Native dispatcher-wait records; storage identities are owned by nt-user-host.

use super::{ExecNtHandler, WaitObject, HOSTED_THREAD_WAIT_INITIAL_RESERVE};
use nt_user_host::object_wait::{ObjectWaiterIdentity, ObjectWaiterTable};

/// The waiter queue: each record parks one blocked caller.
///
/// A single-object wait (NtWaitForSingleObject) records one wait object in slot 0 of its set
/// (count 1); a multi-object wait (NtWaitForMultipleObjects) records up to `WAITER_MAX_EVENTS`
/// typed wait objects + a `wait_all` flag. Object-wait records are heap-backed and grow with real
/// parked wait demand. The stolen reply-cap pool remains a separate transport resource.
const OBJECT_WAITER_INITIAL_RESERVE: usize = HOSTED_THREAD_WAIT_INITIAL_RESERVE;
/// NT's architectural maximum for one multi-object wait.
pub(super) const WAITER_MAX_EVENTS: usize = 64;

#[derive(Clone, Copy)]
pub(super) struct ObjectWaiterRecord {
    pub(super) sequence: u64,
    pub(super) objects: [WaitObject; WAITER_MAX_EVENTS],
    pub(super) event_leases: [nt_kernel_exec::EventLeaseId; WAITER_MAX_EVENTS],
    pub(super) result_indices: [u8; WAITER_MAX_EVENTS],
    pub(super) count: u8,
    pub(super) wait_all: bool,
    pub(super) alertable: bool,
    pub(super) reply_cap: u64,
    pub(super) tid: u64,
    pub(super) pi: usize,
    pub(super) badge: u64,
    pub(super) resume_ip: u64,
    pub(super) resume_sp: u64,
    pub(super) resume_flags: u64,
    pub(super) deadline: nt_delay_execution::Deadline,
    pub(super) pending_wake_index: u64,
    pub(super) pending_wake_object: WaitObject,
}

impl ObjectWaiterRecord {
    const fn empty() -> Self {
        Self {
            sequence: 0,
            objects: [WaitObject::FREE; WAITER_MAX_EVENTS],
            event_leases: [nt_kernel_exec::EventLeaseId::NULL; WAITER_MAX_EVENTS],
            result_indices: [0; WAITER_MAX_EVENTS],
            count: 0,
            wait_all: false,
            alertable: false,
            reply_cap: 0,
            tid: 0,
            pi: 0,
            badge: 0,
            resume_ip: 0,
            resume_sp: 0,
            resume_flags: 0,
            deadline: nt_delay_execution::Deadline::Infinite,
            pending_wake_index: u64::MAX,
            pending_wake_object: WaitObject::FREE,
        }
    }

    fn is_valid_for_park(self) -> bool {
        self.count != 0
            && self.count as usize <= WAITER_MAX_EVENTS
            && self.reply_cap != 0
            && self.sequence != 0
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        sequence: u64,
        objects: &[WaitObject],
        event_leases: &[nt_kernel_exec::EventLeaseId],
        result_indices: &[u8],
        wait_all: bool,
        alertable: bool,
        reply_cap: u64,
        tid: u64,
        pi: usize,
        badge: u64,
        resume_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
        deadline: nt_delay_execution::Deadline,
    ) -> Self {
        let mut record = Self::empty();
        record.sequence = sequence;
        for (index, object) in objects.iter().copied().enumerate() {
            record.objects[index] = object;
            record.event_leases[index] = event_leases[index];
            record.result_indices[index] = result_indices[index];
        }
        record.count = objects.len() as u8;
        record.wait_all = wait_all;
        record.alertable = alertable;
        record.reply_cap = reply_cap;
        record.tid = tid;
        record.pi = pi;
        record.badge = badge;
        record.resume_ip = resume_ip;
        record.resume_sp = resume_sp;
        record.resume_flags = resume_flags;
        record.deadline = deadline;
        record
    }
}

static mut OBJECT_WAITERS: ObjectWaiterTable<ObjectWaiterRecord> = ObjectWaiterTable::new();

pub(super) fn object_waiter_table_reset() -> bool {
    unsafe { (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS)).reset(OBJECT_WAITER_INITIAL_RESERVE) }
}

pub(super) fn object_waiter_table_stats() -> (usize, usize, usize, u64, u64) {
    unsafe { (&*core::ptr::addr_of!(OBJECT_WAITERS)).stats() }
}

pub(super) fn object_waiter_len() -> usize {
    unsafe { (&*core::ptr::addr_of!(OBJECT_WAITERS)).slot_len() }
}

pub(super) fn object_waiter_record(
    slot: usize,
) -> Option<(ObjectWaiterIdentity, ObjectWaiterRecord)> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .get(slot)
            .map(|(identity, record)| (identity, *record))
    }
}

pub(super) fn object_waiter_contains_tid(tid: u64) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .iter()
            .any(|(_, record)| record.tid == tid)
    }
}

pub(super) fn object_waiter_alertable_for_tid(
    tid: u64,
) -> Option<(ObjectWaiterIdentity, ObjectWaiterRecord)> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .iter()
            .find(|(_, record)| record.alertable && record.tid == tid)
            .map(|(identity, record)| (identity, *record))
    }
}

pub(super) fn object_waiter_take_exact(
    identity: ObjectWaiterIdentity,
) -> Option<ObjectWaiterRecord> {
    unsafe { (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS)).take(identity) }
}

pub(super) fn object_waiter_next_deadline(now: nt_delay_execution::TimeSnapshot) -> Option<u64> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .iter()
            .filter_map(|(_, record)| record.deadline.monotonic_target(now))
            .min()
    }
}

pub(super) fn object_waiter_park(record: ObjectWaiterRecord) -> bool {
    if !record.is_valid_for_park() {
        return false;
    }
    unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS))
            .insert(record)
            .is_ok()
    }
}

pub(super) fn object_waiter_clear_pending_wakes() {
    unsafe {
        let table = &mut *core::ptr::addr_of_mut!(OBJECT_WAITERS);
        for slot in 0..table.slot_len() {
            if let Some((identity, _)) = table.get(slot) {
                table.update_exact(identity, |record| {
                    record.pending_wake_index = u64::MAX;
                    record.pending_wake_object = WaitObject::FREE;
                });
            }
        }
    }
}

pub(super) fn object_waiter_mark_pending_wake(
    identity: ObjectWaiterIdentity,
    wake_index: u64,
    wake_object: WaitObject,
) -> bool {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS)).update_exact(identity, |record| {
            record.pending_wake_index = wake_index;
            record.pending_wake_object = wake_object;
        })
    }
}

pub(super) fn object_waiter_pending_wake(
    slot: usize,
) -> Option<(ObjectWaiterIdentity, ObjectWaiterRecord, u64, WaitObject)> {
    let (identity, record) = object_waiter_record(slot)?;
    (record.pending_wake_index != u64::MAX).then_some((
        identity,
        record,
        record.pending_wake_index,
        record.pending_wake_object,
    ))
}

pub(super) fn object_waiter_next_after_sequence(
    sequence: u64,
) -> Option<(ObjectWaiterIdentity, ObjectWaiterRecord)> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .iter()
            .filter(|(_, record)| record.sequence > sequence)
            .min_by_key(|(_, record)| record.sequence)
            .map(|(identity, record)| (identity, *record))
    }
}

pub(super) fn release_wait_object_references(
    handler: &mut ExecNtHandler,
    record: ObjectWaiterRecord,
) {
    for index in (0..record.count as usize).rev() {
        handler
            .release_wait_object_reference(record.objects[index], record.event_leases[index])
            .expect("parked wait lost its retained object reference");
    }
}
