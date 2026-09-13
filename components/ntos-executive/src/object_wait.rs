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
    pub(super) caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
    pub(super) reply_sent: bool,
    pub(super) reference_followup: Option<(usize, Option<nt_io_completion::FileReferenceRelease>)>,
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
    pub(super) native_call_transport: bool,
    pub(super) deadline: nt_delay_execution::Deadline,
}

impl ObjectWaiterRecord {
    const fn empty(caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller) -> Self {
        Self {
            caller,
            reply_sent: false,
            reference_followup: None,
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
            native_call_transport: false,
            deadline: nt_delay_execution::Deadline::Infinite,
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
        caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
        sequence: u64,
        objects: &[WaitObject],
        event_leases: &[nt_kernel_exec::EventLeaseId],
        result_indices: &[u8],
        wait_all: bool,
        alertable: bool,
        reply_cap: u64,
        resume_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
        native_call_transport: bool,
        deadline: nt_delay_execution::Deadline,
    ) -> Self {
        let mut record = Self::empty(caller);
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
        record.tid = u64::from(caller.thread().thread_id());
        record.pi = caller.pi();
        record.badge = caller.badge();
        record.resume_ip = resume_ip;
        record.resume_sp = resume_sp;
        record.resume_flags = resume_flags;
        record.native_call_transport = native_call_transport;
        record.deadline = deadline;
        record
    }
}

pub(super) static mut OBJECT_WAITERS: ObjectWaiterTable<ObjectWaiterRecord> =
    ObjectWaiterTable::new();

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
            .find(|(identity, record)| {
                record.alertable
                    && record.tid == tid
                    && !(&*core::ptr::addr_of!(OBJECT_WAITERS)).is_claimed(*identity)
            })
            .map(|(identity, record)| (identity, *record))
    }
}

pub(super) fn object_waiter_next_deadline(now: nt_delay_execution::TimeSnapshot) -> Option<u64> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .iter()
            .filter(|(identity, _)| !(&*core::ptr::addr_of!(OBJECT_WAITERS)).is_claimed(*identity))
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

pub(super) fn object_waiter_next_after_sequence(
    sequence: u64,
) -> Option<(ObjectWaiterIdentity, ObjectWaiterRecord)> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .iter()
            .filter(|(identity, _)| !(&*core::ptr::addr_of!(OBJECT_WAITERS)).is_claimed(*identity))
            .filter(|(_, record)| record.sequence > sequence)
            .min_by_key(|(_, record)| record.sequence)
            .map(|(identity, record)| (identity, *record))
    }
}

pub(super) fn object_waiter_is_claimed(identity: ObjectWaiterIdentity) -> bool {
    unsafe { (&*core::ptr::addr_of!(OBJECT_WAITERS)).is_claimed(identity) }
}

pub(super) fn release_wait_reference_step(
    handler: &mut ExecNtHandler,
    record: ObjectWaiterRecord,
    index: usize,
) -> Result<Option<nt_io_completion::FileReferenceRelease>, u32> {
    if index >= record.count as usize {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    let object = record.objects[index];
    if object.kind() == WaitObject::KIND_FILE {
        handler.file_completion.release_file(object.id()).map(Some)
    } else {
        handler.release_wait_object_reference(object, record.event_leases[index])?;
        Ok(None)
    }
}

pub(super) fn finish_wait_reference_step(
    handler: &mut ExecNtHandler,
    release: Option<nt_io_completion::FileReferenceRelease>,
) -> Result<(), u32> {
    if let Some(release) = release {
        // A wait reference cannot authorize another driver's CLEANUP/CLOSE transaction.
        if release.cleanup_required {
            return Err(nt_fs::STATUS_INVALID_PARAMETER);
        }
        if let Some(port) = release.port_id {
            handler.try_release_io_completion_reference(port)?;
        }
    }
    Ok(())
}
