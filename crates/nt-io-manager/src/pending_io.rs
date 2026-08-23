//! Generic ownership records for File-bound IRPs that complete after their native syscall returns
//! or parks.
//!
//! Driver completion remains owned by the canonical [`IrpId`](crate::IrpId). This table owns only
//! the executive delivery context needed to publish that terminal result exactly once to user
//! memory, APC/event/File/IOCP surfaces, and an optional synchronous syscall reply.

use alloc::vec::Vec;

pub const IO_DELIVERY_BUFFER_PUBLISHED: u16 = 1 << 0;
pub const IO_DELIVERY_IOSB_PUBLISHED: u16 = 1 << 1;
pub const IO_DELIVERY_APC_PUBLISHED: u16 = 1 << 2;
pub const IO_DELIVERY_FILE_PUBLISHED: u16 = 1 << 3;
pub const IO_DELIVERY_IOCP_PUBLISHED: u16 = 1 << 4;
pub const IO_DELIVERY_EVENT_PUBLISHED: u16 = 1 << 5;
pub const IO_DELIVERY_REPLY_CLAIMED: u16 = 1 << 6;
pub const IO_DELIVERY_REPLY_PUBLISHED: u16 = 1 << 7;
pub const IO_DELIVERY_BACKEND_ACKED: u16 = 1 << 8;
pub const IO_DELIVERY_CREATE_COMMITTED: u16 = 1 << 9;
pub const IO_DELIVERY_HANDLE_PUBLISHED: u16 = 1 << 10;

const IO_DELIVERY_PUBLIC_FLAGS: u16 = IO_DELIVERY_BUFFER_PUBLISHED
    | IO_DELIVERY_IOSB_PUBLISHED
    | IO_DELIVERY_APC_PUBLISHED
    | IO_DELIVERY_FILE_PUBLISHED
    | IO_DELIVERY_IOCP_PUBLISHED
    | IO_DELIVERY_EVENT_PUBLISHED;

/// State needed to turn one successful terminal CREATE into a process-visible handle. The provider
/// context is opaque to the generic owner; the executive interprets it only after resolving the
/// File's dynamically registered device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PendingFileCreate {
    pub handle_va: u64,
    pub desired_access: u32,
    pub synchronous: bool,
    pub provider_context: u64,
    /// Locally committed result after provider metadata and handle ownership are established.
    pub status: u32,
    pub information: u64,
    pub handle_value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PendingFileIoOperation {
    #[default]
    Transfer,
    Create(PendingFileCreate),
}

/// One pending File-bound operation and every completion surface owned by that exact IRP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PendingFileIo {
    /// Generation-protected I/O Manager File identity used for lifetime, cancellation, and signal.
    pub file_id: u64,
    /// Generation-protected I/O Manager IRP identity used for terminal copy and acknowledgement.
    pub irp_id: u64,
    /// IRP major function used to reject a completion routed to the wrong syscall owner.
    pub major: u8,
    pub operation: PendingFileIoOperation,
    /// Completion surfaces already published for this exact record generation.
    pub delivery_state: u16,
    /// Owning process index, thread id, and hosted fault badge.
    pub pi: u32,
    pub tid: u64,
    pub badge: u64,
    /// Optional caller output buffer and its byte capacity.
    pub output_va: u64,
    pub output_len: u32,
    /// Bytes already copied from the retained completion output.
    pub output_offset: u32,
    /// Caller IO_STATUS_BLOCK.
    pub iosb_va: u64,
    /// Optional user APC and its caller-supplied context.
    pub apc_routine: u64,
    pub apc_context: u64,
    /// Whether the request's tagged event suppresses completion-port publication.
    pub completion_port_suppressed: bool,
    /// Whether terminal completion must signal the File object.
    pub signal_file: bool,
    /// Whether terminal completion owns an IOCP packet when no APC is supplied.
    pub publish_iocp: bool,
    /// Executive event-object index, or `u64::MAX` when no event was supplied.
    pub event_obj_idx: u64,
    /// Stolen synchronous syscall reply cap. Async requests have no reply owner.
    pub reply_cap: u64,
    /// Whether this record owns a parked synchronous syscall reply.
    pub reply_required: bool,
    /// Native-syscall resume context restored before replying to a synchronous request.
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
}

const DEFAULT_INITIAL_RESERVE: usize = 16;

/// Reset-safe, growable table of generic pending File I/O delivery owners.
#[derive(Clone, Debug)]
pub struct PendingFileIoTable {
    slots: Vec<Option<PendingFileIo>>,
    initial_reserve: usize,
}

impl Default for PendingFileIoTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingFileIoTable {
    pub const fn new() -> Self {
        Self::with_initial_reserve(DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            initial_reserve,
        }
    }

    fn grow_reservation(&mut self) -> bool {
        if self.slots.len() == self.slots.capacity() {
            let reserve = if self.slots.capacity() == 0 {
                self.initial_reserve.max(1)
            } else {
                1
            };
            if self.slots.try_reserve(reserve).is_err() {
                return false;
            }
        }
        true
    }

    /// Clear stale records and reserve bootstrap storage before an allocator watermark is taken.
    pub fn reset(&mut self) -> bool {
        self.slots.clear();
        if self.slots.capacity() < self.initial_reserve {
            let additional = self.initial_reserve - self.slots.capacity();
            if self.slots.try_reserve(additional).is_err() {
                return false;
            }
        }
        true
    }

    /// Ensure the next pending IRP can transfer ownership without allocating after dispatch.
    pub fn ensure_capacity(&mut self) -> bool {
        if self.slots.iter().any(Option::is_none) || self.slots.len() < self.slots.capacity() {
            return true;
        }
        self.grow_reservation()
    }

    /// Insert one exact pending owner. A canonical IRP may have only one delivery owner.
    pub fn park(&mut self, pending: PendingFileIo) -> Option<usize> {
        let create_valid = match pending.operation {
            PendingFileIoOperation::Transfer => !crate::is_create_major(pending.major),
            PendingFileIoOperation::Create(create) => {
                crate::is_create_major(pending.major)
                    && create.handle_va != 0
                    && create.status == nt_status::NtStatus::PENDING.raw() as u32
                    && create.information == 0
                    && create.handle_value == 0
                    && pending.output_va == 0
                    && pending.output_len == 0
                    && pending.iosb_va != 0
                    && pending.apc_routine == 0
                    && !pending.signal_file
                    && !pending.publish_iocp
                    && pending.event_obj_idx == u64::MAX
            }
        };
        if pending.file_id == 0
            || pending.irp_id == 0
            || !create_valid
            || pending.delivery_state != 0
            || pending.output_offset != 0
            || (pending.output_len != 0 && pending.output_va == 0)
            || (pending.apc_routine != 0 && pending.publish_iocp)
            || pending.reply_required != (pending.reply_cap != 0)
            || self
                .slots
                .iter()
                .any(|slot| slot.is_some_and(|record| record.irp_id == pending.irp_id))
        {
            return None;
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(pending);
                return Some(index);
            }
        }
        if !self.grow_reservation() {
            return None;
        }
        self.slots.push(Some(pending));
        Some(self.slots.len() - 1)
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    pub fn has_capacity(&self) -> bool {
        self.slots.iter().any(Option::is_none) || self.slots.len() < self.slots.capacity()
    }

    pub fn has_thread(&self, tid: u64) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.is_some_and(|pending| pending.tid == tid))
    }

    pub fn drain_all(&self) -> impl Iterator<Item = (usize, PendingFileIo)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.map(|pending| (index, pending)))
    }

    pub fn get(&self, slot: usize) -> Option<PendingFileIo> {
        self.slots.get(slot).copied().flatten()
    }

    /// Validate that a terminal manager projection belongs to this exact delivery owner.
    pub fn matches_completion_exact(
        &self,
        slot: usize,
        irp_id: u64,
        file_id: u64,
        requestor_tid: u64,
        major: u8,
    ) -> bool {
        self.get(slot).is_some_and(|pending| {
            pending.irp_id == irp_id
                && pending.file_id == file_id
                && pending.tid == requestor_tid
                && pending.major == major
        })
    }

    fn required_delivery_state(pending: PendingFileIo) -> u16 {
        let mut required = IO_DELIVERY_BACKEND_ACKED;
        if matches!(pending.operation, PendingFileIoOperation::Create(_)) {
            required |= IO_DELIVERY_CREATE_COMMITTED | IO_DELIVERY_HANDLE_PUBLISHED;
        }
        if pending.output_va != 0 && pending.output_len != 0 {
            required |= IO_DELIVERY_BUFFER_PUBLISHED;
        }
        if pending.iosb_va != 0 {
            required |= IO_DELIVERY_IOSB_PUBLISHED;
        }
        if pending.signal_file {
            required |= IO_DELIVERY_FILE_PUBLISHED;
        }
        if pending.event_obj_idx != u64::MAX {
            required |= IO_DELIVERY_EVENT_PUBLISHED;
        }
        if pending.apc_routine != 0 {
            required |= IO_DELIVERY_APC_PUBLISHED;
        } else if pending.publish_iocp {
            required |= IO_DELIVERY_IOCP_PUBLISHED;
        }
        if pending.reply_required {
            required |= IO_DELIVERY_REPLY_CLAIMED | IO_DELIVERY_REPLY_PUBLISHED;
        }
        required
    }

    pub fn completion_surfaces_published_exact(&self, slot: usize, irp_id: u64) -> bool {
        self.get(slot).is_some_and(|pending| {
            pending.irp_id == irp_id
                && pending.delivery_state
                    & (Self::required_delivery_state(pending) & !IO_DELIVERY_BACKEND_ACKED)
                    == Self::required_delivery_state(pending) & !IO_DELIVERY_BACKEND_ACKED
        })
    }

    /// Commit the local CREATE publication result once. Retrying the user handle write can then
    /// reuse the exact same handle without allocating or duplicating process-visible ownership.
    pub fn commit_create_exact(
        &mut self,
        slot: usize,
        irp_id: u64,
        status: u32,
        information: u64,
        handle_value: u64,
    ) -> Option<u16> {
        if status == nt_status::NtStatus::PENDING.raw() as u32
            || ((status as i32) >= 0) != (handle_value != 0)
        {
            return None;
        }
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id {
            return None;
        }
        let PendingFileIoOperation::Create(mut create) = pending.operation else {
            return None;
        };
        if pending.delivery_state & IO_DELIVERY_CREATE_COMMITTED != 0 {
            return (create.status == status
                && create.information == information
                && create.handle_value == handle_value)
                .then_some(pending.delivery_state);
        }
        create.status = status;
        create.information = information;
        create.handle_value = handle_value;
        pending.operation = PendingFileIoOperation::Create(create);
        pending.delivery_state |= IO_DELIVERY_CREATE_COMMITTED;
        Some(pending.delivery_state)
    }

    pub fn mark_create_handle_published_exact(&mut self, slot: usize, irp_id: u64) -> Option<u16> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id
            || !matches!(pending.operation, PendingFileIoOperation::Create(_))
            || pending.delivery_state & IO_DELIVERY_CREATE_COMMITTED == 0
        {
            return None;
        }
        pending.delivery_state |= IO_DELIVERY_HANDLE_PUBLISHED;
        Some(pending.delivery_state)
    }

    /// Remove an exact owner only after all required surfaces and backend ACK were committed.
    pub fn finish_exact(&mut self, slot: usize, irp_id: u64) -> Option<PendingFileIo> {
        let entry = self.slots.get_mut(slot)?;
        if entry.is_some_and(|pending| {
            pending.irp_id == irp_id
                && pending.delivery_state & Self::required_delivery_state(pending)
                    == Self::required_delivery_state(pending)
        }) {
            entry.take()
        } else {
            None
        }
    }

    pub fn mark_delivery_exact(&mut self, slot: usize, irp_id: u64, flag: u16) -> Option<u16> {
        if flag.count_ones() != 1
            || flag & IO_DELIVERY_PUBLIC_FLAGS == 0
            || flag & !IO_DELIVERY_PUBLIC_FLAGS != 0
        {
            return None;
        }
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id {
            return None;
        }
        pending.delivery_state |= flag;
        Some(pending.delivery_state)
    }

    /// Advance an idempotent retained-output copy. The buffer surface is published only when every
    /// terminal byte has reached the caller.
    pub fn advance_output_exact(
        &mut self,
        slot: usize,
        irp_id: u64,
        copied: u32,
        terminal_output_len: u32,
    ) -> Option<u32> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id
            || terminal_output_len > pending.output_len
            || pending.output_offset > terminal_output_len
        {
            return None;
        }
        let next = pending.output_offset.checked_add(copied)?;
        if next > terminal_output_len {
            return None;
        }
        pending.output_offset = next;
        if next == terminal_output_len {
            pending.delivery_state |= IO_DELIVERY_BUFFER_PUBLISHED;
        }
        Some(next)
    }

    /// Transfer synchronous reply ownership exactly once. `Some(None)` means it was already claimed.
    pub fn claim_reply_cap_exact(&mut self, slot: usize, irp_id: u64) -> Option<Option<u64>> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id || !pending.reply_required {
            return None;
        }
        if pending.delivery_state & IO_DELIVERY_REPLY_CLAIMED != 0 {
            return Some(None);
        }
        let reply_cap = core::mem::replace(&mut pending.reply_cap, 0);
        pending.delivery_state |= IO_DELIVERY_REPLY_CLAIMED;
        Some(Some(reply_cap))
    }

    pub fn mark_reply_published_exact(&mut self, slot: usize, irp_id: u64) -> Option<u16> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id
            || !pending.reply_required
            || pending.delivery_state & IO_DELIVERY_REPLY_CLAIMED == 0
        {
            return None;
        }
        pending.delivery_state |= IO_DELIVERY_REPLY_PUBLISHED;
        Some(pending.delivery_state)
    }

    pub fn mark_backend_acked_exact(&mut self, slot: usize, irp_id: u64) -> Option<u16> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id
            || pending.delivery_state & IO_DELIVERY_BACKEND_ACKED != 0
            || pending.delivery_state
                & (Self::required_delivery_state(*pending) & !IO_DELIVERY_BACKEND_ACKED)
                != Self::required_delivery_state(*pending) & !IO_DELIVERY_BACKEND_ACKED
        {
            return None;
        }
        pending.delivery_state |= IO_DELIVERY_BACKEND_ACKED;
        Some(pending.delivery_state)
    }

    /// Remove every request owned by a terminating thread. The caller must release any reply cap,
    /// request cancellation/abandonment, and release the retained File reference.
    pub fn take_thread_with<F>(&mut self, tid: u64, mut take: F) -> usize
    where
        F: FnMut(PendingFileIo),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|pending| pending.tid == tid) {
                let pending = slot.take().unwrap();
                take(pending);
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn pending(file_id: u64, irp_id: u64, tid: u64) -> PendingFileIo {
        PendingFileIo {
            file_id,
            irp_id,
            major: nt_io_abi::major::IRP_MJ_DEVICE_CONTROL,
            operation: PendingFileIoOperation::Transfer,
            pi: 3,
            tid,
            badge: 9,
            output_va: 0x1000,
            output_len: 64,
            output_offset: 0,
            iosb_va: 0x2000,
            apc_routine: 0x3000,
            apc_context: 0x4000,
            completion_port_suppressed: false,
            signal_file: false,
            publish_iocp: false,
            event_obj_idx: 7,
            reply_cap: 0x50,
            reply_required: true,
            resume_ip: 0x5000,
            resume_sp: 0x6000,
            resume_flags: 0x202,
            delivery_state: 0,
        }
    }

    #[test]
    fn pending_file_io_grows_without_a_policy_limit() {
        let mut table = PendingFileIoTable::with_initial_reserve(1);
        assert!(table.reset());
        let initial_capacity = table.capacity();
        for index in 0..initial_capacity + 3 {
            table
                .park(pending(0x100 + index as u64, 0x1_0000 + index as u64, 7))
                .unwrap();
        }
        assert_eq!(table.len(), initial_capacity + 3);
        assert!(table.capacity() >= table.len());
    }

    #[test]
    fn pending_file_io_rejects_null_and_duplicate_canonical_ids() {
        let mut table = PendingFileIoTable::new();
        assert!(table.park(pending(0, 1, 7)).is_none());
        assert!(table.park(pending(1, 0, 7)).is_none());
        assert!(table.park(pending(1, 2, 7)).is_some());
        assert!(table.park(pending(3, 2, 8)).is_none());
    }

    #[test]
    fn pending_file_io_rejects_inconsistent_async_surfaces() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.output_va = 0;
        assert!(table.park(request).is_none());

        let mut request = pending(1, 3, 7);
        request.publish_iocp = true;
        assert!(table.park(request).is_none());

        let mut request = pending(1, 4, 7);
        request.reply_cap = 0;
        request.reply_required = false;
        request.apc_routine = 0;
        request.publish_iocp = true;
        assert!(table.park(request).is_some());
    }

    #[test]
    fn pending_file_io_delivery_progress_is_generation_exact() {
        let mut table = PendingFileIoTable::new();
        let request = pending(1, 2, 7);
        let slot = table.park(request).unwrap();
        assert_eq!(
            table.mark_delivery_exact(slot, 3, IO_DELIVERY_IOSB_PUBLISHED),
            None
        );
        assert_eq!(
            table.mark_delivery_exact(slot, 2, IO_DELIVERY_IOSB_PUBLISHED),
            Some(IO_DELIVERY_IOSB_PUBLISHED)
        );
        assert_eq!(
            table.mark_delivery_exact(slot, 2, IO_DELIVERY_EVENT_PUBLISHED),
            Some(IO_DELIVERY_IOSB_PUBLISHED | IO_DELIVERY_EVENT_PUBLISHED)
        );
        assert!(table.finish_exact(slot, 3).is_none());
        assert!(table.finish_exact(slot, 2).is_none());
    }

    #[test]
    fn pending_file_io_reply_cap_transfers_once() {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(pending(1, 2, 7)).unwrap();
        assert_eq!(table.claim_reply_cap_exact(slot, 2), Some(Some(0x50)));
        assert_eq!(table.claim_reply_cap_exact(slot, 2), Some(None));
        assert_eq!(table.get(slot).unwrap().reply_cap, 0);
    }

    #[test]
    fn thread_teardown_takes_untouched_and_partially_published_requests() {
        let mut table = PendingFileIoTable::new();
        let first = table.park(pending(1, 2, 7)).unwrap();
        table.park(pending(1, 3, 7)).unwrap();
        table.park(pending(1, 4, 8)).unwrap();
        table
            .mark_delivery_exact(first, 2, IO_DELIVERY_BUFFER_PUBLISHED)
            .unwrap();
        let mut taken = Vec::new();
        assert_eq!(
            table.take_thread_with(7, |pending| taken.push(pending.irp_id)),
            2
        );
        assert_eq!(taken, vec![2, 3]);
        assert_eq!(table.len(), 1);
        assert!(!table.has_thread(7));
        assert!(table.has_thread(8));
    }

    #[test]
    fn completion_identity_includes_file_thread_and_major() {
        let mut table = PendingFileIoTable::new();
        let request = pending(1, 2, 7);
        let slot = table.park(request).unwrap();
        assert!(table.matches_completion_exact(
            slot,
            2,
            1,
            7,
            nt_io_abi::major::IRP_MJ_DEVICE_CONTROL,
        ));
        assert!(!table.matches_completion_exact(
            slot,
            2,
            3,
            7,
            nt_io_abi::major::IRP_MJ_DEVICE_CONTROL,
        ));
        assert!(!table.matches_completion_exact(
            slot,
            2,
            1,
            8,
            nt_io_abi::major::IRP_MJ_DEVICE_CONTROL,
        ));
        assert!(!table.matches_completion_exact(
            slot,
            2,
            1,
            7,
            nt_io_abi::major::IRP_MJ_FLUSH_BUFFERS,
        ));
    }

    #[test]
    fn delivery_flags_and_finish_are_strict() {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(pending(1, 2, 7)).unwrap();
        assert!(table
            .mark_delivery_exact(
                slot,
                2,
                IO_DELIVERY_IOSB_PUBLISHED | IO_DELIVERY_EVENT_PUBLISHED,
            )
            .is_none());
        assert!(table
            .mark_delivery_exact(slot, 2, IO_DELIVERY_REPLY_CLAIMED)
            .is_none());
        assert!(table.finish_exact(slot, 2).is_none());

        assert_eq!(table.advance_output_exact(slot, 2, 32, 64), Some(32));
        assert_eq!(table.get(slot).unwrap().output_offset, 32);
        assert_eq!(table.advance_output_exact(slot, 2, 32, 64), Some(64));
        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_EVENT_PUBLISHED,
            IO_DELIVERY_APC_PUBLISHED,
        ] {
            table.mark_delivery_exact(slot, 2, flag).unwrap();
        }
        assert_eq!(table.claim_reply_cap_exact(slot, 2), Some(Some(0x50)));
        table.mark_reply_published_exact(slot, 2).unwrap();
        assert!(table.completion_surfaces_published_exact(slot, 2));
        assert!(table.finish_exact(slot, 2).is_none());
        table.mark_backend_acked_exact(slot, 2).unwrap();
        assert!(table.finish_exact(slot, 2).is_some());
    }

    #[test]
    fn async_record_cannot_claim_a_reply() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.reply_cap = 0;
        request.reply_required = false;
        let slot = table.park(request).unwrap();
        assert_eq!(table.claim_reply_cap_exact(slot, 2), None);
        assert!(table.mark_reply_published_exact(slot, 2).is_none());
    }

    #[test]
    fn pending_create_commits_one_handle_and_requires_its_publication() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_CREATE;
        request.operation = PendingFileIoOperation::Create(PendingFileCreate {
            handle_va: 0x7000,
            desired_access: 0x12019F,
            synchronous: true,
            provider_context: 0xAABB,
            status: nt_status::NtStatus::PENDING.raw() as u32,
            information: 0,
            handle_value: 0,
        });
        request.output_va = 0;
        request.output_len = 0;
        request.iosb_va = 0x7100;
        request.apc_routine = 0;
        request.signal_file = false;
        request.publish_iocp = false;
        request.event_obj_idx = u64::MAX;
        let slot = table.park(request).unwrap();

        assert!(!table.completion_surfaces_published_exact(slot, 2));
        assert!(table.commit_create_exact(slot, 2, 0, 1, 0x44).is_some());
        assert_eq!(
            table.commit_create_exact(slot, 2, 0, 1, 0x48),
            None,
            "a retry cannot substitute a second handle"
        );
        table.mark_create_handle_published_exact(slot, 2).unwrap();
        table
            .mark_delivery_exact(slot, 2, IO_DELIVERY_IOSB_PUBLISHED)
            .unwrap();
        assert_eq!(table.claim_reply_cap_exact(slot, 2), Some(Some(0x50)));
        table.mark_reply_published_exact(slot, 2).unwrap();
        assert!(table.completion_surfaces_published_exact(slot, 2));
        table.mark_backend_acked_exact(slot, 2).unwrap();
        assert!(table.finish_exact(slot, 2).is_some());
    }

    #[test]
    fn pending_create_failure_commits_a_null_handle() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_CREATE_NAMED_PIPE;
        request.operation = PendingFileIoOperation::Create(PendingFileCreate {
            handle_va: 0x7000,
            desired_access: 0,
            synchronous: false,
            provider_context: 0xAABB,
            status: nt_status::NtStatus::PENDING.raw() as u32,
            information: 0,
            handle_value: 0,
        });
        request.output_va = 0;
        request.output_len = 0;
        request.apc_routine = 0;
        request.signal_file = false;
        request.publish_iocp = false;
        request.event_obj_idx = u64::MAX;
        let slot = table.park(request).unwrap();

        assert!(table
            .commit_create_exact(slot, 2, 0xC000_0022, 0, 0)
            .is_some());
        assert!(table.commit_create_exact(slot, 2, 0, 1, 0).is_none());
        table.mark_create_handle_published_exact(slot, 2).unwrap();
    }
}
