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

/// One pending File-bound operation and every completion surface owned by that exact IRP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PendingFileIo {
    /// Generation-protected I/O Manager File identity used for lifetime, cancellation, and signal.
    pub file_id: u64,
    /// Generation-protected I/O Manager IRP identity used for terminal copy and acknowledgement.
    pub irp_id: u64,
    /// Completion surfaces already published for this exact record generation.
    pub delivery_state: u16,
    /// Owning process index, thread id, and hosted fault badge.
    pub pi: u32,
    pub tid: u64,
    pub badge: u64,
    /// Optional caller output buffer and its byte capacity.
    pub output_va: u64,
    pub output_len: u32,
    /// Caller IO_STATUS_BLOCK.
    pub iosb_va: u64,
    /// Optional user APC and its caller-supplied context.
    pub apc_routine: u64,
    pub apc_context: u64,
    /// Whether the request's tagged event suppresses completion-port publication.
    pub completion_port_suppressed: bool,
    /// Executive event-object index, or `u64::MAX` when no event was supplied.
    pub event_obj_idx: u64,
    /// Stolen synchronous syscall reply cap. Zero means the syscall returned STATUS_PENDING.
    pub reply_cap: u64,
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
        if pending.file_id == 0
            || pending.irp_id == 0
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

    pub fn complete_exact(&mut self, slot: usize, irp_id: u64) -> Option<PendingFileIo> {
        let entry = self.slots.get_mut(slot)?;
        if entry.is_some_and(|pending| pending.irp_id == irp_id) {
            entry.take()
        } else {
            None
        }
    }

    pub fn mark_delivery_exact(&mut self, slot: usize, irp_id: u64, flag: u16) -> Option<u16> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id {
            return None;
        }
        pending.delivery_state |= flag;
        Some(pending.delivery_state)
    }

    /// Transfer synchronous reply ownership exactly once. `Some(None)` means it was already claimed.
    pub fn claim_reply_cap_exact(&mut self, slot: usize, irp_id: u64) -> Option<Option<u64>> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id {
            return None;
        }
        if pending.delivery_state & IO_DELIVERY_REPLY_CLAIMED != 0 {
            return Some(None);
        }
        let reply_cap = core::mem::replace(&mut pending.reply_cap, 0);
        pending.delivery_state |= IO_DELIVERY_REPLY_CLAIMED;
        Some(Some(reply_cap))
    }

    /// Remove undelivered requests owned by a terminating thread. The caller must abandon each IRP.
    pub fn take_undelivered_thread_with<F>(&mut self, tid: u64, mut take: F) -> usize
    where
        F: FnMut(PendingFileIo),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|pending| pending.delivery_state == 0 && pending.tid == tid) {
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
            pi: 3,
            tid,
            badge: 9,
            output_va: 0x1000,
            output_len: 64,
            iosb_va: 0x2000,
            apc_routine: 0x3000,
            apc_context: 0x4000,
            completion_port_suppressed: false,
            event_obj_idx: 7,
            reply_cap: 0x50,
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
        assert!(table.complete_exact(slot, 3).is_none());
        let mut expected = request;
        expected.delivery_state = IO_DELIVERY_IOSB_PUBLISHED | IO_DELIVERY_EVENT_PUBLISHED;
        assert_eq!(table.complete_exact(slot, 2), Some(expected));
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
    fn thread_teardown_takes_only_undelivered_requests() {
        let mut table = PendingFileIoTable::new();
        let first = table.park(pending(1, 2, 7)).unwrap();
        table.park(pending(1, 3, 7)).unwrap();
        table.park(pending(1, 4, 8)).unwrap();
        table
            .mark_delivery_exact(first, 2, IO_DELIVERY_BUFFER_PUBLISHED)
            .unwrap();
        let mut taken = Vec::new();
        assert_eq!(
            table.take_undelivered_thread_with(7, |pending| taken.push(pending.irp_id)),
            1
        );
        assert_eq!(taken, vec![3]);
        assert_eq!(table.len(), 2);
        assert!(table.has_thread(7));
        assert!(table.has_thread(8));
    }
}
