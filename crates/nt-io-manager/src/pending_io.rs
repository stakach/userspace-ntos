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
pub const IO_DELIVERY_FILE_LOCK_RELEASED: u16 = 1 << 11;

const IO_DELIVERY_PUBLIC_FLAGS: u16 = IO_DELIVERY_BUFFER_PUBLISHED
    | IO_DELIVERY_IOSB_PUBLISHED
    | IO_DELIVERY_APC_PUBLISHED
    | IO_DELIVERY_FILE_PUBLISHED
    | IO_DELIVERY_IOCP_PUBLISHED
    | IO_DELIVERY_EVENT_PUBLISHED;
const IO_DELIVERY_MARKABLE_FLAGS: u16 = IO_DELIVERY_PUBLIC_FLAGS | IO_DELIVERY_FILE_LOCK_RELEASED;

/// State needed to turn one successful terminal CREATE into a process-visible handle. The provider
/// context is opaque to the generic owner; the executive interprets it only after resolving the
/// File's dynamically registered device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PendingFileCreate {
    pub handle_va: u64,
    pub desired_access: u32,
    pub provider_context: u64,
    pub reservation_pid: u32,
    pub reserved_handle: u32,
    pub reservation_generation: u64,
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
    /// Device or filesystem control code for control IRPs; zero for other major functions.
    pub control_code: u32,
    pub operation: PendingFileIoOperation,
    /// Completion surfaces already published for this exact record generation.
    pub delivery_state: u16,
    /// Owning process index, thread id, and hosted fault badge.
    pub pi: u32,
    pub tid: u64,
    /// Thread owning the synchronous FILE_OBJECT lock until terminal delivery. Zero for an
    /// asynchronous File or an always-synchronous API waiting on its own completion owner.
    pub sync_lock_owner_tid: u64,
    pub badge: u64,
    /// The initiating thread is gone, but the canonical IRP owner must remain until terminal
    /// completion so its synchronous File lock and retained reference are released in order.
    pub consumer_abandoned: bool,
    /// A queued user APC interrupted the alertable synchronous IRP wait. The
    /// caller remains parked until this exact IRP reaches a real terminal result.
    pub user_apc_interrupt_requested: bool,
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
    /// Whether the parked caller used the native seL4-Call transport. Native calls need only a
    /// terminal MR0 reply; UnknownSyscall replies must restore the complete captured register frame.
    pub native_call_transport: bool,
    pub reply_mrs: [u64; 18],
    /// Native-syscall resume context restored before replying to a synchronous request.
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
}

const DEFAULT_INITIAL_RESERVE: usize = 16;

/// Generation-exact claim on one table slot. Dispatch code reserves before creating an IRP and
/// commits that exact claim afterward, so re-entrant work cannot consume the promised owner slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingFileIoReservation {
    slot: usize,
    generation: u64,
}

/// Reset-safe, growable table of generic pending File I/O delivery owners.
#[derive(Clone, Debug)]
pub struct PendingFileIoTable {
    slots: Vec<Option<PendingFileIo>>,
    reservations: Vec<u64>,
    next_reservation_generation: u64,
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
            reservations: Vec::new(),
            next_reservation_generation: 1,
            initial_reserve,
        }
    }

    fn grow_reservation(&mut self) -> bool {
        let reserve = if self.slots.capacity() == 0 {
            self.initial_reserve.max(1)
        } else {
            1
        };
        if self.slots.len() == self.slots.capacity() {
            if self.slots.try_reserve(reserve).is_err() {
                return false;
            }
        }
        if self.reservations.len() == self.reservations.capacity() {
            let reserve = if self.reservations.capacity() == 0 {
                self.initial_reserve.max(1)
            } else {
                1
            };
            if self.reservations.try_reserve(reserve).is_err() {
                return false;
            }
        }
        true
    }

    /// Clear stale records and reserve bootstrap storage before an allocator watermark is taken.
    pub fn reset(&mut self) -> bool {
        self.slots.clear();
        self.reservations.clear();
        if self.slots.capacity() < self.initial_reserve {
            let additional = self.initial_reserve - self.slots.capacity();
            if self.slots.try_reserve(additional).is_err() {
                return false;
            }
        }
        if self.reservations.capacity() < self.initial_reserve {
            let additional = self.initial_reserve - self.reservations.capacity();
            if self.reservations.try_reserve(additional).is_err() {
                return false;
            }
        }
        true
    }

    fn pending_is_valid(&self, pending: PendingFileIo) -> bool {
        let create_valid = match pending.operation {
            PendingFileIoOperation::Transfer => {
                !crate::is_create_major(pending.major)
                    && (pending.major != nt_io_abi::major::IRP_MJ_WRITE
                        || (pending.output_va == 0 && pending.output_len == 0))
            }
            PendingFileIoOperation::Create(create) => {
                crate::is_create_major(pending.major)
                    && create.handle_va != 0
                    && create.reservation_pid != 0
                    && create.reserved_handle != 0
                    && create.reservation_generation != 0
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
        let control_valid = matches!(
            pending.major,
            nt_io_abi::major::IRP_MJ_DEVICE_CONTROL | nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL
        ) || pending.control_code == 0;
        pending.file_id != 0
            && pending.irp_id != 0
            && create_valid
            && control_valid
            && pending.delivery_state == 0
            && pending.output_offset == 0
            && (pending.sync_lock_owner_tid == 0 || pending.sync_lock_owner_tid == pending.tid)
            && (!matches!(pending.operation, PendingFileIoOperation::Create(_))
                || pending.sync_lock_owner_tid == 0)
            && (!pending.consumer_abandoned
                || matches!(pending.operation, PendingFileIoOperation::Transfer))
            && !pending.user_apc_interrupt_requested
            && (pending.output_len == 0 || pending.output_va != 0)
            && (pending.apc_routine == 0 || !pending.publish_iocp)
            && pending.reply_required == (pending.reply_cap != 0)
            && !self
                .slots
                .iter()
                .any(|slot| slot.is_some_and(|record| record.irp_id == pending.irp_id))
    }

    /// Claim one exact owner slot before dispatching an IRP.
    pub fn reserve(&mut self) -> Option<PendingFileIoReservation> {
        let slot = self
            .slots
            .iter()
            .zip(self.reservations.iter())
            .position(|(slot, reservation)| slot.is_none() && *reservation == 0)
            .or_else(|| {
                self.grow_reservation().then(|| {
                    self.slots.push(None);
                    self.reservations.push(0);
                    self.slots.len() - 1
                })
            })?;
        let generation = self.next_reservation_generation.max(1);
        self.next_reservation_generation = generation.wrapping_add(1).max(1);
        self.reservations[slot] = generation;
        Some(PendingFileIoReservation { slot, generation })
    }

    pub fn cancel_reservation(&mut self, reservation: PendingFileIoReservation) -> bool {
        let Some(generation) = self.reservations.get_mut(reservation.slot) else {
            return false;
        };
        if *generation != reservation.generation || self.slots[reservation.slot].is_some() {
            return false;
        }
        *generation = 0;
        true
    }

    /// Commit one owner into its exact pre-dispatch claim.
    pub fn park_reserved(
        &mut self,
        reservation: PendingFileIoReservation,
        pending: PendingFileIo,
    ) -> Option<usize> {
        if self.reservations.get(reservation.slot).copied() != Some(reservation.generation)
            || self.slots.get(reservation.slot)?.is_some()
            || !self.pending_is_valid(pending)
        {
            return None;
        }
        self.slots[reservation.slot] = Some(pending);
        self.reservations[reservation.slot] = 0;
        Some(reservation.slot)
    }

    /// Insert one exact pending owner. A canonical IRP may have only one delivery owner.
    pub fn park(&mut self, pending: PendingFileIo) -> Option<usize> {
        if !self.pending_is_valid(pending) {
            return None;
        }
        for (index, (slot, reservation)) in self
            .slots
            .iter_mut()
            .zip(self.reservations.iter())
            .enumerate()
        {
            if slot.is_none() && *reservation == 0 {
                *slot = Some(pending);
                return Some(index);
            }
        }
        if !self.grow_reservation() {
            return None;
        }
        self.slots.push(Some(pending));
        self.reservations.push(0);
        Some(self.slots.len() - 1)
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
            && self.reservations.iter().all(|generation| *generation == 0)
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    pub fn allocation_capacity(&self) -> (usize, usize) {
        (self.slots.capacity(), self.reservations.capacity())
    }

    pub fn has_capacity(&self) -> bool {
        self.slots
            .iter()
            .zip(self.reservations.iter())
            .any(|(slot, reservation)| slot.is_none() && *reservation == 0)
            || (self.slots.len() < self.slots.capacity()
                && self.reservations.len() < self.reservations.capacity())
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

    /// Find one synchronous transfer owner whose alertable wait can be
    /// interrupted. File-mode alertability remains canonical in the File policy
    /// table and must be checked by the caller before marking this record.
    pub fn user_apc_interrupt_candidate(&self, tid: u64) -> Option<(usize, PendingFileIo)> {
        self.slots.iter().enumerate().find_map(|(slot, pending)| {
            pending
                .filter(|pending| {
                    pending.tid == tid
                        && pending.sync_lock_owner_tid == tid
                        && pending.reply_required
                        && !pending.consumer_abandoned
                        && !pending.user_apc_interrupt_requested
                        && pending.delivery_state == 0
                        && matches!(pending.operation, PendingFileIoOperation::Transfer)
                })
                .map(|pending| (slot, pending))
        })
    }

    pub fn mark_user_apc_interrupt_requested_exact(
        &mut self,
        slot: usize,
        irp_id: u64,
        file_id: u64,
        tid: u64,
    ) -> Option<()> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id
            || pending.file_id != file_id
            || pending.tid != tid
            || pending.sync_lock_owner_tid != tid
            || !pending.reply_required
            || pending.consumer_abandoned
            || pending.user_apc_interrupt_requested
            || pending.delivery_state != 0
            || !matches!(pending.operation, PendingFileIoOperation::Transfer)
        {
            return None;
        }
        pending.user_apc_interrupt_requested = true;
        Some(())
    }

    pub fn rollback_user_apc_interrupt_requested_exact(
        &mut self,
        slot: usize,
        irp_id: u64,
    ) -> Option<()> {
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        if pending.irp_id != irp_id || !pending.user_apc_interrupt_requested {
            return None;
        }
        pending.user_apc_interrupt_requested = false;
        Some(())
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
        if pending.sync_lock_owner_tid != 0 {
            required |= IO_DELIVERY_FILE_LOCK_RELEASED;
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
        if handle_value != 0 && handle_value != create.reserved_handle as u64 {
            return None;
        }
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
            || flag & IO_DELIVERY_MARKABLE_FLAGS == 0
            || flag & !IO_DELIVERY_MARKABLE_FLAGS != 0
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

    /// Detach the dead thread's user-visible surfaces without retiring the exact IRP owner. The
    /// caller releases any transferred reply cap and requests cancellation; terminal redrive still
    /// owns backend ACK, Busy release, and the retained File reference.
    pub fn abandon_thread_transfers_with<F>(&mut self, tid: u64, mut abandon: F) -> usize
    where
        F: FnMut(PendingFileIo),
    {
        let mut count = 0;
        for pending in self.slots.iter_mut().flatten() {
            if pending.tid != tid
                || pending.consumer_abandoned
                || !matches!(pending.operation, PendingFileIoOperation::Transfer)
            {
                continue;
            }
            let original = *pending;
            pending.consumer_abandoned = true;
            pending.user_apc_interrupt_requested = false;
            pending.output_va = 0;
            pending.output_len = 0;
            pending.output_offset = 0;
            pending.iosb_va = 0;
            pending.apc_routine = 0;
            pending.apc_context = 0;
            pending.signal_file = false;
            pending.publish_iocp = false;
            pending.event_obj_idx = u64::MAX;
            pending.reply_cap = 0;
            pending.reply_required = false;
            pending.native_call_transport = false;
            pending.reply_mrs = [0; 18];
            pending.resume_ip = 0;
            pending.resume_sp = 0;
            pending.resume_flags = 0;
            abandon(original);
            count += 1;
        }
        count
    }

    pub fn take_thread_creates_with<F>(&mut self, tid: u64, mut take: F) -> usize
    where
        F: FnMut(PendingFileIo),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|pending| {
                pending.tid == tid && matches!(pending.operation, PendingFileIoOperation::Create(_))
            }) {
                take(slot.take().unwrap());
                count += 1;
            }
        }
        count
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
            control_code: 0,
            operation: PendingFileIoOperation::Transfer,
            pi: 3,
            tid,
            sync_lock_owner_tid: 0,
            badge: 9,
            consumer_abandoned: false,
            user_apc_interrupt_requested: false,
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
            native_call_transport: false,
            reply_mrs: [0; 18],
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
    fn predispatch_reservation_cannot_be_stolen_and_is_generation_exact() {
        let mut table = PendingFileIoTable::with_initial_reserve(1);
        let reservation = table.reserve().unwrap();
        let competing_slot = table.park(pending(10, 100, 7)).unwrap();
        assert_ne!(competing_slot, reservation.slot);
        assert_eq!(
            table
                .park_reserved(reservation, pending(20, 200, 8))
                .unwrap(),
            reservation.slot
        );
        assert!(!table.cancel_reservation(reservation));

        let cancelled = table.reserve().unwrap();
        assert!(table.cancel_reservation(cancelled));
        assert!(!table.cancel_reservation(cancelled));
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
    fn pending_write_has_no_output_surface_and_requires_terminal_notifications() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_WRITE;
        request.output_va = 0;
        request.output_len = 0;
        request.apc_routine = 0;
        request.publish_iocp = true;
        request.signal_file = true;
        request.event_obj_idx = u64::MAX;
        request.reply_cap = 0;
        request.reply_required = false;
        let slot = table.park(request).unwrap();

        assert_eq!(table.get(slot).unwrap().output_offset, 0);
        assert!(!table.completion_surfaces_published_exact(slot, 2));
        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_FILE_PUBLISHED,
            IO_DELIVERY_IOCP_PUBLISHED,
        ] {
            table.mark_delivery_exact(slot, 2, flag).unwrap();
        }
        assert!(table.completion_surfaces_published_exact(slot, 2));
        table.mark_backend_acked_exact(slot, 2).unwrap();
        let finished = table.finish_exact(slot, 2).unwrap();
        assert_eq!(finished.file_id, request.file_id);
        assert_eq!(finished.irp_id, request.irp_id);
        assert_eq!(finished.major, nt_io_abi::major::IRP_MJ_WRITE);
    }

    #[test]
    fn pending_write_rejects_an_output_copy_surface() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_WRITE;
        assert!(table.park(request).is_none());

        request.output_va = 0;
        request.output_len = 0;
        assert!(table.park(request).is_some());
    }

    #[test]
    fn distinct_pending_writes_can_share_one_file_object() {
        let mut table = PendingFileIoTable::new();
        let mut first = pending(1, 2, 7);
        first.major = nt_io_abi::major::IRP_MJ_WRITE;
        first.output_va = 0;
        first.output_len = 0;
        let mut second = first;
        second.irp_id = 3;
        second.tid = 8;

        assert!(table.park(first).is_some());
        assert!(table.park(second).is_some());
        assert_eq!(table.len(), 2);
        assert!(table.matches_completion_exact(0, 2, 1, 7, nt_io_abi::major::IRP_MJ_WRITE));
    }

    #[test]
    fn pending_read_with_event_requires_output_iosb_event_and_iocp() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_READ;
        request.apc_routine = 0;
        request.publish_iocp = true;
        request.reply_cap = 0;
        request.reply_required = false;
        request.signal_file = false;
        let slot = table.park(request).unwrap();

        table.advance_output_exact(slot, 2, 32, 32).unwrap();
        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_EVENT_PUBLISHED,
            IO_DELIVERY_IOCP_PUBLISHED,
        ] {
            table.mark_delivery_exact(slot, 2, flag).unwrap();
        }
        assert!(table.completion_surfaces_published_exact(slot, 2));
        table.mark_backend_acked_exact(slot, 2).unwrap();
        assert_eq!(
            table.finish_exact(slot, 2).unwrap().major,
            nt_io_abi::major::IRP_MJ_READ
        );
    }

    #[test]
    fn distinct_pending_reads_can_share_one_file_and_signal_it_without_an_event() {
        let mut table = PendingFileIoTable::new();
        let mut first = pending(1, 2, 7);
        first.major = nt_io_abi::major::IRP_MJ_READ;
        first.apc_routine = 0;
        first.publish_iocp = true;
        first.reply_cap = 0;
        first.reply_required = false;
        first.event_obj_idx = u64::MAX;
        first.signal_file = true;
        let mut second = first;
        second.irp_id = 3;
        second.tid = 8;

        assert!(table.park(first).is_some());
        assert!(table.park(second).is_some());
        assert_eq!(table.len(), 2);
        assert!(table.matches_completion_exact(1, 3, 1, 8, nt_io_abi::major::IRP_MJ_READ));
    }

    #[test]
    fn synchronous_pending_read_requires_file_event_and_reply_publication() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_READ;
        request.apc_routine = 0;
        request.publish_iocp = true;
        request.signal_file = true;
        request.sync_lock_owner_tid = request.tid;
        let slot = table.park(request).unwrap();

        table.advance_output_exact(slot, 2, 8, 8).unwrap();
        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_EVENT_PUBLISHED,
            IO_DELIVERY_FILE_PUBLISHED,
            IO_DELIVERY_IOCP_PUBLISHED,
        ] {
            table.mark_delivery_exact(slot, 2, flag).unwrap();
        }
        assert!(!table.completion_surfaces_published_exact(slot, 2));
        assert_eq!(table.claim_reply_cap_exact(slot, 2), Some(Some(0x50)));
        table.mark_reply_published_exact(slot, 2).unwrap();
        assert!(!table.completion_surfaces_published_exact(slot, 2));
        table
            .mark_delivery_exact(slot, 2, IO_DELIVERY_FILE_LOCK_RELEASED)
            .unwrap();
        assert!(table.completion_surfaces_published_exact(slot, 2));
    }

    #[test]
    fn user_apc_interruption_marks_only_one_exact_synchronous_transfer() {
        let mut table = PendingFileIoTable::new();
        let asynchronous_slot = table.park(pending(1, 2, 7)).unwrap();
        let mut synchronous = pending(3, 4, 7);
        synchronous.sync_lock_owner_tid = 7;
        let synchronous_slot = table.park(synchronous).unwrap();

        let (slot, candidate) = table.user_apc_interrupt_candidate(7).unwrap();
        assert_eq!(slot, synchronous_slot);
        assert_eq!(candidate.irp_id, 4);
        assert!(table
            .mark_user_apc_interrupt_requested_exact(slot, 5, 3, 7)
            .is_none());
        table
            .mark_user_apc_interrupt_requested_exact(slot, 4, 3, 7)
            .unwrap();
        assert!(table.user_apc_interrupt_candidate(7).is_none());
        assert!(
            !table
                .get(asynchronous_slot)
                .unwrap()
                .user_apc_interrupt_requested
        );
        assert!(table.get(slot).unwrap().user_apc_interrupt_requested);
        assert!(table
            .rollback_user_apc_interrupt_requested_exact(slot, 5)
            .is_none());
        table
            .rollback_user_apc_interrupt_requested_exact(slot, 4)
            .unwrap();
        assert_eq!(table.user_apc_interrupt_candidate(7).unwrap().0, slot);

        table
            .mark_delivery_exact(slot, 4, IO_DELIVERY_IOSB_PUBLISHED)
            .unwrap();
        assert!(table.user_apc_interrupt_candidate(7).is_none());
    }

    #[test]
    fn pending_transceive_preserves_control_identity_and_async_event_surfaces() {
        const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL;
        request.control_code = FSCTL_PIPE_TRANSCEIVE;
        request.apc_routine = 0;
        request.publish_iocp = true;
        request.reply_cap = 0;
        request.reply_required = false;
        request.signal_file = false;
        let slot = table.park(request).unwrap();

        assert_eq!(table.get(slot).unwrap().control_code, FSCTL_PIPE_TRANSCEIVE);
        table.advance_output_exact(slot, 2, 24, 24).unwrap();
        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_EVENT_PUBLISHED,
            IO_DELIVERY_IOCP_PUBLISHED,
        ] {
            table.mark_delivery_exact(slot, 2, flag).unwrap();
        }
        assert!(table.completion_surfaces_published_exact(slot, 2));
    }

    #[test]
    fn pending_transceive_accepts_zero_length_output_and_sync_reply() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL;
        request.control_code = 0x0011_C017;
        request.output_va = 0;
        request.output_len = 0;
        request.signal_file = true;
        let slot = table.park(request).unwrap();

        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_EVENT_PUBLISHED,
            IO_DELIVERY_FILE_PUBLISHED,
            IO_DELIVERY_APC_PUBLISHED,
        ] {
            table.mark_delivery_exact(slot, 2, flag).unwrap();
        }
        assert_eq!(table.claim_reply_cap_exact(slot, 2), Some(Some(0x50)));
        table.mark_reply_published_exact(slot, 2).unwrap();
        assert!(table.completion_surfaces_published_exact(slot, 2));
    }

    #[test]
    fn async_pipe_listen_uses_generic_event_and_iocp_surfaces() {
        const FSCTL_PIPE_LISTEN: u32 = 0x0011_0008;
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL;
        request.control_code = FSCTL_PIPE_LISTEN;
        request.output_va = 0;
        request.output_len = 0;
        request.reply_cap = 0;
        request.reply_required = false;
        request.apc_routine = 0;
        request.publish_iocp = true;
        request.signal_file = false;
        let slot = table.park(request).unwrap();

        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_EVENT_PUBLISHED,
            IO_DELIVERY_IOCP_PUBLISHED,
        ] {
            table.mark_delivery_exact(slot, 2, flag).unwrap();
        }
        assert!(table.completion_surfaces_published_exact(slot, 2));
        table.mark_backend_acked_exact(slot, 2).unwrap();
        let finished = table.finish_exact(slot, 2).unwrap();
        assert_eq!(finished.file_id, request.file_id);
        assert_eq!(finished.irp_id, request.irp_id);
        assert_eq!(finished.control_code, FSCTL_PIPE_LISTEN);
    }

    #[test]
    fn pipe_listen_apc_excludes_iocp_and_allows_rearm_generation() {
        const FSCTL_PIPE_LISTEN: u32 = 0x0011_0008;
        let mut table = PendingFileIoTable::new();
        let mut first = pending(1, 2, 7);
        first.major = nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL;
        first.control_code = FSCTL_PIPE_LISTEN;
        first.output_va = 0;
        first.output_len = 0;
        first.reply_cap = 0;
        first.reply_required = false;
        first.publish_iocp = false;
        let first_slot = table.park(first).unwrap();

        let mut second = first;
        second.irp_id = 3;
        second.event_obj_idx = 8;
        let second_slot = table.park(second).unwrap();
        assert_ne!(first_slot, second_slot);
        assert_eq!(table.len(), 2);

        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_EVENT_PUBLISHED,
            IO_DELIVERY_APC_PUBLISHED,
        ] {
            table.mark_delivery_exact(first_slot, 2, flag).unwrap();
        }
        assert!(table.completion_surfaces_published_exact(first_slot, 2));
        assert!(!table.completion_surfaces_published_exact(second_slot, 3));
    }

    #[test]
    fn synchronous_pipe_listen_requires_file_lock_and_reply_before_ack() {
        const FSCTL_PIPE_LISTEN: u32 = 0x0011_0008;
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL;
        request.control_code = FSCTL_PIPE_LISTEN;
        request.output_va = 0;
        request.output_len = 0;
        request.apc_routine = 0;
        request.publish_iocp = true;
        request.signal_file = true;
        request.sync_lock_owner_tid = request.tid;
        let slot = table.park(request).unwrap();

        for flag in [
            IO_DELIVERY_IOSB_PUBLISHED,
            IO_DELIVERY_EVENT_PUBLISHED,
            IO_DELIVERY_FILE_PUBLISHED,
            IO_DELIVERY_IOCP_PUBLISHED,
        ] {
            table.mark_delivery_exact(slot, 2, flag).unwrap();
        }
        assert_eq!(table.claim_reply_cap_exact(slot, 2), Some(Some(0x50)));
        table.mark_reply_published_exact(slot, 2).unwrap();
        assert!(!table.completion_surfaces_published_exact(slot, 2));
        table
            .mark_delivery_exact(slot, 2, IO_DELIVERY_FILE_LOCK_RELEASED)
            .unwrap();
        assert!(table.completion_surfaces_published_exact(slot, 2));
    }

    #[test]
    fn non_control_pending_owner_rejects_control_code_metadata() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.major = nt_io_abi::major::IRP_MJ_READ;
        request.control_code = 0x1122_3344;
        assert!(table.park(request).is_none());
        request.control_code = 0;
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
    fn abandoned_synchronous_transfer_retains_terminal_lock_owner_only() {
        let mut table = PendingFileIoTable::new();
        let mut request = pending(1, 2, 7);
        request.sync_lock_owner_tid = 7;
        request.reply_required = true;
        request.reply_cap = 0x50;
        request.resume_ip = 0x1000;
        request.resume_sp = 0x2000;
        request.resume_flags = 0x202;
        let slot = table.park(request).unwrap();
        let mut detached = None;
        assert_eq!(
            table.abandon_thread_transfers_with(7, |pending| detached = Some(pending)),
            1
        );
        assert_eq!(detached.unwrap().reply_cap, 0x50);
        let owner = table.get(slot).unwrap();
        assert!(owner.consumer_abandoned);
        assert_eq!(owner.reply_cap, 0);
        assert!(!owner.reply_required);
        assert!(!table.completion_surfaces_published_exact(slot, 2));
        table
            .mark_delivery_exact(slot, 2, IO_DELIVERY_FILE_LOCK_RELEASED)
            .unwrap();
        assert!(table.completion_surfaces_published_exact(slot, 2));
        table.mark_backend_acked_exact(slot, 2).unwrap();
        assert!(table.finish_exact(slot, 2).is_some());
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
            provider_context: 0xAABB,
            reservation_pid: 4,
            reserved_handle: 0x44,
            reservation_generation: 7,
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
            provider_context: 0xAABB,
            reservation_pid: 4,
            reserved_handle: 0x44,
            reservation_generation: 8,
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
