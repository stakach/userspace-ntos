//! Filesystem-owned byte-range lock policy.
//!
//! This is the host-testable equivalent of one filesystem's `FILE_LOCK` state. The I/O Manager
//! owns IRPs and user completion surfaces; this table owns only active ranges, FIFO waiters, and
//! the exact `FILE_OBJECT`/process/key identity used by FsRtl conflict and cleanup rules.

use alloc::vec::Vec;

use crate::{
    STATUS_CANCELLED, STATUS_FILE_LOCK_CONFLICT, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_LOCK_NOT_GRANTED, STATUS_RANGE_NOT_LOCKED, STATUS_SUCCESS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRangeLockOwner {
    pub file_object: u64,
    pub process_id: u64,
    pub key: u32,
}

impl ByteRangeLockOwner {
    pub const fn new(file_object: u64, process_id: u64, key: u32) -> Self {
        Self {
            file_object,
            process_id,
            key,
        }
    }

    const fn is_valid(self) -> bool {
        self.file_object != 0 && self.process_id != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRangeLockRequest {
    /// Stable filesystem identity (FCB/node identity), shared by independently opened objects.
    pub file_id: u64,
    pub owner: ByteRangeLockOwner,
    pub byte_offset: u64,
    pub length: u64,
    pub exclusive: bool,
}

impl ByteRangeLockRequest {
    pub const fn new(
        file_id: u64,
        owner: ByteRangeLockOwner,
        byte_offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Self {
        Self {
            file_id,
            owner,
            byte_offset,
            length,
            exclusive,
        }
    }

    const fn is_valid(self) -> bool {
        self.file_id != 0
            && self.owner.is_valid()
            && (self.length == 0 || self.byte_offset.checked_add(self.length - 1).is_some())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRangeWaitId(u64);

impl ByteRangeWaitId {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRangeLockResult {
    Granted,
    Pending(ByteRangeWaitId),
    Failed(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRangeLockCompletion<C> {
    pub wait_id: ByteRangeWaitId,
    pub context: C,
    pub status: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WaitingLock<C> {
    id: ByteRangeWaitId,
    request: ByteRangeLockRequest,
    context: C,
}

#[derive(Clone, Debug)]
pub struct ByteRangeLockTable<C> {
    active: Vec<ByteRangeLockRequest>,
    waiting: Vec<WaitingLock<C>>,
    completed: Vec<ByteRangeLockCompletion<C>>,
    next_wait_id: u64,
}

impl<C> Default for ByteRangeLockTable<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> ByteRangeLockTable<C> {
    pub const fn new() -> Self {
        Self {
            active: Vec::new(),
            waiting: Vec::new(),
            completed: Vec::new(),
            next_wait_id: 1,
        }
    }

    pub fn reset(&mut self) {
        self.active.clear();
        self.waiting.clear();
        self.completed.clear();
        self.next_wait_id = 1;
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn waiting_count(&self) -> usize {
        self.waiting.len()
    }

    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    pub fn pop_completion(&mut self) -> Option<ByteRangeLockCompletion<C>> {
        self.completed.pop()
    }

    fn ranges_overlap(left: ByteRangeLockRequest, right: ByteRangeLockRequest) -> bool {
        if left.file_id != right.file_id || left.length == 0 || right.length == 0 {
            return false;
        }
        let left_end = left.byte_offset + left.length - 1;
        let right_end = right.byte_offset + right.length - 1;
        left.byte_offset <= right_end && right.byte_offset <= left_end
    }

    fn blocks(existing: ByteRangeLockRequest, candidate: ByteRangeLockRequest) -> bool {
        Self::ranges_overlap(existing, candidate)
            && if candidate.exclusive {
                true
            } else {
                existing.exclusive && existing.owner != candidate.owner
            }
    }

    fn blocked_by_active(&self, request: ByteRangeLockRequest) -> bool {
        self.active
            .iter()
            .copied()
            .any(|active| Self::blocks(active, request))
    }

    fn blocked_by_waiter(&self, request: ByteRangeLockRequest) -> bool {
        self.waiting
            .iter()
            .any(|waiting| Self::blocks(waiting.request, request))
    }

    fn allocate_wait_id(&mut self) -> ByteRangeWaitId {
        let id = ByteRangeWaitId(self.next_wait_id.max(1));
        self.next_wait_id = self.next_wait_id.wrapping_add(1).max(1);
        id
    }

    pub fn lock(
        &mut self,
        request: ByteRangeLockRequest,
        fail_immediately: bool,
        context: C,
    ) -> ByteRangeLockResult {
        if !request.is_valid() {
            return ByteRangeLockResult::Failed(crate::STATUS_INVALID_PARAMETER);
        }
        if !self.blocked_by_active(request) && !self.blocked_by_waiter(request) {
            if self.active.try_reserve(1).is_err() {
                return ByteRangeLockResult::Failed(STATUS_INSUFFICIENT_RESOURCES);
            }
            self.active.push(request);
            return ByteRangeLockResult::Granted;
        }
        if fail_immediately {
            return ByteRangeLockResult::Failed(STATUS_LOCK_NOT_GRANTED);
        }
        // Reserve every terminal path before publishing the waiter. Cancellation, CLEANUP, and a
        // later unlock must never fail because completion bookkeeping needs to allocate.
        if self.waiting.try_reserve(1).is_err()
            || self.completed.try_reserve(1).is_err()
            || self.active.try_reserve(1).is_err()
        {
            return ByteRangeLockResult::Failed(STATUS_INSUFFICIENT_RESOURCES);
        }
        let id = self.allocate_wait_id();
        self.waiting.push(WaitingLock {
            id,
            request,
            context,
        });
        ByteRangeLockResult::Pending(id)
    }

    fn reserve_reconsideration(&mut self) -> Result<(), u32> {
        let count = self.waiting.len();
        self.active
            .try_reserve(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.completed
            .try_reserve(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
    }

    fn reconsider_waiters(&mut self) {
        let mut index = 0;
        while index < self.waiting.len() {
            let candidate = self.waiting[index].request;
            let blocked_by_active = self
                .active
                .iter()
                .copied()
                .any(|active| Self::blocks(active, candidate));
            let blocked_by_earlier_waiter = self.waiting[..index]
                .iter()
                .any(|waiting| Self::blocks(waiting.request, candidate));
            if blocked_by_active || blocked_by_earlier_waiter {
                index += 1;
                continue;
            }
            let waiting = self.waiting.remove(index);
            self.active.push(waiting.request);
            self.completed.push(ByteRangeLockCompletion {
                wait_id: waiting.id,
                context: waiting.context,
                status: STATUS_SUCCESS,
            });
        }
    }

    pub fn unlock_single(&mut self, request: ByteRangeLockRequest) -> u32 {
        if !request.is_valid() {
            return crate::STATUS_INVALID_PARAMETER;
        }
        let Some(index) = self.active.iter().position(|active| {
            active.file_id == request.file_id
                && active.owner == request.owner
                && active.byte_offset == request.byte_offset
                && active.length == request.length
        }) else {
            return STATUS_RANGE_NOT_LOCKED;
        };
        if self.reserve_reconsideration().is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        self.active.remove(index);
        self.reconsider_waiters();
        STATUS_SUCCESS
    }

    pub fn cancel_wait(&mut self, wait_id: ByteRangeWaitId) -> bool {
        let Some(index) = self
            .waiting
            .iter()
            .position(|waiting| waiting.id == wait_id)
        else {
            return false;
        };
        if self.completed.try_reserve(1).is_err() {
            return false;
        }
        let waiting = self.waiting.remove(index);
        self.completed.push(ByteRangeLockCompletion {
            wait_id: waiting.id,
            context: waiting.context,
            status: STATUS_CANCELLED,
        });
        true
    }

    pub fn cancel_waits_for(&mut self, file_object: u64, process_id: u64) -> u32 {
        let count = self
            .waiting
            .iter()
            .filter(|waiting| {
                waiting.request.owner.file_object == file_object
                    && waiting.request.owner.process_id == process_id
            })
            .count();
        if self.completed.try_reserve(count).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let mut index = 0;
        while index < self.waiting.len() {
            if self.waiting[index].request.owner.file_object == file_object
                && self.waiting[index].request.owner.process_id == process_id
            {
                let waiting = self.waiting.remove(index);
                self.completed.push(ByteRangeLockCompletion {
                    wait_id: waiting.id,
                    context: waiting.context,
                    status: STATUS_CANCELLED,
                });
            } else {
                index += 1;
            }
        }
        STATUS_SUCCESS
    }

    pub fn cleanup_file_object(&mut self, file_object: u64, process_id: u64) -> u32 {
        if file_object == 0 || process_id == 0 {
            return crate::STATUS_INVALID_PARAMETER;
        }
        if self.reserve_reconsideration().is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let _ = self.cancel_waits_for(file_object, process_id);
        self.active.retain(|lock| {
            lock.owner.file_object != file_object || lock.owner.process_id != process_id
        });
        self.reconsider_waiters();
        STATUS_SUCCESS
    }

    /// Issue FILE_OBJECT cleanup after its final handle closes. A duplicated FILE_OBJECT can cross
    /// process handle tables, so final cleanup must release every process-owned range and waiter
    /// associated with that object identity.
    pub fn cleanup_file_object_all(&mut self, file_object: u64) -> u32 {
        if file_object == 0 {
            return crate::STATUS_INVALID_PARAMETER;
        }
        let count = self
            .waiting
            .iter()
            .filter(|waiting| waiting.request.owner.file_object == file_object)
            .count();
        if self.reserve_reconsideration().is_err() || self.completed.try_reserve(count).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let mut index = 0;
        while index < self.waiting.len() {
            if self.waiting[index].request.owner.file_object == file_object {
                let waiting = self.waiting.remove(index);
                self.completed.push(ByteRangeLockCompletion {
                    wait_id: waiting.id,
                    context: waiting.context,
                    status: STATUS_CANCELLED,
                });
            } else {
                index += 1;
            }
        }
        self.active
            .retain(|lock| lock.owner.file_object != file_object);
        self.reconsider_waiters();
        STATUS_SUCCESS
    }

    fn access_allowed(
        &self,
        file_id: u64,
        owner: ByteRangeLockOwner,
        byte_offset: u64,
        length: u64,
        write: bool,
    ) -> bool {
        let access = ByteRangeLockRequest::new(file_id, owner, byte_offset, length, write);
        if !access.is_valid() || length == 0 {
            return access.is_valid();
        }
        if !write {
            return self.active.iter().copied().all(|lock| {
                !Self::ranges_overlap(lock, access) || !lock.exclusive || lock.owner == owner
            });
        }
        let access_end = byte_offset + length - 1;
        if self.active.iter().copied().any(|lock| {
            lock.file_id == file_id
                && lock.exclusive
                && lock.owner == owner
                && lock.length != 0
                && lock.byte_offset <= byte_offset
                && lock.byte_offset + lock.length - 1 >= access_end
        }) {
            return true;
        }
        self.active
            .iter()
            .copied()
            .all(|lock| !Self::ranges_overlap(lock, access))
    }

    pub fn check_read(
        &self,
        file_id: u64,
        owner: ByteRangeLockOwner,
        byte_offset: u64,
        length: u64,
    ) -> u32 {
        if self.access_allowed(file_id, owner, byte_offset, length, false) {
            STATUS_SUCCESS
        } else {
            STATUS_FILE_LOCK_CONFLICT
        }
    }

    pub fn check_write(
        &self,
        file_id: u64,
        owner: ByteRangeLockOwner,
        byte_offset: u64,
        length: u64,
    ) -> u32 {
        if self.access_allowed(file_id, owner, byte_offset, length, true) {
            STATUS_SUCCESS
        } else {
            STATUS_FILE_LOCK_CONFLICT
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(file_object: u64, process_id: u64, key: u32) -> ByteRangeLockOwner {
        ByteRangeLockOwner::new(file_object, process_id, key)
    }

    fn request(
        file_id: u64,
        file_object: u64,
        process_id: u64,
        key: u32,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> ByteRangeLockRequest {
        ByteRangeLockRequest::new(
            file_id,
            owner(file_object, process_id, key),
            offset,
            length,
            exclusive,
        )
    }

    #[test]
    fn shared_ranges_coexist_but_exclusive_conflicts() {
        let mut locks = ByteRangeLockTable::new();
        let first = request(7, 10, 1, 0, 100, 20, false);
        let second = request(7, 11, 2, 0, 110, 20, false);
        let exclusive = request(7, 12, 3, 0, 105, 2, true);
        assert_eq!(locks.lock(first, true, 1), ByteRangeLockResult::Granted);
        assert_eq!(locks.lock(second, true, 2), ByteRangeLockResult::Granted);
        assert_eq!(
            locks.lock(exclusive, true, 3),
            ByteRangeLockResult::Failed(STATUS_LOCK_NOT_GRANTED)
        );
        assert_eq!(locks.active_count(), 2);
    }

    #[test]
    fn conflicting_waiters_complete_in_fifo_order() {
        let mut locks = ByteRangeLockTable::new();
        let held = request(7, 10, 1, 0, 0, 100, true);
        let first = request(7, 11, 2, 0, 10, 10, true);
        let second = request(7, 12, 3, 0, 10, 10, false);
        assert_eq!(locks.lock(held, true, 0), ByteRangeLockResult::Granted);
        assert!(matches!(
            locks.lock(first, false, 11),
            ByteRangeLockResult::Pending(_)
        ));
        assert!(matches!(
            locks.lock(second, false, 12),
            ByteRangeLockResult::Pending(_)
        ));
        assert_eq!(locks.unlock_single(held), STATUS_SUCCESS);
        assert_eq!(locks.active_count(), 1);
        assert_eq!(locks.completed_count(), 1);
        assert_eq!(locks.pop_completion().unwrap().context, 11);
        assert_eq!(locks.unlock_single(first), STATUS_SUCCESS);
        assert_eq!(locks.pop_completion().unwrap().context, 12);
    }

    #[test]
    fn nonconflicting_waiter_does_not_stall_behind_blocked_range() {
        let mut locks = ByteRangeLockTable::new();
        let left = request(7, 10, 1, 0, 0, 10, true);
        let right = request(7, 20, 1, 0, 100, 10, true);
        let blocked = request(7, 11, 2, 0, 0, 10, true);
        let independent = request(7, 21, 2, 0, 100, 10, true);
        assert_eq!(locks.lock(left, true, 0), ByteRangeLockResult::Granted);
        assert_eq!(locks.lock(right, true, 0), ByteRangeLockResult::Granted);
        assert!(matches!(
            locks.lock(blocked, false, 11),
            ByteRangeLockResult::Pending(_)
        ));
        assert!(matches!(
            locks.lock(independent, false, 21),
            ByteRangeLockResult::Pending(_)
        ));
        assert_eq!(locks.unlock_single(right), STATUS_SUCCESS);
        assert_eq!(locks.pop_completion().unwrap().context, 21);
        assert_eq!(locks.waiting_count(), 1);
    }

    #[test]
    fn unlock_requires_exact_owner_key_and_range() {
        let mut locks = ByteRangeLockTable::new();
        let held = request(7, 10, 1, 5, 40, 8, true);
        assert_eq!(locks.lock(held, true, ()), ByteRangeLockResult::Granted);
        assert_eq!(
            locks.unlock_single(request(7, 10, 1, 6, 40, 8, true)),
            STATUS_RANGE_NOT_LOCKED
        );
        assert_eq!(
            locks.unlock_single(request(7, 10, 1, 5, 40, 7, true)),
            STATUS_RANGE_NOT_LOCKED
        );
        assert_eq!(locks.unlock_single(held), STATUS_SUCCESS);

        let shared = request(7, 10, 1, 5, 80, 8, false);
        assert_eq!(locks.lock(shared, true, ()), ByteRangeLockResult::Granted);
        assert_eq!(
            locks.unlock_single(request(7, 10, 1, 5, 80, 8, true)),
            STATUS_SUCCESS
        );
    }

    #[test]
    fn cleanup_releases_only_the_exact_file_object_and_cancels_its_waiters() {
        let mut locks = ByteRangeLockTable::new();
        let held = request(7, 10, 1, 0, 0, 10, true);
        let other_object = request(7, 20, 1, 0, 20, 10, true);
        let cancelled = request(7, 10, 1, 1, 20, 10, true);
        let granted = request(7, 30, 2, 0, 0, 10, true);
        assert_eq!(locks.lock(held, true, 0), ByteRangeLockResult::Granted);
        assert_eq!(
            locks.lock(other_object, true, 0),
            ByteRangeLockResult::Granted
        );
        assert!(matches!(
            locks.lock(cancelled, false, 10),
            ByteRangeLockResult::Pending(_)
        ));
        assert!(matches!(
            locks.lock(granted, false, 30),
            ByteRangeLockResult::Pending(_)
        ));
        assert_eq!(locks.cleanup_file_object(10, 1), STATUS_SUCCESS);
        assert_eq!(locks.active_count(), 2);
        let completions = [
            locks.pop_completion().unwrap(),
            locks.pop_completion().unwrap(),
        ];
        assert!(completions
            .iter()
            .any(|completion| completion.context == 10 && completion.status == STATUS_CANCELLED));
        assert!(completions
            .iter()
            .any(|completion| completion.context == 30 && completion.status == STATUS_SUCCESS));
    }

    #[test]
    fn reads_and_writes_observe_owner_and_key() {
        let mut locks = ByteRangeLockTable::new();
        let held = request(7, 10, 1, 5, 10, 10, true);
        assert_eq!(locks.lock(held, true, ()), ByteRangeLockResult::Granted);
        assert_eq!(locks.check_read(7, owner(10, 1, 5), 12, 1), STATUS_SUCCESS);
        assert_eq!(
            locks.check_read(7, owner(10, 1, 6), 12, 1),
            STATUS_FILE_LOCK_CONFLICT
        );
        assert_eq!(
            locks.check_write(7, owner(11, 1, 5), 12, 1),
            STATUS_FILE_LOCK_CONFLICT
        );
        assert_eq!(locks.check_write(7, owner(10, 1, 5), 12, 1), STATUS_SUCCESS);
        assert_eq!(locks.check_write(7, owner(11, 2, 0), 12, 0), STATUS_SUCCESS);

        let mut shared = ByteRangeLockTable::new();
        let held_shared = request(7, 10, 1, 5, 10, 10, false);
        assert_eq!(
            shared.lock(held_shared, true, ()),
            ByteRangeLockResult::Granted
        );
        assert_eq!(
            shared.check_write(7, owner(10, 1, 5), 12, 1),
            STATUS_FILE_LOCK_CONFLICT
        );
    }

    #[test]
    fn zero_length_locks_do_not_conflict() {
        let mut locks = ByteRangeLockTable::new();
        let first = request(7, 10, 1, 0, 100, 0, true);
        let second = request(7, 11, 2, 0, 100, 0, true);
        assert_eq!(locks.lock(first, true, ()), ByteRangeLockResult::Granted);
        assert_eq!(locks.lock(second, true, ()), ByteRangeLockResult::Granted);
        assert_eq!(
            locks.check_write(7, owner(12, 3, 0), 100, 1),
            STATUS_SUCCESS
        );
    }

    #[test]
    fn final_file_object_cleanup_spans_process_owners() {
        let mut locks = ByteRangeLockTable::new();
        let first = request(7, 10, 1, 0, 0, 10, true);
        let second = request(7, 10, 2, 0, 20, 10, true);
        let waiter = request(7, 20, 3, 0, 0, 30, true);
        assert_eq!(locks.lock(first, true, 0), ByteRangeLockResult::Granted);
        assert_eq!(locks.lock(second, true, 0), ByteRangeLockResult::Granted);
        assert!(matches!(
            locks.lock(waiter, false, 20),
            ByteRangeLockResult::Pending(_)
        ));
        assert_eq!(locks.cleanup_file_object_all(10), STATUS_SUCCESS);
        assert_eq!(locks.active_count(), 1);
        assert_eq!(locks.pop_completion().unwrap().context, 20);
    }
}
