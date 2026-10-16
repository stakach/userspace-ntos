//! Process-local address waits. The native thread-alert calls provide the blocking primitive;
//! this table owns the address comparison and FIFO waiter selection in user space.

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

const STATUS_ALERTED: NtStatus = 0x0000_0101;
const BUCKETS: usize = 256;

struct Waiter {
    address: usize,
    thread_id: u64,
    sequence: u64,
    next: *mut Waiter,
}

struct Bucket {
    locked: AtomicBool,
    head: core::cell::UnsafeCell<*mut Waiter>,
    tail: core::cell::UnsafeCell<*mut Waiter>,
    sequence: core::cell::UnsafeCell<u64>,
}

// Every queue link is accessed under `locked`. A waiter remains on its caller's stack until its
// native wait returns, then removes itself under the same lock.
unsafe impl Sync for Bucket {}

impl Bucket {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            head: core::cell::UnsafeCell::new(ptr::null_mut()),
            tail: core::cell::UnsafeCell::new(ptr::null_mut()),
            sequence: core::cell::UnsafeCell::new(0),
        }
    }

    fn lock(&self) -> BucketGuard<'_> {
        while self.locked.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        BucketGuard(self)
    }
}

struct BucketGuard<'a>(&'a Bucket);

impl Drop for BucketGuard<'_> {
    fn drop(&mut self) {
        self.0.locked.store(false, Ordering::Release);
    }
}

impl BucketGuard<'_> {
    /// # Safety
    /// All pointers name stack waiters still linked under this bucket lock.
    unsafe fn push(&self, entry: *mut Waiter) {
        let bucket = self.0;
        let sequence = unsafe { &mut *bucket.sequence.get() };
        *sequence = sequence.wrapping_add(1);
        // SAFETY: the caller owns the entry until it removes it under this lock.
        unsafe {
            (*entry).sequence = *sequence;
            if (*bucket.tail.get()).is_null() {
                *bucket.head.get() = entry;
            } else {
                (**bucket.tail.get()).next = entry;
            }
            *bucket.tail.get() = entry;
        }
    }

    /// # Safety
    /// `entry` must still name a live stack waiter while the bucket is locked.
    unsafe fn remove(&self, entry: *mut Waiter) -> bool {
        let bucket = self.0;
        let mut previous: *mut Waiter = ptr::null_mut();
        let mut current = unsafe { *bucket.head.get() };
        while !current.is_null() {
            if current == entry {
                let next = unsafe { (*current).next };
                unsafe {
                    if previous.is_null() {
                        *bucket.head.get() = next;
                    } else {
                        (*previous).next = next;
                    }
                    if (*bucket.tail.get()) == current {
                        *bucket.tail.get() = previous;
                    }
                    (*current).next = ptr::null_mut();
                }
                return true;
            }
            previous = current;
            current = unsafe { (*current).next };
        }
        false
    }

    /// Remove the oldest waiter for an address and return its thread ID. New waiters can be
    /// excluded by a sequence snapshot when waking all.
    unsafe fn take(&self, address: usize, last_sequence: Option<u64>) -> Option<u64> {
        let mut current = unsafe { *self.0.head.get() };
        while !current.is_null() {
            let selected = unsafe {
                (*current).address == address
                    && last_sequence.is_none_or(|last| (*current).sequence <= last)
            };
            if selected {
                let thread_id = unsafe { (*current).thread_id };
                // SAFETY: current was found in this locked queue.
                unsafe { self.remove(current) };
                return Some(thread_id);
            }
            current = unsafe { (*current).next };
        }
        None
    }
}

pub struct AddressWaitTable {
    buckets: [Bucket; BUCKETS],
}

impl AddressWaitTable {
    pub const fn new() -> Self {
        Self {
            buckets: [const { Bucket::new() }; BUCKETS],
        }
    }

    fn bucket(&self, address: usize) -> &Bucket {
        &self.buckets[(address >> 4) % BUCKETS]
    }

    /// Wait only while 1, 2, 4, or 8 bytes at `address` equal `compare`. The transport must
    /// implement `NtWaitForAlertByThreadId(NULL, timeout)` and return a real native status.
    ///
    /// # Safety
    /// Non-null pointers must remain readable for `size` bytes during the comparison. `timeout`
    /// follows the native `LARGE_INTEGER` lifetime contract of the transport.
    pub unsafe fn wait(
        &self,
        address: *const u8,
        compare: *const u8,
        size: usize,
        thread_id: u64,
        timeout: *const i64,
        native_wait: impl FnOnce(*const i64) -> NtStatus,
    ) -> NtStatus {
        if !matches!(size, 1 | 2 | 4 | 8)
            || address.is_null()
            || compare.is_null()
            || thread_id == 0
        {
            return STATUS_INVALID_PARAMETER;
        }
        let bucket = self.bucket(address as usize);
        let mut entry = Waiter {
            address: address as usize,
            thread_id,
            sequence: 0,
            next: ptr::null_mut(),
        };
        {
            let guard = bucket.lock();
            // SAFETY: the pointers are readable for size bytes, as required by the caller.
            for offset in 0..size {
                if unsafe { ptr::read_volatile(address.add(offset)) }
                    != unsafe { ptr::read_volatile(compare.add(offset)) }
                {
                    return STATUS_SUCCESS;
                }
            }
            // SAFETY: entry remains on this stack through native_wait and cleanup.
            unsafe { guard.push(&mut entry) };
        }

        let status = native_wait(timeout);
        // A wake may already have removed the entry; address identity is never read from the
        // entry after it leaves this scope. Cleanup handles timeout and unsupported transports.
        {
            let guard = bucket.lock();
            // SAFETY: entry is still live on this stack, and removal is idempotent.
            unsafe { guard.remove(&mut entry) };
        }
        if status == STATUS_ALERTED {
            STATUS_SUCCESS
        } else {
            status
        }
    }

    pub fn wake_one(&self, address: *const u8, mut alert: impl FnMut(u64) -> NtStatus) {
        if address.is_null() {
            return;
        }
        let thread_id = {
            let guard = self.bucket(address as usize).lock();
            // SAFETY: the guard owns the queue links.
            unsafe { guard.take(address as usize, None) }
        };
        if let Some(thread_id) = thread_id {
            let _ = alert(thread_id);
        }
    }

    pub fn wake_all(&self, address: *const u8, mut alert: impl FnMut(u64) -> NtStatus) {
        if address.is_null() {
            return;
        }
        let bucket = self.bucket(address as usize);
        let last_sequence = {
            let _guard = bucket.lock();
            // SAFETY: the guard owns the sequence counter.
            unsafe { *bucket.sequence.get() }
        };
        loop {
            let thread_id = {
                let guard = bucket.lock();
                // SAFETY: the guard owns the queue links. The snapshot excludes later arrivals.
                unsafe { guard.take(address as usize, Some(last_sequence)) }
            };
            let Some(thread_id) = thread_id else { break };
            let _ = alert(thread_id);
        }
    }
}

impl Default for AddressWaitTable {
    fn default() -> Self {
        Self::new()
    }
}

pub static ADDRESS_WAITS: AddressWaitTable = AddressWaitTable::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_size_and_skips_native_wait_when_bytes_differ() {
        let table = AddressWaitTable::new();
        let address = [0u8; 8];
        let different = [1u8; 8];
        assert_eq!(
            unsafe {
                table.wait(
                    address.as_ptr(),
                    different.as_ptr(),
                    8,
                    7,
                    ptr::null(),
                    |_| panic!("waited"),
                )
            },
            STATUS_SUCCESS
        );
        for size in [0, 3, 5, 16] {
            assert_eq!(
                unsafe {
                    table.wait(
                        address.as_ptr(),
                        address.as_ptr(),
                        size,
                        7,
                        ptr::null(),
                        |_| panic!("waited"),
                    )
                },
                STATUS_INVALID_PARAMETER
            );
        }
    }

    #[test]
    fn equal_bytes_park_and_timeout_removes_waiter() {
        let table = AddressWaitTable::new();
        let value = 0x1234u16;
        let timeout = -100i64;
        let status = unsafe {
            table.wait(
                (&value as *const u16).cast(),
                (&value as *const u16).cast(),
                2,
                27,
                &timeout,
                |seen| {
                    assert_eq!(seen, &timeout);
                    0x0000_0102
                },
            )
        };
        assert_eq!(status, 0x0000_0102);
        table.wake_one((&value as *const u16).cast(), |_| panic!("stale waiter"));
    }

    #[test]
    fn wake_single_selects_oldest_and_alert_maps_to_success() {
        let table = AddressWaitTable::new();
        let value = 0u64;
        let address = (&value as *const u64).cast();
        let status = unsafe {
            table.wait(address, address, 8, 41, ptr::null(), |_| {
                table.wake_one(address, |id| {
                    assert_eq!(id, 41);
                    STATUS_SUCCESS
                });
                STATUS_ALERTED
            })
        };
        assert_eq!(status, STATUS_SUCCESS);
        table.wake_one(address, |_| panic!("duplicate wake"));
    }

    #[test]
    fn unsupported_native_wait_status_is_preserved_and_unlinked() {
        let table = AddressWaitTable::new();
        let value = 0u8;
        let status = unsafe {
            table.wait(&value, &value, 1, 5, ptr::null(), |_| {
                crate::STATUS_INVALID_SYSTEM_SERVICE
            })
        };
        assert_eq!(status, crate::STATUS_INVALID_SYSTEM_SERVICE);
        table.wake_all(&value, |_| panic!("stale waiter"));
    }

    #[test]
    fn wake_single_is_fifo_per_address() {
        let table = AddressWaitTable::new();
        let value = 0u8;
        let address = &value as *const u8 as usize;
        let mut first = Waiter {
            address,
            thread_id: 11,
            sequence: 0,
            next: ptr::null_mut(),
        };
        let mut other_address = Waiter {
            address: address + 1,
            thread_id: 12,
            sequence: 0,
            next: ptr::null_mut(),
        };
        let mut second = Waiter {
            address,
            thread_id: 13,
            sequence: 0,
            next: ptr::null_mut(),
        };
        {
            let guard = table.bucket(address).lock();
            unsafe {
                guard.push(&mut first);
                guard.push(&mut other_address);
                guard.push(&mut second);
            }
        }
        let mut alerted = [0u64; 2];
        let mut count = 0;
        for _ in 0..2 {
            table.wake_one(&value, |id| {
                alerted[count] = id;
                count += 1;
                STATUS_SUCCESS
            });
        }
        assert_eq!(alerted, [11, 13]);
        let guard = table.bucket(address).lock();
        assert!(unsafe { guard.remove(&mut other_address) });
    }

    #[test]
    fn wake_all_does_not_include_later_waiters() {
        let table = AddressWaitTable::new();
        let value = 0u8;
        let address = &value as *const u8 as usize;
        let mut first = Waiter {
            address,
            thread_id: 21,
            sequence: 0,
            next: ptr::null_mut(),
        };
        let mut later = Waiter {
            address,
            thread_id: 22,
            sequence: 0,
            next: ptr::null_mut(),
        };
        unsafe { table.bucket(address).lock().push(&mut first) };
        let mut alerted = [0u64; 2];
        let mut count = 0;
        table.wake_all(&value, |id| {
            alerted[count] = id;
            count += 1;
            unsafe { table.bucket(address).lock().push(&mut later) };
            STATUS_SUCCESS
        });
        assert_eq!(count, 1);
        table.wake_one(&value, |id| {
            alerted[count] = id;
            count += 1;
            STATUS_SUCCESS
        });
        assert_eq!(alerted, [21, 22]);
    }
}
