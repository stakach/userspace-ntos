//! `RTL_RESOURCE` — the multiple-reader / single-writer lock, the pure host-testable core.
//!
//! Faithful to `references/reactos/sdk/lib/rtl/resource.c` (itself derived from Wine). An
//! `RTL_RESOURCE` is a reader/writer lock layered over a critical section plus two counting
//! semaphores (shared-waiter + exclusive-waiter queues). The load-bearing observable state is the
//! signed `NumberActive` counter and the two waiter counts:
//!
//! * `NumberActive == 0` — free.
//! * `NumberActive > 0`  — that many shared (reader) holders.
//! * `NumberActive < 0`  — an exclusive (writer) holder, recursively (`-1` = one, `-2` = re-entered
//!   once, …). `OwningThread` records the writer's thread id for recursive-acquire detection.
//!
//! This module models exactly those state transitions in a pure [`Resource`] value so they can be
//! host-tested. The `nt-ntdll-dll` exports wrap it: they interpret the raw `RTL_RESOURCE` fields at
//! their byte-exact x64 offsets, drive the critical section / semaphores through the real seams, and
//! call into this core for the counter arithmetic. On the single-threaded userspace runtime the
//! semaphore waits never actually block (there is only ever one thread contending), so the counter
//! logic here is the whole observable contract.

/// A pure model of `RTL_RESOURCE`'s lock state (the fields the acquire/release/convert arithmetic
/// touches). The critical section and semaphores are transport concerns handled by the DLL wrapper;
/// this value is the reader/writer bookkeeping.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Resource {
    /// `NumberActive` — signed: `0` free, `>0` shared holders, `<0` recursive exclusive depth.
    pub number_active: i32,
    /// `SharedWaiters` — count of readers queued on the shared semaphore.
    pub shared_waiters: u32,
    /// `ExclusiveWaiters` — count of writers queued on the exclusive semaphore.
    pub exclusive_waiters: u32,
    /// `OwningThread` — the exclusive owner's thread id (`0` = none / shared-only).
    pub owning_thread: u64,
}

/// The number of tokens to release on a semaphore as a side effect of a state transition, so the
/// wrapper can drive `NtReleaseSemaphore` on the real handle. `None` = no release.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SemaphoreRelease {
    /// Release `n` tokens on the shared (reader) semaphore.
    Shared(u32),
    /// Release `n` tokens on the exclusive (writer) semaphore.
    Exclusive(u32),
}

/// The verdict of an acquire attempt: whether it was granted, and (if it must block) which
/// semaphore queue the caller was enqueued on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Acquire {
    /// Granted immediately (the counter was updated).
    Granted,
    /// Would block: the caller was enqueued on the shared/exclusive waiter queue (the corresponding
    /// waiter count was bumped). Only returned when `wait` was requested.
    Blocked,
    /// Not granted and `wait == false` — the caller must not block.
    Failed,
}

impl Resource {
    /// `RtlInitializeResource` — a freshly-initialised resource is fully unlocked.
    pub fn new() -> Resource {
        Resource::default()
    }

    /// `RtlDeleteResource` — tear the lock state back down to the initialised zero state (the
    /// wrapper additionally closes the two semaphore handles and deletes the critical section).
    pub fn delete(&mut self) {
        *self = Resource::default();
    }

    /// `RtlAcquireResourceExclusive(Resource, Wait)` for `current_thread`. Faithful to
    /// `resource.c:RtlAcquireResourceExclusive` (the single, non-looping evaluation — the wrapper's
    /// `goto start` re-evaluation after a real wait is a transport concern).
    pub fn acquire_exclusive(&mut self, current_thread: u64, wait: bool) -> Acquire {
        if self.number_active == 0 {
            // Free → take it exclusively.
            self.number_active = -1;
            self.owning_thread = current_thread;
            Acquire::Granted
        } else if self.number_active < 0 {
            // An exclusive lock is held.
            if self.owning_thread == current_thread {
                // Recursive write acquire by the owner → deepen.
                self.number_active -= 1;
                return Acquire::Granted;
            }
            if wait {
                self.exclusive_waiters += 1;
                Acquire::Blocked
            } else {
                Acquire::Failed
            }
        } else {
            // One or more shared holders block an exclusive acquire.
            if wait {
                self.exclusive_waiters += 1;
                Acquire::Blocked
            } else {
                Acquire::Failed
            }
        }
    }

    /// `RtlAcquireResourceShared(Resource, Wait)` for `current_thread`. Faithful to
    /// `resource.c:RtlAcquireResourceShared` (single evaluation).
    pub fn acquire_shared(&mut self, current_thread: u64, wait: bool) -> Acquire {
        if self.number_active < 0 {
            // An exclusive holder is active.
            if self.owning_thread == current_thread {
                // The writer may also take a (recursive) read → deepen the exclusive depth.
                self.number_active -= 1;
                return Acquire::Granted;
            }
            if wait {
                self.shared_waiters += 1;
                Acquire::Blocked
            } else {
                Acquire::Failed
            }
        } else {
            // Free or shared → add a reader.
            self.number_active += 1;
            Acquire::Granted
        }
    }

    /// `RtlReleaseResource(Resource)` — drop one hold. Returns the semaphore release the wrapper must
    /// perform (wake a queued writer, or drain the queued readers), if any. Faithful to
    /// `resource.c:RtlReleaseResource`.
    pub fn release(&mut self) -> Option<SemaphoreRelease> {
        if self.number_active > 0 {
            // A reader leaves.
            self.number_active -= 1;
            if self.number_active == 0 && self.exclusive_waiters > 0 {
                self.exclusive_waiters -= 1;
                return Some(SemaphoreRelease::Exclusive(1));
            }
        } else if self.number_active < 0 {
            // A writer leaves (or unwinds one level of recursion).
            self.number_active += 1;
            if self.number_active == 0 {
                self.owning_thread = 0;
                if self.exclusive_waiters > 0 {
                    self.exclusive_waiters -= 1;
                    return Some(SemaphoreRelease::Exclusive(1));
                } else if self.shared_waiters > 0 {
                    // Prevent new writers from joining until the queued readers run.
                    let n = self.shared_waiters;
                    self.number_active = self.shared_waiters as i32;
                    self.shared_waiters = 0;
                    return Some(SemaphoreRelease::Shared(n));
                }
            }
        }
        None
    }

    /// `RtlConvertExclusiveToShared(Resource)` — downgrade the sole writer to a reader, waking any
    /// queued readers. Faithful to `resource.c:RtlConvertExclusiveToShared`.
    pub fn convert_exclusive_to_shared(&mut self) -> Option<SemaphoreRelease> {
        if self.number_active == -1 {
            self.owning_thread = 0;
            if self.shared_waiters > 0 {
                let n = self.shared_waiters;
                // The downgraded writer counts as a reader too (+1).
                self.number_active = self.shared_waiters as i32 + 1;
                self.shared_waiters = 0;
                return Some(SemaphoreRelease::Shared(n));
            }
            self.number_active = 1;
        }
        None
    }

    /// `RtlConvertSharedToExclusive(Resource)` for `current_thread`. Faithful to
    /// `resource.c:RtlConvertSharedToExclusive`: when this is the sole reader it upgrades in place;
    /// otherwise the caller must enqueue on the exclusive semaphore (returns [`Acquire::Blocked`])
    /// and, after the real wait, the wrapper re-enters and finalises the upgrade via
    /// [`Resource::finish_shared_to_exclusive`].
    pub fn convert_shared_to_exclusive(&mut self, current_thread: u64) -> Acquire {
        if self.number_active == 1 {
            self.owning_thread = current_thread;
            self.number_active = -1;
            Acquire::Granted
        } else {
            self.exclusive_waiters += 1;
            Acquire::Blocked
        }
    }

    /// Finalise a `RtlConvertSharedToExclusive` after its exclusive-semaphore wait completed (the
    /// re-entry tail of `resource.c:RtlConvertSharedToExclusive`).
    pub fn finish_shared_to_exclusive(&mut self, current_thread: u64) {
        self.owning_thread = current_thread;
        self.number_active = -1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: u64 = 0x1111;
    const T2: u64 = 0x2222;

    #[test]
    fn init_is_unlocked() {
        let r = Resource::new();
        assert_eq!(r.number_active, 0);
        assert_eq!(r.shared_waiters, 0);
        assert_eq!(r.exclusive_waiters, 0);
        assert_eq!(r.owning_thread, 0);
    }

    #[test]
    fn shared_acquire_release_counts() {
        let mut r = Resource::new();
        assert_eq!(r.acquire_shared(T1, true), Acquire::Granted);
        assert_eq!(r.number_active, 1);
        assert_eq!(r.acquire_shared(T2, true), Acquire::Granted);
        assert_eq!(r.number_active, 2); // two concurrent readers
        assert_eq!(r.release(), None);
        assert_eq!(r.number_active, 1);
        assert_eq!(r.release(), None);
        assert_eq!(r.number_active, 0); // back to free
    }

    #[test]
    fn exclusive_acquire_sets_owner_and_release_frees() {
        let mut r = Resource::new();
        assert_eq!(r.acquire_exclusive(T1, true), Acquire::Granted);
        assert_eq!(r.number_active, -1);
        assert_eq!(r.owning_thread, T1);
        assert_eq!(r.release(), None);
        assert_eq!(r.number_active, 0);
        assert_eq!(r.owning_thread, 0);
    }

    #[test]
    fn exclusive_is_recursive_for_owner() {
        let mut r = Resource::new();
        assert_eq!(r.acquire_exclusive(T1, true), Acquire::Granted);
        assert_eq!(r.acquire_exclusive(T1, true), Acquire::Granted); // recursive
        assert_eq!(r.number_active, -2);
        // A recursive read by the writer deepens too.
        assert_eq!(r.acquire_shared(T1, true), Acquire::Granted);
        assert_eq!(r.number_active, -3);
        r.release();
        r.release();
        assert_eq!(r.number_active, -1);
        assert_eq!(r.owning_thread, T1); // still owned until fully released
        r.release();
        assert_eq!(r.number_active, 0);
        assert_eq!(r.owning_thread, 0);
    }

    #[test]
    fn no_wait_acquire_fails_under_contention() {
        let mut r = Resource::new();
        r.acquire_exclusive(T1, true);
        // A different thread cannot acquire without waiting.
        assert_eq!(r.acquire_shared(T2, false), Acquire::Failed);
        assert_eq!(r.acquire_exclusive(T2, false), Acquire::Failed);
        // A reader cannot be added while a writer holds; state untouched.
        assert_eq!(r.number_active, -1);
    }

    #[test]
    fn waiters_enqueue_on_the_right_semaphore() {
        let mut r = Resource::new();
        r.acquire_exclusive(T1, true);
        assert_eq!(r.acquire_shared(T2, true), Acquire::Blocked);
        assert_eq!(r.shared_waiters, 1);
        assert_eq!(r.acquire_exclusive(T2, true), Acquire::Blocked);
        assert_eq!(r.exclusive_waiters, 1);
    }

    #[test]
    fn release_wakes_queued_writer_before_readers() {
        let mut r = Resource::new();
        r.acquire_exclusive(T1, true); // writer holds
        r.acquire_shared(T2, true); // reader queued
        r.acquire_exclusive(T2, true); // writer queued
        assert_eq!(r.shared_waiters, 1);
        assert_eq!(r.exclusive_waiters, 1);
        // Releasing the writer wakes the queued writer first (exclusive wins).
        assert_eq!(r.release(), Some(SemaphoreRelease::Exclusive(1)));
        assert_eq!(r.exclusive_waiters, 0);
        assert_eq!(r.number_active, 0);
        assert_eq!(r.owning_thread, 0);
        assert_eq!(r.shared_waiters, 1); // reader still queued
    }

    #[test]
    fn release_drains_queued_readers_when_no_writer_waits() {
        let mut r = Resource::new();
        r.acquire_exclusive(T1, true);
        r.acquire_shared(T2, true); // reader queued
        r.acquire_shared(0x3333, true); // another reader queued
        assert_eq!(r.shared_waiters, 2);
        // No writer queued → releasing wakes ALL queued readers and installs the reader count.
        assert_eq!(r.release(), Some(SemaphoreRelease::Shared(2)));
        assert_eq!(r.shared_waiters, 0);
        assert_eq!(r.number_active, 2);
    }

    #[test]
    fn reader_release_wakes_a_queued_writer() {
        let mut r = Resource::new();
        r.acquire_shared(T1, true); // one reader
        r.acquire_exclusive(T2, true); // writer queued behind it
        assert_eq!(r.exclusive_waiters, 1);
        // Last reader leaves → the writer is woken.
        assert_eq!(r.release(), Some(SemaphoreRelease::Exclusive(1)));
        assert_eq!(r.exclusive_waiters, 0);
        assert_eq!(r.number_active, 0);
    }

    #[test]
    fn convert_exclusive_to_shared_no_waiters() {
        let mut r = Resource::new();
        r.acquire_exclusive(T1, true);
        assert_eq!(r.convert_exclusive_to_shared(), None);
        assert_eq!(r.number_active, 1); // now a single reader
        assert_eq!(r.owning_thread, 0);
    }

    #[test]
    fn convert_exclusive_to_shared_wakes_readers() {
        let mut r = Resource::new();
        r.acquire_exclusive(T1, true);
        r.acquire_shared(T2, true); // reader queued
        assert_eq!(
            r.convert_exclusive_to_shared(),
            Some(SemaphoreRelease::Shared(1))
        );
        // Downgraded writer (1) + the woken reader (1) = 2 active.
        assert_eq!(r.number_active, 2);
        assert_eq!(r.shared_waiters, 0);
        assert_eq!(r.owning_thread, 0);
    }

    #[test]
    fn convert_shared_to_exclusive_sole_reader_upgrades() {
        let mut r = Resource::new();
        r.acquire_shared(T1, true);
        assert_eq!(r.convert_shared_to_exclusive(T1), Acquire::Granted);
        assert_eq!(r.number_active, -1);
        assert_eq!(r.owning_thread, T1);
    }

    #[test]
    fn convert_shared_to_exclusive_blocks_with_other_readers() {
        let mut r = Resource::new();
        r.acquire_shared(T1, true);
        r.acquire_shared(T2, true); // two readers
        assert_eq!(r.convert_shared_to_exclusive(T1), Acquire::Blocked);
        assert_eq!(r.exclusive_waiters, 1);
        // The wrapper finalises after the real wait completes.
        r.finish_shared_to_exclusive(T1);
        assert_eq!(r.number_active, -1);
        assert_eq!(r.owning_thread, T1);
    }

    #[test]
    fn delete_resets_state() {
        let mut r = Resource::new();
        r.acquire_exclusive(T1, true);
        r.delete();
        assert_eq!(r, Resource::new());
    }
}
