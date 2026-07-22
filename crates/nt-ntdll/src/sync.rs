//! Category C — the stateful synchronisation primitives: `RTL_CRITICAL_SECTION`, `RTL_SRWLOCK`,
//! `RTL_RUN_ONCE`.
//!
//! ★ This is the subtle category, treated **honestly** (see `ntdll_plan.md`): the **contended /
//! blocking** path of `RtlEnterCriticalSection` (`RtlpWaitForCriticalSection`, which blocks via
//! `NtWaitForKeyedEvent`) is literally the current boot deadlock. The fix "at the root" is to make
//! our critical section **correct by construction**:
//!
//! - The **data-structure layout** ([`CriticalSection`]) matches what hosted binaries read directly
//!   (`RTL_CRITICAL_SECTION { DebugInfo; LockCount; RecursionCount; OwningThread; LockSemaphore;
//!   SpinCount; }`, x64).
//! - The **uncontended fast path** — the interlocked `LockCount` CAS (`InterlockedIncrement` from
//!   `-1` to `0`, recursion when the owner re-enters) — is implemented + host-tested here. This is
//!   the overwhelmingly common path (an uncontended lock never blocks).
//! - The **contended blocking path** ([`WaitSeam`]) is an **honest documented seam**, NOT a fake.
//!   It does not spin-and-return or fabricate acquisition; it defines the exact operation that must
//!   happen (register the waiter on the CS's keyed event and block via `NtWaitForKeyedEvent`, wake
//!   the successor on leave via `NtReleaseKeyedEvent`) and routes it through the swappable
//!   [`crate::transport`] once the wait plane is wired (Step 6 / loader integration). Host tests
//!   assert the seam is *invoked* on contention (not that it fabricates success).

use crate::transport::{self, Backend};
use crate::{NtStatus, STATUS_INVALID_SYSTEM_SERVICE};

/// Sentinel `OwningThread` for "unowned".
const NO_OWNER: u64 = 0;

pub const RTL_CRITICAL_SECTION_ALL_FLAG_BITS: u32 = 0xFF00_0000;
pub const RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO: u32 = 0x0100_0000;
pub const RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN: u32 = 0x0200_0000;
pub const RTL_CRITICAL_SECTION_FLAG_STATIC_INIT: u32 = 0x0400_0000;
pub const RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE: u32 = 0x0800_0000;
pub const RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO: u32 = 0x1000_0000;
pub const STATUS_INVALID_PARAMETER_2: NtStatus = 0xC000_00F0;
pub const STATUS_INVALID_PARAMETER_3: NtStatus = 0xC000_00F1;

/// Validate and normalize `RtlInitializeCriticalSectionEx` parameters.
pub fn critical_section_init_flags(
    spin_count: u32,
    flags: u32,
    os_major: u32,
    os_minor: u32,
) -> Result<(u32, u32), NtStatus> {
    let flags = flags & RTL_CRITICAL_SECTION_ALL_FLAG_BITS;
    let mut allowed = RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO
        | RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN
        | RTL_CRITICAL_SECTION_FLAG_STATIC_INIT;
    if (os_major, os_minor) >= (6, 1) {
        allowed |=
            RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE | RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO;
    }
    if flags & !allowed != 0 {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    if spin_count & RTL_CRITICAL_SECTION_ALL_FLAG_BITS != 0 {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    Ok((spin_count, flags))
}

pub fn effective_critical_section_spin_count(spin_count: u32, processors: u32) -> usize {
    if processors > 1 {
        spin_count as usize
    } else {
        0
    }
}

/// Route a keyed-event syscall by name through the swappable transport. Resolves the SSN via the
/// shared ABI table (single source of truth); an unknown name (never, for these two) returns
/// [`STATUS_INVALID_SYSTEM_SERVICE`] rather than a silent success.
fn keyed_event_syscall(name: &str, handle: u64, key: u64) -> NtStatus {
    match nt_syscall_abi::ssn_of(name) {
        Some(ssn) => transport::syscall(
            Backend::for_ssn(ssn),
            ssn,
            &[handle, key, /*Alertable*/ 0, /*Timeout*/ 0],
        ),
        None => STATUS_INVALID_SYSTEM_SERVICE,
    }
}

/// `RTL_CRITICAL_SECTION` (x64 layout). Fields the hosted binaries read by offset are named; the
/// executive/loader marshals the real struct. `lock_count` is the interlocked lock word: `-1` means
/// free, `>= 0` means held (with `lock_count` waiters queued behind the owner — the NT convention).
#[repr(C)]
#[derive(Debug)]
pub struct CriticalSection {
    /// `DebugInfo` pointer (unused in the fast path).
    pub debug_info: u64,
    /// The interlocked lock word (`-1` == free).
    pub lock_count: i32,
    /// Re-entrancy depth of the owning thread.
    pub recursion_count: i32,
    /// Owning thread id (`ClientId.UniqueThread`), or [`NO_OWNER`].
    pub owning_thread: u64,
    /// The keyed-event / semaphore handle used to block contended waiters.
    pub lock_semaphore: u64,
    /// Adaptive spin count before blocking.
    pub spin_count: u64,
}

impl Default for CriticalSection {
    fn default() -> Self {
        Self::new()
    }
}

/// The outcome of a fast-path acquire attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Acquire {
    /// The lock was free and is now held by the caller (uncontended).
    Acquired,
    /// The caller already owned it; `recursion_count` was bumped (recursive re-entry).
    Recursed,
    /// The lock is held by another thread — the caller must block via the [`WaitSeam`].
    Contended,
}

impl CriticalSection {
    /// `RtlInitializeCriticalSection`: a free CS with the default spin count.
    pub const fn new() -> Self {
        CriticalSection {
            debug_info: 0,
            lock_count: -1,
            recursion_count: 0,
            owning_thread: NO_OWNER,
            lock_semaphore: 0,
            spin_count: 0,
        }
    }

    /// `RtlInitializeCriticalSectionAndSpinCount` / `RtlInitializeCriticalSectionEx`.
    pub const fn with_spin_count(spin_count: u64) -> Self {
        let mut cs = Self::new();
        cs.spin_count = spin_count & 0x00FF_FFFF; // Windows masks the flag bits
        cs
    }

    /// The **uncontended fast path** of `RtlEnterCriticalSection` for thread `tid`.
    ///
    /// Models `InterlockedIncrement(&LockCount)`:
    /// - free (`-1` → `0`): the caller takes ownership → [`Acquire::Acquired`].
    /// - already owned by `tid`: bump `recursion_count` → [`Acquire::Recursed`].
    /// - owned by another thread (`LockCount` goes `>= 0` for a new waiter): the caller must block →
    ///   [`Acquire::Contended`] (the [`WaitSeam`] takes over; this method does NOT block or fake it).
    ///
    /// Returns the classification. On contention `lock_count` has been incremented to register the
    /// waiter (exactly as NT does before calling `RtlpWaitForCriticalSection`).
    pub fn try_enter(&mut self, tid: u64) -> Acquire {
        // Recursive re-entry: the owner re-takes its own lock without touching the wait plane.
        if self.owning_thread == tid && self.lock_count >= 0 {
            self.lock_count += 1;
            self.recursion_count += 1;
            return Acquire::Recursed;
        }
        // InterlockedIncrement(&LockCount): -1 -> 0 means we won it uncontended.
        self.lock_count += 1;
        if self.lock_count == 0 {
            self.owning_thread = tid;
            self.recursion_count = 1;
            Acquire::Acquired
        } else {
            // LockCount is now >= 1: another thread owns it and we are a queued waiter.
            Acquire::Contended
        }
    }

    /// `RtlLeaveCriticalSection` (fast path) for the owning thread.
    ///
    /// Decrements `recursion_count`; on the final leave it releases ownership
    /// (`InterlockedDecrement(&LockCount)`). Returns `Some(waiter_present)` where `true` means a
    /// contended waiter remains and the caller must wake exactly one successor through the
    /// [`WaitSeam`] (`NtReleaseKeyedEvent`); `false` means the lock is now fully free. Returns
    /// `None` if `tid` is not the owner (a contract violation the caller shouldn't hit).
    pub fn leave(&mut self, tid: u64) -> Option<bool> {
        if self.owning_thread != tid || self.lock_count < 0 {
            return None;
        }
        self.recursion_count -= 1;
        if self.recursion_count > 0 {
            self.lock_count -= 1;
            return Some(false); // still held recursively by the same thread
        }
        // Final leave: relinquish ownership.
        self.owning_thread = NO_OWNER;
        self.lock_count -= 1; // InterlockedDecrement
        let waiter_present = self.lock_count >= 0; // a queued waiter remains
        Some(waiter_present)
    }

    /// Complete ownership transfer after the contended wait is signaled. The waiter's earlier
    /// `try_enter` already incremented `lock_count`, so handoff only installs owner and recursion.
    pub fn finish_wait(&mut self, tid: u64) {
        self.owning_thread = tid;
        self.recursion_count = 1;
    }

    /// `RtlDeleteCriticalSection`: reset the descriptor (the real one also frees `LockSemaphore`).
    pub fn delete(&mut self) {
        *self = Self::new();
    }
}

/// `RTL_CRITICAL_SECTION_DEBUG` (x64 layout, 0x30 bytes — see
/// `references/reactos/sdk/include/ndk/rtltypes.h`). Every `RtlInitializeCriticalSection(Ex)` that is
/// NOT `RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO` allocates one of these from the process heap
/// (`RtlpAllocateDebugInfo`) and stores its address in `RTL_CRITICAL_SECTION.DebugInfo` (offset 0).
///
/// This is load-bearing: consumers (e.g. msvcrt's per-locale-category CRT init) dereference
/// `DebugInfo` and read/write its fields (msvcrt writes `[DebugInfo+0x28]`, the `Flags`/`Spare`
/// union). A NULL `DebugInfo` faults them. We allocate a real, correctly-sized, zeroed struct — not a
/// fake — matching real ntdll's `RtlpAllocateDebugInfo` behaviour.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtlCriticalSectionDebug {
    /// `Type` @ 0x00 — `RTL_CRITSECT_TYPE` (0).
    pub ty: u16,
    /// `CreatorBackTraceIndex` @ 0x02.
    pub creator_back_trace_index: u16,
    /// `CriticalSection` @ 0x08 — back-pointer to the owning `RTL_CRITICAL_SECTION`.
    pub critical_section: u64,
    /// `ProcessLocksList.Flink` @ 0x10.
    pub process_locks_flink: u64,
    /// `ProcessLocksList.Blink` @ 0x18.
    pub process_locks_blink: u64,
    /// `EntryCount` @ 0x20.
    pub entry_count: u32,
    /// `ContentionCount` @ 0x24.
    pub contention_count: u32,
    /// The `Flags`/`Spare` union @ 0x28 (msvcrt writes here) + trailing `Creator*`/`SpareWORD`.
    pub flags_spare: u64,
}

/// `RTL_CRITSECT_TYPE` (`references/reactos/sdk/include/ndk/rtltypes.h:264`).
pub const RTL_CRITSECT_TYPE: u16 = 0;

impl RtlCriticalSectionDebug {
    /// The x64 struct size that must be allocated + valid (msvcrt derefs through `+0x28`).
    pub const SIZE: usize = 0x30;

    /// Populate a zeroed `RTL_CRITICAL_SECTION_DEBUG` for the critical section at address `cs_addr`,
    /// exactly as `RtlInitializeCriticalSectionEx` does after `RtlpAllocateDebugInfo`:
    /// `Type = RTL_CRITSECT_TYPE`, `CriticalSection = cs`, `ProcessLocksList` self-linked (an empty
    /// list head at `debug_addr+0x10`), all counters/flags zero. `debug_addr` is where the struct
    /// lives (its `ProcessLocksList` links point at itself, the NT convention for an empty entry
    /// before it is inserted into the process lock list).
    pub fn init(cs_addr: u64, debug_addr: u64) -> Self {
        let locks_list = debug_addr.wrapping_add(0x10);
        RtlCriticalSectionDebug {
            ty: RTL_CRITSECT_TYPE,
            creator_back_trace_index: 0,
            critical_section: cs_addr,
            // An empty LIST_ENTRY points its Flink/Blink at itself.
            process_locks_flink: locks_list,
            process_locks_blink: locks_list,
            entry_count: 0,
            contention_count: 0,
            flags_spare: 0,
        }
    }
}

// Compile-time proof the x64 layout matches RTL_CRITICAL_SECTION_DEBUG (0x30 bytes, fields at their
// documented offsets) so the struct we hand a hosted binary is byte-compatible with what it reads.
const _: () = {
    assert!(core::mem::size_of::<RtlCriticalSectionDebug>() == 0x30);
    assert!(core::mem::offset_of!(RtlCriticalSectionDebug, ty) == 0x00);
    assert!(core::mem::offset_of!(RtlCriticalSectionDebug, critical_section) == 0x08);
    assert!(core::mem::offset_of!(RtlCriticalSectionDebug, process_locks_flink) == 0x10);
    assert!(core::mem::offset_of!(RtlCriticalSectionDebug, process_locks_blink) == 0x18);
    assert!(core::mem::offset_of!(RtlCriticalSectionDebug, entry_count) == 0x20);
    assert!(core::mem::offset_of!(RtlCriticalSectionDebug, contention_count) == 0x24);
    assert!(core::mem::offset_of!(RtlCriticalSectionDebug, flags_spare) == 0x28);
};

/// The **contended-blocking seam** for a critical section. This is the honest home for the path
/// that literally deadlocks today: instead of faking acquisition, it names the exact keyed-event
/// operations and routes them through the swappable [`transport`]. Until the wait plane is wired
/// (Step 6), invoking it returns the transport's not-implemented status — never a fabricated
/// success — so a contended caller cannot silently proceed as if it holds the lock.
pub struct WaitSeam;

impl WaitSeam {
    /// `RtlpWaitForCriticalSection` → `NtWaitForKeyedEvent(cs.LockSemaphore, &cs, ...)`: block the
    /// caller until the current owner releases. Routes through [`transport::syscall`] with the
    /// `NtWaitForKeyedEvent` SSN. **Blocking, not faked** — on an unwired transport it returns the
    /// seam's not-implemented status rather than pretending the lock was taken.
    pub fn wait_for_ownership(cs: &CriticalSection) -> NtStatus {
        let key = cs as *const CriticalSection as u64;
        keyed_event_syscall("NtWaitForKeyedEvent", cs.lock_semaphore, key)
    }

    /// `RtlpUnWaitCriticalSection` → `NtReleaseKeyedEvent`: wake exactly one queued waiter on leave.
    pub fn wake_one(cs: &CriticalSection) -> NtStatus {
        let key = cs as *const CriticalSection as u64;
        keyed_event_syscall("NtReleaseKeyedEvent", cs.lock_semaphore, key)
    }
}

// --- RTL_SRWLOCK ------------------------------------------------------------------------------

/// `RTL_SRWLOCK` — a single pointer-width word. Bit 0 is the `Locked` bit; the upper bits form the
/// waiter/shared-count. The uncontended fast paths (acquire/release, exclusive + shared) are
/// implemented here; the contended path shares the [`WaitSeam`] keyed-event model.
#[repr(C)]
#[derive(Debug)]
pub struct SrwLock {
    /// The lock word. `0` == free.
    pub value: usize,
}

/// Bit 0 of the SRW word: exclusively locked.
const SRW_LOCK_BIT: usize = 0x1;
/// The shared-count lives above the low control bit.
const SRW_SHARED_SHIFT: u32 = 4;
const SRW_SHARED_UNIT: usize = 1 << SRW_SHARED_SHIFT;

impl SrwLock {
    /// `RtlInitializeSRWLock`.
    pub const fn new() -> Self {
        SrwLock { value: 0 }
    }

    /// `RtlTryAcquireSRWLockExclusive`: succeed only if fully free.
    pub fn try_acquire_exclusive(&mut self) -> bool {
        if self.value == 0 {
            self.value = SRW_LOCK_BIT;
            true
        } else {
            false
        }
    }

    /// `RtlReleaseSRWLockExclusive`: clear the lock bit. Returns `false` on a contract violation
    /// (not exclusively held).
    pub fn release_exclusive(&mut self) -> bool {
        if self.value & SRW_LOCK_BIT != 0 {
            self.value &= !SRW_LOCK_BIT;
            true
        } else {
            false
        }
    }

    /// `RtlTryAcquireSRWLockShared`: succeed if not exclusively held; bumps the shared count.
    pub fn try_acquire_shared(&mut self) -> bool {
        if self.value & SRW_LOCK_BIT != 0 {
            return false;
        }
        self.value += SRW_SHARED_UNIT;
        true
    }

    /// `RtlReleaseSRWLockShared`: decrement the shared count. Returns `false` if no shared holder.
    pub fn release_shared(&mut self) -> bool {
        if self.value < SRW_SHARED_UNIT || self.value & SRW_LOCK_BIT != 0 {
            return false;
        }
        self.value -= SRW_SHARED_UNIT;
        true
    }

    /// The current shared-holder count.
    pub fn shared_count(&self) -> usize {
        self.value >> SRW_SHARED_SHIFT
    }
}

impl Default for SrwLock {
    fn default() -> Self {
        Self::new()
    }
}

// --- RTL_RUN_ONCE -----------------------------------------------------------------------------

/// `RTL_RUN_ONCE` state (`RtlRunOnceExecuteOnce`). A pointer-width word encoding the run state.
#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunOnce {
    /// The state word: `Uninitialized` / `InProgress` / `Complete`.
    pub state: usize,
}

/// `RUN_ONCE` states (low 2 bits of the word).
const RUN_ONCE_UNINIT: usize = 0;
const RUN_ONCE_IN_PROGRESS: usize = 1;
const RUN_ONCE_COMPLETE: usize = 2;

/// The result of beginning a run-once.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RunOnceBegin {
    /// This caller won the race and must run the init routine, then call [`RunOnce::complete`].
    Run,
    /// Initialisation already completed — proceed without running.
    AlreadyComplete,
    /// Another caller is running the init — this caller must wait (the [`WaitSeam`] path).
    Pending,
}

impl RunOnce {
    /// `RtlRunOnceInitialize`.
    pub const fn new() -> Self {
        RunOnce {
            state: RUN_ONCE_UNINIT,
        }
    }

    /// `RtlRunOnceBeginInitialize`: claim the run for this caller if uninitialised.
    pub fn begin(&mut self) -> RunOnceBegin {
        match self.state & 0x3 {
            RUN_ONCE_COMPLETE => RunOnceBegin::AlreadyComplete,
            RUN_ONCE_IN_PROGRESS => RunOnceBegin::Pending,
            _ => {
                self.state = RUN_ONCE_IN_PROGRESS;
                RunOnceBegin::Run
            }
        }
    }

    /// `RtlRunOnceComplete`: mark initialisation complete.
    pub fn complete(&mut self) {
        self.state = RUN_ONCE_COMPLETE;
    }

    /// Whether the one-time init has completed.
    pub fn is_complete(&self) -> bool {
        self.state & 0x3 == RUN_ONCE_COMPLETE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: u64 = 0x1111;
    const T2: u64 = 0x2222;

    #[test]
    fn cs_uncontended_acquire_and_leave() {
        let mut cs = CriticalSection::new();
        assert_eq!(cs.lock_count, -1); // free
        assert_eq!(cs.try_enter(T1), Acquire::Acquired);
        assert_eq!(cs.owning_thread, T1);
        assert_eq!(cs.recursion_count, 1);
        // Final leave with no waiters → fully free, no wake needed.
        assert_eq!(cs.leave(T1), Some(false));
        assert_eq!(cs.lock_count, -1);
        assert_eq!(cs.owning_thread, NO_OWNER);
    }

    #[test]
    fn cs_recursive_reentry() {
        let mut cs = CriticalSection::new();
        assert_eq!(cs.try_enter(T1), Acquire::Acquired);
        assert_eq!(cs.try_enter(T1), Acquire::Recursed);
        assert_eq!(cs.lock_count, 1);
        assert_eq!(cs.recursion_count, 2);
        assert_eq!(cs.leave(T1), Some(false)); // still held (recursion 2->1)
        assert_eq!(cs.lock_count, 0);
        assert_eq!(cs.leave(T1), Some(false)); // now released
        assert_eq!(cs.owning_thread, NO_OWNER);
    }

    #[test]
    fn cs_contention_classifies_and_seams_do_not_fake() {
        let mut cs = CriticalSection::new();
        assert_eq!(cs.try_enter(T1), Acquire::Acquired);
        // A second thread contends: NOT acquired, and the waiter is registered (LockCount bumped).
        assert_eq!(cs.try_enter(T2), Acquire::Contended);
        assert!(cs.lock_count >= 1);
        // The blocking seam must NOT fabricate success on the unwired host transport.
        assert_eq!(
            WaitSeam::wait_for_ownership(&cs),
            crate::STATUS_NOT_IMPLEMENTED
        );
        // The owner leaving with a queued waiter reports a wake is required.
        assert_eq!(cs.leave(T1), Some(true));
        assert_eq!(cs.lock_count, 0);
        cs.finish_wait(T2);
        assert_eq!(cs.owning_thread, T2);
        assert_eq!(cs.recursion_count, 1);
        assert_eq!(cs.leave(T2), Some(false));
        assert_eq!(cs.lock_count, -1);
        assert_eq!(WaitSeam::wake_one(&cs), crate::STATUS_NOT_IMPLEMENTED);
    }

    #[test]
    fn cs_leave_by_non_owner_rejected() {
        let mut cs = CriticalSection::new();
        cs.try_enter(T1);
        assert_eq!(cs.leave(T2), None);
    }

    #[test]
    fn cs_spin_count_masked() {
        let cs = CriticalSection::with_spin_count(0x8000_0400);
        assert_eq!(cs.spin_count, 0x400); // flag bits masked off
    }

    #[test]
    fn cs_init_validates_flag_and_spin_parameter_indices() {
        assert_eq!(
            critical_section_init_flags(0x0100_0000, 0, 6, 1),
            Err(STATUS_INVALID_PARAMETER_2)
        );
        assert_eq!(
            critical_section_init_flags(0, 0x2000_0000, 6, 1),
            Err(STATUS_INVALID_PARAMETER_3)
        );
        assert!(critical_section_init_flags(
            4000,
            RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO | 7,
            6,
            1
        )
        .is_ok());
    }

    #[test]
    fn cs_init_applies_version_and_processor_rules() {
        assert!(
            critical_section_init_flags(0, RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE, 6, 1).is_ok()
        );
        assert_eq!(
            critical_section_init_flags(0, RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE, 6, 0),
            Err(STATUS_INVALID_PARAMETER_3)
        );
        assert_eq!(effective_critical_section_spin_count(4000, 1), 0);
        assert_eq!(effective_critical_section_spin_count(4000, 2), 4000);
    }

    #[test]
    fn cs_debug_info_is_populated_not_null() {
        // The fix for the msvcrt locale-init [DebugInfo+0x28] fault: RtlInitializeCriticalSection(Ex)
        // must allocate a real, correctly-sized, zeroed RTL_CRITICAL_SECTION_DEBUG and set the
        // fields per RtlpAllocateDebugInfo / RtlInitializeCriticalSectionEx.
        let cs_addr = 0x0011_2233_4400_0000u64; // where the RTL_CRITICAL_SECTION lives
        let debug_addr = 0x0055_6677_8800_0000u64; // where the debug struct is allocated
        let dbg = RtlCriticalSectionDebug::init(cs_addr, debug_addr);

        // Sufficient size so a consumer can write through +0x28 (msvcrt) and past it.
        assert_eq!(RtlCriticalSectionDebug::SIZE, 0x30);
        assert!(RtlCriticalSectionDebug::SIZE >= 0x28 + 8);

        // Real fields set exactly as RtlInitializeCriticalSectionEx does.
        assert_eq!(dbg.ty, RTL_CRITSECT_TYPE);
        assert_eq!(dbg.critical_section, cs_addr); // back-pointer
        assert_eq!(dbg.entry_count, 0);
        assert_eq!(dbg.contention_count, 0);
        assert_eq!(dbg.flags_spare, 0); // the +0x28 union starts zeroed
                                        // Empty LIST_ENTRY: both links point at the list head (debug_addr+0x10).
        assert_eq!(dbg.process_locks_flink, debug_addr + 0x10);
        assert_eq!(dbg.process_locks_blink, debug_addr + 0x10);
    }

    #[test]
    fn srw_exclusive_excludes() {
        let mut l = SrwLock::new();
        assert!(l.try_acquire_exclusive());
        assert!(!l.try_acquire_exclusive()); // exclusive is exclusive
        assert!(!l.try_acquire_shared()); // shared blocked while exclusive
        assert!(l.release_exclusive());
        assert!(l.try_acquire_shared());
    }

    #[test]
    fn srw_shared_stacks() {
        let mut l = SrwLock::new();
        assert!(l.try_acquire_shared());
        assert!(l.try_acquire_shared());
        assert_eq!(l.shared_count(), 2);
        assert!(!l.try_acquire_exclusive()); // exclusive blocked while shared held
        assert!(l.release_shared());
        assert!(l.release_shared());
        assert_eq!(l.shared_count(), 0);
        assert!(!l.release_shared()); // underflow rejected
        assert!(l.try_acquire_exclusive()); // now free
    }

    #[test]
    fn run_once_single_runner() {
        let mut ro = RunOnce::new();
        assert_eq!(ro.begin(), RunOnceBegin::Run);
        // A concurrent caller sees Pending until complete.
        // (Model the same word: a second begin() observes InProgress.)
        assert_eq!(ro.begin(), RunOnceBegin::Pending);
        ro.complete();
        assert!(ro.is_complete());
        assert_eq!(ro.begin(), RunOnceBegin::AlreadyComplete);
    }
}
