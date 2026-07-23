//! Host-testable module reference and callout metadata transitions.

pub const LOAD_COUNT_PINNED: u16 = u16::MAX;

pub const GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT: u32 = 0x0000_0001;
pub const GET_DLL_HANDLE_EX_PIN: u32 = 0x0000_0002;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GetDllHandleAction {
    Unchanged,
    AddReference,
    Pin,
}

/// Validate `LdrGetDllHandleEx` flags and select the module-lifetime transition. Pinning is the
/// only form that permits a null output handle; pin and unchanged-refcount are contradictory.
pub fn get_dll_handle_action(
    flags: u32,
    output_handle_present: bool,
) -> Option<GetDllHandleAction> {
    if flags & !(GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT | GET_DLL_HANDLE_EX_PIN) != 0
        || flags == GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT | GET_DLL_HANDLE_EX_PIN
        || (!output_handle_present && flags & GET_DLL_HANDLE_EX_PIN == 0)
    {
        return None;
    }
    Some(if flags & GET_DLL_HANDLE_EX_PIN != 0 {
        GetDllHandleAction::Pin
    } else if flags & GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT != 0 {
        GetDllHandleAction::Unchanged
    } else {
        GetDllHandleAction::AddReference
    })
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReferenceReleasePlan {
    Pinned,
    DecrementTo(u16),
    TeardownRequired,
    Invalid,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ReferenceRelease {
    pub base: u64,
    pub releases: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceReleaseLedger<const N: usize> {
    entries: [ReferenceRelease; N],
    len: usize,
}

impl<const N: usize> ReferenceReleaseLedger<N> {
    pub const fn new() -> Self {
        Self {
            entries: [ReferenceRelease {
                base: 0,
                releases: 0,
            }; N],
            len: 0,
        }
    }

    pub fn record(&mut self, base: u64) -> bool {
        if let Some(entry) = self.entries[..self.len]
            .iter_mut()
            .find(|entry| entry.base == base)
        {
            let Some(next) = entry.releases.checked_add(1) else {
                return false;
            };
            entry.releases = next;
            return true;
        }
        if self.len == N {
            return false;
        }
        self.entries[self.len] = ReferenceRelease { base, releases: 1 };
        self.len += 1;
        true
    }

    pub fn as_slice(&self) -> &[ReferenceRelease] {
        &self.entries[..self.len]
    }
}

impl<const N: usize> Default for ReferenceReleaseLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn plan_reference_release(load_count: u16, releases: u32) -> ReferenceReleasePlan {
    if load_count == LOAD_COUNT_PINNED {
        return ReferenceReleasePlan::Pinned;
    }
    if releases == 0 || load_count == 0 || releases > u32::from(load_count) {
        return ReferenceReleasePlan::Invalid;
    }
    if releases == u32::from(load_count) {
        return ReferenceReleasePlan::TeardownRequired;
    }
    ReferenceReleasePlan::DecrementTo(load_count - releases as u16)
}

/// Persistent successful process-attach order, used in reverse for process shutdown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachLedger<const N: usize> {
    entries: [u64; N],
    len: usize,
}

impl<const N: usize> AttachLedger<N> {
    pub const fn new() -> Self {
        Self {
            entries: [0; N],
            len: 0,
        }
    }

    pub fn record(&mut self, base: u64) -> bool {
        if self.as_slice().contains(&base) {
            return true;
        }
        if self.len == N {
            return false;
        }
        self.entries[self.len] = base;
        self.len += 1;
        true
    }

    pub fn remove(&mut self, base: u64) -> bool {
        let Some(index) = self.as_slice().iter().position(|entry| *entry == base) else {
            return false;
        };
        self.entries.copy_within(index + 1..self.len, index);
        self.len -= 1;
        self.entries[self.len] = 0;
        true
    }

    /// Replace one observed corrupt entry without changing order or length.
    pub fn replace_if(&mut self, index: usize, observed: u64, replacement: u64) -> bool {
        if replacement == 0
            || index >= self.len
            || self.entries[index] != observed
            || self.as_slice().contains(&replacement)
        {
            return false;
        }
        self.entries[index] = replacement;
        true
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.entries[..self.len]
    }
}

impl<const N: usize> Default for AttachLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ThreadInitState {
    Reserved,
    Committed,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ThreadInitEntry {
    teb: u64,
    state: ThreadInitState,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ThreadInitError {
    InvalidTeb,
    CapacityExceeded,
    NotReserved,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ThreadReserveOutcome {
    Created,
    AlreadyReserved,
    AlreadyCommitted,
}

/// Fixed-capacity ownership ledger balancing future thread-attach and thread-detach callouts.
pub struct ThreadInitLedger<const N: usize> {
    entries: [Option<ThreadInitEntry>; N],
    len: usize,
}

impl<const N: usize> ThreadInitLedger<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            len: 0,
        }
    }

    pub fn reserve(&mut self, teb: u64) -> Result<ThreadReserveOutcome, ThreadInitError> {
        if teb == 0 {
            return Err(ThreadInitError::InvalidTeb);
        }
        if let Some(entry) = self.entries[..self.len]
            .iter()
            .flatten()
            .find(|entry| entry.teb == teb)
        {
            return Ok(match entry.state {
                ThreadInitState::Reserved => ThreadReserveOutcome::AlreadyReserved,
                ThreadInitState::Committed => ThreadReserveOutcome::AlreadyCommitted,
            });
        }
        if self.len == N {
            return Err(ThreadInitError::CapacityExceeded);
        }
        self.entries[self.len] = Some(ThreadInitEntry {
            teb,
            state: ThreadInitState::Reserved,
        });
        self.len += 1;
        Ok(ThreadReserveOutcome::Created)
    }

    pub fn commit(&mut self, teb: u64) -> Result<(), ThreadInitError> {
        if teb == 0 {
            return Err(ThreadInitError::InvalidTeb);
        }
        let Some(entry) = self.entries[..self.len]
            .iter_mut()
            .flatten()
            .find(|entry| entry.teb == teb)
        else {
            return Err(ThreadInitError::NotReserved);
        };
        entry.state = ThreadInitState::Committed;
        Ok(())
    }

    pub fn cancel(&mut self, teb: u64) -> bool {
        self.remove_if_state(teb, ThreadInitState::Reserved)
            .is_some()
    }

    pub fn take_committed_for_shutdown(&mut self, teb: u64) -> bool {
        self.remove_if_state(teb, ThreadInitState::Committed)
            .is_some()
    }

    fn remove_if_state(&mut self, teb: u64, state: ThreadInitState) -> Option<ThreadInitEntry> {
        let index = self.entries[..self.len]
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.teb == teb && entry.state == state))?;
        let removed = self.entries[index];
        self.entries.copy_within(index + 1..self.len, index);
        self.len -= 1;
        self.entries[self.len] = None;
        removed
    }
}

impl<const N: usize> Default for ThreadInitLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply `LdrAddRefDll` semantics to a loader entry's load count.
pub fn add_reference(load_count: u16, pin: bool) -> u16 {
    if load_count == LOAD_COUNT_PINNED || pin {
        LOAD_COUNT_PINNED
    } else {
        load_count.wrapping_add(1)
    }
}

/// Plan an add-reference update without mutating loader state. Keeping this pure lets the target
/// loader validate an entire import graph before publishing any count changes.
pub fn plan_reference_add(load_count: u16, pin: bool) -> u16 {
    add_reference(load_count, pin)
}

/// Thread callouts may only be disabled for a module without an allocated TLS slot.
pub fn can_disable_thread_callouts(tls_index: u16) -> bool {
    tls_index == 0
}

/// Report whether the current TEB owns the active top-level loader callout transaction.
pub fn is_thread_within_loader_callout(owner_teb: u64, current_teb: u64) -> bool {
    owner_teb != 0 && owner_teb == current_teb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_references_increment_until_pinned() {
        assert_eq!(add_reference(1, false), 2);
        assert_eq!(add_reference(LOAD_COUNT_PINNED, false), LOAD_COUNT_PINNED);
    }

    #[test]
    fn pin_is_permanent() {
        assert_eq!(add_reference(1, true), LOAD_COUNT_PINNED);
        assert_eq!(add_reference(LOAD_COUNT_PINNED, true), LOAD_COUNT_PINNED);
    }

    #[test]
    fn reference_add_plans_are_side_effect_free_and_saturate_at_pinned() {
        assert_eq!(plan_reference_add(1, false), 2);
        assert_eq!(plan_reference_add(0xfffe, false), LOAD_COUNT_PINNED);
        assert_eq!(
            plan_reference_add(LOAD_COUNT_PINNED, false),
            LOAD_COUNT_PINNED
        );
        assert_eq!(plan_reference_add(1, true), LOAD_COUNT_PINNED);
    }

    #[test]
    fn get_dll_handle_ex_selects_reference_behavior() {
        assert_eq!(
            get_dll_handle_action(0, true),
            Some(GetDllHandleAction::AddReference)
        );
        assert_eq!(
            get_dll_handle_action(GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT, true),
            Some(GetDllHandleAction::Unchanged)
        );
        assert_eq!(
            get_dll_handle_action(GET_DLL_HANDLE_EX_PIN, true),
            Some(GetDllHandleAction::Pin)
        );
        assert_eq!(
            get_dll_handle_action(GET_DLL_HANDLE_EX_PIN, false),
            Some(GetDllHandleAction::Pin)
        );
    }

    #[test]
    fn get_dll_handle_ex_rejects_invalid_flags_and_missing_output() {
        assert_eq!(get_dll_handle_action(0, false), None);
        assert_eq!(
            get_dll_handle_action(GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT, false),
            None
        );
        assert_eq!(
            get_dll_handle_action(
                GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT | GET_DLL_HANDLE_EX_PIN,
                true
            ),
            None
        );
        assert_eq!(get_dll_handle_action(4, true), None);
        assert_eq!(get_dll_handle_action(u32::MAX, true), None);
    }

    #[test]
    fn tls_slot_prevents_disabling_thread_callouts() {
        assert!(can_disable_thread_callouts(0));
        assert!(!can_disable_thread_callouts(1));
    }

    #[test]
    fn loader_callout_state_is_teb_specific() {
        assert!(is_thread_within_loader_callout(0x1000, 0x1000));
        assert!(!is_thread_within_loader_callout(0x1000, 0x2000));
        assert!(!is_thread_within_loader_callout(0, 0));
    }

    #[test]
    fn thread_init_ledger_balances_committed_threads_once() {
        let mut ledger = ThreadInitLedger::<2>::new();
        assert_eq!(ledger.reserve(0x1000), Ok(ThreadReserveOutcome::Created));
        assert_eq!(ledger.reserve(0x1000), Ok(ThreadReserveOutcome::AlreadyReserved));
        assert!(!ledger.take_committed_for_shutdown(0x1000));

        assert_eq!(ledger.commit(0x1000), Ok(()));
        assert_eq!(ledger.commit(0x1000), Ok(()));
        assert_eq!(ledger.reserve(0x1000), Ok(ThreadReserveOutcome::AlreadyCommitted));
        assert!(ledger.take_committed_for_shutdown(0x1000));
        assert!(!ledger.take_committed_for_shutdown(0x1000));
    }

    #[test]
    fn thread_init_ledger_handles_cancel_capacity_and_invalid_transitions() {
        let mut ledger = ThreadInitLedger::<1>::new();
        assert_eq!(ledger.reserve(0), Err(ThreadInitError::InvalidTeb));
        assert_eq!(ledger.commit(0), Err(ThreadInitError::InvalidTeb));
        assert_eq!(ledger.commit(1), Err(ThreadInitError::NotReserved));
        assert_eq!(ledger.reserve(1), Ok(ThreadReserveOutcome::Created));
        assert_eq!(ledger.reserve(2), Err(ThreadInitError::CapacityExceeded));
        assert!(ledger.cancel(1));
        assert!(!ledger.cancel(1));
        assert_eq!(ledger.reserve(2), Ok(ThreadReserveOutcome::Created));
        assert_eq!(ledger.commit(2), Ok(()));
        assert!(!ledger.cancel(2));
        assert!(ledger.take_committed_for_shutdown(2));
    }

    #[test]
    fn reference_release_plans_never_publish_a_zero_count() {
        assert_eq!(
            plan_reference_release(LOAD_COUNT_PINNED, 99),
            ReferenceReleasePlan::Pinned
        );
        assert_eq!(
            plan_reference_release(3, 1),
            ReferenceReleasePlan::DecrementTo(2)
        );
        assert_eq!(
            plan_reference_release(3, 2),
            ReferenceReleasePlan::DecrementTo(1)
        );
        assert_eq!(
            plan_reference_release(1, 1),
            ReferenceReleasePlan::TeardownRequired
        );
        assert_eq!(
            plan_reference_release(2, 2),
            ReferenceReleasePlan::TeardownRequired
        );
        assert_eq!(plan_reference_release(0, 1), ReferenceReleasePlan::Invalid);
        assert_eq!(plan_reference_release(1, 0), ReferenceReleasePlan::Invalid);
        assert_eq!(plan_reference_release(1, 2), ReferenceReleasePlan::Invalid);
    }

    #[test]
    fn release_ledger_preserves_import_edge_multiplicity() {
        let mut ledger = ReferenceReleaseLedger::<3>::new();
        assert!(ledger.record(10));
        assert!(ledger.record(20));
        assert!(ledger.record(10));
        assert_eq!(
            ledger.as_slice(),
            &[
                ReferenceRelease {
                    base: 10,
                    releases: 2
                },
                ReferenceRelease {
                    base: 20,
                    releases: 1
                }
            ]
        );
        assert!(ledger.record(30));
        assert!(!ledger.record(40));
    }

    #[test]
    fn attach_ledger_preserves_success_order_and_deduplicates() {
        let mut ledger = AttachLedger::<3>::new();
        assert!(ledger.record(10));
        assert!(ledger.record(20));
        assert!(ledger.record(10));
        assert_eq!(ledger.as_slice(), &[10, 20]);
        assert!(ledger.record(30));
        assert!(!ledger.record(40));
    }

    #[test]
    fn attach_ledger_removes_rolled_back_modules() {
        let mut ledger = AttachLedger::<4>::new();
        ledger.record(10);
        ledger.record(20);
        ledger.record(30);
        assert!(ledger.remove(20));
        assert_eq!(ledger.as_slice(), &[10, 30]);
        assert!(!ledger.remove(40));
    }

    #[test]
    fn attach_ledger_repairs_only_the_observed_unique_slot() {
        let mut ledger = AttachLedger::<4>::new();
        ledger.record(10);
        ledger.record(20);
        ledger.record(30);
        assert!(ledger.replace_if(1, 20, 40));
        assert_eq!(ledger.as_slice(), &[10, 40, 30]);
        assert!(!ledger.replace_if(1, 20, 50));
        assert!(!ledger.replace_if(1, 40, 30));
        assert!(!ledger.replace_if(3, 0, 50));
    }
}
