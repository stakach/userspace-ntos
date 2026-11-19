use super::*;
use alloc::vec::Vec;

const RW: u32 = 0x04;
const RO: u32 = 0x02;
const FAILED: u32 = 0xC000_0017;
const REFUSED: u32 = 0xC000_0022;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Target {
    process: u64,
    generation: u64,
}

const TARGET: Target = Target { process: 7, generation: 3 };

#[derive(Default)]
struct Io {
    calls: Vec<(&'static str, u64, u32, u32)>,
    refuse: Vec<u64>,
    uncertain: Vec<u64>,
    live: Option<Target>,
}

impl Io {
    fn effect(&mut self, descriptor: &Target, page: u64) -> InstallationEffect {
        if self.live.is_some_and(|live| live != *descriptor) {
            return InstallationEffect::Refused(INVALID);
        }
        if let Some(index) = self.refuse.iter().position(|p| *p == page) {
            self.refuse.remove(index);
            return InstallationEffect::Refused(REFUSED);
        }
        if self.uncertain.contains(&page) {
            return InstallationEffect::Uncertain(REFUSED);
        }
        InstallationEffect::Acknowledged
    }
}

impl PrivateAllocationPrefixIo<Target> for Io {
    fn unmap(&mut self, descriptor: &Target, page: u64) -> InstallationEffect {
        self.calls.push(("unmap", page, 0, 0));
        self.effect(descriptor, page)
    }
    fn reprotect(&mut self, descriptor: &Target, page: u64, current: u32, restore: u32)
        -> InstallationEffect {
        self.calls.push(("reprotect", page, current, restore));
        self.effect(descriptor, page)
    }
}

fn mapped_prefix(pages: &[u64]) -> PrivateAllocationPrefix<Target> {
    let mut prefix = PrivateAllocationPrefix::new();
    prefix.begin(TARGET).unwrap();
    for page in pages {
        prefix.apply(*page, PrefixEffect::Mapped, || Ok(())).unwrap();
    }
    prefix
}

#[test]
fn refused_unmap_retains_exact_prefix_and_failure() {
    let mut prefix = mapped_prefix(&[0x1000]);
    // The second page's installation fails; its own owner keeps that page.
    assert_eq!(prefix.apply(0x2000, PrefixEffect::Mapped, || Err(FAILED)), Err(FAILED));
    let mut io = Io { refuse: alloc::vec![0x1000], ..Io::default() };
    let outcome = prefix.fail(&mut io, FAILED);
    assert_eq!(
        outcome,
        PrefixRollbackOutcome::CleanupPending { status: FAILED, rollback_status: REFUSED }
    );
    assert!(!outcome.is_settled());
    assert!(!prefix.is_idle());
    assert_eq!(prefix.descriptor(), Some(TARGET));
    assert!(prefix.covers(0x1000));
    assert!(!prefix.covers(0x2000));
    assert_eq!(prefix.retained_pages(), 1);
    // A retained owner fences a new allocation and cannot be published.
    assert_eq!(prefix.begin(TARGET), Err(STATUS_INSUFFICIENT_RESOURCES));
    assert_eq!(prefix.commit(), Err(INVALID));
    assert_eq!(prefix.advance(&mut io), PrefixRollbackOutcome::RolledBack(FAILED));
    assert!(prefix.is_idle());
    assert_eq!(io.calls, [("unmap", 0x1000, 0, 0), ("unmap", 0x1000, 0, 0)]);
}

#[test]
fn refused_protection_restore_stays_pending_without_claiming_old_protection() {
    let mut prefix = PrivateAllocationPrefix::new();
    prefix.begin(TARGET).unwrap();
    let reprotect = PrefixEffect::Reprotected { old: RW, new: RO };
    prefix.apply(0x5000, reprotect, || Ok(())).unwrap();
    prefix.apply(0x6000, reprotect, || Ok(())).unwrap();
    let mut io = Io { refuse: alloc::vec![0x5000], ..Io::default() };
    assert_eq!(
        prefix.fail(&mut io, FAILED),
        PrefixRollbackOutcome::CleanupPending { status: FAILED, rollback_status: REFUSED }
    );
    // 0x6000 was restored and is no longer owned; 0x5000 still carries the new protection.
    assert!(!prefix.covers(0x6000));
    assert!(prefix.covers(0x5000));
    assert_eq!(prefix.advance(&mut io), PrefixRollbackOutcome::RolledBack(FAILED));
    assert_eq!(
        io.calls,
        [
            ("reprotect", 0x6000, RO, RW),
            ("reprotect", 0x5000, RO, RW),
            ("reprotect", 0x5000, RO, RW),
        ]
    );
}

#[test]
fn acknowledged_rollback_reverses_mixed_prefix_last_first() {
    let mut prefix = PrivateAllocationPrefix::new();
    prefix.begin(TARGET).unwrap();
    prefix.apply(0x1000, PrefixEffect::Reprotected { old: RW, new: RO }, || Ok(())).unwrap();
    prefix.apply(0x3000, PrefixEffect::Mapped, || Ok(())).unwrap();
    prefix.apply(0x4000, PrefixEffect::Mapped, || Ok(())).unwrap();
    let mut io = Io::default();
    assert_eq!(prefix.fail(&mut io, FAILED), PrefixRollbackOutcome::RolledBack(FAILED));
    assert!(prefix.is_idle());
    assert_eq!(
        io.calls,
        [("unmap", 0x4000, 0, 0), ("unmap", 0x3000, 0, 0), ("reprotect", 0x1000, RO, RW)]
    );
}

#[test]
fn repeated_refusal_never_skips_or_replays_acknowledged_pages() {
    let mut prefix = mapped_prefix(&[0x1000, 0x2000, 0x3000]);
    let mut io = Io { refuse: alloc::vec![0x2000, 0x2000], ..Io::default() };
    assert!(!prefix.fail(&mut io, FAILED).is_settled());
    assert!(!prefix.advance(&mut io).is_settled());
    assert_eq!(prefix.retained_pages(), 2);
    assert_eq!(prefix.advance(&mut io), PrefixRollbackOutcome::RolledBack(FAILED));
    assert_eq!(
        io.calls.iter().map(|call| call.1).collect::<Vec<_>>(),
        [0x3000, 0x2000, 0x2000, 0x2000, 0x1000]
    );
}

#[test]
fn uncertain_reversal_quarantines_without_replay() {
    let mut prefix = mapped_prefix(&[0x1000, 0x2000]);
    let mut io = Io { uncertain: alloc::vec![0x2000], ..Io::default() };
    let quarantined =
        PrefixRollbackOutcome::Quarantined { status: FAILED, rollback_status: REFUSED };
    assert_eq!(prefix.fail(&mut io, FAILED), quarantined);
    assert!(prefix.is_quarantined());
    assert_eq!(prefix.advance(&mut io), quarantined);
    assert_eq!(io.calls, [("unmap", 0x2000, 0, 0)]);
    assert_eq!(prefix.retained_pages(), 2);
    assert_eq!(prefix.begin(TARGET), Err(STATUS_INSUFFICIENT_RESOURCES));
}

#[test]
fn stale_process_generation_refuses_and_retains() {
    let mut prefix = mapped_prefix(&[0x1000]);
    let mut io = Io {
        live: Some(Target { generation: 4, ..TARGET }),
        ..Io::default()
    };
    assert_eq!(
        prefix.fail(&mut io, FAILED),
        PrefixRollbackOutcome::CleanupPending { status: FAILED, rollback_status: INVALID }
    );
    assert!(prefix.covers(0x1000));
}

#[test]
fn unrecordable_effect_is_never_invoked() {
    let mut prefix = PrivateAllocationPrefix::new();
    prefix.begin(TARGET).unwrap();
    for run in 0..PREFIX_RUN_CAPACITY as u64 {
        // Alternate gaps so each page is its own run.
        prefix.apply(0x1000 + run * 0x2000, PrefixEffect::Mapped, || Ok(())).unwrap();
    }
    let mut invoked = false;
    let page = 0x1000 + PREFIX_RUN_CAPACITY as u64 * 0x2000;
    assert_eq!(
        prefix.apply(page, PrefixEffect::Mapped, || {
            invoked = true;
            Ok(())
        }),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert!(!invoked);
    // Contiguous pages still extend the last run.
    prefix.apply(page - 0x1000, PrefixEffect::Mapped, || Ok(())).unwrap();
    assert_eq!(prefix.retained_pages(), PREFIX_RUN_CAPACITY as u64 + 1);
    assert_eq!(prefix.apply(0x1000, PrefixEffect::Mapped, || Ok(())), Err(INVALID));
}

#[test]
fn successful_allocation_transfers_prefix_to_publication() {
    let mut prefix = mapped_prefix(&[0x1000]);
    prefix.commit().unwrap();
    assert!(prefix.is_idle());
    prefix.begin(TARGET).unwrap();
}
