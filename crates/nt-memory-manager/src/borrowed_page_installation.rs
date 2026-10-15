//! A view owns a copied cap; its canonical source frame is never part of view cleanup.

use crate::private_page_installation::{InstallationCap, InstallationEffect};

pub trait BorrowedPageInstallationIo<D> {
    fn reserve(&mut self) -> Result<InstallationCap, u32>;
    /// Refusal must leave the destination empty.
    fn copy(&mut self, source: InstallationCap, destination: InstallationCap)
        -> InstallationEffect;
    fn map(&mut self, descriptor: D, destination: InstallationCap) -> InstallationEffect;
    /// Atomically transfer only the copied cap into a borrowed resident record.
    fn publish(&mut self, descriptor: D, destination: InstallationCap) -> InstallationEffect;
    fn unmap(&mut self, destination: InstallationCap) -> InstallationEffect;
    fn delete(&mut self, destination: InstallationCap) -> InstallationEffect;
    fn recycle(&mut self, destination: InstallationCap) -> InstallationEffect;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BorrowedPageInstallOutcome {
    Published,
    Failed(u32),
    Retained(u32),
    Quarantined(u32),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Reserve,
    Copy,
    Map,
    Publish,
    Unmap(u32),
    Delete(u32),
    Recycle(u32),
    Complete,
    Failed(u32),
    Quarantined(u32),
}

pub struct BorrowedPageInstallation<D> {
    descriptor: D,
    source: InstallationCap,
    copied: Option<InstallationCap>,
    invalid_destination: Option<InstallationCap>,
    phase: Phase,
}

impl<D: Copy + Eq> BorrowedPageInstallation<D> {
    pub fn new(descriptor: D, source: InstallationCap) -> Option<Self> {
        (source.cap != 0).then_some(Self {
            descriptor,
            source,
            copied: None,
            invalid_destination: None,
            phase: Phase::Reserve,
        })
    }
    pub fn descriptor(&self) -> D {
        self.descriptor
    }
    pub fn source(&self) -> InstallationCap {
        self.source
    }
    /// Retain the backend's invalid return for diagnosis, without acquiring source ownership.
    pub fn invalid_destination(&self) -> Option<InstallationCap> {
        self.invalid_destination
    }
    pub fn owns_cap(&self, cap: u64) -> bool {
        cap != 0 && self.copied.is_some_and(|copy| copy.cap == cap)
    }
    pub fn abort_unentered(&mut self, descriptor: D) -> bool {
        if descriptor != self.descriptor || self.phase != Phase::Reserve || self.copied.is_some() {
            return false;
        }
        self.phase = Phase::Failed(0xc000_000d);
        true
    }

    pub fn advance(
        &mut self,
        io: &mut impl BorrowedPageInstallationIo<D>,
    ) -> BorrowedPageInstallOutcome {
        loop {
            match self.phase {
                Phase::Reserve => match io.reserve() {
                    Ok(copy) if copy.cap != 0 && copy != self.source => {
                        self.copied = Some(copy);
                        self.phase = Phase::Copy;
                    }
                    Ok(copy) => {
                        self.invalid_destination = Some(copy);
                        self.phase = Phase::Quarantined(0xc000_000d);
                    }
                    Err(status) => return BorrowedPageInstallOutcome::Retained(status),
                },
                Phase::Copy => match io.copy(self.source, self.copied.unwrap()) {
                    InstallationEffect::Acknowledged => self.phase = Phase::Map,
                    InstallationEffect::Refused(status) => self.phase = Phase::Recycle(status),
                    InstallationEffect::Uncertain(status) => {
                        self.phase = Phase::Quarantined(status)
                    }
                },
                Phase::Map => match io.map(self.descriptor, self.copied.unwrap()) {
                    InstallationEffect::Acknowledged => self.phase = Phase::Publish,
                    InstallationEffect::Refused(status) => self.phase = Phase::Delete(status),
                    InstallationEffect::Uncertain(status) => {
                        self.phase = Phase::Quarantined(status)
                    }
                },
                Phase::Publish => match io.publish(self.descriptor, self.copied.unwrap()) {
                    InstallationEffect::Acknowledged => {
                        self.copied = None;
                        self.phase = Phase::Complete;
                    }
                    InstallationEffect::Refused(status) => self.phase = Phase::Unmap(status),
                    InstallationEffect::Uncertain(status) => {
                        self.phase = Phase::Quarantined(status)
                    }
                },
                Phase::Unmap(failure) => match io.unmap(self.copied.unwrap()) {
                    InstallationEffect::Acknowledged => self.phase = Phase::Delete(failure),
                    InstallationEffect::Refused(status) => {
                        return BorrowedPageInstallOutcome::Retained(status)
                    }
                    InstallationEffect::Uncertain(status) => {
                        self.phase = Phase::Quarantined(status)
                    }
                },
                Phase::Delete(failure) => match io.delete(self.copied.unwrap()) {
                    InstallationEffect::Acknowledged => self.phase = Phase::Recycle(failure),
                    InstallationEffect::Refused(status) => {
                        return BorrowedPageInstallOutcome::Retained(status)
                    }
                    InstallationEffect::Uncertain(status) => {
                        self.phase = Phase::Quarantined(status)
                    }
                },
                Phase::Recycle(failure) => match io.recycle(self.copied.unwrap()) {
                    InstallationEffect::Acknowledged => {
                        self.copied = None;
                        self.phase = Phase::Failed(failure);
                    }
                    InstallationEffect::Refused(status) => {
                        return BorrowedPageInstallOutcome::Retained(status)
                    }
                    InstallationEffect::Uncertain(status) => {
                        self.phase = Phase::Quarantined(status)
                    }
                },
                Phase::Complete => return BorrowedPageInstallOutcome::Published,
                Phase::Failed(status) => return BorrowedPageInstallOutcome::Failed(status),
                Phase::Quarantined(status) => {
                    return BorrowedPageInstallOutcome::Quarantined(status)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    struct Io {
        events: Vec<(&'static str, u64)>,
        refuse: Option<&'static str>,
        uncertain: Option<&'static str>,
        cleanup_refuse: Option<&'static str>,
        reserved: u64,
    }
    impl Io {
        fn effect(&mut self, name: &'static str, cap: u64) -> InstallationEffect {
            self.events.push((name, cap));
            if self.uncertain == Some(name) {
                InstallationEffect::Uncertain(2)
            } else if self.refuse == Some(name) || self.cleanup_refuse == Some(name) {
                InstallationEffect::Refused(1)
            } else {
                InstallationEffect::Acknowledged
            }
        }
    }
    impl BorrowedPageInstallationIo<u64> for Io {
        fn reserve(&mut self) -> Result<InstallationCap, u32> {
            self.events.push(("reserve", self.reserved));
            Ok(InstallationCap { cap: self.reserved })
        }
        fn copy(
            &mut self,
            source: InstallationCap,
            destination: InstallationCap,
        ) -> InstallationEffect {
            assert_eq!(source.cap, 7);
            self.effect("copy", destination.cap)
        }
        fn map(&mut self, _: u64, cap: InstallationCap) -> InstallationEffect {
            self.effect("map", cap.cap)
        }
        fn publish(&mut self, _: u64, cap: InstallationCap) -> InstallationEffect {
            self.effect("publish", cap.cap)
        }
        fn unmap(&mut self, cap: InstallationCap) -> InstallationEffect {
            self.effect("unmap", cap.cap)
        }
        fn delete(&mut self, cap: InstallationCap) -> InstallationEffect {
            self.effect("delete", cap.cap)
        }
        fn recycle(&mut self, cap: InstallationCap) -> InstallationEffect {
            self.effect("recycle", cap.cap)
        }
    }
    fn backend() -> Io {
        Io {
            events: Vec::new(),
            refuse: None,
            uncertain: None,
            cleanup_refuse: None,
            reserved: 8,
        }
    }

    #[test]
    fn copied_view_cap_transfers_without_source_ownership() {
        let mut owner = BorrowedPageInstallation::new(3, InstallationCap { cap: 7 }).unwrap();
        let mut io = backend();
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Published
        );
        assert!(!owner.owns_cap(7));
        assert!(!owner.owns_cap(8));
        assert_eq!(
            io.events,
            [("reserve", 8), ("copy", 8), ("map", 8), ("publish", 8)]
        );
    }
    #[test]
    fn registration_refusal_and_cleanup_refusal_keep_exact_copied_owner() {
        let mut owner = BorrowedPageInstallation::new(3, InstallationCap { cap: 7 }).unwrap();
        let mut io = backend();
        io.refuse = Some("publish");
        // First cleanup succeeds: source is neither unmapped nor deleted.
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Failed(1)
        );
        assert!(io.events.iter().all(|(_, cap)| *cap == 8));
        assert_eq!(
            &io.events[4..],
            [("unmap", 8), ("delete", 8), ("recycle", 8)]
        );

        let mut owner = BorrowedPageInstallation::new(3, InstallationCap { cap: 7 }).unwrap();
        let mut io = backend();
        io.refuse = Some("map");
        io.uncertain = Some("delete");
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Quarantined(2)
        );
        assert!(owner.owns_cap(8));
        let events = io.events.clone();
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Quarantined(2)
        );
        assert_eq!(io.events, events);
    }
    #[test]
    fn uncertain_map_never_replays_or_recycles_source_or_copy() {
        let mut owner = BorrowedPageInstallation::new(3, InstallationCap { cap: 7 }).unwrap();
        let mut io = backend();
        io.uncertain = Some("map");
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Quarantined(2)
        );
        assert!(owner.owns_cap(8));
        let events = io.events.clone();
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Quarantined(2)
        );
        assert_eq!(io.events, events);
        assert!(!io
            .events
            .iter()
            .any(|(name, _)| *name == "unmap" || *name == "delete" || *name == "recycle"));
    }

    #[test]
    fn cleanup_refusal_retries_only_unacknowledged_prefix() {
        for step in ["unmap", "delete", "recycle"] {
            let mut owner = BorrowedPageInstallation::new(3, InstallationCap { cap: 7 }).unwrap();
            let mut io = backend();
            io.refuse = Some("publish");
            io.cleanup_refuse = Some(step);
            assert_eq!(
                owner.advance(&mut io),
                BorrowedPageInstallOutcome::Retained(1)
            );
            assert!(owner.owns_cap(8));
            assert!(!owner.owns_cap(7));
            io.cleanup_refuse = None;
            assert_eq!(
                owner.advance(&mut io),
                BorrowedPageInstallOutcome::Failed(1)
            );
            for name in [
                "reserve", "copy", "map", "publish", "unmap", "delete", "recycle",
            ] {
                assert_eq!(
                    io.events.iter().filter(|(event, _)| *event == name).count(),
                    if name == step { 2 } else { 1 },
                    "{step}: {name}"
                );
            }
            assert!(io.events.iter().all(|(_, cap)| *cap == 8));
        }
    }

    #[test]
    fn invalid_same_source_destination_is_retained_but_never_owned_or_deleted() {
        let mut owner = BorrowedPageInstallation::new(3, InstallationCap { cap: 7 }).unwrap();
        let mut io = backend();
        io.reserved = 7;
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Quarantined(0xc000_000d)
        );
        assert_eq!(
            owner.invalid_destination(),
            Some(InstallationCap { cap: 7 })
        );
        assert!(!owner.owns_cap(7));
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Quarantined(0xc000_000d)
        );
        assert_eq!(io.events, [("reserve", 7)]);
    }

    #[test]
    fn unentered_view_abort_has_no_capability_effects() {
        let mut owner = BorrowedPageInstallation::new(3, InstallationCap { cap: 7 }).unwrap();
        assert!(!owner.abort_unentered(4));
        assert!(owner.abort_unentered(3));
        let mut io = backend();
        assert_eq!(
            owner.advance(&mut io),
            BorrowedPageInstallOutcome::Failed(0xc000_000d)
        );
        assert!(io.events.is_empty());
        let mut entered = BorrowedPageInstallation::new(3, InstallationCap { cap: 7 }).unwrap();
        io.uncertain = Some("copy");
        entered.advance(&mut io);
        assert!(!entered.abort_unentered(3));
        assert!(entered.owns_cap(8));
    }
}
