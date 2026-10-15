//! Exclusive unmapped image backing, distinct from the copies owned by mapped views.

use crate::private_page_installation::{InstallationCap, InstallationEffect};

pub trait ImageSourcePageIo<D> {
    /// Acquire an exclusively owned, zeroed, unmapped frame. Failure retains partial backend work.
    fn acquire(&mut self, descriptor: D) -> Result<InstallationCap, u32>;
    /// Fill exact canonical bytes and retire every scratch alias before acknowledging success.
    /// Any possible write or outstanding scratch alias on failure must return Uncertain.
    fn initialize(&mut self, descriptor: D, frame: InstallationCap) -> InstallationEffect;
    /// Retire all aliases before checked frame-pool transfer. Refusal retains the original owner.
    fn release(&mut self, descriptor: D, frame: InstallationCap) -> InstallationEffect;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageSourcePageOutcome {
    Ready(InstallationCap),
    Retired,
    Failed(u32),
    Retained(u32),
    Quarantined(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Acquire,
    Initialize,
    Ready,
    Retiring(Option<u32>),
    Retired,
    Quarantined(u32),
}

/// Keep this non-cloneable owner in the exact area/RVA cache row before invoking the backend.
pub struct ImageSourcePage<D> {
    descriptor: D,
    frame: Option<InstallationCap>,
    phase: Phase,
}

impl<D: Copy + Eq> ImageSourcePage<D> {
    pub const fn new(descriptor: D) -> Self {
        Self {
            descriptor,
            frame: None,
            phase: Phase::Acquire,
        }
    }

    pub fn descriptor(&self) -> D {
        self.descriptor
    }

    pub fn ready_frame(&self) -> Option<InstallationCap> {
        (self.phase == Phase::Ready).then_some(self.frame).flatten()
    }

    pub fn is_retiring(&self) -> bool {
        matches!(self.phase, Phase::Retiring(_))
    }

    pub fn owns_cap(&self, cap: u64) -> bool {
        cap != 0 && self.frame.is_some_and(|frame| frame.cap == cap)
    }

    /// The native caller must also prove that acquisition retained no partial backend resource.
    pub fn abort_unentered(&mut self, descriptor: D) -> bool {
        if descriptor != self.descriptor || self.phase != Phase::Acquire || self.frame.is_some() {
            return false;
        }
        self.phase = Phase::Retired;
        true
    }

    /// Caller must first prove that all view references and unpublished mappings have drained.
    pub fn begin_retirement(&mut self, descriptor: D) -> bool {
        if descriptor != self.descriptor || self.phase != Phase::Ready {
            return false;
        }
        self.phase = Phase::Retiring(None);
        true
    }

    pub fn advance(&mut self, io: &mut impl ImageSourcePageIo<D>) -> ImageSourcePageOutcome {
        loop {
            match self.phase {
                Phase::Acquire => match io.acquire(self.descriptor) {
                    Ok(frame) if frame.cap != 0 => {
                        self.frame = Some(frame);
                        self.phase = Phase::Initialize;
                    }
                    Ok(_) => {
                        self.phase = Phase::Quarantined(0xc000_000d);
                    }
                    Err(status) => return ImageSourcePageOutcome::Retained(status),
                },
                Phase::Initialize => match io.initialize(self.descriptor, self.frame.unwrap()) {
                    InstallationEffect::Acknowledged => self.phase = Phase::Ready,
                    InstallationEffect::Refused(status) => {
                        self.phase = Phase::Retiring(Some(status))
                    }
                    InstallationEffect::Uncertain(status) => {
                        self.phase = Phase::Quarantined(status)
                    }
                },
                Phase::Ready => return ImageSourcePageOutcome::Ready(self.frame.unwrap()),
                Phase::Retiring(failure) => {
                    match io.release(self.descriptor, self.frame.unwrap()) {
                        InstallationEffect::Acknowledged => {
                            self.frame = None;
                            self.phase = Phase::Retired;
                            return failure.map_or(
                                ImageSourcePageOutcome::Retired,
                                ImageSourcePageOutcome::Failed,
                            );
                        }
                        InstallationEffect::Refused(status) => {
                            return ImageSourcePageOutcome::Retained(status)
                        }
                        InstallationEffect::Uncertain(status) => {
                            self.phase = Phase::Quarantined(status)
                        }
                    }
                }
                Phase::Retired => return ImageSourcePageOutcome::Retired,
                Phase::Quarantined(status) => return ImageSourcePageOutcome::Quarantined(status),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    struct Io {
        events: Vec<&'static str>,
        initialize: InstallationEffect,
        release: InstallationEffect,
    }
    impl ImageSourcePageIo<(u64, u32)> for Io {
        fn acquire(&mut self, _: (u64, u32)) -> Result<InstallationCap, u32> {
            self.events.push("acquire");
            Ok(InstallationCap { cap: 7 })
        }
        fn initialize(&mut self, _: (u64, u32), _: InstallationCap) -> InstallationEffect {
            self.events.push("initialize");
            self.initialize
        }
        fn release(&mut self, _: (u64, u32), _: InstallationCap) -> InstallationEffect {
            self.events.push("release");
            self.release
        }
    }
    fn io() -> Io {
        Io {
            events: Vec::new(),
            initialize: InstallationEffect::Acknowledged,
            release: InstallationEffect::Acknowledged,
        }
    }

    #[test]
    fn canonical_source_is_ready_only_after_fill_and_retirement_is_exact() {
        let mut owner = ImageSourcePage::new((9, 0x2000));
        let mut io = io();
        assert_eq!(owner.ready_frame(), None);
        assert_eq!(
            owner.advance(&mut io),
            ImageSourcePageOutcome::Ready(InstallationCap { cap: 7 })
        );
        assert_eq!(io.events, ["acquire", "initialize"]);
        assert!(!owner.begin_retirement((10, 0x2000)));
        assert!(owner.owns_cap(7));
        assert!(owner.begin_retirement((9, 0x2000)));
        io.release = InstallationEffect::Refused(1);
        assert_eq!(owner.advance(&mut io), ImageSourcePageOutcome::Retained(1));
        assert!(owner.owns_cap(7));
        assert_eq!(owner.ready_frame(), None);
        io.release = InstallationEffect::Acknowledged;
        assert_eq!(owner.advance(&mut io), ImageSourcePageOutcome::Retired);
        assert!(!owner.owns_cap(7));
        assert!(!owner.is_retiring());
    }

    #[test]
    fn refused_fill_cleans_only_owned_unmapped_source() {
        let mut owner = ImageSourcePage::new((9, 0));
        let mut io = io();
        io.initialize = InstallationEffect::Refused(2);
        io.release = InstallationEffect::Refused(3);
        assert_eq!(owner.advance(&mut io), ImageSourcePageOutcome::Retained(3));
        assert!(owner.owns_cap(7));
        assert!(owner.is_retiring());
        io.release = InstallationEffect::Acknowledged;
        assert_eq!(owner.advance(&mut io), ImageSourcePageOutcome::Failed(2));
        assert_eq!(io.events, ["acquire", "initialize", "release", "release"]);
    }

    #[test]
    fn uncertain_fill_or_recycle_never_replays_or_reuses_backing() {
        for uncertain_fill in [true, false] {
            let mut owner = ImageSourcePage::new((9, 0));
            let mut io = io();
            if uncertain_fill {
                io.initialize = InstallationEffect::Uncertain(4);
            } else {
                io.initialize = InstallationEffect::Refused(2);
                io.release = InstallationEffect::Uncertain(4);
            }
            assert_eq!(
                owner.advance(&mut io),
                ImageSourcePageOutcome::Quarantined(4)
            );
            let events = io.events.clone();
            assert_eq!(
                owner.advance(&mut io),
                ImageSourcePageOutcome::Quarantined(4)
            );
            assert_eq!(io.events, events);
            assert!(owner.owns_cap(7));
            assert!(!owner.begin_retirement((9, 0)));
            assert!(!owner.is_retiring());
        }
    }

    #[test]
    fn unentered_abort_requires_exact_descriptor_and_no_acquired_frame() {
        let mut owner = ImageSourcePage::new((9, 0));
        assert!(!owner.abort_unentered((10, 0)));
        assert!(owner.abort_unentered((9, 0)));
        let mut io = io();
        assert_eq!(owner.advance(&mut io), ImageSourcePageOutcome::Retired);
        assert!(io.events.is_empty());
        let mut entered = ImageSourcePage::new((9, 0));
        entered.advance(&mut io);
        assert!(!entered.abort_unentered((9, 0)));
        assert!(entered.owns_cap(7));
    }
}
