//! Admission decisions at the boot-volume to native-storage cutover.
//!
//! The caller supplies the current mount and publication observations. This module retains no
//! owner or phase: the mount route, PnP transactions, and relation publication remain authoritative.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutoverPhase {
    Boot,
    Draining,
    NativeUnpublished,
    NativePublished,
    Unavailable,
}

impl CutoverPhase {
    /// Native mount admission requires the route publication for this exact mount generation.
    pub fn for_native_mount<M: Eq>(mount: M, published_mount: Option<M>) -> Self {
        if published_mount.is_some_and(|published| published == mount) {
            Self::NativePublished
        } else {
            Self::NativeUnpublished
        }
    }

    /// Only the exact controller grant may create a new lifecycle while the mount drains.
    pub const fn admit_unentered_start(self, exact_boot_controller: bool) -> bool {
        match self {
            Self::Boot | Self::NativePublished | Self::Unavailable => true,
            Self::Draining => exact_boot_controller,
            Self::NativeUnpublished => false,
        }
    }

    /// A video CREATE can write SYSTEM, so it needs boot admission or a published native route.
    pub const fn admit_video_create(self) -> bool {
        matches!(self, Self::Boot | Self::NativePublished)
    }
}

/// A new drain must wait for every entered FILTER/START and synchronous video CREATE.
pub const fn admit_native_drain(entered_lifecycle: bool, entered_video_create: bool) -> bool {
    !entered_lifecycle && !entered_video_create
}

/// A deferred callback may act only on the registration generation it retained at START.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferredVideoOwner<I> {
    identity: I,
}

impl<I: Copy + Eq> DeferredVideoOwner<I> {
    pub const fn new(identity: I) -> Self { Self { identity } }

    pub fn matches_current(self, current: Option<I>) -> bool {
        current == Some(self.identity)
    }

    pub const fn identity(self) -> I { self.identity }
}

#[cfg(test)]
mod tests {
    use super::{admit_native_drain, CutoverPhase, DeferredVideoOwner};

    #[test]
    fn drain_waits_for_entered_owners() {
        assert!(admit_native_drain(false, false));
        assert!(!admit_native_drain(true, false));
        assert!(!admit_native_drain(false, true));
        assert!(!admit_native_drain(true, true));
    }

    #[test]
    fn draining_admits_only_the_exact_controller_grant() {
        assert!(!CutoverPhase::Draining.admit_unentered_start(false));
        assert!(CutoverPhase::Draining.admit_unentered_start(true));
        assert!(!CutoverPhase::NativeUnpublished.admit_unentered_start(false));
        assert!(!CutoverPhase::NativeUnpublished.admit_unentered_start(true));
        assert!(CutoverPhase::Unavailable.admit_unentered_start(false));
        assert!(CutoverPhase::Boot.admit_unentered_start(false));
        assert!(CutoverPhase::NativePublished.admit_unentered_start(false));
    }

    #[test]
    fn video_create_requires_a_writable_published_route() {
        assert!(CutoverPhase::Boot.admit_video_create());
        assert!(!CutoverPhase::Draining.admit_video_create());
        assert!(!CutoverPhase::NativeUnpublished.admit_video_create());
        assert!(!CutoverPhase::Unavailable.admit_video_create());
        assert!(CutoverPhase::NativePublished.admit_video_create());
    }

    #[test]
    fn stale_or_other_mount_publication_cannot_admit_video_create() {
        assert!(!CutoverPhase::for_native_mount(29u64, None).admit_video_create());
        assert!(!CutoverPhase::for_native_mount(29u64, Some(28)).admit_video_create());
        assert!(CutoverPhase::for_native_mount(29u64, Some(29)).admit_video_create());
    }

    #[test]
    fn deferred_video_owner_rejects_reused_device_number_or_generation() {
        let owner = DeferredVideoOwner::new((18u64, 7u64, 41u64));
        assert!(owner.matches_current(Some((18, 7, 41))));
        assert!(!owner.matches_current(Some((18, 7, 42))));
        assert!(!owner.matches_current(Some((18, 8, 41))));
        assert!(!owner.matches_current(None));
    }
}
