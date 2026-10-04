use super::*;
use alloc::vec::Vec;

const FAIL: u32 = 0xc000009a;
const FRAME: InstallationCap = InstallationCap { cap: 10 };
const ALIAS: InstallationCap = InstallationCap { cap: 11 };

#[derive(Default)]
struct Io {
    calls: Vec<&'static str>,
    refuse: Option<&'static str>,
    uncertain: Option<&'static str>,
    publication: Option<PrivatePagePublication<u64>>,
}
impl Io {
    fn effect(&mut self, name: &'static str) -> InstallationEffect {
        self.calls.push(name);
        if self.uncertain == Some(name) {
            self.uncertain = None;
            return InstallationEffect::Uncertain(FAIL);
        }
        if self.refuse == Some(name) {
            self.refuse = None;
            return InstallationEffect::Refused(FAIL);
        }
        InstallationEffect::Acknowledged
    }
}
impl PrivatePageInstallationIo<u64> for Io {
    fn acquire_frame(&mut self, _: &u64) -> Result<InstallationCap, u32> {
        self.calls.push("acquire");
        Ok(FRAME)
    }
    fn reserve_alias(&mut self, _: &u64) -> Result<InstallationCap, u32> {
        self.calls.push("reserve");
        Ok(ALIAS)
    }
    fn copy_alias(&mut self, frame: InstallationCap, alias: InstallationCap) -> InstallationEffect {
        assert_eq!(frame, FRAME);
        assert_eq!(alias, ALIAS);
        self.effect("copy")
    }
    fn map_frame(&mut self, _: &u64, frame: InstallationCap) -> InstallationEffect {
        assert_eq!(frame, FRAME);
        self.effect("map-frame")
    }
    fn map_alias(&mut self, _: &u64, alias: InstallationCap) -> InstallationEffect {
        assert_eq!(alias, ALIAS);
        self.effect("map-alias")
    }
    fn publish(&mut self, publication: PrivatePagePublication<u64>) -> InstallationEffect {
        let effect = self.effect("publish");
        if effect == InstallationEffect::Acknowledged {
            self.publication = Some(publication);
        }
        effect
    }
    fn unmap(&mut self, cap: InstallationCap) -> InstallationEffect {
        self.effect(if cap == FRAME {
            "unmap-frame"
        } else {
            assert_eq!(cap, ALIAS);
            "unmap-alias"
        })
    }
    fn delete_alias(&mut self, alias: InstallationCap) -> InstallationEffect {
        assert_eq!(alias, ALIAS);
        self.effect("delete")
    }
    fn recycle_alias(&mut self, alias: InstallationCap) -> InstallationEffect {
        assert_eq!(alias, ALIAS);
        self.effect("recycle")
    }
    fn release_frame(&mut self, frame: InstallationCap) -> InstallationEffect {
        assert_eq!(frame, FRAME);
        self.effect("release")
    }
}

#[test]
fn publication_transfers_exact_owners_only_after_both_maps_ack() {
    let mut owner = PrivatePageInstallation::new();
    let mut io = Io::default();
    owner.begin(42, true).unwrap();
    let operation = owner.operation().unwrap();
    assert_eq!(owner.advance(&mut io), PrivatePageInstallOutcome::Published);
    assert_eq!(
        io.calls,
        [
            "acquire",
            "map-frame",
            "reserve",
            "copy",
            "map-alias",
            "publish"
        ]
    );
    assert_eq!(
        io.publication,
        Some(PrivatePagePublication {
            operation,
            descriptor: 42,
            frame: FRAME,
            alias: Some(ALIAS)
        })
    );
    assert!(owner.is_idle());
    assert!(!owner.owns_cap(FRAME.cap));
}

#[test]
fn mapping_copy_and_registration_refusals_release_only_acknowledged_resources() {
    for refusal in ["map-frame", "copy", "map-alias", "publish"] {
        let mut owner = PrivatePageInstallation::new();
        let mut io = Io {
            refuse: Some(refusal),
            ..Default::default()
        };
        owner.begin(42, true).unwrap();
        assert_eq!(
            owner.advance(&mut io),
            PrivatePageInstallOutcome::Failed(FAIL)
        );
        assert!(owner.is_idle());
        assert!(io.publication.is_none());
        assert_eq!(io.calls.last(), Some(&"release"));
        assert_eq!(
            io.calls.iter().filter(|&&call| call == "release").count(),
            1
        );
        assert_eq!(io.calls.contains(&"unmap-frame"), refusal != "map-frame");
        assert_eq!(
            io.calls.contains(&"delete"),
            matches!(refusal, "map-alias" | "publish")
        );
        assert_eq!(io.calls.contains(&"unmap-alias"), refusal == "publish");
        assert_eq!(io.calls.contains(&"recycle"), refusal != "map-frame");
    }
}

#[test]
fn cleanup_refusals_keep_exact_caps_and_do_not_replay_accepted_prefix() {
    for blocked in ["unmap-alias", "delete", "recycle", "unmap-frame", "release"] {
        let mut owner = PrivatePageInstallation::new();
        let mut io = Io {
            refuse: Some("publish"),
            ..Default::default()
        };
        // Fail publication then the selected cleanup stage in the same advance.
        let mut backend = CleanupRefusal {
            inner: &mut io,
            blocked,
            fired: false,
        };
        owner.begin(42, true).unwrap();
        assert_eq!(
            owner.advance(&mut backend),
            PrivatePageInstallOutcome::CleanupPending(FAIL)
        );
        assert!(owner.owns_cap(FRAME.cap));
        assert_eq!(owner.begin(99, false), Err(INVALID));
        assert_eq!(owner.descriptor(), Some(42));
        assert_eq!(
            owner.advance(&mut backend),
            PrivatePageInstallOutcome::Failed(FAIL)
        );
        assert!(owner.is_idle());
        assert_eq!(
            io.calls.iter().filter(|&&call| call == "publish").count(),
            1
        );
        assert_eq!(
            io.calls.iter().filter(|&&call| call == "map-frame").count(),
            1
        );
        assert_eq!(io.calls.iter().filter(|&&call| call == blocked).count(), 2);
    }
}

struct CleanupRefusal<'a> {
    inner: &'a mut Io,
    blocked: &'static str,
    fired: bool,
}
impl CleanupRefusal<'_> {
    fn cleanup(&mut self, name: &'static str) -> InstallationEffect {
        if name == self.blocked && !self.fired {
            self.fired = true;
            self.inner.refuse = Some(name);
        }
        self.inner.effect(name)
    }
}
impl PrivatePageInstallationIo<u64> for CleanupRefusal<'_> {
    fn acquire_frame(&mut self, descriptor: &u64) -> Result<InstallationCap, u32> {
        self.inner.acquire_frame(descriptor)
    }
    fn reserve_alias(&mut self, descriptor: &u64) -> Result<InstallationCap, u32> {
        self.inner.reserve_alias(descriptor)
    }
    fn copy_alias(&mut self, frame: InstallationCap, alias: InstallationCap) -> InstallationEffect {
        self.inner.copy_alias(frame, alias)
    }
    fn map_frame(&mut self, descriptor: &u64, frame: InstallationCap) -> InstallationEffect {
        self.inner.map_frame(descriptor, frame)
    }
    fn map_alias(&mut self, descriptor: &u64, alias: InstallationCap) -> InstallationEffect {
        self.inner.map_alias(descriptor, alias)
    }
    fn publish(&mut self, publication: PrivatePagePublication<u64>) -> InstallationEffect {
        self.inner.publish(publication)
    }
    fn unmap(&mut self, cap: InstallationCap) -> InstallationEffect {
        self.cleanup(if cap == FRAME {
            "unmap-frame"
        } else {
            "unmap-alias"
        })
    }
    fn delete_alias(&mut self, _: InstallationCap) -> InstallationEffect {
        self.cleanup("delete")
    }
    fn recycle_alias(&mut self, _: InstallationCap) -> InstallationEffect {
        self.cleanup("recycle")
    }
    fn release_frame(&mut self, _: InstallationCap) -> InstallationEffect {
        self.cleanup("release")
    }
}

#[test]
fn uncertain_effect_freezes_owned_caps_and_forbids_any_replay() {
    for unknown in ["map-frame", "copy", "map-alias", "publish"] {
        let mut owner = PrivatePageInstallation::new();
        let mut io = Io {
            uncertain: Some(unknown),
            ..Default::default()
        };
        owner.begin(42, true).unwrap();
        assert_eq!(
            owner.advance(&mut io),
            PrivatePageInstallOutcome::Quarantined(FAIL)
        );
        assert!(owner.owns_cap(FRAME.cap));
        let calls = io.calls.len();
        assert_eq!(
            owner.advance(&mut io),
            PrivatePageInstallOutcome::Quarantined(FAIL)
        );
        assert_eq!(io.calls.len(), calls);
        assert_eq!(owner.begin(99, false), Err(INVALID));
    }
}

#[test]
fn private_stack_page_needs_no_optional_root_alias() {
    let mut owner = PrivatePageInstallation::new();
    let mut io = Io::default();
    owner.begin(42, false).unwrap();
    assert_eq!(owner.advance(&mut io), PrivatePageInstallOutcome::Published);
    assert_eq!(io.calls, ["acquire", "map-frame", "publish"]);
    assert_eq!(io.publication.unwrap().alias, None);
}

#[test]
fn uncertain_cleanup_never_recycles_or_releases_retained_backing() {
    let mut owner = PrivatePageInstallation::new();
    let mut io = Io {
        refuse: Some("publish"),
        uncertain: Some("unmap-alias"),
        ..Default::default()
    };
    owner.begin(42, true).unwrap();
    assert_eq!(
        owner.advance(&mut io),
        PrivatePageInstallOutcome::Quarantined(FAIL)
    );
    assert!(owner.owns_cap(FRAME.cap));
    assert!(owner.owns_cap(ALIAS.cap));
    assert!(!io.calls.contains(&"release"));
    assert!(!io.calls.contains(&"recycle"));
    let calls = io.calls.len();
    assert_eq!(
        owner.advance(&mut io),
        PrivatePageInstallOutcome::Quarantined(FAIL)
    );
    assert_eq!(io.calls.len(), calls);
}
