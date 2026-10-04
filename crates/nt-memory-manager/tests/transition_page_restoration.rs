use nt_memory_manager::private_page_installation::{InstallationCap, InstallationEffect as Effect};
use nt_memory_manager::transition_page_restoration::{
    TransitionPageRestoration, TransitionRestorationIo, TransitionRestorationOutcome as Outcome,
};
use nt_memory_manager::{MemoryLifetime, PagefilePage, ProcessGeneration, ProcessIdentity};

fn source() -> PagefilePage {
    PagefilePage {
        owner: 7,
        lifetime: MemoryLifetime::Process(ProcessIdentity {
            pid: 304,
            generation: ProcessGeneration::Hosted(2),
        }),
        page: 0x6000_1000,
        protection: 4,
        backing: 91,
    }
}

#[derive(Default)]
struct Io {
    events: Vec<&'static str>,
    failures: Vec<(&'static str, Effect)>,
    restored: Option<PagefilePage>,
}
impl Io {
    fn effect(&mut self, name: &'static str) -> Effect {
        self.events.push(name);
        match self.failures.first().copied() {
            Some((target, effect)) if target == name => {
                self.failures.remove(0);
                effect
            }
            _ => Effect::Acknowledged,
        }
    }
}
impl TransitionRestorationIo<u64> for Io {
    fn map_frame(&mut self, _: &u64, _: PagefilePage) -> Effect {
        self.effect("map")
    }
    fn reserve_alias(&mut self, _: &u64) -> Result<InstallationCap, u32> {
        self.events.push("reserve");
        Ok(InstallationCap { cap: 92 })
    }
    fn copy_alias(&mut self, _: PagefilePage, _: InstallationCap) -> Effect {
        self.effect("copy")
    }
    fn map_alias(&mut self, _: &u64, _: InstallationCap) -> Effect {
        self.effect("alias-map")
    }
    fn publish_resident(&mut self, _: &u64, _: PagefilePage, _: Option<InstallationCap>) -> Effect {
        self.effect("publish")
    }
    fn unmap(&mut self, cap: InstallationCap) -> Effect {
        self.effect(if cap.cap == 91 {
            "frame-unmap"
        } else {
            "alias-unmap"
        })
    }
    fn delete_alias(&mut self, _: InstallationCap) -> Effect {
        self.effect("delete")
    }
    fn recycle_alias(&mut self, _: InstallationCap, _: bool) -> Effect {
        self.effect("recycle")
    }
    fn restore_available(&mut self, page: PagefilePage) -> Effect {
        let effect = self.effect("restore");
        if effect == Effect::Acknowledged {
            self.restored = Some(page);
        }
        effect
    }
}

#[test]
fn existing_transition_frame_transfers_without_allocation_zeroing_or_new_charge() {
    let mut owner = TransitionPageRestoration::new(17, source(), true).unwrap();
    let mut io = Io::default();
    assert_eq!(owner.advance(&mut io), Outcome::Published);
    assert_eq!(
        io.events,
        ["map", "reserve", "copy", "alias-map", "publish"]
    );
    assert!(owner.is_settled());
    assert_eq!(io.restored, None);
}

#[test]
fn refused_publication_restores_original_only_after_every_cleanup_ack() {
    let mut owner = TransitionPageRestoration::new(17, source(), true).unwrap();
    let mut io = Io {
        failures: vec![("publish", Effect::Refused(5))],
        ..Io::default()
    };
    assert_eq!(owner.advance(&mut io), Outcome::Restored(5));
    assert_eq!(
        io.events,
        [
            "map",
            "reserve",
            "copy",
            "alias-map",
            "publish",
            "alias-unmap",
            "delete",
            "recycle",
            "frame-unmap",
            "restore"
        ]
    );
    assert_eq!(io.restored, Some(source()));
}

#[test]
fn known_map_and_alias_refusals_never_clean_up_an_unentered_effect() {
    for (stage, expected) in [
        ("map", vec!["map", "restore"]),
        (
            "copy",
            vec![
                "map",
                "reserve",
                "copy",
                "recycle",
                "frame-unmap",
                "restore",
            ],
        ),
        (
            "alias-map",
            vec![
                "map",
                "reserve",
                "copy",
                "alias-map",
                "delete",
                "recycle",
                "frame-unmap",
                "restore",
            ],
        ),
    ] {
        let mut owner = TransitionPageRestoration::new(17, source(), true).unwrap();
        let mut io = Io {
            failures: vec![(stage, Effect::Refused(5))],
            ..Io::default()
        };
        assert_eq!(owner.advance(&mut io), Outcome::Restored(5));
        assert_eq!(io.events, expected);
        assert_eq!(io.restored, Some(source()));
    }
}

#[test]
fn each_refused_cleanup_retries_only_unacknowledged_effect_before_availability() {
    for cleanup in ["alias-unmap", "delete", "recycle", "frame-unmap", "restore"] {
        let mut owner = TransitionPageRestoration::new(17, source(), true).unwrap();
        let mut io = Io {
            failures: vec![
                ("publish", Effect::Refused(5)),
                (cleanup, Effect::Refused(6)),
            ],
            ..Io::default()
        };
        assert_eq!(owner.advance(&mut io), Outcome::CleanupPending(6));
        assert_eq!(io.restored, None);
        assert_eq!(owner.advance(&mut io), Outcome::Restored(5));
        assert_eq!(
            io.events.iter().filter(|event| **event == cleanup).count(),
            2
        );
        assert_eq!(io.events.iter().filter(|event| **event == "map").count(), 1);
        assert_eq!(io.restored, Some(source()));
    }
}

#[test]
fn uncertain_map_or_cleanup_retains_backing_without_replay_or_put_back() {
    for stage in ["map", "delete"] {
        let mut owner = TransitionPageRestoration::new(17, source(), true).unwrap();
        let failures = if stage == "delete" {
            vec![
                ("publish", Effect::Refused(5)),
                (stage, Effect::Uncertain(9)),
            ]
        } else {
            vec![(stage, Effect::Uncertain(9))]
        };
        let mut io = Io {
            failures,
            ..Io::default()
        };
        assert_eq!(owner.advance(&mut io), Outcome::Quarantined(9));
        let events = io.events.clone();
        assert_eq!(owner.advance(&mut io), Outcome::Quarantined(9));
        assert_eq!(io.events, events);
        assert_eq!(io.restored, None);
        assert!(owner.owns_backing(91));
    }
}

#[test]
fn exact_teardown_drains_known_prefix_but_cannot_adopt_another_target() {
    let mut owner = TransitionPageRestoration::new(17, source(), true).unwrap();
    let mut io = Io::default();
    assert!(!owner.begin_retirement(&18));
    assert!(owner.begin_retirement(&17));
    assert_eq!(
        owner.advance(&mut io),
        Outcome::Restored(nt_memory_manager::STATUS_INVALID_HANDLE)
    );
    assert_eq!(io.events, ["restore"]);
    assert_eq!(io.restored, Some(source()));
}
