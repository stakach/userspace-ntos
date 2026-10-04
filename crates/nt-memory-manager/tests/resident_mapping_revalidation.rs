use nt_memory_manager::private_page_installation::{InstallationCap, InstallationEffect};
use nt_memory_manager::resident_mapping_revalidation::{
    ResidentMappingRevalidation, ResidentMappingRevalidationIo,
    ResidentMappingRevalidationOutcome as Outcome,
};
use nt_memory_manager::{ProcessGeneration, ProcessIdentity, STATUS_INVALID_HANDLE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Descriptor {
    process: ProcessIdentity,
    pi: u64,
    pml4: u64,
    page: u64,
    record: u64,
    protection: u32,
}

fn descriptor() -> Descriptor {
    Descriptor {
        process: ProcessIdentity {
            pid: 952,
            generation: ProcessGeneration::Hosted(11),
        },
        pi: 15,
        pml4: 0x32204,
        page: 0x7ffaa05f000,
        record: 0x33cd,
        protection: 0x80,
    }
}

const MAPPED: InstallationCap = InstallationCap { cap: 0x34483 };
const SOURCE: InstallationCap = InstallationCap { cap: 0x20000 };

struct Io {
    current: Descriptor,
    mapped_address: Result<u64, u32>,
    source_address: Result<u64, u32>,
    effect: InstallationEffect,
    events: Vec<&'static str>,
    invalidate_after_query: bool,
    panic_in_map: bool,
}

impl Default for Io {
    fn default() -> Self {
        Self {
            current: descriptor(),
            mapped_address: Ok(0x12345000),
            source_address: Ok(0x12345000),
            effect: InstallationEffect::Acknowledged,
            events: Vec::new(),
            invalidate_after_query: false,
            panic_in_map: false,
        }
    }
}

impl ResidentMappingRevalidationIo<Descriptor> for Io {
    fn validate_current(
        &mut self,
        captured: &Descriptor,
        mapped: InstallationCap,
        source: InstallationCap,
    ) -> Result<(), u32> {
        self.events.push("validate");
        if *captured != self.current || mapped != MAPPED || source != SOURCE {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    fn frame_address(&mut self, cap: InstallationCap) -> Result<u64, u32> {
        if cap == MAPPED {
            self.events.push("mapped-address");
            self.mapped_address
        } else {
            assert_eq!(cap, SOURCE);
            self.events.push("source-address");
            if self.invalidate_after_query {
                self.current.record += 1;
            }
            self.source_address
        }
    }

    fn map_existing(
        &mut self,
        captured: &Descriptor,
        mapped: InstallationCap,
    ) -> InstallationEffect {
        assert_eq!(*captured, self.current);
        assert_eq!(mapped, MAPPED);
        self.events.push("map");
        assert!(!self.panic_in_map, "interrupted entered effect");
        self.effect
    }
}

fn owner() -> ResidentMappingRevalidation<Descriptor> {
    ResidentMappingRevalidation::begin(descriptor(), MAPPED, SOURCE, true).unwrap()
}

#[test]
fn queued_nonpresent_fault_reestablishes_only_same_existing_frame_once() {
    let mut owner = owner();
    let mut io = Io::default();
    assert_eq!(owner.advance(&mut io), Outcome::Revalidated);
    assert_eq!(
        io.events,
        [
            "validate",
            "mapped-address",
            "source-address",
            "validate",
            "map"
        ]
    );
    assert!(owner.is_revalidated());
    assert!(!owner.blocks_retirement());
    assert_eq!(owner.descriptor(), descriptor());
    assert_eq!(owner.mapped(), MAPPED);
    assert_eq!(owner.source(), SOURCE);
    let events = io.events.clone();
    assert_eq!(owner.advance(&mut io), Outcome::Revalidated);
    assert_eq!(io.events, events);
}

#[test]
fn exact_generation_vspace_page_record_and_protection_are_revalidated() {
    let mut altered = Vec::new();
    let mut d = descriptor();
    d.process.generation = ProcessGeneration::Hosted(12);
    altered.push(d);
    let mut d = descriptor();
    d.process.pid += 1;
    altered.push(d);
    let mut d = descriptor();
    d.pi += 1;
    altered.push(d);
    let mut d = descriptor();
    d.pml4 += 1;
    altered.push(d);
    let mut d = descriptor();
    d.page += 0x1000;
    altered.push(d);
    let mut d = descriptor();
    d.record += 1;
    altered.push(d);
    let mut d = descriptor();
    d.protection = 2;
    altered.push(d);
    for current in altered {
        let mut owner = owner();
        let mut io = Io {
            current,
            ..Io::default()
        };
        assert_eq!(
            owner.advance(&mut io),
            Outcome::Refused(STATUS_INVALID_HANDLE)
        );
        assert_eq!(io.events, ["validate"]);
    }
    let mut owner = owner();
    let mut io = Io {
        invalidate_after_query: true,
        ..Io::default()
    };
    assert_eq!(
        owner.advance(&mut io),
        Outcome::Refused(STATUS_INVALID_HANDLE)
    );
    assert!(!io.events.contains(&"map"));
}

#[test]
fn mismatched_zero_or_unaligned_physical_witness_never_maps() {
    for (mapped, source) in [(0x1000, 0x2000), (0, 0), (0x1001, 0x1001)] {
        let mut owner = owner();
        let mut io = Io {
            mapped_address: Ok(mapped),
            source_address: Ok(source),
            ..Io::default()
        };
        assert_eq!(
            owner.advance(&mut io),
            Outcome::Refused(STATUS_INVALID_HANDLE)
        );
        assert!(!io.events.contains(&"map"));
    }
}

#[test]
fn either_checked_query_failure_preserves_actual_status_without_mapping() {
    for first in [true, false] {
        let mut owner = owner();
        let mut io = Io::default();
        if first {
            io.mapped_address = Err(7);
        } else {
            io.source_address = Err(7);
        }
        assert_eq!(owner.advance(&mut io), Outcome::Refused(7));
        assert!(!io.events.contains(&"map"));
        assert!(!owner.blocks_retirement());
    }
}

#[test]
fn known_unentered_map_refusal_requires_full_fresh_validation_for_retry() {
    let mut owner = owner();
    let mut io = Io {
        effect: InstallationEffect::Refused(8),
        ..Io::default()
    };
    assert_eq!(owner.advance(&mut io), Outcome::Refused(8));
    assert!(!owner.blocks_retirement());
    io.events.clear();
    io.effect = InstallationEffect::Acknowledged;
    io.current.process.generation = ProcessGeneration::Hosted(12);
    assert_eq!(
        owner.advance(&mut io),
        Outcome::Refused(STATUS_INVALID_HANDLE)
    );
    assert_eq!(io.events, ["validate"]);
    io.current = descriptor();
    assert_eq!(owner.advance(&mut io), Outcome::Revalidated);
}

#[test]
fn uncertain_map_is_sticky_and_never_replays_or_releases_any_resource() {
    let mut owner = owner();
    let mut io = Io {
        effect: InstallationEffect::Uncertain(9),
        ..Io::default()
    };
    assert_eq!(owner.advance(&mut io), Outcome::Quarantined(9));
    assert!(owner.is_quarantined());
    assert!(owner.blocks_retirement());
    let events = io.events.clone();
    io.effect = InstallationEffect::Acknowledged;
    assert_eq!(owner.advance(&mut io), Outcome::Quarantined(9));
    assert_eq!(io.events, events);
    assert_eq!(owner.mapped(), MAPPED);
    assert_eq!(owner.source(), SOURCE);
}

#[test]
fn pending_effect_is_recorded_before_backend_entry_and_cannot_be_replayed() {
    let mut owner = owner();
    let mut io = Io {
        panic_in_map: true,
        ..Io::default()
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.advance(&mut io)));
    assert!(result.is_err());
    assert!(owner.blocks_retirement());
    let events = io.events.clone();
    io.panic_in_map = false;
    assert_eq!(
        owner.advance(&mut io),
        Outcome::Quarantined(STATUS_INVALID_HANDLE)
    );
    assert!(owner.is_quarantined());
    assert_eq!(io.events, events);
}

#[test]
fn present_protection_fault_and_missing_caps_are_not_revalidation_admissions() {
    assert!(ResidentMappingRevalidation::begin(descriptor(), MAPPED, SOURCE, false).is_err());
    assert!(ResidentMappingRevalidation::begin(
        descriptor(),
        InstallationCap { cap: 0 },
        SOURCE,
        true
    )
    .is_err());
    assert!(ResidentMappingRevalidation::begin(
        descriptor(),
        MAPPED,
        InstallationCap { cap: 0 },
        true
    )
    .is_err());
}

#[test]
fn two_queued_nonpresent_faults_install_once_then_revalidate_exact_publication() {
    use nt_memory_manager::borrowed_page_installation::{
        BorrowedPageInstallOutcome, BorrowedPageInstallation, BorrowedPageInstallationIo,
    };

    struct JointIo {
        io: Io,
        mapped_ack: bool,
        published: Option<(Descriptor, InstallationCap)>,
    }

    impl BorrowedPageInstallationIo<Descriptor> for JointIo {
        fn reserve(&mut self) -> Result<InstallationCap, u32> {
            self.io.events.push("reserve");
            Ok(MAPPED)
        }
        fn copy(
            &mut self,
            source: InstallationCap,
            destination: InstallationCap,
        ) -> InstallationEffect {
            assert_eq!(source, SOURCE);
            assert_eq!(destination, MAPPED);
            self.io.events.push("copy");
            self.io.mapped_address = self.io.source_address;
            InstallationEffect::Acknowledged
        }
        fn map(
            &mut self,
            captured: Descriptor,
            destination: InstallationCap,
        ) -> InstallationEffect {
            assert_eq!(captured, self.io.current);
            assert_eq!(destination, MAPPED);
            self.io.events.push("initial-map");
            self.mapped_ack = true;
            InstallationEffect::Acknowledged
        }
        fn publish(
            &mut self,
            captured: Descriptor,
            destination: InstallationCap,
        ) -> InstallationEffect {
            assert!(self.mapped_ack);
            assert_eq!(captured, self.io.current);
            assert_eq!(destination, MAPPED);
            assert!(self.published.is_none());
            self.io.events.push("publish");
            self.published = Some((captured, destination));
            InstallationEffect::Acknowledged
        }
        fn unmap(&mut self, _: InstallationCap) -> InstallationEffect {
            panic!("successful delayed fault must not withdraw the published frame");
        }
        fn delete(&mut self, _: InstallationCap) -> InstallationEffect {
            panic!("successful delayed fault must not delete a retained cap");
        }
        fn recycle(&mut self, _: InstallationCap) -> InstallationEffect {
            panic!("successful delayed fault must not recycle a retained cap");
        }
    }

    impl ResidentMappingRevalidationIo<Descriptor> for JointIo {
        fn validate_current(
            &mut self,
            captured: &Descriptor,
            mapped: InstallationCap,
            source: InstallationCap,
        ) -> Result<(), u32> {
            if self.published != Some((*captured, mapped)) {
                return Err(STATUS_INVALID_HANDLE);
            }
            self.io.validate_current(captured, mapped, source)
        }
        fn frame_address(&mut self, cap: InstallationCap) -> Result<u64, u32> {
            self.io.frame_address(cap)
        }
        fn map_existing(
            &mut self,
            captured: &Descriptor,
            mapped: InstallationCap,
        ) -> InstallationEffect {
            assert_eq!(self.published, Some((*captured, mapped)));
            self.io.map_existing(captured, mapped)
        }
    }

    // Both fault messages captured nonpresent before the first mapping acknowledgement.
    let queued = [(descriptor(), true), (descriptor(), true)];
    let mut io = JointIo {
        io: Io::default(),
        mapped_ack: false,
        published: None,
    };
    let mut first = BorrowedPageInstallation::new(queued[0].0, SOURCE).unwrap();
    assert_eq!(
        first.advance(&mut io),
        BorrowedPageInstallOutcome::Published
    );
    assert_eq!(io.io.events, ["reserve", "copy", "initial-map", "publish"]);
    assert_eq!(io.published, Some((descriptor(), MAPPED)));
    assert!(!first.owns_cap(MAPPED.cap));
    assert!(!first.owns_cap(SOURCE.cap));

    let publication = io.published;
    let start = io.io.events.len();
    let mut second =
        ResidentMappingRevalidation::begin(queued[1].0, MAPPED, SOURCE, queued[1].1).unwrap();
    assert_eq!(second.advance(&mut io), Outcome::Revalidated);
    assert_eq!(
        &io.io.events[start..],
        [
            "validate",
            "mapped-address",
            "source-address",
            "validate",
            "map"
        ]
    );
    assert_eq!(io.published, publication);
    for stage in ["reserve", "copy", "initial-map", "publish", "map"] {
        assert_eq!(
            io.io.events.iter().filter(|event| **event == stage).count(),
            1
        );
    }
}
