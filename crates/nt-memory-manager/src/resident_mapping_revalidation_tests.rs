use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
struct Page {
    generation: u64,
    address: u64,
}

struct Io {
    page: Page,
    bytes: [u8; 4096],
    validations: usize,
    queries: usize,
    maps: usize,
    fail_validation: Option<usize>,
    fail_query: Option<usize>,
    backing_address: u64,
    effect: InstallationEffect,
}

impl Io {
    fn new() -> Self {
        Self {
            page: Page {
                generation: 7,
                address: 0x1000,
            },
            bytes: [0x5a; 4096],
            validations: 0,
            queries: 0,
            maps: 0,
            fail_validation: None,
            fail_query: None,
            backing_address: 0x8000,
            effect: InstallationEffect::Acknowledged,
        }
    }

    fn owner(&self) -> ResidentMappingRevalidation<Page> {
        ResidentMappingRevalidation::begin(
            self.page,
            InstallationCap { cap: 10 },
            InstallationCap { cap: 20 },
            true,
        )
        .unwrap()
    }
}

impl ResidentMappingRevalidationIo<Page> for Io {
    fn validate_current(
        &mut self,
        page: &Page,
        mapped: InstallationCap,
        backing: InstallationCap,
    ) -> Result<(), u32> {
        self.validations += 1;
        if self.fail_validation == Some(self.validations)
            || *page != self.page
            || mapped.cap != 10
            || backing.cap != 20
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    fn frame_address(&mut self, cap: InstallationCap) -> Result<u64, u32> {
        self.queries += 1;
        if self.fail_query == Some(self.queries) {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(if cap.cap == 10 {
            0x8000
        } else {
            self.backing_address
        })
    }

    fn map_existing(&mut self, page: &Page, mapped: InstallationCap) -> InstallationEffect {
        assert_eq!(page.address, self.page.address);
        assert_eq!(mapped.cap, 10);
        self.maps += 1;
        self.effect
    }
}

#[test]
fn acknowledged_revalidation_preserves_stack_bytes_and_never_replays_map() {
    let mut io = Io::new();
    io.bytes[16..24].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
    let original = io.bytes;
    let mut owner = io.owner();
    assert_eq!(
        owner.advance(&mut io),
        ResidentMappingRevalidationOutcome::Revalidated
    );
    assert_eq!((io.validations, io.queries, io.maps), (2, 2, 1));
    assert_eq!(io.bytes, original);
    assert!(owner.is_revalidated());
    assert!(!owner.blocks_retirement());
    assert_eq!(
        owner.advance(&mut io),
        ResidentMappingRevalidationOutcome::Revalidated
    );
    assert_eq!((io.validations, io.queries, io.maps), (2, 2, 1));
}

#[test]
fn stale_generation_or_changed_mapping_is_refused_before_effect() {
    for changed_generation in [true, false] {
        let mut io = Io::new();
        let mut owner = io.owner();
        if changed_generation {
            io.page.generation += 1;
        } else {
            io.page.address += 4096;
        }
        assert_eq!(
            owner.advance(&mut io),
            ResidentMappingRevalidationOutcome::Refused(STATUS_INVALID_HANDLE)
        );
        assert_eq!((io.queries, io.maps), (0, 0));
    }
}

#[test]
fn physical_mismatch_or_query_failure_never_maps_replacement_backing() {
    for case in 0..3 {
        let mut io = Io::new();
        let mut owner = io.owner();
        match case {
            0 => io.backing_address += 4096,
            1 => io.fail_query = Some(1),
            _ => io.fail_query = Some(2),
        }
        assert_eq!(
            owner.advance(&mut io),
            ResidentMappingRevalidationOutcome::Refused(STATUS_INVALID_HANDLE)
        );
        assert_eq!(io.maps, 0);
        assert_eq!(io.bytes, [0x5a; 4096]);
    }
}

#[test]
fn ownership_change_after_physical_queries_is_refused_before_map() {
    let mut io = Io::new();
    io.fail_validation = Some(2);
    let mut owner = io.owner();
    assert_eq!(
        owner.advance(&mut io),
        ResidentMappingRevalidationOutcome::Refused(STATUS_INVALID_HANDLE)
    );
    assert_eq!((io.validations, io.queries, io.maps), (2, 2, 0));
}

#[test]
fn uncertain_mapping_retains_original_owners_and_forbids_replay() {
    let mut io = Io::new();
    io.effect = InstallationEffect::Uncertain(0xc000_009a);
    let mut owner = io.owner();
    assert_eq!(
        owner.advance(&mut io),
        ResidentMappingRevalidationOutcome::Quarantined(0xc000_009a)
    );
    assert!(owner.blocks_retirement());
    assert!(owner.is_quarantined());
    assert_eq!((owner.mapped().cap, owner.source().cap), (10, 20));
    assert_eq!(
        owner.advance(&mut io),
        ResidentMappingRevalidationOutcome::Quarantined(0xc000_009a)
    );
    assert_eq!((io.validations, io.queries, io.maps), (2, 2, 1));
}

#[test]
fn known_no_effect_refusal_can_retry_only_after_fresh_checks() {
    let mut io = Io::new();
    io.effect = InstallationEffect::Refused(0xc000_009a);
    let mut owner = io.owner();
    assert_eq!(
        owner.advance(&mut io),
        ResidentMappingRevalidationOutcome::Refused(0xc000_009a)
    );
    assert!(!owner.blocks_retirement());
    io.effect = InstallationEffect::Acknowledged;
    assert_eq!(
        owner.advance(&mut io),
        ResidentMappingRevalidationOutcome::Revalidated
    );
    assert_eq!((io.validations, io.queries, io.maps), (4, 4, 2));
}

#[test]
fn interrupted_map_entry_quarantines_without_effect_replay() {
    let mut io = Io::new();
    let mut owner = io.owner();
    owner.phase = Phase::MapPending;
    assert!(owner.blocks_retirement());
    assert_eq!(
        owner.advance(&mut io),
        ResidentMappingRevalidationOutcome::Quarantined(STATUS_INVALID_HANDLE)
    );
    assert_eq!((io.validations, io.queries, io.maps), (0, 0, 0));
}

#[test]
fn protection_fault_or_missing_cap_cannot_begin_revalidation() {
    let page = Io::new().page;
    for (mapped, backing, not_present) in [(10, 20, false), (0, 20, true), (10, 0, true)] {
        assert!(matches!(
            ResidentMappingRevalidation::begin(
                page,
                InstallationCap { cap: mapped },
                InstallationCap { cap: backing },
                not_present
            ),
            Err(STATUS_INVALID_HANDLE)
        ));
    }
}
