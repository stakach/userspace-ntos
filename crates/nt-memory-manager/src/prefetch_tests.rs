use super::*;
use alloc::vec;

const PROCESS: PrefetchProcess = PrefetchProcess {
    pi: 2,
    generation: 7,
};

#[test]
fn reservation_identity_exhaustion_never_wraps_or_reuses_an_id() {
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate_id(&counter), Ok(u64::MAX - 1));
    assert_eq!(allocate_id(&counter), Err(RESOURCES));
    assert_eq!(allocate_id(&counter), Err(RESOURCES));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
}

struct Io {
    cap: u64,
    alloc_status: u32,
    fail_map: bool,
    fail_fill: bool,
    fail_unmap: bool,
    fail_delete: bool,
    calls: Vec<(&'static str, u64)>,
}

impl Default for Io {
    fn default() -> Self {
        Self {
            cap: 42,
            alloc_status: 0,
            fail_map: false,
            fail_fill: false,
            fail_unmap: false,
            fail_delete: false,
            calls: Vec::new(),
        }
    }
}

impl AliasRetirementIo for Io {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.calls.push(("unmap", cap));
        if self.fail_unmap {
            Err(4)
        } else {
            Ok(())
        }
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.calls.push(("delete", cap));
        if self.fail_delete {
            Err(5)
        } else {
            Ok(())
        }
    }
}

impl PrefetchIo for Io {
    fn allocate(&mut self) -> (u64, u32) {
        self.calls.push(("allocate", self.cap));
        (self.cap, self.alloc_status)
    }
    fn map(&mut self, cap: u64, alias: u64) -> Result<(), u32> {
        self.calls.push(("map-cap", cap));
        self.calls.push(("map-address", alias));
        if self.fail_map {
            Err(2)
        } else {
            Ok(())
        }
    }
    fn fill(&mut self, alias: u64) -> Result<(), u32> {
        self.calls.push(("fill", alias));
        if self.fail_fill {
            Err(3)
        } else {
            Ok(())
        }
    }
}

fn reserve(table: &mut PrefetchFrames, page: u64) -> PrefetchReservation {
    table
        .reserve(PROCESS, page, |index| Some(0x100000 + index as u64 * 4096))
        .unwrap()
}

#[test]
fn reservation_holds_key_and_alias_without_exposing_memory() {
    let mut table = PrefetchFrames::new();
    let ticket = reserve(&mut table, 0x1000);
    assert!(table.contains(2, 0x1000));
    assert!(!table.process_is_empty(2));
    assert_eq!(table.lookup(PROCESS, 0x1000), Err(RESOURCES));
    assert!(table
        .reserve(PROCESS, 0x1000, |_| panic!(
            "duplicate must not select alias"
        ))
        .is_err());
    let other = PrefetchProcess { pi: 3, ..PROCESS };
    assert!(table.reserve(other, 0x2000, |_| Some(0x100000)).is_err());
    let mut io = Io::default();
    assert!(table.retry_retirement(PROCESS, 0x1000, &mut io).is_err());
    table.retire(ticket, &mut io).unwrap();
    assert!(io.calls.is_empty());
    assert!(table.process_is_empty(2));
}

#[test]
fn construction_publishes_the_exact_reserved_row_after_other_reservations() {
    let mut table = PrefetchFrames::new();
    let first = reserve(&mut table, 0x1000);
    let second = reserve(&mut table, 0x2000);
    let mut io = Io::default();
    table.build(second, &mut io).unwrap();
    io.cap = 43;
    table.build(first, &mut io).unwrap();
    assert_eq!(
        table.lookup(PROCESS, 0x1000),
        Ok(Some(PrefetchPage {
            frame: 43,
            alias: 0x100000
        }))
    );
    assert_eq!(
        table.lookup(PROCESS, 0x2000),
        Ok(Some(PrefetchPage {
            frame: 42,
            alias: 0x101000
        }))
    );
    let calls = io.calls.len();
    assert!(table.build(first, &mut io).is_err());
    assert_eq!(io.calls.len(), calls);
    assert_eq!(table.retire_process(PROCESS, &mut io), (2, 0));
}

#[test]
fn invalid_geometry_or_address_exhaustion_never_reserves_a_row() {
    let mut table = PrefetchFrames::new();
    assert!(table
        .reserve(
            PrefetchProcess {
                generation: 0,
                ..PROCESS
            },
            0x1000,
            |_| Some(0x100000)
        )
        .is_err());
    for page in [1, u64::MAX - 4095] {
        assert!(table.reserve(PROCESS, page, |_| Some(0x100000)).is_err());
    }
    for address in [None, Some(0), Some(1), Some(u64::MAX - 4095)] {
        assert!(table.reserve(PROCESS, 0x1000, |_| address).is_err());
        assert!(table.process_is_empty(2));
    }
    assert_eq!(reserve(&mut table, 0x1000).index, 0);
}

#[test]
fn allocation_failure_without_slot_retires_reservation_without_backend_delete() {
    for status in [0, 1] {
        let mut table = PrefetchFrames::new();
        let ticket = reserve(&mut table, 0x1000);
        let mut io = Io {
            cap: 0,
            alloc_status: status,
            ..Io::default()
        };
        assert!(table.build(ticket, &mut io).is_err());
        assert!(table.process_is_empty(2));
        assert_eq!(io.calls, vec![("allocate", 0)]);
    }
}

#[test]
fn failed_retype_retains_its_empty_root_slot_until_checked_deletion() {
    let mut table = PrefetchFrames::new();
    let ticket = reserve(&mut table, 0x1000);
    let mut io = Io {
        alloc_status: 1,
        fail_delete: true,
        ..Io::default()
    };
    assert_eq!(table.build(ticket, &mut io), Err(1));
    assert_eq!(io.calls, vec![("allocate", 42), ("delete", 42)]);
    assert_eq!(table.lookup(PROCESS, 0x1000), Err(RESOURCES));
    assert!(!table.process_is_empty(2));
    io.fail_delete = false;
    table.retry_retirement(PROCESS, 0x1000, &mut io).unwrap();
    assert!(table.process_is_empty(2));
    assert_eq!(io.calls.last(), Some(&("delete", 42)));
}

#[test]
fn map_failure_retains_unmapped_cap_without_filling_or_unmapping_it() {
    let mut table = PrefetchFrames::new();
    let ticket = reserve(&mut table, 0x1000);
    let mut io = Io {
        fail_map: true,
        fail_delete: true,
        ..Io::default()
    };
    assert_eq!(table.build(ticket, &mut io), Err(2));
    assert_eq!(table.lookup(PROCESS, 0x1000), Err(RESOURCES));
    io.fail_delete = false;
    table.retire(ticket, &mut io).unwrap();
    assert_eq!(
        io.calls,
        vec![
            ("allocate", 42),
            ("map-cap", 42),
            ("map-address", 0x100000),
            ("delete", 42),
            ("delete", 42)
        ]
    );
}

#[test]
fn fill_failure_retains_mapping_and_retries_unmap_before_delete() {
    let mut table = PrefetchFrames::new();
    let ticket = reserve(&mut table, 0x1000);
    let mut io = Io {
        fail_fill: true,
        fail_unmap: true,
        ..Io::default()
    };
    assert_eq!(table.build(ticket, &mut io), Err(3));
    assert_eq!(table.lookup(PROCESS, 0x1000), Err(RESOURCES));
    assert!(!io.calls.iter().any(|(op, _)| *op == "delete"));
    io.fail_unmap = false;
    table.retire(ticket, &mut io).unwrap();
    assert_eq!(
        &io.calls[io.calls.len() - 2..],
        &[("unmap", 42), ("delete", 42)]
    );
}

#[test]
fn failed_delete_hides_frame_and_retains_alias_without_replaying_unmap() {
    let mut table = PrefetchFrames::new();
    let ticket = reserve(&mut table, 0x1000);
    let mut io = Io::default();
    table.build(ticket, &mut io).unwrap();
    io.fail_delete = true;
    assert_eq!(table.retire(ticket, &mut io), Err(5));
    assert_eq!(table.lookup(PROCESS, 0x1000), Err(RESOURCES));
    assert!(table.reserve(PROCESS, 0x2000, |_| Some(0x100000)).is_err());
    io.fail_delete = false;
    table.retire(ticket, &mut io).unwrap();
    assert_eq!(io.calls.iter().filter(|(op, _)| *op == "unmap").count(), 1);
    assert_eq!(table.lookup(PROCESS, 0x1000), Ok(None));
}

#[test]
fn process_retirement_is_scoped_and_hides_every_failed_row() {
    let mut table = PrefetchFrames::new();
    let first = reserve(&mut table, 0x1000);
    let second = reserve(&mut table, 0x2000);
    let other = PrefetchProcess { pi: 3, ..PROCESS };
    let third = table.reserve(other, 0x1000, |_| Some(0x200000)).unwrap();
    let mut io = Io::default();
    for (ticket, cap) in [(first, 42), (second, 43), (third, 44)] {
        io.cap = cap;
        table.build(ticket, &mut io).unwrap();
    }
    io.fail_unmap = true;
    assert_eq!(table.retire_process(PROCESS, &mut io), (0, 2));
    assert!(table.lookup(PROCESS, 0x1000).is_err());
    assert!(table.lookup(PROCESS, 0x2000).is_err());
    assert!(table.lookup(other, 0x1000).unwrap().is_some());
    io.fail_unmap = false;
    assert_eq!(table.retire_process(PROCESS, &mut io), (2, 0));
    assert!(table.process_is_empty(2));
    assert!(!table.process_is_empty(3));
}

#[test]
fn stale_and_foreign_tickets_cannot_publish_or_retire_reused_row_cap_or_alias() {
    let mut table = PrefetchFrames::new();
    let old = reserve(&mut table, 0x1000);
    let mut io = Io::default();
    table.build(old, &mut io).unwrap();
    table.retire(old, &mut io).unwrap();
    let new = reserve(&mut table, 0x1000);
    assert_eq!(old.index, new.index);
    assert_ne!(old.id, new.id);
    let mut foreign = PrefetchFrames::new();
    let elsewhere = reserve(&mut foreign, 0x1000);
    let calls = io.calls.len();
    for invalid in [old, elsewhere] {
        assert!(table.build(invalid, &mut io).is_err());
        assert!(table.retire(invalid, &mut io).is_err());
    }
    assert_eq!(io.calls.len(), calls);
    table.build(new, &mut io).unwrap();
    assert_eq!(table.lookup(PROCESS, 0x1000).unwrap().unwrap().frame, 42);
}

#[test]
fn process_generation_mismatch_cannot_observe_replace_or_release_retained_owner() {
    let mut table = PrefetchFrames::new();
    let ticket = reserve(&mut table, 0x1000);
    let mut io = Io::default();
    table.build(ticket, &mut io).unwrap();
    let newer = PrefetchProcess {
        generation: 8,
        ..PROCESS
    };
    assert!(table.lookup(newer, 0x1000).is_err());
    assert!(table.reserve(newer, 0x2000, |_| Some(0x300000)).is_err());
    assert!(table.retry_retirement(newer, 0x1000, &mut io).is_err());
    let calls = io.calls.len();
    assert_eq!(table.retire_process(newer, &mut io), (0, 0));
    assert_eq!(io.calls.len(), calls);
    assert!(!table.process_is_empty(2));
    table.retire(ticket, &mut io).unwrap();
    assert!(table.reserve(newer, 0x1000, |_| Some(0x100000)).is_ok());
}
