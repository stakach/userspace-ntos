use super::*;
use alloc::vec::Vec;

const SOURCE: TemporaryAliasSource = TemporaryAliasSource {
    process: 7,
    page: 0x2000,
    frame: 90,
};

#[derive(Default)]
struct Io {
    calls: Vec<(&'static str, u64)>,
    reserve_error: u32,
    copy_error: u32,
    map_error: u32,
    delete_error: u32,
    null_slot: bool,
}
fn status(error: u32) -> Result<(), u32> {
    if error == 0 {
        Ok(())
    } else {
        Err(error)
    }
}
impl TemporaryAliasIo for Io {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        self.calls.push(("reserve", 0));
        status(self.reserve_error)?;
        Ok(if self.null_slot { 0 } else { 100 })
    }
    fn copy(&mut self, source: u64, slot: u64) -> Result<(), u32> {
        assert_eq!(slot, 100);
        self.calls.push(("copy", source));
        status(self.copy_error)
    }
    fn map(&mut self, slot: u64, address: u64, _: bool) -> Result<(), u32> {
        assert_eq!(slot, 100);
        self.calls.push(("map", address));
        status(self.map_error)
    }
    fn delete(&mut self, slot: u64) -> Result<(), u32> {
        self.calls.push(("delete", slot));
        status(self.delete_error)
    }
}

#[test]
fn successful_copies_reuse_one_reserved_empty_slot() {
    let mut owner = TemporaryAlias::new();
    let mut io = Io::default();
    for writable in [false, true] {
        assert_eq!(
            owner.with_frame(SOURCE, 0x8000, writable, &mut io, |va| va + 4),
            Ok(0x8004)
        );
        assert!(owner.pending().is_none());
    }
    assert_eq!(
        io.calls.iter().filter(|(op, _)| *op == "reserve").count(),
        1
    );
    assert_eq!(io.calls.iter().filter(|(op, _)| *op == "delete").count(), 2);
}

#[test]
fn failed_delete_retains_exact_source_and_rejects_overwrite() {
    let mut owner = TemporaryAlias::new();
    let mut io = Io {
        delete_error: 13,
        ..Io::default()
    };
    let mut accessed = false;
    assert_eq!(
        owner.with_frame(SOURCE, 0x8000, true, &mut io, |_| accessed = true),
        Err(13)
    );
    assert!(accessed);
    let pending = owner.pending().unwrap();
    assert_eq!(
        pending,
        TemporaryAliasSnapshot {
            source: SOURCE,
            slot: 100,
            address: 0x8000,
            writable: true
        }
    );
    let calls = io.calls.len();
    assert_eq!(
        owner.with_frame(
            TemporaryAliasSource {
                process: 8,
                ..SOURCE
            },
            0x9000,
            false,
            &mut io,
            |_| panic!()
        ),
        Err(RESOURCES)
    );
    assert_eq!(io.calls.len(), calls);
    assert_eq!(owner.drain(&mut io), Err(13));
    assert_eq!(owner.pending(), Some(pending));
    io.delete_error = 0;
    owner.drain(&mut io).unwrap();
    let calls = io.calls.len();
    owner.drain(&mut io).unwrap();
    assert_eq!(io.calls.len(), calls);
    owner
        .with_frame(SOURCE, 0x9000, false, &mut io, |_| ())
        .unwrap();
}

#[test]
fn map_failure_preserves_primary_error_and_cleanup_owner() {
    let mut owner = TemporaryAlias::new();
    let mut io = Io {
        map_error: 12,
        delete_error: 13,
        ..Io::default()
    };
    assert_eq!(
        owner.with_frame(SOURCE, 0x8000, false, &mut io, |_| panic!()),
        Err(12)
    );
    assert_eq!(owner.pending().unwrap().source, SOURCE);
    io.delete_error = 0;
    owner.drain(&mut io).unwrap();
    assert_eq!(
        io.calls,
        [
            ("reserve", 0),
            ("copy", 90),
            ("map", 0x8000),
            ("delete", 100),
            ("delete", 100)
        ]
    );
}

#[test]
fn failed_copy_keeps_empty_slot_without_deletion_or_reallocation() {
    let mut owner = TemporaryAlias::new();
    let mut io = Io {
        copy_error: 11,
        ..Io::default()
    };
    assert_eq!(
        owner.with_frame(SOURCE, 0x8000, false, &mut io, |_| panic!()),
        Err(11)
    );
    assert!(owner.pending().is_none());
    owner.drain(&mut io).unwrap();
    assert_eq!(io.calls, [("reserve", 0), ("copy", 90)]);
    io.copy_error = 0;
    owner
        .with_frame(SOURCE, 0x8000, false, &mut io, |_| ())
        .unwrap();
    assert_eq!(
        io.calls.iter().filter(|(op, _)| *op == "reserve").count(),
        1
    );
}

#[test]
fn invalid_ranges_have_no_backend_effects() {
    for (source, address) in [
        (TemporaryAliasSource { frame: 0, ..SOURCE }, 0x8000),
        (TemporaryAliasSource { page: 1, ..SOURCE }, 0x8000),
        (
            TemporaryAliasSource {
                page: u64::MAX - 4095,
                ..SOURCE
            },
            0x8000,
        ),
        (SOURCE, 0),
        (SOURCE, 1),
        (SOURCE, u64::MAX - 4095),
    ] {
        let mut owner = TemporaryAlias::new();
        let mut io = Io::default();
        assert_eq!(
            owner.with_frame(source, address, false, &mut io, |_| panic!()),
            Err(INVALID)
        );
        assert!(io.calls.is_empty());
    }
}

#[test]
fn reservation_failure_and_null_success_do_not_copy() {
    for (error, null_slot, expected) in [(10, false, 10), (0, true, RESOURCES)] {
        let mut owner = TemporaryAlias::new();
        let mut io = Io {
            reserve_error: error,
            null_slot,
            ..Io::default()
        };
        assert_eq!(
            owner.with_frame(SOURCE, 0x8000, false, &mut io, |_| panic!()),
            Err(expected)
        );
        assert_eq!(io.calls, [("reserve", 0)]);
        assert!(owner.pending().is_none());
    }
}

#[test]
fn retained_mapping_excludes_source_until_acknowledged_deletion() {
    let mut owner = TemporaryAlias::new();
    let mut io = Io {
        delete_error: 13,
        ..Io::default()
    };
    assert_eq!(
        owner.with_frame(SOURCE, 0x8000, false, &mut io, |_| ()),
        Err(13)
    );
    assert!(!owner.process_available(7));
    assert!(owner.process_available(8));
    assert!(!owner.backing_release_available());
    for (base, size) in [
        (0x2000, 1),
        (0x1fff, 2),
        (0x2fff, 1),
        (0, 0x4000),
        (u64::MAX, 2),
    ] {
        assert!(!owner.memory_available(7, base, size));
    }
    for (base, size) in [(0, 0x2000), (0x3000, 1), (0x2000, 0)] {
        assert!(owner.memory_available(7, base, size));
    }
    assert!(owner.memory_available(8, 0x2000, 0x1000));
    io.delete_error = 0;
    owner.drain(&mut io).unwrap();
    assert!(owner.process_available(7));
    assert!(owner.backing_release_available());
    assert!(owner.memory_available(7, 0x2000, 0x1000));
}
