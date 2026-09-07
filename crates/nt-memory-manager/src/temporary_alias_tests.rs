use super::*;
use alloc::vec::Vec;

const SOURCE: TemporaryAliasSource = TemporaryAliasSource {
    scope: TemporaryAliasScope::ClientPage {
        process: 7,
        page: 0x2000,
    },
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
    assert!(!owner.owns_slot(0));
    assert!(!owner.owns_slot(100));
    for writable in [false, true] {
        assert_eq!(
            owner.with_frame(SOURCE, 0x8000, writable, &mut io, |va| va + 4),
            Ok(0x8004)
        );
        assert!(owner.pending().is_none());
        assert!(owner.owns_slot(100));
        assert!(!owner.owns_slot(90));
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
                scope: TemporaryAliasScope::ClientPage {
                    process: 8,
                    page: 0x2000
                },
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
        (
            TemporaryAliasSource {
                scope: TemporaryAliasScope::ClientPage {
                    process: 7,
                    page: 1,
                },
                ..SOURCE
            },
            0x8000,
        ),
        (
            TemporaryAliasSource {
                scope: TemporaryAliasScope::ClientPage {
                    process: 7,
                    page: u64::MAX - 4095,
                },
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

#[test]
fn untracked_frame_cleanup_excludes_all_address_spaces() {
    let mut owner = TemporaryAlias::new();
    let mut io = Io {
        delete_error: 13,
        ..Io::default()
    };
    let source = TemporaryAliasSource {
        scope: TemporaryAliasScope::Frame,
        frame: 90,
    };
    assert_eq!(
        owner.with_frame(source, 0x8000, false, &mut io, |_| ()),
        Err(13)
    );
    for process in [0, 7, 8, u64::MAX] {
        assert!(!owner.process_available(process));
        assert!(!owner.memory_available(process, 0, 1));
        assert!(!owner.memory_available(process, 0x9000, 4096));
        assert!(owner.memory_available(process, 0x9000, 0));
    }
    assert!(!owner.backing_release_available());
    io.delete_error = 0;
    owner.drain(&mut io).unwrap();
    assert!(owner.process_available(0));
    assert!(owner.memory_available(7, 0, 1));
    assert!(owner.backing_release_available());
}

#[test]
fn bounded_access_rejects_invalid_ranges_before_backend_effects() {
    let mut owner = TemporaryAlias::new();
    let mut io = Io::default();
    for range in [2..1, 0..4097, usize::MAX..usize::MAX] {
        assert_eq!(
            owner.with_range(SOURCE, 0x8000, range, true, &mut io, |_| panic!()),
            Err(INVALID)
        );
        assert!(io.calls.is_empty());
    }
    assert_eq!(
        owner.with_range(SOURCE, 0x8000, 4095..4096, false, &mut io, |address| {
            address
        }),
        Ok(0x8fff)
    );
    assert_eq!(
        owner.with_range(SOURCE, 0x8000, 4096..4096, false, &mut io, |address| {
            address
        }),
        Ok(0x9000)
    );
}

#[derive(Default)]
struct PageIo {
    calls: Vec<(&'static str, u64)>,
    fail_at: Option<usize>,
}
impl PageIo {
    fn step(&mut self, operation: &'static str, argument: u64) -> Result<(), u32> {
        let index = self.calls.len();
        self.calls.push((operation, argument));
        if self.fail_at == Some(index) {
            Err(42)
        } else {
            Ok(())
        }
    }
}
impl TemporaryAliasIo for PageIo {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        self.step("reserve", 0)?;
        Ok(100)
    }
    fn copy(&mut self, source: u64, slot: u64) -> Result<(), u32> {
        assert_eq!(slot, 100);
        self.step("copy", source)
    }
    fn map(&mut self, slot: u64, address: u64, writable: bool) -> Result<(), u32> {
        assert_eq!(slot, 100);
        self.step(if writable { "write-map" } else { "read-map" }, address)
    }
    fn delete(&mut self, slot: u64) -> Result<(), u32> {
        self.step("delete", slot)
    }
}

#[test]
fn page_copy_closes_source_before_mapping_destination_and_preserves_all_bytes() {
    let mut owner = TemporaryAlias::new();
    let mut io = PageIo::default();
    let mut destination = [0u8; 4096];
    owner
        .copy_page(
            90,
            91,
            0x8000,
            &mut io,
            |address, bytes| {
                assert_eq!(address, 0x8000);
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = (index % 251) as u8;
                }
            },
            |address, bytes| {
                assert_eq!(address, 0x8000);
                destination.copy_from_slice(bytes);
            },
        )
        .unwrap();
    assert!(destination
        .iter()
        .enumerate()
        .all(|(index, byte)| *byte == (index % 251) as u8));
    assert_eq!(
        io.calls,
        [
            ("reserve", 0),
            ("copy", 90),
            ("read-map", 0x8000),
            ("delete", 100),
            ("copy", 91),
            ("write-map", 0x8000),
            ("delete", 100)
        ]
    );
    assert!(owner.pending().is_none());
}

#[test]
fn page_copy_failure_matrix_retains_cleanup_and_never_publishes_success() {
    for fail_at in 0..7 {
        let mut owner = TemporaryAlias::new();
        let mut io = PageIo {
            fail_at: Some(fail_at),
            ..PageIo::default()
        };
        let mut read = false;
        let mut written = false;
        assert_eq!(
            owner.copy_page(
                90,
                91,
                0x8000,
                &mut io,
                |_, bytes| {
                    read = true;
                    bytes.fill(0xab);
                },
                |_, bytes| {
                    written = true;
                    assert!(bytes.iter().all(|byte| *byte == 0xab));
                },
            ),
            Err(42)
        );
        assert_eq!(read, fail_at >= 3);
        assert_eq!(written, fail_at == 6);
        if [3, 6].contains(&fail_at) {
            let pending = owner.pending().unwrap();
            assert_eq!(pending.source.scope, TemporaryAliasScope::Frame);
            assert_eq!(pending.source.frame, if fail_at == 3 { 90 } else { 91 });
            assert!(!owner.backing_release_available());
            assert!(!owner.process_available(7));
            let calls = io.calls.len();
            assert_eq!(
                owner.copy_page(92, 93, 0x8000, &mut io, |_, _| panic!(), |_, _| panic!()),
                Err(RESOURCES)
            );
            assert_eq!(io.calls.len(), calls);
        } else {
            assert!(owner.pending().is_none());
        }
        io.fail_at = None;
        owner.drain(&mut io).unwrap();
        assert!(owner.backing_release_available());
    }
}

#[test]
fn page_copy_rejects_null_frames_without_side_effects() {
    for (source, destination) in [(0, 91), (90, 0)] {
        let mut owner = TemporaryAlias::new();
        let mut io = PageIo::default();
        assert_eq!(
            owner.copy_page(
                source,
                destination,
                0x8000,
                &mut io,
                |_, _| panic!(),
                |_, _| panic!()
            ),
            Err(INVALID)
        );
        assert!(io.calls.is_empty());
    }
}
