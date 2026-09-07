use super::*;
use alloc::vec::Vec;

#[derive(Default)]
struct Io {
    calls: Vec<(&'static str, u64)>,
    fail_at: Option<usize>,
    next: u64,
    null_slot: bool,
    same_slot: bool,
}
impl Io {
    fn step(&mut self, operation: &'static str, value: u64) -> Result<(), u32> {
        let index = self.calls.len();
        self.calls.push((operation, value));
        if self.fail_at == Some(index) {
            Err(42)
        } else {
            Ok(())
        }
    }
}
impl ProviderAliasSegmentIo for Io {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        self.step("reserve", 0)?;
        if self.null_slot {
            return Ok(0);
        }
        if self.same_slot {
            return Ok(100);
        }
        self.next += 1;
        Ok(99 + self.next)
    }
    fn retype(&mut self, raw: u64, radix: u32) -> Result<(), u32> {
        assert_eq!(radix, 12);
        self.step("retype", raw)
    }
    fn mint(&mut self, raw: u64, guarded: u64, guard_bits: u64) -> Result<(), u32> {
        assert_eq!(raw, 100);
        assert_eq!(guard_bits, 52);
        self.step("mint", guarded)
    }
}

#[test]
fn ready_segment_is_idempotent_without_allocating_or_retyping() {
    let mut owner = ProviderAliasSegment::new(12);
    let mut io = Io::default();
    assert_eq!(owner.ensure(&mut io), Ok(101));
    assert_eq!(owner.ensure(&mut io), Ok(101));
    assert_eq!(
        io.calls,
        [
            ("reserve", 0),
            ("retype", 100),
            ("reserve", 0),
            ("mint", 101)
        ]
    );
    assert_eq!(
        owner.snapshot(),
        ProviderAliasSegmentSnapshot {
            raw: 100,
            raw_retyped: true,
            guarded: 101,
            guarded_minted: true,
        }
    );
}

#[test]
fn each_construction_failure_retries_only_its_retained_stage() {
    for fail_at in 0..4 {
        let mut owner = ProviderAliasSegment::new(12);
        let mut io = Io {
            fail_at: Some(fail_at),
            ..Io::default()
        };
        assert_eq!(owner.ensure(&mut io), Err(BankError::Backend(42)));
        let held = owner.snapshot();
        assert_eq!(held.raw, if fail_at == 0 { 0 } else { 100 });
        assert_eq!(held.raw_retyped, fail_at >= 2);
        assert_eq!(held.guarded, if fail_at == 3 { 101 } else { 0 });
        assert!(!held.guarded_minted);
        assert_eq!(owner.ready(), None);
        let calls = io.calls.len();
        io.fail_at = None;
        assert_eq!(owner.ensure(&mut io), Ok(101));
        let expected = [
            ("reserve", 0),
            ("retype", 100),
            ("reserve", 0),
            ("mint", 101),
        ];
        assert_eq!(&io.calls[calls..], &expected[fail_at..]);
    }
}

#[test]
fn repeated_mint_failure_never_discards_or_retypes_the_raw_owner() {
    let mut owner = ProviderAliasSegment::new(12);
    let mut io = Io {
        fail_at: Some(3),
        ..Io::default()
    };
    assert_eq!(owner.ensure(&mut io), Err(BankError::Backend(42)));
    let held = owner.snapshot();
    for _ in 0..4 {
        io.fail_at = Some(io.calls.len());
        assert_eq!(owner.ensure(&mut io), Err(BankError::Backend(42)));
        assert_eq!(owner.snapshot(), held);
        assert_eq!(io.calls.last(), Some(&("mint", 101)));
    }
    io.fail_at = None;
    assert_eq!(owner.ensure(&mut io), Ok(101));
    assert_eq!(
        io.calls
            .iter()
            .filter(|(operation, _)| *operation == "retype")
            .count(),
        1
    );
}

#[test]
fn invalid_geometry_has_no_backend_effects() {
    for radix in [0, 64, u32::MAX] {
        let mut owner = ProviderAliasSegment::new(radix);
        let mut io = Io::default();
        assert_eq!(owner.ensure(&mut io), Err(BankError::InvalidRequest));
        assert!(io.calls.is_empty());
    }
}

#[test]
fn malformed_reserved_slots_do_not_publish_a_segment() {
    let mut owner = ProviderAliasSegment::new(12);
    let mut io = Io {
        null_slot: true,
        ..Io::default()
    };
    assert_eq!(owner.ensure(&mut io), Err(BankError::InvalidBackend));
    assert_eq!(owner.snapshot().raw, 0);
    io.null_slot = false;
    io.same_slot = true;
    assert_eq!(owner.ensure(&mut io), Err(BankError::InvalidBackend));
    assert_eq!(
        owner.snapshot(),
        ProviderAliasSegmentSnapshot {
            raw: 100,
            raw_retyped: true,
            guarded: 0,
            guarded_minted: false,
        }
    );
    assert_eq!(
        io.calls
            .iter()
            .filter(|(operation, _)| *operation == "mint")
            .count(),
        0
    );
}
