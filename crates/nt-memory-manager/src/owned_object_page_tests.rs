use super::*;
use alloc::collections::BTreeMap;
use alloc::vec;

const FAILED: u32 = 0xc000_0001;
const FRAME: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target {
    root: u64,
    generation: u64,
}

const ROOT: Target = Target {
    root: 1,
    generation: 9,
};
const A: Target = Target {
    root: 2,
    generation: 4,
};
const B: Target = Target {
    root: 3,
    generation: 6,
};

struct Cap {
    target: Target,
    populated: bool,
    mapped: bool,
}

struct Backend {
    calls: Vec<(&'static str, u64, Target, u64)>,
    fail: Vec<(&'static str, Target)>,
    caps: BTreeMap<u64, Cap>,
    next: u64,
    backing: bool,
    zero_acquire: bool,
    zero_copy: bool,
    bytes: u64,
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            fail: Vec::new(),
            caps: BTreeMap::new(),
            next: 20,
            backing: false,
            zero_acquire: false,
            zero_copy: false,
            bytes: 0,
        }
    }
}

impl Backend {
    fn check(
        &mut self,
        op: &'static str,
        cap: u64,
        target: Target,
        rights: u64,
    ) -> Result<(), u32> {
        self.calls.push((op, cap, target, rights));
        if self.fail.contains(&(op, target)) {
            Err(FAILED)
        } else {
            Ok(())
        }
    }
    fn count(&self, op: &str) -> usize {
        self.calls.iter().filter(|call| call.0 == op).count()
    }
}

impl ObjectPageIo<u64, Target> for Backend {
    fn acquire_zeroed_frame(&mut self, descriptor: &u64) -> Result<u64, u32> {
        assert_eq!(*descriptor, 77);
        self.check("acquire", FRAME, ROOT, 0)?;
        assert!(!self.backing);
        if self.zero_acquire {
            return Ok(0);
        }
        self.backing = true;
        self.bytes = 0;
        Ok(FRAME)
    }
    fn prepare_alias(&mut self, descriptor: &u64, target: Target) -> Result<(), u32> {
        assert_eq!(*descriptor, 77);
        assert!(self.backing);
        self.check("prepare", 0, target, 0)
    }
    fn copy(&mut self, frame: u64, target: Target) -> (u64, u32) {
        assert_eq!(frame, FRAME);
        assert!(self.backing);
        let slot = if self.zero_copy {
            0
        } else {
            self.next += 1;
            self.next
        };
        let result = self.check("copy", slot, target, 0);
        if slot != 0 {
            assert!(self
                .caps
                .insert(
                    slot,
                    Cap {
                        target,
                        populated: result.is_ok(),
                        mapped: false
                    }
                )
                .is_none());
        }
        (slot, result.err().unwrap_or(0))
    }
    fn map(&mut self, slot: u64, target: Target, rights: u64) -> Result<(), u32> {
        self.check("map", slot, target, rights)?;
        let cap = self.caps.get_mut(&slot).unwrap();
        assert_eq!(cap.target, target);
        assert!(cap.populated && !cap.mapped);
        cap.mapped = true;
        Ok(())
    }
    fn unmap(&mut self, slot: u64, target: Target) -> Result<(), u32> {
        self.check("unmap", slot, target, 0)?;
        let cap = self.caps.get_mut(&slot).unwrap();
        assert_eq!(cap.target, target);
        assert!(cap.populated && cap.mapped);
        cap.mapped = false;
        Ok(())
    }
    fn delete(&mut self, slot: u64, target: Target) -> Result<(), u32> {
        self.check("delete", slot, target, 0)?;
        let cap = self.caps.get_mut(&slot).unwrap();
        assert_eq!(cap.target, target);
        assert!(cap.populated && !cap.mapped);
        cap.populated = false;
        Ok(())
    }
    fn recycle_alias(&mut self, slot: u64, target: Target) -> Result<(), u32> {
        self.check("recycle", slot, target, 0)?;
        let cap = self.caps.remove(&slot).unwrap();
        assert_eq!(cap.target, target);
        assert!(!cap.populated && !cap.mapped);
        Ok(())
    }
    fn initialize(&mut self, descriptor: &u64, target: Target) -> Result<(), u32> {
        assert_eq!(*descriptor, 77);
        assert_eq!(target, ROOT);
        assert!(self
            .caps
            .values()
            .any(|cap| cap.target == ROOT && cap.mapped));
        self.check("initialize", 0, target, 0)?;
        self.bytes = 77;
        Ok(())
    }
    fn release_backing(&mut self, frame: u64) -> Result<(), u32> {
        assert_eq!(frame, FRAME);
        assert!(self.backing && self.caps.is_empty());
        self.check("release", frame, ROOT, 0)?;
        self.backing = false;
        Ok(())
    }
}

fn page() -> OwnedObjectPage<u64, Target> {
    OwnedObjectPage::new(77, ROOT)
}

#[test]
fn initializes_once_through_rw_alias_without_mapping_original_frame() {
    let mut page = page();
    let mut io = Backend::default();
    assert!(!page.is_initialized());
    page.construct(&mut io).unwrap();
    assert_eq!(page.descriptor(), &77);
    assert_eq!(page.root_target(), ROOT);
    assert_eq!(page.frame_cap(), Some(FRAME));
    assert_eq!(page.live_alias(ROOT), Some((21, ROOT_ALIAS_RIGHTS)));
    assert!(page.owns_cap(FRAME) && page.owns_cap(21));
    assert!(!page.owns_cap(0));
    assert!(!io
        .calls
        .iter()
        .any(|call| call.0 == "map" && call.1 == FRAME));
    io.bytes = 99;
    let calls = io.calls.len();
    page.construct(&mut io).unwrap();
    page.map_alias(ROOT, ROOT_ALIAS_RIGHTS, &mut io).unwrap();
    assert_eq!(io.calls.len(), calls);
    assert_eq!(io.bytes, 99, "live bytes must never be reinitialized");
    assert_eq!(page.map_alias(ROOT, 1, &mut io), Err(INVALID));
    page.retire(&mut io).unwrap();
    assert!(page.is_released());
}

#[test]
fn acquisition_failure_and_zero_cap_have_no_alias_effects() {
    for zero in [false, true] {
        let mut page = page();
        let mut io = Backend {
            zero_acquire: zero,
            ..Backend::default()
        };
        if !zero {
            io.fail.push(("acquire", ROOT));
        }
        assert_eq!(
            page.construct(&mut io),
            Err(if zero { RESOURCES } else { FAILED })
        );
        assert_eq!(page.frame_cap(), None);
        assert_eq!(io.count("copy"), 0);
        assert_eq!(io.count("initialize"), 0);
        io.fail.clear();
        io.zero_acquire = false;
        page.construct(&mut io).unwrap();
        page.retire(&mut io).unwrap();
    }
}

#[test]
fn prepare_failure_retains_backing_and_preadmitted_row() {
    let mut page = page();
    let mut io = Backend::default();
    io.fail.push(("prepare", ROOT));
    assert_eq!(page.construct(&mut io), Err(FAILED));
    assert_eq!(page.stats().alias_rows, 1);
    assert!(page.owns_cap(FRAME));
    assert_eq!(io.count("copy"), 0);
    io.fail.clear();
    page.construct(&mut io).unwrap();
    assert_eq!(io.count("acquire"), 1);
    assert_eq!(page.stats().alias_rows, 1);
    page.retire(&mut io).unwrap();
}

#[test]
fn failed_copy_retains_empty_slot_until_recycle_then_retries() {
    let mut page = page();
    let mut io = Backend::default();
    io.fail = vec![("copy", ROOT), ("recycle", ROOT)];
    assert_eq!(page.construct(&mut io), Err(FAILED));
    assert!(page.owns_cap(21));
    assert_eq!(page.stats().pending_aliases, 1);
    assert_eq!(io.count("delete"), 0);
    assert_eq!(page.construct(&mut io), Err(FAILED));
    assert_eq!(io.count("copy"), 1);
    io.fail.clear();
    page.construct(&mut io).unwrap();
    assert!(!page.owns_cap(21));
    assert_eq!(page.live_alias(ROOT), Some((22, ROOT_ALIAS_RIGHTS)));
    assert_eq!(io.count("acquire"), 1);
    page.retire(&mut io).unwrap();
}

#[test]
fn zero_copy_cap_never_maps_or_initializes() {
    let mut page = page();
    let mut io = Backend {
        zero_copy: true,
        ..Backend::default()
    };
    assert_eq!(page.construct(&mut io), Err(RESOURCES));
    assert_eq!(io.count("map"), 0);
    assert_eq!(io.count("initialize"), 0);
    assert_eq!(page.stats().alias_caps, 0);
    page.retire(&mut io).unwrap();
    assert_eq!(io.count("release"), 1);
}

#[test]
fn map_failure_retains_populated_candidate_and_retirement_drains_it() {
    let mut page = page();
    let mut io = Backend::default();
    io.fail = vec![("map", ROOT), ("delete", ROOT)];
    assert_eq!(page.construct(&mut io), Err(FAILED));
    assert!(page.owns_cap(21));
    assert_eq!(page.retire(&mut io), Err(FAILED));
    assert_eq!(io.count("release"), 0);
    assert_eq!(io.count("unmap"), 0);
    io.fail.clear();
    page.retire(&mut io).unwrap();
    assert!(page.is_released());
    assert_eq!(io.count("initialize"), 0);
    assert_eq!(page.construct(&mut io), Err(INVALID));
}

#[test]
fn initialization_failure_reuses_root_alias_but_forbids_other_targets() {
    let mut page = page();
    let mut io = Backend::default();
    io.fail.push(("initialize", ROOT));
    assert_eq!(page.construct(&mut io), Err(FAILED));
    assert!(!page.is_initialized());
    assert_eq!(page.live_alias(ROOT), None);
    assert_eq!(page.map_alias(A, 1, &mut io), Err(INVALID));
    io.fail.clear();
    page.construct(&mut io).unwrap();
    assert_eq!(io.count("acquire"), 1);
    assert_eq!(io.count("copy"), 1);
    assert_eq!(io.count("map"), 1);
    assert_eq!(io.count("initialize"), 2);
    page.retire(&mut io).unwrap();
}

#[test]
fn exact_targets_are_independent_and_idempotent() {
    let mut page = page();
    let mut io = Backend::default();
    page.construct(&mut io).unwrap();
    page.map_alias(A, 1, &mut io).unwrap();
    let a = page.live_alias(A).unwrap();
    io.fail = vec![("map", B), ("delete", B)];
    assert_eq!(page.map_alias(B, 1, &mut io), Err(FAILED));
    assert_eq!(page.live_alias(A), Some(a));
    assert_eq!(page.live_alias(B), None);
    let calls = io.calls.len();
    page.map_alias(A, 1, &mut io).unwrap();
    assert_eq!(io.calls.len(), calls);
    io.fail.clear();
    page.map_alias(B, 1, &mut io).unwrap();
    let next_generation = Target {
        generation: A.generation + 1,
        ..A
    };
    page.map_alias(next_generation, 1, &mut io).unwrap();
    assert_ne!(page.live_alias(next_generation).unwrap().0, a.0);
    assert_eq!(page.stats().alias_rows, 4);
    page.retire(&mut io).unwrap();
}

#[test]
fn remap_recovers_old_mapping_before_reusing_same_cap() {
    let mut page = page();
    let mut io = Backend::default();
    page.construct(&mut io).unwrap();
    page.map_alias(A, 1, &mut io).unwrap();
    let cap = page.live_alias(A).unwrap().0;
    io.fail.push(("map", A));
    assert_eq!(page.map_alias(A, 3, &mut io), Err(FAILED));
    assert_eq!(page.live_alias(A), None);
    assert!(page.owns_cap(cap));
    let copies = io.count("copy");
    io.fail.clear();
    page.map_alias(A, 3, &mut io).unwrap();
    assert_eq!(io.count("copy"), copies);
    assert_eq!(page.live_alias(A), Some((cap, 3)));
    let maps: Vec<_> = io
        .calls
        .iter()
        .filter(|call| call.0 == "map" && call.2 == A)
        .map(|call| call.3)
        .collect();
    assert_eq!(maps, vec![1, 3, 1, 1, 3]);
    assert_eq!(io.count("initialize"), 1);
    page.retire(&mut io).unwrap();
}

#[test]
fn each_retirement_failure_preserves_progress_and_withdraws_admission() {
    for stage in ["unmap", "delete", "recycle", "release"] {
        let mut page = page();
        let mut io = Backend::default();
        page.construct(&mut io).unwrap();
        page.map_alias(A, 1, &mut io).unwrap();
        io.fail
            .push((stage, if stage == "release" { ROOT } else { A }));
        assert_eq!(page.retire(&mut io), Err(FAILED));
        assert!(!page.is_initialized() && !page.is_released());
        assert!(page.owns_cap(FRAME));
        assert_eq!(page.live_alias(ROOT), None);
        assert_eq!(page.map_alias(B, 1, &mut io), Err(INVALID));
        assert_eq!(page.construct(&mut io), Err(INVALID));
        let root_unmaps = io
            .calls
            .iter()
            .filter(|call| call.0 == "unmap" && call.2 == ROOT)
            .count();
        io.fail.clear();
        page.retire(&mut io).unwrap();
        assert!(page.is_released());
        assert!(!page.owns_cap(FRAME));
        assert_eq!(root_unmaps, usize::from(stage == "release"));
        assert_eq!(
            io.calls
                .iter()
                .filter(|call| call.0 == "unmap" && call.2 == ROOT)
                .count(),
            1
        );
        let calls = io.calls.len();
        page.retire(&mut io).unwrap();
        assert_eq!(io.calls.len(), calls);
    }
}

#[test]
fn retirement_before_acquisition_has_no_backend_effects() {
    let mut page = page();
    let mut io = Backend::default();
    assert!(!page.is_released());
    page.retire(&mut io).unwrap();
    assert!(page.is_released());
    assert!(io.calls.is_empty());
    assert_eq!(page.construct(&mut io), Err(INVALID));
}

#[test]
fn retirement_after_initialization_error_never_retries_initialization() {
    let mut page = page();
    let mut io = Backend::default();
    io.fail.push(("initialize", ROOT));
    assert_eq!(page.construct(&mut io), Err(FAILED));
    page.retire(&mut io).unwrap();
    assert_eq!(io.count("initialize"), 1);
    assert!(page.is_released());
}

#[test]
fn failed_provider_retirement_keeps_root_mapping_until_every_provider_alias_drains() {
    let mut page = page();
    let mut io = Backend::default();
    page.construct(&mut io).unwrap();
    page.map_alias(A, 1, &mut io).unwrap();
    page.map_alias(B, 1, &mut io).unwrap();
    let root_cap = page.live_alias(ROOT).unwrap().0;
    io.fail.push(("delete", B));
    assert_eq!(page.retire(&mut io), Err(FAILED));
    assert_eq!(
        page.live_alias(ROOT),
        None,
        "retirement withdraws public mapping admission"
    );
    assert!(io.caps.get(&root_cap).unwrap().mapped);
    assert_eq!(
        page.aliases
            .iter()
            .find(|row| row.target == ROOT)
            .unwrap()
            .transition
            .live(),
        Some((root_cap, ROOT_ALIAS_RIGHTS))
    );
    assert!(page.owns_cap(root_cap) && page.owns_cap(FRAME));
    assert_eq!(io.count("release"), 0);
    io.fail.clear();
    page.retire(&mut io).unwrap();
    let root_unmap = io
        .calls
        .iter()
        .position(|call| call.0 == "unmap" && call.2 == ROOT)
        .unwrap();
    let last_provider_recycle = io
        .calls
        .iter()
        .rposition(|call| call.0 == "recycle" && call.2 != ROOT)
        .unwrap();
    assert!(last_provider_recycle < root_unmap);
}
