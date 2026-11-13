//! A captured mounted directory query is a live signaler before any physical sector is claimed.

extern crate alloc;

#[path = "../../../components/ntos-executive/src/mounted_directory_lookup.rs"]
mod mounted_directory_lookup;

const DIRECTORY: &str = include_str!("../../../components/ntos-executive/src/mounted_directory_lookup.rs");
const VOLUME: &str = include_str!("../../../components/ntos-executive/src/mounted_volume.rs");
const BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn quiesce_uses_the_retained_directory_queue_not_a_physical_claim() {
    let owner = DIRECTORY.find("pub fn has_outstanding(&self)").expect("directory queue owner predicate");
    let predicate = &DIRECTORY[owner..DIRECTORY[owner..].find('\n').unwrap() + owner];
    assert!(predicate.contains("!self.entries.is_empty()"),
        "claimed and resolved directory IRPs still need completion handoff");

    let accessor = VOLUME.find("pub(crate) fn mounted_directory_outstanding()")
        .expect("mounted directory owner accessor");
    let accessor = &VOLUME[accessor..VOLUME[accessor..].find("\n}").unwrap() + accessor];
    assert!(accessor.contains("MOUNT_DIRECTORY_QUEUE"));
    assert!(accessor.contains("has_outstanding()"));
    assert!(!accessor.contains("claim_next()"),
        "a claimed sector cannot erase the logical directory owner");
    assert!(BLOCK.contains("claim_mounted_directory_sector()"),
        "the native service lane must redrive the retained directory owner");
}

#[test]
fn every_no_signaler_gate_defers_for_mounted_directory_owner() {
    let crash_guard = SERVICE.split_once("macro_rules! park_and_log").unwrap().1
        .split_once("macro_rules! mark_wait_parked").unwrap().0;
    let waiting_guard = SERVICE.split_once("macro_rules! mark_wait_parked").unwrap().1
        .split_once("// Boot-milestone watchdog").unwrap().0;
    let lsass_guard = SERVICE.split_once("b\"lsass-post-signal-fault\"").unwrap().1
        .split_once("[quiesce] every live process parked/waiting").unwrap().0;
    for (site, guard) in [
        ("crash park", crash_guard),
        ("cooperative wait", waiting_guard),
        ("LSASS fault", lsass_guard),
    ] {
        assert!(guard.contains("!crate::mounted_volume::mounted_directory_outstanding()"),
            "{site} quiesced while an exact mounted directory IRP can redrive its parked caller");
    }
}
