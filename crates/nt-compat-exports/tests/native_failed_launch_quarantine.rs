//! A driver launch whose rollback is refused is retained, not a root panic (#361).

extern crate alloc;

#[path = "../../../components/ntos-executive/src/failed_launch_quarantine.rs"]
mod failed_launch_quarantine;

use failed_launch_quarantine::{FailedLaunch, FailedLaunchQuarantine};

const DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;

fn launch(instance: usize, service: &[u8]) -> FailedLaunch {
    FailedLaunch {
        instance,
        service: service.to_vec(),
        load_status: 0xC000_009Au32 as i32,
        cleanup_status: DEVICE_BUSY,
        domain_id: 7,
        domain_cookie: 9,
    }
}

#[test]
fn a_refused_cleanup_keeps_the_instance_and_its_identity_until_retirement() {
    let mut quarantine = FailedLaunchQuarantine::new();
    quarantine.quarantine(launch(3, b"\\Driver\\E1000")).unwrap();
    assert!(quarantine.retains_instance(3));
    assert!(quarantine.blocks_reload(b"\\driver\\e1000"), "no same-name reload meanwhile");
    assert!(!quarantine.blocks_reload(b"\\Driver\\Other"));

    // The owner still refuses: the record and its original load status stay.
    assert!(quarantine.retire(|_| Err(DEVICE_BUSY)).is_empty());
    assert_eq!(quarantine.len(), 1);

    // A later retirement finishes the physical cleanup and releases the identity.
    assert_eq!(quarantine.retire(|instance| { assert_eq!(instance, 3); Ok(()) }), [3]);
    assert!(!quarantine.retains_instance(3));
    assert!(!quarantine.blocks_reload(b"\\Driver\\E1000"));
}

#[test]
fn one_record_per_instance() {
    let mut quarantine = FailedLaunchQuarantine::new();
    quarantine.quarantine(launch(1, b"a")).unwrap();
    let mut again = launch(1, b"a");
    again.cleanup_status = 0xC000_0001u32 as i32;
    quarantine.quarantine(again).unwrap();
    assert_eq!(quarantine.len(), 1);
}

#[test]
fn load_driver_retains_a_refused_rollback_instead_of_panicking() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(!launch.contains("driver launch rollback indeterminate"));
    assert!(launch.contains("pub(crate) unsafe fn retire_quarantined_launches()"));
}
