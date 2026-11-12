use nt_io_manager::video_monitor_array_projection::{
    MonitorPdoIdentity, MonitorPdoReferenceLedger,
};
use nt_io_manager::{HostedDomainId, HostedDomainIdentity};

fn child_with_provider(cookie: u64, address: u64, generation: u64) -> MonitorPdoIdentity {
    MonitorPdoIdentity::new(
        HostedDomainIdentity { domain_id: HostedDomainId(7), cookie },
        address,
        generation,
    ).unwrap()
}

fn child(address: u64, generation: u64) -> MonitorPdoIdentity {
    child_with_provider(0x70, address, generation)
}

#[test]
fn populated_monitor_array_acquires_and_releases_each_pdo_once() {
    let first_child = child(0x1000, 11);
    let second_child = child(0x2000, 12);
    let mut references = MonitorPdoReferenceLedger::new(&[first_child, second_child]).unwrap();

    let first = references.begin_acquire().unwrap().unwrap();
    assert_eq!(first.pdo(), first_child);
    assert!(references.begin_acquire().is_err(), "an in-flight native effect cannot be replayed");
    references.complete_acquire(first).unwrap();

    let second = references.begin_acquire().unwrap().unwrap();
    assert_eq!(second.pdo(), second_child);
    references.complete_acquire(second).unwrap();
    assert!(references.begin_acquire().unwrap().is_none());

    let first_release = references.begin_release().unwrap().unwrap();
    assert_eq!(first_release.pdo(), first_child);
    assert!(references.begin_release().is_err(), "a native dereference cannot be duplicated");
    references.complete_release(first_release).unwrap();

    let second_release = references.begin_release().unwrap().unwrap();
    assert_eq!(second_release.pdo(), second_child);
    references.complete_release(second_release).unwrap();
    assert!(references.begin_release().unwrap().is_none());
    assert!(references.all_released());
}

#[test]
fn uncertain_reference_or_dereference_never_permits_replay() {
    let mut acquire = MonitorPdoReferenceLedger::new(&[child(0x3000, 13)]).unwrap();
    let ticket = acquire.begin_acquire().unwrap().unwrap();
    acquire.mark_uncertain(ticket).unwrap();
    assert!(acquire.begin_acquire().is_err());
    assert!(acquire.begin_release().is_err());

    let mut release = MonitorPdoReferenceLedger::new(&[child(0x3000, 13)]).unwrap();
    let ticket = release.begin_acquire().unwrap().unwrap();
    release.complete_acquire(ticket).unwrap();
    let ticket = release.begin_release().unwrap().unwrap();
    release.mark_uncertain(ticket).unwrap();
    assert!(release.begin_release().is_err());
    assert!(!release.all_released());
}

#[test]
fn stale_child_generation_cannot_complete_the_live_reference_effect() {
    let mut live = MonitorPdoReferenceLedger::new(&[child(0x4000, 22)]).unwrap();
    let mut stale = MonitorPdoReferenceLedger::new(&[child(0x4000, 21)]).unwrap();
    let live_ticket = live.begin_acquire().unwrap().unwrap();
    let stale_ticket = stale.begin_acquire().unwrap().unwrap();

    assert!(live.complete_acquire(stale_ticket).is_err());
    let mut stale_provider = MonitorPdoReferenceLedger::new(&[
        child_with_provider(0x6f, 0x4000, 22),
    ]).unwrap();
    let stale_provider_ticket = stale_provider.begin_acquire().unwrap().unwrap();
    assert!(live.complete_acquire(stale_provider_ticket).is_err());
    assert!(live.begin_acquire().is_err(), "the live effect is still in flight");
    live.complete_acquire(live_ticket).unwrap();

    let release = live.begin_release().unwrap().unwrap();
    live.complete_release(release).unwrap();
    assert!(live.all_released());
}
