//! A parked mounted CREATE keeps its exact Executive File owner through terminal delivery.

#[path = "../../../components/ntos-executive/src/mounted_create_owner_snapshot.rs"]
mod mounted_create_owner_snapshot;

use mounted_create_owner_snapshot::{OwnerKey, OwnerSnapshot, Phase};

const HANDOFF: &str = include_str!("../../../components/ntos-executive/src/file_dispatch_handoff.rs");
const DELIVERY: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const EXEC: &str = include_str!("../../../components/ntos-executive/src/main.rs");

fn key(irp: u64, slot: u64, generation: u64, device: u64, physical: u64) -> OwnerKey {
    OwnerKey { table: 7, slot, generation, irp, file: irp + 100, device,
        physical, logical: 9 }
}

#[test]
fn stale_owner_cannot_inherit_terminal_reply_or_ack_from_another_create() {
    let snapshot = OwnerSnapshot::new();
    let a = key(130, 2, 4, 19, 5);
    let b = key(131, 2, 5, 19, 5);
    assert!(snapshot.park(a, 0, 24, 0xabc, 0x1234, 8, 2, 100));
    assert!(snapshot.park(b, 1, 25, 0xdef, 0x5678, 12, 3, 200));
    assert!(!snapshot.advance(a, Phase::Terminal, 0, 0, 300));
    assert!(!snapshot.advance(OwnerKey { device: 20, ..b }, Phase::Terminal, 0, 0, 301));
    assert!(!snapshot.advance(OwnerKey { physical: 6, ..b }, Phase::Terminal, 0, 0, 302));
    assert!(!snapshot.advance(OwnerKey { logical: 10, ..b }, Phase::Terminal, 0, 0, 303));
    let before = snapshot.read().unwrap();
    assert_eq!(before.key, b);
    assert_eq!(before.phase, Phase::Parked);
    assert_eq!(before.delivery, 0);
    assert_eq!(before.parked_100ns, 200);
    assert_eq!(before.terminal_100ns, None);
    assert_eq!(before.reply_100ns, None);
    assert_eq!(before.ack_100ns, None);
    assert!(snapshot.advance(b, Phase::Terminal, 0, 0, 400));
    assert_eq!(snapshot.read().unwrap().delivery, 0,
        "a provider terminal is not Reply publication or backend ACK");
    assert!(snapshot.advance(b, Phase::Terminal, 0, 0, 450));
    assert_eq!(snapshot.read().unwrap().terminal_100ns, Some(400),
        "a repeated terminal cannot reset its first observed timestamp");
    assert!(snapshot.advance(b, Phase::ReplyPublished, 0, 1 << 7, 500));
    assert_eq!(snapshot.read().unwrap().delivery & (1 << 8), 0);
    assert!(snapshot.advance(b, Phase::BackendAcked, 0, (1 << 7) | (1 << 8), 600));
    let acked = snapshot.read().unwrap();
    assert_eq!(acked.delivery, (1 << 7) | (1 << 8));
    assert_eq!((acked.parked_100ns, acked.terminal_100ns,
        acked.reply_100ns, acked.ack_100ns),
        (200, Some(400), Some(500), Some(600)));
    assert!(snapshot.advance(b, Phase::BackendAcked, 0, (1 << 7) | (1 << 8), 650));
    assert_eq!(snapshot.read().unwrap().ack_100ns, Some(600),
        "a repeated ACK cannot reset its first observed timestamp");
    assert!(!snapshot.advance(a, Phase::BackendAcked, 0, 0, 700));
    assert_eq!(snapshot.read().unwrap(), acked,
        "a stale owner must not change the observed timing or delivery");
}

#[test]
fn native_wiring_observes_exact_park_and_delivery_without_census_borrow() {
    assert!(HANDOFF.contains("mounted_create_owner_trace::park_exact"));
    assert!(DELIVERY.contains("mounted_create_owner_trace::terminal_exact"));
    assert!(DELIVERY.contains("mounted_create_owner_trace::reply_exact"));
    assert!(DELIVERY.contains("mounted_create_owner_trace::ack_exact"));
    assert!(EXEC.contains("service_sec_image::mounted_create_owner_trace::print_snapshot()"));
    let census = EXEC.split("pub(crate) fn census_tick_static(").nth(1).unwrap()
        .split("fn print_add_device_rollback_census").next().unwrap();
    assert!(!census.contains("PENDING_FILE_IO"));
    assert!(!census.contains("MOUNT_CREATE_QUEUE"));
}
