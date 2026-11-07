use nt_hosted_runtime::{HostedDriverThreadObjectKey, HostedDriverThreadObjectRecord};

fn key(cookie: u64) -> HostedDriverThreadObjectKey {
    HostedDriverThreadObjectKey::new(7, 0x71, cookie, 0x8008_0002, 0x262d2, 0x1000_e85e190)
        .unwrap()
}

#[test]
fn system_thread_wait_signals_only_after_exact_termination() {
    let identity = key(9);
    let mut object = HostedDriverThreadObjectRecord::new(identity);
    assert!(object.publish_canonical(identity, 4, 96, 0x44, 0x1f_ffff));
    assert_eq!(object.canonical(), Some((4, 96, 0x44, 0x1f_ffff)));
    assert!(!object.wait_ready(identity));
    assert!(object.terminate(identity));
    assert!(object.wait_ready(identity));
    // PM may report termination before its retained pointer reference is
    // released. Retrying that same physical retirement must still pass.
    assert!(object.terminate(identity));
}

#[test]
fn system_thread_object_rejects_cross_generation_and_repeated_effects() {
    let identity = key(9);
    let other_generation = key(10);
    let mut object = HostedDriverThreadObjectRecord::new(identity);
    assert!(!object.publish_canonical(other_generation, 4, 96, 0x44, 0x1f_ffff));
    assert!(!object.publish_canonical(identity, 0, 96, 0x44, 0x1f_ffff));
    assert!(!object.publish_canonical(identity, 4, 0, 0x44, 0x1f_ffff));
    assert!(!object.publish_canonical(identity, 4, 96, 0, 0x1f_ffff));
    assert!(!object.terminate(identity));
    assert!(!object.terminate(other_generation));
    assert!(object.publish_canonical(identity, 4, 96, 0x44, 0x1f_ffff));
    assert!(!object.publish_canonical(identity, 4, 97, 0x48, 0x1f_ffff));
    assert!(!object.matches_public(identity, 4, 96, 0x48));
    assert!(!object.matches_public(other_generation, 4, 96, 0x44));
    assert!(object.matches_public(identity, 4, 96, 0x44));
    assert!(!object.terminate(other_generation));
    assert!(object.terminate(identity));
    assert!(object.terminate(identity));
}
