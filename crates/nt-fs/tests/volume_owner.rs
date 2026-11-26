use nt_fs::VolumeOwnerGate;

#[test]
fn moved_out_volume_owner_refuses_peers_and_releases_only_on_exact_consumption() {
    let gate = VolumeOwnerGate::new();
    let mut volume = Some(41);
    let owner = gate.try_claim().ok().unwrap();
    let moved = volume.take().unwrap();
    let first = owner.epoch();
    assert!(gate.is_owned());
    assert!(gate.try_claim().is_err());
    volume = Some(moved);
    assert!(unsafe { owner.release() }.is_ok());
    assert!(!gate.is_owned());

    let next = gate.try_claim().ok().unwrap();
    let moved = volume.take().unwrap();
    assert!(next.epoch() > first);
    volume = Some(moved);
    assert!(unsafe { next.release() }.is_ok());
    assert!(!gate.is_owned());
}

#[test]
fn uncertain_or_lost_owner_keeps_volume_fenced() {
    let gate = VolumeOwnerGate::new();
    let mut volume = Some(41);
    let owner = gate.try_claim().ok().unwrap();
    let _moved = volume.take().unwrap();
    drop(owner);
    assert!(gate.is_owned());
    assert!(gate.try_claim().is_err());
}

#[test]
fn one_volume_owner_cannot_release_a_different_volume() {
    let first = VolumeOwnerGate::new();
    let second = VolumeOwnerGate::new();
    let mut first_volume = Some(41);
    let mut second_volume = Some(42);
    let first_owner = first.try_claim().ok().unwrap();
    let second_owner = second.try_claim().ok().unwrap();
    let first_moved = first_volume.take().unwrap();
    let second_moved = second_volume.take().unwrap();
    first_volume = Some(first_moved);
    assert!(unsafe { first_owner.release() }.is_ok());
    assert!(!first.is_owned());
    assert!(second.is_owned());
    assert!(second.try_claim().is_err());
    second_volume = Some(second_moved);
    assert!(unsafe { second_owner.release() }.is_ok());
}
