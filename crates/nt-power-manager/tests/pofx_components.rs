//! The PoFx activation count belongs to one registered PDO and driver instance.
//! A native POHANDLE is only a projection of this owned, generation-safe record.

use nt_power_manager::pofx::{ComponentEvent, PofxError, PofxManager};

const OWNER: u64 = 0x50;
const PDO: u64 = 0x60;

#[test]
fn activation_before_start_keeps_only_that_component_active() {
    let mut pofx = PofxManager::new();
    let handle = pofx.register(OWNER, PDO, 2).unwrap();

    // Registration starts with every component accessible in F0. A reference
    // acquired before StartDevicePowerManagement keeps its component active.
    assert_eq!(pofx.activate(OWNER, handle, 1).unwrap(), ComponentEvent::None);
    assert_eq!(pofx.start(OWNER, handle).unwrap(), vec![0]);
    assert_eq!(pofx.component(OWNER, handle, 0).unwrap().references, 0);
    assert_eq!(pofx.component(OWNER, handle, 1).unwrap().references, 1);
    assert!(!pofx.component(OWNER, handle, 0).unwrap().active);
    assert!(pofx.component(OWNER, handle, 1).unwrap().active);

    assert_eq!(
        pofx.activate(OWNER, handle, 0).unwrap(),
        ComponentEvent::BecameActive
    );
    assert_eq!(pofx.activate(OWNER, handle, 0).unwrap(), ComponentEvent::None);
    assert_eq!(pofx.component(OWNER, handle, 0).unwrap().references, 2);
}

#[test]
fn idle_balances_each_activation_and_only_final_release_changes_condition() {
    let mut pofx = PofxManager::new();
    let handle = pofx.register(OWNER, PDO, 1).unwrap();
    assert_eq!(pofx.start(OWNER, handle).unwrap(), vec![0]);

    assert_eq!(pofx.activate(OWNER, handle, 0).unwrap(), ComponentEvent::BecameActive);
    assert_eq!(pofx.activate(OWNER, handle, 0).unwrap(), ComponentEvent::None);
    assert_eq!(pofx.idle(OWNER, handle, 0).unwrap(), ComponentEvent::None);
    assert!(pofx.component(OWNER, handle, 0).unwrap().active);
    assert_eq!(pofx.idle(OWNER, handle, 0).unwrap(), ComponentEvent::BecameIdle);
    assert!(!pofx.component(OWNER, handle, 0).unwrap().active);
    assert_eq!(pofx.idle(OWNER, handle, 0), Err(PofxError::UnbalancedIdle));
}

#[test]
fn registration_handle_is_scoped_to_exact_owner_and_lifetime() {
    let mut pofx = PofxManager::new();
    let handle = pofx.register(OWNER, PDO, 1).unwrap();
    assert_eq!(pofx.register(OWNER, PDO, 1), Err(PofxError::AlreadyRegistered));
    assert_eq!(pofx.activate(OWNER + 1, handle, 0), Err(PofxError::WrongOwner));
    assert_eq!(pofx.activate(OWNER, handle, 1), Err(PofxError::InvalidComponent));

    pofx.unregister(OWNER, handle).unwrap();
    let replacement = pofx.register(OWNER, PDO, 1).unwrap();
    assert_ne!(replacement, handle);
    assert_eq!(pofx.activate(OWNER, handle, 0), Err(PofxError::UnknownHandle));
    assert_eq!(pofx.activate(OWNER, replacement, 0).unwrap(), ComponentEvent::None);
}

#[test]
fn distinct_registrations_cannot_change_each_others_counts() {
    let mut pofx = PofxManager::new();
    let first = pofx.register(OWNER, PDO, 1).unwrap();
    let second = pofx.register(OWNER + 1, PDO + 1, 1).unwrap();
    pofx.start(OWNER, first).unwrap();
    pofx.start(OWNER + 1, second).unwrap();

    assert_eq!(pofx.activate(OWNER, first, 0).unwrap(), ComponentEvent::BecameActive);
    assert_eq!(pofx.component(OWNER + 1, second, 0).unwrap().references, 0);
    pofx.unregister(OWNER, first).unwrap();
    assert_eq!(pofx.component(OWNER + 1, second, 0).unwrap().references, 0);
}
