//! The WDDM bridge interface dxgkrnl returns to win32k for `IOCTL_WDDM_BRIDGE_QUERY_INTERFACE`.
//!
//! Boot 44510687412: win32k called dxgkrnl+0xa8060 (slot 0x268, SendIoctl) from its own lane.
//! Provider code addresses must never reach win32k; each slot is rewritten to an entry in
//! win32k's domain, and a routed entry reaches the provider only through an exact binding.

use nt_io_manager::wddm_bridge_interface::*;

const RUN_VA: u64 = 0x0000_0100_0e00_0000;
const IMAGE_LEN: u64 = 0x10_0000;
const CALLER: BridgeCallerIdentity = BridgeCallerIdentity { domain: 3, generation: 7 };
const PROVIDER: BridgeProviderIdentity = BridgeProviderIdentity {
    instance: 15,
    domain_id: 21,
    domain_cookie: 0x5151,
    publication_cookie: 9,
};

fn word(output: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(output[offset..offset + 8].try_into().unwrap())
}

/// Version 8: every slot present except 0x230, each at `RUN_VA + offset * 0x100`.
fn interface() -> [u8; WDDM_BRIDGE_INTERFACE_LEN] {
    let mut output = [0u8; WDDM_BRIDGE_INTERFACE_LEN];
    output[..8].copy_from_slice(&0x0000_0270_0000_0008u64.to_le_bytes());
    for offset in (WDDM_BRIDGE_FIRST_SLOT..WDDM_BRIDGE_INTERFACE_LEN).step_by(8) {
        let target = if offset == 0x230 { 0 } else { RUN_VA + offset as u64 * 0x100 };
        output[offset..offset + 8].copy_from_slice(&target.to_le_bytes());
    }
    output
}

fn entry(slot: usize, route: BridgeSlotRoute) -> u64 {
    match route {
        BridgeSlotRoute::Routed => 0xa000 + slot as u64,
        BridgeSlotRoute::Unrouted => 0xf000 + slot as u64,
    }
}

fn projected() -> BridgeProjection {
    let mut output = interface();
    project_bridge_interface(&mut output, RUN_VA, IMAGE_LEN, |_| true, entry).unwrap()
}

#[test]
fn only_send_ioctl_has_a_route() {
    // win32k's only indirect call through the table is WddmBridgeSendIoctl's (VMA 0x16526d).
    assert_eq!(WDDM_BRIDGE_SEND_IOCTL_SLOT, (0x268 - WDDM_BRIDGE_FIRST_SLOT) / 8);
    for slot in 0..WDDM_BRIDGE_SLOT_COUNT {
        let expected = if slot == WDDM_BRIDGE_SEND_IOCTL_SLOT {
            BridgeSlotRoute::Routed
        } else {
            BridgeSlotRoute::Unrouted
        };
        assert_eq!(bridge_slot_route(slot), expected);
    }
}

#[test]
fn no_provider_code_address_survives_projection() {
    let mut output = interface();
    let projection =
        project_bridge_interface(&mut output, RUN_VA, IMAGE_LEN, |_| true, entry).unwrap();
    assert_eq!(&output[..8], &0x0000_0270_0000_0008u64.to_le_bytes());
    assert_eq!(word(&output, 0x268), 0xa000 + WDDM_BRIDGE_SEND_IOCTL_SLOT as u64);
    assert_eq!(word(&output, 0x8), 0xf000);
    assert_eq!(word(&output, 0x230), 0, "a slot absent at this version stays absent");
    for offset in (WDDM_BRIDGE_FIRST_SLOT..WDDM_BRIDGE_INTERFACE_LEN).step_by(8) {
        assert!(!(RUN_VA..RUN_VA + IMAGE_LEN).contains(&word(&output, offset)));
    }
    assert_eq!(projection.provider_rva(WDDM_BRIDGE_SEND_IOCTL_SLOT), Some(0x268 * 0x100));
    assert_eq!(projection.provider_rva((0x230 - WDDM_BRIDGE_FIRST_SLOT) / 8), None);
}

#[test]
fn a_slot_outside_the_provider_code_rejects_the_whole_table() {
    let original = interface();
    let mut output = original;
    output[0x10..0x18].copy_from_slice(&(RUN_VA + IMAGE_LEN).to_le_bytes());
    assert_eq!(
        project_bridge_interface(&mut output, RUN_VA, IMAGE_LEN, |_| true, entry),
        Err(BridgeProjectionError::SlotOutsideProvider { slot: 1 })
    );
    let mut nonexecutable = original;
    assert_eq!(
        project_bridge_interface(&mut nonexecutable, RUN_VA, IMAGE_LEN,
            |rva| rva != 0x268 * 0x100, entry),
        Err(BridgeProjectionError::SlotOutsideProvider { slot: WDDM_BRIDGE_SEND_IOCTL_SLOT })
    );
    assert_eq!(nonexecutable, original, "nothing is rewritten before every slot is proven");
    let mut short = [0u8; WDDM_BRIDGE_INTERFACE_LEN - 8];
    assert_eq!(
        project_bridge_interface(&mut short, RUN_VA, IMAGE_LEN, |_| true, entry),
        Err(BridgeProjectionError::Length)
    );
}

#[test]
fn a_routed_slot_resolves_only_for_the_exact_caller_and_live_provider() {
    let mut bindings = BridgeBindings::new();
    bindings.publish(CALLER, PROVIDER, projected()).unwrap();
    let live = |provider: BridgeProviderIdentity| provider == PROVIDER;
    let target = bindings.resolve(CALLER, WDDM_BRIDGE_SEND_IOCTL_SLOT, live).unwrap();
    assert_eq!(target.provider, PROVIDER);
    assert_eq!(target.provider_rva, 0x268 * 0x100);

    let other_generation = BridgeCallerIdentity { generation: 8, ..CALLER };
    assert_eq!(
        bindings.resolve(other_generation, WDDM_BRIDGE_SEND_IOCTL_SLOT, live),
        Err(BridgeResolveError::NoBinding)
    );
    assert_eq!(
        bindings.resolve(CALLER, 0, live),
        Err(BridgeResolveError::Unrouted),
        "an unrouted slot never reaches the provider"
    );
    assert_eq!(
        bindings.resolve(CALLER, WDDM_BRIDGE_SLOT_COUNT, live),
        Err(BridgeResolveError::Unrouted)
    );
}

#[test]
fn a_republished_provider_identity_never_inherits_an_old_binding() {
    for changed in [
        BridgeProviderIdentity { domain_cookie: 0x5152, ..PROVIDER },
        BridgeProviderIdentity { domain_id: 22, ..PROVIDER },
        BridgeProviderIdentity { publication_cookie: 10, ..PROVIDER },
    ] {
        let mut bindings = BridgeBindings::new();
        bindings.publish(CALLER, PROVIDER, projected()).unwrap();
        assert_eq!(
            bindings.resolve(CALLER, WDDM_BRIDGE_SEND_IOCTL_SLOT, |live| live == changed),
            Err(BridgeResolveError::ProviderRetired)
        );
        assert_eq!(
            bindings.resolve(CALLER, WDDM_BRIDGE_SEND_IOCTL_SLOT, |live| live == PROVIDER),
            Err(BridgeResolveError::NoBinding),
            "a stale binding is dropped, not revived"
        );
    }
    let mut bindings = BridgeBindings::new();
    bindings.publish(CALLER, PROVIDER, projected()).unwrap();
    assert_eq!(
        bindings.resolve(CALLER, WDDM_BRIDGE_SEND_IOCTL_SLOT, |_| false),
        Err(BridgeResolveError::ProviderRetired)
    );
}

#[test]
fn provider_retirement_drops_its_bindings() {
    let mut bindings = BridgeBindings::new();
    bindings.publish(CALLER, PROVIDER, projected()).unwrap();
    let other = BridgeCallerIdentity { domain: 4, generation: 1 };
    let other_provider = BridgeProviderIdentity { instance: 16, domain_id: 30, ..PROVIDER };
    bindings.publish(other, other_provider, projected()).unwrap();
    assert_eq!(bindings.retire_provider(PROVIDER.domain_id, PROVIDER.domain_cookie), 1);
    let live = |provider: BridgeProviderIdentity| provider == PROVIDER || provider == other_provider;
    assert_eq!(
        bindings.resolve(CALLER, WDDM_BRIDGE_SEND_IOCTL_SLOT, live),
        Err(BridgeResolveError::NoBinding)
    );
    assert!(bindings.resolve(other, WDDM_BRIDGE_SEND_IOCTL_SLOT, live).is_ok());
}

#[test]
fn a_new_query_replaces_the_callers_binding() {
    let mut bindings = BridgeBindings::new();
    bindings.publish(CALLER, PROVIDER, projected()).unwrap();
    let successor = BridgeProviderIdentity { domain_cookie: 0x6161, publication_cookie: 11, ..PROVIDER };
    bindings.publish(CALLER, successor, projected()).unwrap();
    assert_eq!(bindings.len(), 1);
    let target = bindings
        .resolve(CALLER, WDDM_BRIDGE_SEND_IOCTL_SLOT, |live| live == successor)
        .unwrap();
    assert_eq!(target.provider, successor);
}

#[test]
fn an_absent_send_ioctl_slot_has_no_target() {
    let mut output = interface();
    output[0x268..0x270].fill(0);
    let projection =
        project_bridge_interface(&mut output, RUN_VA, IMAGE_LEN, |_| true, entry).unwrap();
    let mut bindings = BridgeBindings::new();
    bindings.publish(CALLER, PROVIDER, projection).unwrap();
    assert_eq!(
        bindings.resolve(CALLER, WDDM_BRIDGE_SEND_IOCTL_SLOT, |live| live == PROVIDER),
        Err(BridgeResolveError::AbsentSlot)
    );
}
