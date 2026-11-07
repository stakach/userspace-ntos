use nt_pnp::acpi_hal_route_callback::{PciRouteCallback, PciRouteCallbackLedger};

fn callback(cookie: u64) -> PciRouteCallback {
    PciRouteCallback { domain_id: 7, domain_cookie: cookie, vspace: 13,
        image_base: 0x1000_0000, image_len: 0x8000, image_generation: 17,
        callback: 0x1000_1234 }
}

#[test]
fn callback_registration_retains_exact_image_owner_until_unregister() {
    let mut ledger = PciRouteCallbackLedger::new();
    let owner = callback(11);
    ledger.register(owner).unwrap();
    assert_eq!(ledger.current(), Some(owner));
    assert!(ledger.blocks_retirement(7, 11, 13));
    assert!(!ledger.blocks_retirement(7, 12, 13));
    assert!(ledger.unregister(7, 12, 13).is_err());
    assert_eq!(ledger.current(), Some(owner));
    ledger.unregister(7, 11, 13).unwrap();
    assert_eq!(ledger.current(), None);
}

#[test]
fn malformed_callback_extent_and_foreign_replacement_fail_closed() {
    let mut ledger = PciRouteCallbackLedger::new();
    let mut invalid = callback(11);
    invalid.callback = invalid.image_base + invalid.image_len;
    assert!(ledger.register(invalid).is_err());
    ledger.register(callback(11)).unwrap();
    assert!(ledger.register(callback(12)).is_err());
    assert_eq!(ledger.current(), Some(callback(11)));
}
