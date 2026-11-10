use nt_compat_exports::debug_filter::{DebugFilterMasks, SetFilterError};

const SYSTEM_WIDE: u32 = u32::MAX;
const UNKNOWN_COMPONENT: u32 = 200;
const LAST_COMPONENT: u32 = 155;
const RAW_MASK: u32 = 0x8000_0000;

#[test]
fn initial_system_mask_enables_only_error_across_components() {
    let masks = DebugFilterMasks::new();
    for component in [0, LAST_COMPONENT, UNKNOWN_COMPONENT, SYSTEM_WIDE] {
        assert!(masks.query(component, 0));
        assert!(!masks.query(component, 1));
        assert!(!masks.query(component, RAW_MASK | 0b100));
    }
}

#[test]
fn unknown_components_share_default_mask_and_raw_levels_convert_like_reactos() {
    let mut masks = DebugFilterMasks::new();
    masks.set(UNKNOWN_COMPONENT, 2, true, true).unwrap();
    assert!(masks.query(UNKNOWN_COMPONENT + 1, 2));
    assert!(masks.query(UNKNOWN_COMPONENT + 1, RAW_MASK | 0b100));
    assert!(!masks.query(LAST_COMPONENT, 2));
    assert!(!masks.query(UNKNOWN_COMPONENT, RAW_MASK));
    masks.set(UNKNOWN_COMPONENT, RAW_MASK | 0b100, false, true).unwrap();
    assert!(!masks.query(UNKNOWN_COMPONENT + 1, 2));
}

#[test]
fn privilege_denial_preserves_state_and_system_mask_changes_are_visible() {
    let mut masks = DebugFilterMasks::new();
    assert_eq!(masks.set(SYSTEM_WIDE, 0, false, false), Err(SetFilterError::AccessDenied));
    assert!(masks.query(12, 0));
    masks.set(SYSTEM_WIDE, 0, false, true).unwrap();
    assert!(!masks.query(12, 0));
    masks.set(12, 0, true, true).unwrap();
    assert!(masks.query(12, 0));
    assert!(!masks.query(13, 0));
}
