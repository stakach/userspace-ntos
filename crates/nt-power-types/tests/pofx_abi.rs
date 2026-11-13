//! x64 PO_FX_DEVICE_V3 and component layouts consumed by pinned LiberNT dxgkrnl.

use core::mem::{offset_of, size_of};
use nt_power_types::pofx::{PoFxComponentIdleState, PoFxComponentV2, PoFxDeviceV3};

#[test]
fn released_dxgkrnl_registration_layout_matches_wdk_x64() {
    assert_eq!(size_of::<PoFxDeviceV3>(), 160);
    assert_eq!(offset_of!(PoFxDeviceV3, version), 0);
    assert_eq!(offset_of!(PoFxDeviceV3, component_active_condition_callback), 16);
    assert_eq!(offset_of!(PoFxDeviceV3, device_context), 88);
    assert_eq!(offset_of!(PoFxDeviceV3, component_count), 96);
    assert_eq!(offset_of!(PoFxDeviceV3, components), 104);
    assert_eq!(size_of::<PoFxComponentV2>(), 56);
    assert_eq!(offset_of!(PoFxComponentV2, idle_states), 32);
    assert_eq!(offset_of!(PoFxComponentV2, providers), 48);
    assert_eq!(size_of::<PoFxComponentIdleState>(), 24);
}
