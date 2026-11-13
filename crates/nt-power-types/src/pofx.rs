//! AMD64 PoFx registration ABI from WDK `wdm.h`.
//!
//! Native callers pass a variable-length `PO_FX_DEVICE_V3` whose trailing
//! component array is represented here by its first element. Validate the
//! count and full range before reading more entries from driver memory.

pub const PO_FX_VERSION_V3: u32 = 3;
pub const PO_FX_FLAG_BLOCKING: u32 = 1;
pub const PO_FX_FLAG_ASYNC_ONLY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PoFxComponentIdleState {
    pub transition_latency: u64,
    pub residency_requirement: u64,
    pub nominal_power: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PoFxComponentV2 {
    pub id: [u8; 16],
    pub flags: u64,
    pub deepest_wakeable_idle_state: u32,
    pub idle_state_count: u32,
    pub idle_states: u64,
    pub provider_count: u32,
    pub providers: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PoFxDeviceV3 {
    pub version: u32,
    pub flags: u64,
    pub component_active_condition_callback: u64,
    pub component_idle_condition_callback: u64,
    pub component_idle_state_callback: u64,
    pub device_power_required_callback: u64,
    pub device_power_not_required_callback: u64,
    pub power_control_callback: u64,
    pub directed_power_up_callback: u64,
    pub directed_power_down_callback: u64,
    pub directed_fx_timeout_in_seconds: u32,
    pub device_context: u64,
    pub component_count: u32,
    pub components: [PoFxComponentV2; 1],
}
