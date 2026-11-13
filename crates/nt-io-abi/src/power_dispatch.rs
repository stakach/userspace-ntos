//! Pointer-free POWER dispatch scalars on the driver-peer wire.

use crate::major;
use nt_power_types::{IRP_MN_QUERY_POWER, IRP_MN_SET_POWER, IRP_MN_WAIT_WAKE,
    POWER_STATE_TYPE_DEVICE, POWER_STATE_TYPE_SYSTEM};

pub const fn valid_power_dispatch(
    major: u8,
    minor: u8,
    state_type: u32,
    state: u32,
    system_context: u32,
    shutdown_type: u32,
    input_len: u32,
    output_len: u32,
) -> bool {
    if major != major::IRP_MJ_POWER {
        return state_type == 0 && state == 0 && system_context == 0 && shutdown_type == 0;
    }
    if input_len != 0 || output_len != 0 {
        return false;
    }
    match minor {
        IRP_MN_WAIT_WAKE => state_type == POWER_STATE_TYPE_SYSTEM
            && system_context == 0 && shutdown_type == 0,
        IRP_MN_SET_POWER | IRP_MN_QUERY_POWER =>
            state_type == POWER_STATE_TYPE_DEVICE || state_type == POWER_STATE_TYPE_SYSTEM,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_type_without_substituting_provider_state() {
        assert!(valid_power_dispatch(major::IRP_MJ_POWER, IRP_MN_SET_POWER, 1, 0, 0, 0, 0, 0));
        assert!(valid_power_dispatch(major::IRP_MJ_POWER, IRP_MN_SET_POWER,
            POWER_STATE_TYPE_SYSTEM, 1, 0x1234, 5, 0, 0));
        assert!(valid_power_dispatch(major::IRP_MJ_POWER, IRP_MN_QUERY_POWER,
            POWER_STATE_TYPE_SYSTEM, 6, 0, 0, 0, 0));
        assert!(valid_power_dispatch(major::IRP_MJ_POWER, IRP_MN_WAIT_WAKE, 0, u32::MAX, 0, 0, 0, 0));
        assert!(!valid_power_dispatch(major::IRP_MJ_POWER, IRP_MN_SET_POWER, 2, 1, 0, 0, 0, 0));
        assert!(!valid_power_dispatch(major::IRP_MJ_POWER, IRP_MN_WAIT_WAKE, 1, 1, 0, 0, 0, 0));
        assert!(!valid_power_dispatch(major::IRP_MJ_POWER, IRP_MN_WAIT_WAKE, 0, 1, 1, 0, 0, 0));
        assert!(!valid_power_dispatch(major::IRP_MJ_POWER, IRP_MN_SET_POWER, 1, 1, 0, 0, 1, 0));
        assert!(!valid_power_dispatch(major::IRP_MJ_PNP, 0, 1, 1, 0, 0, 0, 0));
        assert!(!valid_power_dispatch(major::IRP_MJ_PNP, 0, 0, 0, 1, 0, 0, 0));
    }
}
