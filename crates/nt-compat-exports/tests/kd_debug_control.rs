use nt_compat_exports::kd_debug_control::{classify_command, ROS_INTERNAL_COMMAND};

const STATUS_NOT_IMPLEMENTED: i32 = 0xc000_0002_u32 as i32;
const STATUS_INVALID_INFO_CLASS: i32 = 0xc000_0003_u32 as i32;

#[test]
fn non_debug_reactos_keyboard_request_does_not_claim_a_debugger_effect() {
    assert_eq!(ROS_INTERNAL_COMMAND, 0x2073_6f52);
    assert_eq!(classify_command(ROS_INTERNAL_COMMAND), STATUS_INVALID_INFO_CLASS);
}

#[test]
fn known_unavailable_debug_operations_fail_explicitly() {
    for command in 7..=20 {
        assert_eq!(classify_command(command), STATUS_NOT_IMPLEMENTED);
    }
    for command in [0, 1, 6, 21, u32::MAX] {
        assert_eq!(classify_command(command), STATUS_INVALID_INFO_CLASS);
    }
}
