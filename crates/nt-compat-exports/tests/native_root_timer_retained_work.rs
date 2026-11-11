//! Every retained retry that the timer pump can mark due must participate in
//! the physical root wake selection. A missing candidate can leave a parked
//! service and its Reply with all CPUs blocked in Receive.

const SELECTOR: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
const ROOT: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

const RETAINED_RETRIES: [&str; 5] = [
    "section_pagein_work",
    "provider_section_map_work",
    "native_image_pagein_work",
    "vm_lock_pagein_work",
    "vm_copy_work",
];
const NATIVE_DIRECTORY_RETRIES: [&str; 3] = [
    "native_directory_open_work",
    "native_file_target_open_work",
    "native_directory_effect_work",
];

#[test]
fn retained_page_and_map_retries_can_wake_the_root() {
    let selector = SELECTOR
        .split_once("pub(super) unsafe fn next(")
        .map(|(_, body)| body)
        .expect("canonical root timer selector");
    let pump = ROOT
        .split_once("unsafe fn timer_retry_wake_due(")
        .and_then(|(_, body)| body.split_once("unsafe fn timer_hosted_driver_wake_due("))
        .map(|(body, _)| body)
        .expect("root timer retry pump");

    for owner in RETAINED_RETRIES.into_iter().chain(NATIVE_DIRECTORY_RETRIES) {
        let deadline = format!("{owner}::next_deadline()");
        let due = format!("{owner}::wake_due(now_100ns)");
        let redrive = format!("crate::{owner}::redrive(");
        assert!(
            selector.contains(&deadline),
            "{owner} retains a retry but cannot arm a physical root wake"
        );
        assert!(
            pump.contains(&due),
            "{owner} has no retry readiness scan on timer delivery"
        );
        let redriven = match owner {
            "native_directory_effect_work" => {
                SERVICE.contains("crate::native_directory_effect_work::redrive_effects(")
                    && SERVICE.contains("crate::native_directory_effect_work::redrive_detached(")
            }
            _ => SERVICE.contains(&redrive),
        };
        assert!(
            redriven,
            "{owner} has no service-loop redriver after timer delivery"
        );
    }
}
