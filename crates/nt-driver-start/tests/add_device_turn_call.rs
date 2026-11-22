//! A parked AddDevice serialises only its own devnode; other drivers' Calls run (#420).
//!
//! The exclusive turn deferred every root Call. When Disk's AddDevice child targeted
//! storahci while storahci's primary was starting its second adapter, storahci's own Calls
//! were deferred too. It could never finish that start or admit the child: a livelock.

use nt_driver_start::{add_device_turn_call, AddDeviceTurnCall};

#[test]
fn a_call_to_the_target_driver_is_admitted_during_another_drivers_add_device() {
    assert_eq!(add_device_turn_call(false, false), AddDeviceTurnCall::Admit,
        "the child's target driver could not run while another driver's AddDevice was parked");
}

#[test]
fn the_turn_defers_only_what_the_root_defers_for_every_call() {
    assert_eq!(add_device_turn_call(true, false), AddDeviceTurnCall::Defer);
    assert_eq!(add_device_turn_call(false, true), AddDeviceTurnCall::Defer);
    assert_eq!(add_device_turn_call(true, true), AddDeviceTurnCall::Defer);
}
