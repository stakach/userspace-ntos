//! A parked AddDevice's child that no lane admitted is retried when its lane goes idle, not
//! on a timer (#420, after #427).
//!
//! Boot 44999127278: Disk's AddDevice child (storahci's SCSI claim SRB) was refused because
//! storahci's primary was busy starting its second adapter. After 76c07ac29 the child waited,
//! but the parked turn reran it on every 100 ms retry shot while storahci stayed busy.

use nt_component_suspension::{
    peer_registry::PeerRegistry, ComponentSuspensionLanes, LaneBinding, ReplyBindingObservation,
};
use nt_driver_start::{arm_add_device_retry_shot, AddDeviceChildAction, AddDeviceChildWait};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

#[test]
fn a_waiting_child_is_selected_exactly_when_its_target_lane_goes_idle() {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(20, 2);
    let (target, _) = lanes
        .allocate_shared_staged(
            &mut peers,
            1,
            2,
            LaneBinding {
                executor_id: 10,
                receive_endpoint: 20,
                reply_object: 30,
            },
        )
        .unwrap();
    lanes
        .begin_startup(target, 30, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::Free)
        })
        .unwrap();
    lanes
        .complete_startup(target, 30, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
        })
        .unwrap();

    // The target is busy in its own work; the child step is refused admission.
    lanes.begin_dispatch(target, 30).unwrap();
    let mut wait = AddDeviceChildWait::new();
    assert_eq!(
        wait.action(lanes.idle_epoch()),
        AddDeviceChildAction::RunChild
    );
    wait.observe(true, lanes.idle_epoch());

    // Every root event while the target is busy runs nothing and arms no retry.
    for _ in 0..3 {
        assert_eq!(
            wait.action(lanes.idle_epoch()),
            AddDeviceChildAction::AwaitLaneIdle,
            "a child was polled while its target lane was busy"
        );
        assert!(
            !arm_add_device_retry_shot(true),
            "a retry shot polled the busy target"
        );
    }

    // The target goes idle: the next root pass runs the child, with no timer.
    lanes.finish_dispatch(target, 30).unwrap();
    assert_eq!(
        wait.action(lanes.idle_epoch()),
        AddDeviceChildAction::RunChild
    );
}

#[test]
fn a_child_that_was_not_refused_runs_and_keeps_its_retry_shot() {
    let mut wait = AddDeviceChildWait::new();
    wait.observe(false, 4);
    assert_eq!(wait.action(4), AddDeviceChildAction::RunChild);
    assert!(arm_add_device_retry_shot(false));
    // A refused child that was retried and admitted stops waiting.
    wait.observe(true, 4);
    assert_eq!(wait.action(4), AddDeviceChildAction::AwaitLaneIdle);
    wait.observe(false, 5);
    assert_eq!(wait.action(5), AddDeviceChildAction::RunChild);
}
