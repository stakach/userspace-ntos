use nt_io_manager::power_irp_request::{PowerIrpPlan, PowerIrpPlanError};

#[test]
fn request_owns_two_frames_above_the_top_device_stack() {
    let plan = PowerIrpPlan::new(3, 0x02).unwrap();
    assert_eq!(plan.stack_count, 5);
    assert_eq!(plan.request_location, 3);
    assert_eq!(plan.metadata_location, 4);
    assert_eq!(plan.initial_location, 6);
    assert_eq!(plan.pre_dispatch_location, 4);
    assert_eq!(PowerIrpPlan::POWER_TYPE_OFFSET, 0x10);
    assert_eq!(PowerIrpPlan::POWER_STATE_OFFSET, 0x18);
}

#[test]
fn only_power_request_minors_and_representable_stack_sizes_are_accepted() {
    for minor in [0x00, 0x02, 0x03] {
        assert!(PowerIrpPlan::new(1, minor).is_ok());
    }
    assert_eq!(PowerIrpPlan::new(1, 0x01), Err(PowerIrpPlanError::InvalidMinor));
    assert_eq!(PowerIrpPlan::new(0, 0x02), Err(PowerIrpPlanError::InvalidStack));
    assert_eq!(PowerIrpPlan::new(31, 0x02), Err(PowerIrpPlanError::InvalidStack));
    assert_eq!(PowerIrpPlan::new(30, 0x02).unwrap().stack_count, 32);
}
