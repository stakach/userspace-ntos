use nt_io_manager::power_irp_request::{PowerParameters, PowerParameterError};

#[test]
fn power_parameters_preserve_minor_type_and_state() {
    let set = PowerParameters::device(0x02, 1).unwrap();
    assert_eq!(set.minor(), 0x02);
    assert_eq!(set.state_type(), 1);
    assert_eq!(set.state(), 1);

    let wake = PowerParameters::wait_wake(3).unwrap();
    assert_eq!(wake.minor(), 0x00);
    assert_eq!(wake.state_type(), 0);
    assert_eq!(wake.state(), 3);

    assert_eq!(PowerParameters::device(0x01, 1), Err(PowerParameterError::InvalidMinor));
    // The kernel preserves even an unspecified raw state for the actual driver
    // to decide; PoRequestPowerIrp itself validates the minor only.
    assert_eq!(PowerParameters::device(0x02, 0).unwrap().state(), 0);
    assert_eq!(PowerParameters::wait_wake(0).unwrap().state(), 0);
    let system = PowerParameters::system(0x03, 6).unwrap();
    assert_eq!((system.minor(), system.state_type(), system.state()), (0x03, 0, 6));
    // IoAllocateIrp zeroes the PoRequestPowerIrp packet. A forwarded system
    // POWER IRP, however, retains the caller's raw context and action.
    assert_eq!((system.system_context(), system.shutdown_type()), (0, 0));
    let forwarded = system.with_forwarded_context(0x1234_5678, 5).unwrap();
    assert_eq!((forwarded.system_context(), forwarded.shutdown_type()), (0x1234_5678, 5));
    assert_eq!(wake.with_forwarded_context(1, 5), Err(PowerParameterError::InvalidMinor));
}

#[test]
fn power_dispatch_wire_has_dedicated_scalar_fields() {
    let request = nt_io_abi::IrpDispatchRequest {
        abi_version: nt_io_abi::IO_ABI_VERSION as u16,
        power_state_type: 1,
        power_state: 3,
        power_system_context: 0x1234_5678,
        power_shutdown_type: 5,
        ..Default::default()
    };
    assert_eq!(request.power_state_type, 1);
    assert_eq!(request.power_state, 3);
    assert_eq!(request.power_system_context, 0x1234_5678);
    assert_eq!(request.power_shutdown_type, 5);
    assert_eq!(nt_io_abi::IO_ABI_VERSION, 18);
}
