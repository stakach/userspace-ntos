use nt_io_abi::ioctl;
use nt_io_manager::kernel_irp_builder::{plan_device_io_control_request, MdlAccess};
use nt_io_manager::win32k_source_irp_ioctl_wire::{
    self as wire, SourceIrpIoctlRequest, WireError,
};

#[test]
fn in_direct_read_pin_is_not_a_type3_input_buffer() {
    let code = (0x22 << 16) | (0x880 << 2) | ioctl::METHOD_IN_DIRECT;
    let plan = plan_device_io_control_request(code, false, 1, 0x1000, 0x2000, 16, 0x3000, 16).unwrap();
    let mdl = plan.mdl.unwrap();
    assert_eq!(mdl.access, MdlAccess::Read);
    assert_eq!((mdl.buffer, mdl.length), (0x3000, 16));
    let nt_io_manager::WdmIoStackParameters::DeviceControl { type3_input_buffer, .. } = plan.stack.parameters
        else { panic!("IOCTL stack"); };
    assert_eq!(type3_input_buffer, 0);
    let request = SourceIrpIoctlRequest {
        nonce: 1, source_irp_va: 0x4000, source_ticket_serial: 2,
        native_allocation_generation: 3, device_object_va: 0x1000, code,
        input: &[0x31; 16], output_initial: &[0x85; 16], output_capacity: 16,
        event: None, output_va: mdl.buffer, iosb_va: 0x5000,
        system_buffer_va: 0x6000, system_buffer_generation: 4,
        mdl_va: 0x7000, mdl_generation: 5, input_va: type3_input_buffer, event_body_va: 0,
    };
    let mut packet = vec![0; wire::packet_len(code, 16, 16).unwrap()];
    wire::encode_request(request, &mut packet).unwrap();
    let decoded = wire::decode_request(&packet).unwrap();
    assert_eq!(decoded.input_va, 0);
    assert_eq!((decoded.output_va, decoded.output_capacity), (mdl.buffer, mdl.length));
    assert_eq!((decoded.mdl_va, decoded.mdl_generation), (0x7000, 5));
    assert_eq!(wire::encode_request(SourceIrpIoctlRequest { input_va: mdl.buffer, ..request }, &mut packet),
        Err(WireError::Malformed));
}
