use nt_io_manager::kernel_irp_builder::{
    plan_wmi_reginfo_request, KernelIrpPlanError, IRP_BUFFERED_IO, IRP_DEALLOCATE_BUFFER,
};
use nt_io_manager::{WdmIoStackParameters, WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE};

#[test]
fn reginfo_plan_owns_output_buffer_before_dispatch() {
    let plan = plan_wmi_reginfo_request(2, 0x1000, 4096).unwrap();
    assert_eq!(plan.packet_size as usize, WDM_X64_IRP_SIZE + 2 * WDM_X64_IO_STACK_LOCATION_SIZE);
    assert_eq!(plan.next_stack_offset, WDM_X64_IRP_SIZE + WDM_X64_IO_STACK_LOCATION_SIZE);
    assert_eq!(plan.stack.minor, 8);
    assert_eq!(plan.stack.device_object, 0x1000);
    assert_eq!(plan.system_buffer_len, 4096);
    assert_eq!(plan.irp_flags, IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER);
    assert_eq!(plan.stack.parameters, WdmIoStackParameters::Wmi {
        provider_id: 0x1000,
        data_path: 0,
        buffer_size: 4096,
        buffer: 0,
    });
}

#[test]
fn reginfo_plan_rejects_unowned_or_invalid_packet() {
    assert_eq!(plan_wmi_reginfo_request(0, 0x1000, 4096), Err(KernelIrpPlanError::InvalidStackSize));
    assert_eq!(plan_wmi_reginfo_request(2, 0, 4096), Err(KernelIrpPlanError::InvalidIrpHeader));
    assert_eq!(plan_wmi_reginfo_request(2, 0x1000, 0), Err(KernelIrpPlanError::InvalidIrpHeader));
}
