//! Native PCI IPI bridge uses boot topology, exact image bounds, and hosted IRQL.

#[test]
fn one_cpu_ipi_is_not_a_multi_cpu_shortcut() {
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_pci_kernel.rs");
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(adapter.contains("reg.bind(\"KeIpiGenericCall\""));
    assert!(adapter.contains("published_image_for_callback"));
    assert!(adapter.contains("call_on4_raw"));
    assert!(adapter.contains("IpiAdmission::NeedsBroadcast"));
    assert!(adapter.contains("hosted_raise_irql(IPI_LEVEL)"));
    assert!(adapter.contains("hosted_lower_irql(old_irql)"));
    assert!(launch.contains("FSD_SERVICE_PCI_IPI_PREFLIGHT_LABEL"));
    assert!(launch.contains("\"KeNumberProcessors\" => FSD_DATA_KE_NUMBER_PROCESSORS_VA"));
    assert!(launch.contains("FSD_DATA_KE_NUMBER_PROCESSORS_OFF) as *mut u8"));
    assert!(launch.contains("SYSTEM_PROCESSOR_COUNT.load("));
}
