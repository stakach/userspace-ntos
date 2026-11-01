//! A live DMA claim must keep its resource window mapped when StopDevice is retried.

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn device_dma_leases_are_retired_before_their_grant_mappings() {
    let start = DRIVER.find("unsafe fn clear_hosted_resource_projection(")
        .expect("resource projection retirement");
    let end = DRIVER[start..].find("\nfn authenticated_hosted_device(")
        .map(|offset| start + offset).expect("end of resource projection retirement");
    let clear = &DRIVER[start..end];
    syn::parse_str::<syn::ItemFn>(clear)
        .expect("complete resource projection retirement function");

    let retire_dma = clear.find("revoke_hosted_dma_adapter_leases(binding)?")
        .expect("exact DMA lease retirement is required");
    let unmap_resources = clear.find("clear_hosted_resource_map_caps_for_device(")
        .expect("resource grant mappings are eventually released");
    assert!(retire_dma < unmap_resources,
        "a live DMA record makes lease retirement return DEVICE_BUSY; its grant must remain mapped");
}

#[test]
fn every_owner_lease_is_checked_before_retiring_the_first_sibling() {
    let start = DRIVER.find("unsafe fn clear_hosted_resource_projection(")
        .expect("resource projection retirement");
    let end = DRIVER[start..].find("\nfn authenticated_hosted_device(")
        .map(|offset| start + offset).expect("end of resource projection retirement");
    let clear = &DRIVER[start..end];
    let preflight = clear.find("preflight_hosted_dma_adapter_leases(binding)?")
        .expect("all matching DMA leases need a read-only preflight");
    let retire_irq = clear.find("retire_hosted_irq_connections_for_binding(binding)?")
        .expect("ISR delivery must be masked and drained");
    let second_preflight = clear[retire_irq..]
        .find("preflight_hosted_dma_adapter_leases(binding)?")
        .map(|offset| retire_irq + offset)
        .expect("DMA leases must be checked again after IRQ drain");
    let retire = clear.find("revoke_hosted_dma_adapter_leases(binding)?")
        .expect("exact lease retirement");
    assert!(preflight < retire_irq && retire_irq < second_preflight && second_preflight < retire,
        "a busy second lease cannot retire a sibling; ISR delivery must drain before adapters retire");

    let helper_start = DRIVER.find("unsafe fn preflight_hosted_dma_adapter_leases(")
        .expect("DMA lease preflight helper");
    let helper_end = DRIVER[helper_start..].find("\nunsafe fn ")
        .map(|offset| helper_start + offset).expect("end of DMA lease preflight helper");
    let helper = &DRIVER[helper_start..helper_end];
    syn::parse_str::<syn::ItemFn>(helper).expect("complete DMA lease preflight helper");
    assert!(helper.contains("lease.owner == owner")
        && helper.contains("hosted_dma_adapter_has_live_records("),
        "the preflight must inspect every lease of this owner for live shared records");
}

#[test]
fn active_scsi_child_reservation_blocks_controller_resource_teardown() {
    let start = DRIVER.find("unsafe fn clear_hosted_resource_projection(")
        .expect("resource projection retirement");
    let end = DRIVER[start..].find("\nfn authenticated_hosted_device(")
        .map(|offset| start + offset).expect("end of resource projection retirement");
    let clear = &DRIVER[start..end];
    let busy = clear.find("hosted_scsi_dma_reservation::active_for_controller(binding.device_id)")
        .expect("exact controller SCSI reservation preflight");
    let retire_dma = clear.find("revoke_hosted_dma_adapter_leases(binding)?")
        .expect("DMA lease retirement");
    let retire_irq = clear.find("retire_hosted_irq_connections_for_binding(binding)?")
        .expect("IRQ retirement");
    assert!(busy < retire_dma && busy < retire_irq,
        "a pending SCSI child owns the grant until canonical ACK, before any teardown effect");
    assert!(clear[busy..retire_dma].contains("return Err(nt_status::NtStatus::DEVICE_BUSY)"),
        "active reservation preflight must refuse resource retirement");
}
