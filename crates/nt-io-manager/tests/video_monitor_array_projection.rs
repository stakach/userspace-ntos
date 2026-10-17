use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::video_monitor_array_projection::{
    decode_monitor_array, MonitorArrayAllocation, MonitorArrayProjection,
    VIDEO_MONITOR_DEVICE_X64_BYTES,
};
use nt_io_manager::{IoManager, MockObjectPort};

fn allocation(address: u64, generation: u64) -> SourcePoolAllocationIdentity {
    SourcePoolAllocationIdentity {
        component_address: address,
        capacity: 0x40,
        pool_generation: generation,
    }
}

#[test]
fn provider_array_survives_completion_until_exact_dependent_free_and_effect_barrier() {
    let mut io = IoManager::new(MockObjectPort::new());
    let provider = io.register_hosted_domain();
    let dependent = io.register_hosted_domain();
    let source = MonitorArrayAllocation::new(provider, allocation(0x1000, 7)).unwrap();
    let projected = MonitorArrayAllocation::new(dependent, allocation(0x2000, 11)).unwrap();
    let mut lease = MonitorArrayProjection::new(source, projected).unwrap();

    lease.publish().unwrap();
    assert!(!lease.provider_retirement_ready());
    assert!(lease.claim_dependent_free(projected.with_allocation(allocation(0x2000, 12))).is_err());
    assert!(lease.claim_dependent_free(source).is_err());
    assert!(!lease.provider_retirement_ready());

    lease.claim_dependent_free(projected).unwrap();
    assert!(lease.claim_dependent_free(projected).is_err());
    assert!(!lease.provider_retirement_ready());
    lease.confirm_provider_effect_quiesced().unwrap();
    assert!(lease.provider_retirement_ready());
    lease.confirm_provider_retired(source).unwrap();
    assert!(!lease.provider_retirement_ready());
}

#[test]
fn unpublished_or_uncertain_projection_never_authorizes_provider_retirement() {
    let mut io = IoManager::new(MockObjectPort::new());
    let provider = io.register_hosted_domain();
    let dependent = io.register_hosted_domain();
    let source = MonitorArrayAllocation::new(provider, allocation(0x3000, 3)).unwrap();
    let projected = MonitorArrayAllocation::new(dependent, allocation(0x4000, 4)).unwrap();
    let mut lease = MonitorArrayProjection::new(source, projected).unwrap();

    assert!(lease.claim_dependent_free(projected).is_err());
    lease.confirm_provider_effect_quiesced().unwrap();
    assert!(!lease.provider_retirement_ready());
    lease.publish().unwrap();
    lease.mark_effect_uncertain();
    lease.claim_dependent_free(projected).unwrap();
    assert!(!lease.provider_retirement_ready());
}

#[test]
fn monitor_array_requires_a_bounded_null_pdo_terminator() {
    assert_eq!(VIDEO_MONITOR_DEVICE_X64_BYTES, 24);
    let mut bytes = [0u8; 3 * VIDEO_MONITOR_DEVICE_X64_BYTES];
    bytes[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[VIDEO_MONITOR_DEVICE_X64_BYTES + 8..VIDEO_MONITOR_DEVICE_X64_BYTES + 16]
        .copy_from_slice(&0x2000u64.to_le_bytes());
    let array = decode_monitor_array(&bytes).unwrap();
    assert_eq!(array.len(), 2);
    assert_eq!(array[0].pdo, 0x1000);
    assert_eq!(array[1].pdo, 0x2000);

    bytes[2 * VIDEO_MONITOR_DEVICE_X64_BYTES + 8..2 * VIDEO_MONITOR_DEVICE_X64_BYTES + 16]
        .copy_from_slice(&0x3000u64.to_le_bytes());
    assert!(decode_monitor_array(&bytes).is_err());
    assert!(decode_monitor_array(&bytes[..2 * VIDEO_MONITOR_DEVICE_X64_BYTES]).is_err());
}

#[test]
fn sealed_stop_can_retire_an_unpublished_array_after_effect_quiescence() {
    let mut io = IoManager::new(MockObjectPort::new());
    let provider = io.register_hosted_domain();
    let dependent = io.register_hosted_domain();
    let source = MonitorArrayAllocation::new(provider, allocation(0x5000, 5)).unwrap();
    let projected = MonitorArrayAllocation::new(dependent, allocation(0x6000, 6)).unwrap();
    let mut lease = MonitorArrayProjection::new(source, projected).unwrap();
    lease.abort_unpublished().unwrap();
    assert!(!lease.provider_retirement_ready());
    lease.confirm_provider_effect_quiesced().unwrap();
    assert!(lease.provider_retirement_ready());
    lease.confirm_provider_retired(source).unwrap();
}
