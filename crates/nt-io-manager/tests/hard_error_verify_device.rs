use nt_io_manager::hard_error_verify_device::plan_hard_error_verify_device;
use nt_io_manager::source_irp_ledger::{
    SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpLedger, SourceIrpOwner,
};
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, IoManager, MockDriverBackend, MockObjectPort,
};
use nt_types::NtPath;

const IRP: u64 = 0x20_0000;
const THREAD: u64 = 0x30_0000;
const DEVICE: u64 = 0x40_0000;

fn path(value: &str) -> NtPath {
    NtPath::parse_str(value).unwrap()
}

#[test]
fn verify_device_write_requires_live_exact_irp_thread_and_domain_device() {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io
        .create_driver(&path("\\Driver\\VerifyOne"), Box::new(MockDriverBackend::new()))
        .unwrap();
    let other_driver = io
        .create_driver(&path("\\Driver\\VerifyTwo"), Box::new(MockDriverBackend::new()))
        .unwrap();
    let device = io
        .create_device(
            driver,
            Some(&path("\\Device\\VerifyOne")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let other_device = io
        .create_device(
            other_driver,
            Some(&path("\\Device\\VerifyTwo")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let domain = io.register_hosted_domain();
    let other_domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(domain, DEVICE, device).unwrap();
    // Reused component addresses in other domains are never authority for this IRP.
    io.bind_hosted_device_identity(other_domain, DEVICE, other_device)
        .unwrap();

    let allocation = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedCaller(1),
        domain,
        component_address: IRP,
        bytes: 0x128,
        stack_count: 2,
        pool_generation: 7,
    };
    let mut ledger = SourceIrpLedger::new();
    let ticket = ledger.register(allocation).unwrap();
    let source = SourceIrpForwardIdentity::new(ticket, allocation).unwrap();
    let canonical_device = io.hosted_device_by_identity(domain, DEVICE);
    assert_eq!(canonical_device, Some(device));

    assert_eq!(
        plan_hard_error_verify_device(
            &ledger,
            source,
            THREAD,
            Some(THREAD), // PM resolved this live canonical ETHREAD.
            DEVICE,
            canonical_device,
        ),
        Ok(Some((THREAD, DEVICE)))
    );
    assert_eq!(
        plan_hard_error_verify_device(&ledger, source, 0, None, DEVICE, None),
        Ok(None),
        "ReactOS ignores an IRP with no requestor thread"
    );
    assert!(
        plan_hard_error_verify_device(&ledger, source, THREAD, None, DEVICE, canonical_device)
            .is_err(),
        "a stale or fabricated ETHREAD is not writable"
    );
    assert!(
        plan_hard_error_verify_device(&ledger, source, THREAD, Some(THREAD + 8), DEVICE, canonical_device)
            .is_err(),
        "a different live ETHREAD cannot receive this IRP's verify device"
    );
    assert!(
        plan_hard_error_verify_device(
            &ledger,
            source,
            THREAD,
            Some(THREAD),
            DEVICE,
            io.hosted_device_by_identity(other_domain, DEVICE).filter(|id| *id == device),
        )
        .is_err(),
        "same numeric device pointer in another domain is unrelated"
    );
    let stale = SourceIrpForwardIdentity::new(
        ticket,
        SourceIrpAllocation {
            pool_generation: allocation.pool_generation + 1,
            ..allocation
        },
    )
    .unwrap();
    assert!(
        plan_hard_error_verify_device(&ledger, stale, THREAD, Some(THREAD), DEVICE, canonical_device)
            .is_err(),
        "a recycled source allocation cannot authorize an old IRP"
    );
    ledger.begin_hosted_caller_retirement(ticket, allocation).unwrap();
    assert!(
        plan_hard_error_verify_device(&ledger, source, THREAD, Some(THREAD), DEVICE, canonical_device)
            .is_err(),
        "retirement fences new ETHREAD effects"
    );
}
