use nt_syscall::{NativeService, NativeServiceTable};

#[test]
fn current_processor_services_are_explicit_native_contracts() {
    let table = NativeServiceTable::test_profile();
    for (name, argc) in [
        ("NtGetCurrentProcessorNumber", 0),
        ("NtGetCurrentProcessorNumberEx", 1),
    ] {
        let service = NativeService::ALL
            .iter()
            .copied()
            .find(|service| service.name() == name)
            .expect("processor identity must not fall through to an unknown syscall");
        assert_eq!(service.arg_count(), (argc, argc));
        let number = table
            .number_of(service)
            .expect("service must be registered in the test profile");
        assert_eq!(
            table.lookup(number).map(|entry| entry.service),
            Some(service)
        );
    }
}
