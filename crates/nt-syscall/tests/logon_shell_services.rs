use nt_syscall::{NativeService, NativeServiceTable, UserlandAbiProfile};

/// Services the shell start-up path issues: rpcrt4 cancels another thread's pipe read with
/// `NtCancelIoFileEx`, msgina and kernel32 read power state with `NtPowerInformation`, and
/// advapi32's `RegNotifyChangeKeyValue` (explorer, shell32, userenv, mmdevapi) posts registry
/// change requests with `NtNotifyChangeKey`.
#[test]
fn shell_startup_services_route_at_the_numbers_ntdll_issues() {
    for (service, name, number, argc) in [
        (NativeService::NtCancelIoFileEx, "NtCancelIoFileEx", 0x300, 3),
        (NativeService::NtPowerInformation, "NtPowerInformation", 139, 5),
        (NativeService::NtNotifyChangeKey, "NtNotifyChangeKey", 117, 10),
        (NativeService::NtNotifyChangeMultipleKeys, "NtNotifyChangeMultipleKeys", 0x455, 12),
    ] {
        assert_eq!(service.name(), name);
        assert!(NativeService::ALL.contains(&service));
        assert_eq!(nt_syscall_abi::ssn_of(name), Some(number));
        assert_eq!(service.arg_count(), (argc, argc));
        let table = NativeServiceTable::from_numbers(
            UserlandAbiProfile::Windows7, &[(service, number)]);
        assert_eq!(table.lookup(number).map(|entry| entry.service), Some(service));
    }
}
