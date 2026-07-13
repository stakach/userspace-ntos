use super::*;
use alloc::string::String;
use alloc::vec;
use nt_config_manager::{ConfigManager, RegistryKeyId, RegistryValueType};
use nt_process::ProcessManager;

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// A kernel-services layer wiring the real subsystems the dispatcher routes to (spec §9.3).
struct KernelServices {
    cm: ConfigManager,
    pm: ProcessManager,
    paths: Vec<String>, // simulated OBJECT_ATTRIBUTES targets (arg = index)
    key_handles: Vec<RegistryKeyId>, // handle = index into this table
    last_mode: Option<ProcessorMode>,
}

impl NativeSyscallHandler for KernelServices {
    fn handle(&mut self, ctx: &NativeCallContext, args: &[u64], out: &mut Vec<u8>) -> u32 {
        self.last_mode = Some(ctx.previous_mode);
        match ctx.service {
            NativeService::NtOpenKey => {
                // NtOpenKey(KeyHandle*, DesiredAccess, ObjectAttributes*): args[2] models the
                // OBJECT_ATTRIBUTES path (indexed into our simulated user namespace).
                let path = match self.paths.get(args[2] as usize) {
                    Some(p) => p,
                    None => return STATUS_INVALID_PARAMETER,
                };
                match self.cm.registry().open_key(path) {
                    Some(k) => {
                        self.key_handles.push(k);
                        out.extend_from_slice(&((self.key_handles.len() - 1) as u64).to_le_bytes());
                        STATUS_SUCCESS
                    }
                    None => STATUS_OBJECT_NAME_NOT_FOUND,
                }
            }
            NativeService::NtQueryValueKey => {
                let key = match self.key_handles.get(args[0] as usize) {
                    Some(k) => *k,
                    None => return STATUS_INVALID_HANDLE,
                };
                match self.cm.registry().query_dword(key, "Answer") {
                    Some(v) => {
                        out.extend_from_slice(&v.to_le_bytes());
                        STATUS_SUCCESS
                    }
                    None => STATUS_OBJECT_NAME_NOT_FOUND,
                }
            }
            NativeService::NtTerminateProcess => self
                .pm
                .terminate_process(args[0] as u32, args[1] as u32)
                .map(|_| STATUS_SUCCESS)
                .unwrap_or(STATUS_INVALID_HANDLE),
            NativeService::NtClose => STATUS_SUCCESS,
            _ => STATUS_NOT_IMPLEMENTED, // never silently succeed (spec §9.2)
        }
    }
}

fn services() -> KernelServices {
    let mut cm = ConfigManager::new();
    cm.register_service("Svc", "svc.sys", None, None, 3, 1);
    cm.set_service_parameter(
        "Svc",
        "Answer",
        RegistryValueType::Dword,
        42u32.to_le_bytes().to_vec(),
    );
    // The authoritative path of the Parameters key (however the config manager laid it out).
    let params_key = cm.service_parameters_key("Svc").unwrap();
    let params_path = cm.registry().key_path(params_key).unwrap();
    KernelServices {
        cm,
        pm: ProcessManager::new(),
        paths: vec![params_path, String::from(r"\Registry\Machine\DoesNotExist")],
        key_handles: Vec::new(),
        last_mode: None,
    }
}

fn dispatcher() -> NativeSyscallDispatcher {
    NativeSyscallDispatcher::new(NativeServiceTable::test_profile())
}

fn origin(mode: ProcessorMode) -> SyscallOrigin {
    SyscallOrigin::new(4, 4, mode)
}

#[test]
fn service_table_numbering() {
    let t = NativeServiceTable::test_profile();
    assert_eq!(t.len(), NativeService::ALL.len());
    // Round-trip number <-> service.
    let n = t.number_of(NativeService::NtOpenKey).unwrap();
    assert_eq!(t.lookup(n).unwrap().service, NativeService::NtOpenKey);
    assert_eq!(NativeService::NtOpenKey.name(), "NtOpenKey");
    assert_eq!(t.lookup(0).unwrap().service, NativeService::NtClose); // first in ALL
}

#[test]
fn unknown_service_rejected() {
    let d = dispatcher();
    let mut ks = services();
    // A number past the table → INVALID_SYSTEM_SERVICE, handler not invoked.
    let r = d.dispatch(9999, &[], &origin(ProcessorMode::UserMode), &mut ks);
    assert_eq!(r.status, STATUS_INVALID_SYSTEM_SERVICE);
    assert!(ks.last_mode.is_none()); // handler never ran
}

#[test]
fn argument_count_validated() {
    let d = dispatcher();
    let mut ks = services();
    // NtClose requires exactly 1 arg.
    let r = d.dispatch_service(
        NativeService::NtClose,
        &[],
        &origin(ProcessorMode::UserMode),
        &mut ks,
    );
    assert_eq!(r.status, STATUS_INVALID_PARAMETER);
    let r = d.dispatch_service(
        NativeService::NtClose,
        &[0x10],
        &origin(ProcessorMode::UserMode),
        &mut ks,
    );
    assert_eq!(r.status, STATUS_SUCCESS);
}

#[test]
fn nt_vs_zw_previous_mode() {
    let d = dispatcher();
    let mut ks = services();
    // Nt* from user mode → PreviousMode = UserMode.
    d.dispatch_service(
        NativeService::NtClose,
        &[1],
        &origin(ProcessorMode::UserMode),
        &mut ks,
    );
    assert_eq!(ks.last_mode, Some(ProcessorMode::UserMode));
    // Zw* from the kernel → PreviousMode = KernelMode (same service, spec §8.4).
    d.dispatch_service(
        NativeService::NtClose,
        &[1],
        &origin(ProcessorMode::KernelMode),
        &mut ks,
    );
    assert_eq!(ks.last_mode, Some(ProcessorMode::KernelMode));
}

#[test]
fn end_to_end_registry_query() {
    // NtOpenKey (path 0 = the Svc Parameters key) → NtQueryValueKey Answer == 42.
    let d = dispatcher();
    let mut ks = services();
    let open = d.dispatch_service(
        NativeService::NtOpenKey,
        &[0, 0, 0],
        &origin(ProcessorMode::UserMode),
        &mut ks,
    );
    assert_eq!(open.status, STATUS_SUCCESS);
    let handle = u64::from_le_bytes(open.output[..8].try_into().unwrap());
    let q = d.dispatch_service(
        NativeService::NtQueryValueKey,
        &[handle, 0, 0, 0],
        &origin(ProcessorMode::UserMode),
        &mut ks,
    );
    assert_eq!(q.status, STATUS_SUCCESS);
    assert_eq!(u32::from_le_bytes(q.output[..4].try_into().unwrap()), 42);
    // Opening a missing key → OBJECT_NAME_NOT_FOUND.
    let miss = d.dispatch_service(
        NativeService::NtOpenKey,
        &[0, 0, 1],
        &origin(ProcessorMode::UserMode),
        &mut ks,
    );
    assert_eq!(miss.status, STATUS_OBJECT_NAME_NOT_FOUND);
}

#[test]
fn end_to_end_process_terminate() {
    let d = dispatcher();
    let mut ks = services();
    let pid = ks.pm.create_process("p.exe", None, None);
    ks.pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let r = d.dispatch_service(
        NativeService::NtTerminateProcess,
        &[pid as u64, 3],
        &origin(ProcessorMode::UserMode),
        &mut ks,
    );
    assert_eq!(r.status, STATUS_SUCCESS);
    assert!(ks.pm.is_process_signaled(pid));
    assert_eq!(ks.pm.wait_process(pid), Some(3));
}

#[test]
fn unimplemented_service_does_not_silently_succeed() {
    let d = dispatcher();
    let mut ks = services();
    let r = d.dispatch_service(
        NativeService::NtCreateThreadEx,
        &[0, 0, 0],
        &origin(ProcessorMode::UserMode),
        &mut ks,
    );
    assert_eq!(r.status, STATUS_NOT_IMPLEMENTED);
}

#[test]
fn win7_table_registers_migrated_services() {
    // Workstream A: the executive migrates hand-wired ladder cases onto a real-SSN table built
    // via `from_numbers`. Verify the newly-catalogued services register + round-trip by number,
    // exactly as the executive's `build_nt_table` wires them (real Win7-SP1 SSNs).
    let pairs = [
        (NativeService::NtQuerySystemInformation, 0xb5u32),
        (NativeService::NtQueryInformationProcess, 161),
        (NativeService::NtProtectVirtualMemory, 143),
        (NativeService::NtDisplayString, 70),
        (NativeService::NtQueryDebugFilterState, 148),
        (NativeService::NtOpenThreadToken, 135),
    ];
    let t = NativeServiceTable::from_numbers(UserlandAbiProfile::Windows7, &pairs);
    assert_eq!(t.len(), pairs.len());
    for (svc, num) in pairs {
        assert_eq!(t.lookup(num).unwrap().service, svc);
        assert_eq!(t.number_of(svc), Some(num));
    }
    // A number NOT registered → miss (the dispatcher would fall back to the ladder / reject).
    assert!(t.lookup(0xdead).is_none());
    // The new variants carry canonical names + tight arg-count bounds.
    assert_eq!(NativeService::NtDisplayString.name(), "NtDisplayString");
    assert_eq!(NativeService::NtDisplayString.arg_count(), (1, 1));
    assert_eq!(NativeService::NtProtectVirtualMemory.arg_count(), (5, 5));
    assert_eq!(NativeService::NtQueryInformationProcess.arg_count(), (5, 5));
    assert_eq!(NativeService::NtOpenThreadToken.arg_count(), (4, 4));
    assert_eq!(NativeService::NtQueryDebugFilterState.arg_count(), (2, 2));
}

#[test]
fn group_c_first_cut_services_register() {
    // Group C first cut (demand-fill/alloc subset reached via ExecLoopCtx): NtAllocateVirtualMemory
    // (reads Type at stack arg5 → 6-arg) + NtOpenSection register at their real Win7 SSNs.
    let pairs = [
        (NativeService::NtAllocateVirtualMemory, 0x12u32),
        (NativeService::NtOpenSection, 131),
    ];
    let t = NativeServiceTable::from_numbers(UserlandAbiProfile::Windows7, &pairs);
    assert_eq!(t.len(), pairs.len());
    for (svc, num) in pairs {
        assert_eq!(t.lookup(num).unwrap().service, svc);
    }
    assert_eq!(NativeService::NtAllocateVirtualMemory.arg_count(), (6, 6));
    assert_eq!(NativeService::NtOpenSection.arg_count(), (0, 4));
}

#[test]
fn group_a_services_register_with_register_only_bounds() {
    // Group A (create-handle + no-op) services register at their real Win7 SSNs and carry the
    // capped (0,4) arg bounds so the executive's table-driven dispatch reads only registers.
    let pairs = [
        (NativeService::NtCreatePort, 48u32),
        (NativeService::NtCreateThread, 55),
        (NativeService::NtCreateEvent, 37),
        (NativeService::NtCreateSemaphore, 53),
        (NativeService::NtOpenProcessToken, 129),
        (NativeService::NtMakeTemporaryObject, 110),
        (NativeService::NtFreeVirtualMemory, 87),
        (NativeService::NtResumeThread, 214),
        (NativeService::NtSetInformationObject, 236),
        (NativeService::NtSetSecurityObject, 246),
    ];
    let t = NativeServiceTable::from_numbers(UserlandAbiProfile::Windows7, &pairs);
    assert_eq!(t.len(), pairs.len());
    for (svc, num) in pairs {
        let e = t.lookup(num).unwrap();
        assert_eq!(e.service, svc);
        assert_eq!(e.max_args, 4, "{} should cap at 4 register args", svc.name());
    }
}

#[test]
fn group_b2_out_writing_query_services_register() {
    // Group B2: out-writing query services register at their real Win7 SSNs; the executive drains
    // their queued out-writes after dispatch. QueryVolumeInformationFile reads a stack arg5.
    let pairs = [
        (NativeService::NtQuerySystemTime, 182u32),
        (NativeService::NtQueryPerformanceCounter, 173),
        (NativeService::NtQueryVolumeInformationFile, 187),
    ];
    let t = NativeServiceTable::from_numbers(UserlandAbiProfile::Windows7, &pairs);
    assert_eq!(t.len(), pairs.len());
    for (svc, num) in pairs {
        assert_eq!(t.lookup(num).unwrap().service, svc);
    }
    assert_eq!(NativeService::NtQuerySystemTime.arg_count(), (1, 1));
    assert_eq!(NativeService::NtQueryPerformanceCounter.arg_count(), (2, 2));
    assert_eq!(NativeService::NtQueryVolumeInformationFile.arg_count(), (5, 5));
}

#[test]
fn group_b_query_and_namespace_services_register() {
    // Group B1: query + object-namespace services register at their real Win7 SSNs with the
    // arg bounds the executive's table dispatch relies on (QueryVirtualMemory reads a stack arg6).
    let pairs = [
        (NativeService::NtQueryVirtualMemory, 186u32),
        (NativeService::NtQueryInformationToken, 163),
        (NativeService::NtQueryObject, 170),
        (NativeService::NtWaitForSingleObject, 281),
        (NativeService::NtOpenDirectoryObject, 119),
        (NativeService::NtCreateDirectoryObject, 36),
        (NativeService::NtCreateSymbolicLinkObject, 54),
        (NativeService::NtOpenSymbolicLinkObject, 133),
    ];
    let t = NativeServiceTable::from_numbers(UserlandAbiProfile::Windows7, &pairs);
    assert_eq!(t.len(), pairs.len());
    for (svc, num) in pairs {
        assert_eq!(t.lookup(num).unwrap().service, svc);
    }
    assert_eq!(NativeService::NtQueryVirtualMemory.arg_count(), (6, 6));
    assert_eq!(NativeService::NtQueryInformationToken.arg_count(), (5, 5));
    assert_eq!(NativeService::NtQueryObject.arg_count(), (5, 5));
    assert_eq!(NativeService::NtWaitForSingleObject.arg_count(), (3, 3));
    assert_eq!(NativeService::NtOpenDirectoryObject.arg_count(), (0, 4));
}

#[test]
fn migrated_services_dispatch_and_validate() {
    // Register on a test dispatcher and prove: (a) a bad arg count is rejected before the handler,
    // (b) a good call reaches the handler with the previous mode set.
    let table = NativeServiceTable::from_numbers(
        UserlandAbiProfile::Windows7,
        &[(NativeService::NtDisplayString, 70)],
    );
    let d = NativeSyscallDispatcher::new(table);
    let mut ks = services();
    // NtDisplayString needs exactly 1 arg.
    let bad = d.dispatch(70, &[], &origin(ProcessorMode::UserMode), &mut ks);
    assert_eq!(bad.status, STATUS_INVALID_PARAMETER);
    assert!(ks.last_mode.is_none()); // handler never ran
    let ok = d.dispatch(70, &[0x1234], &origin(ProcessorMode::UserMode), &mut ks);
    // KernelServices' catch-all returns NOT_IMPLEMENTED — the point is it REACHED the handler
    // (mode captured) after passing validation, i.e. dispatch is table-driven, not a ladder.
    assert_eq!(ok.status, STATUS_NOT_IMPLEMENTED);
    assert_eq!(ks.last_mode, Some(ProcessorMode::UserMode));
}

#[test]
fn user_probe_copyin_ranges() {
    let mut p = UserProbe::new();
    p.add_range(0x1_0000, 0x1000, false); // read-only
    p.add_range(0x2_0000, 0x1000, true); // read-write
    assert!(p.probe_for_read(0x1_0000, 0x800).is_ok());
    assert_eq!(
        p.probe_for_write(0x1_0000, 0x10),
        Err(STATUS_ACCESS_VIOLATION)
    ); // ro range
    assert!(p.probe_for_write(0x2_0000, 0x1000).is_ok());
    assert_eq!(
        p.probe_for_read(0x1_0FF0, 0x100),
        Err(STATUS_ACCESS_VIOLATION)
    ); // crosses end
    assert_eq!(p.probe_for_read(0x9_0000, 1), Err(STATUS_ACCESS_VIOLATION)); // unmapped
}
