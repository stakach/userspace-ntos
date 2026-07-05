//! Drive the real, unmodified Windows 7 `ntdll.dll` (`references/ntdll.dll`) through the wired
//! subsystems: load it as a PE image, extract its real syscall numbers, and execute its export
//! stubs against a dispatcher keyed by those numbers.

use nt_config_manager::{ConfigManager, RegistryValueType};
use nt_fs::{FileSystem, MemFs};
use nt_syscall::{
    NativeService, NativeSyscallDispatcher, ProcessorMode, SyscallOrigin, STATUS_SUCCESS,
};
use nt_user_host::{KernelServices, NtdllImage, WindowsProfile};

/// The real Windows 7 ntdll lives in the gitignored `references/` dir; skip if it isn't present
/// (fresh clone / CI) so these tests only run where the artifact exists.
fn real_ntdll() -> Option<Vec<u8>> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../references/ntdll.dll"
    ))
    .ok()
}

fn build_services() -> KernelServices {
    let mut cm = ConfigManager::new();
    cm.register_service("Svc", "svc.sys", None, None, 3, 1);
    cm.set_service_parameter(
        "Svc",
        "Answer",
        RegistryValueType::Dword,
        42u32.to_le_bytes().to_vec(),
    );
    let params = cm.service_parameters_key("Svc").unwrap();
    let reg_path = cm.registry().key_path(params).unwrap();
    let fs = FileSystem::new(MemFs::with_fixture());
    KernelServices::new(WindowsProfile::windows7_sp1(), cm, fs, vec![reg_path])
}

fn origin() -> SyscallOrigin {
    SyscallOrigin::new(4, 4, ProcessorMode::UserMode)
}

#[test]
fn real_ntdll_syscall_numbers_match_win7_ssdt() {
    let Some(bytes) = real_ntdll() else { return };
    let img = NtdllImage::load(&bytes, 0x1_8000_0000).unwrap();
    assert!(
        img.syscall_stub_count() > 300,
        "stubs={}",
        img.syscall_stub_count()
    );
    // Known Windows 7 SP1 x64 SSDT numbers.
    assert_eq!(img.syscall_number("NtClose"), Some(0x0C));
    assert_eq!(img.syscall_number("NtOpenKey"), Some(0x0F));
    assert_eq!(img.syscall_number("NtQueryValueKey"), Some(0x14));
    assert_eq!(img.syscall_number("NtQuerySystemInformation"), Some(0x33));
    assert_eq!(img.syscall_number("NtWaitForSingleObject"), Some(0x01));
}

#[test]
fn service_table_uses_real_ntdll_numbers() {
    let Some(bytes) = real_ntdll() else { return };
    let img = NtdllImage::load(&bytes, 0x1_8000_0000).unwrap();
    let t = img.service_table();
    assert_eq!(t.number_of(NativeService::NtClose), Some(0x0C));
    assert_eq!(t.number_of(NativeService::NtOpenKey), Some(0x0F));
    assert_eq!(
        t.lookup(0x14).unwrap().service,
        NativeService::NtQueryValueKey
    );
}

#[test]
fn drive_real_ntdll_stubs_end_to_end() {
    let Some(bytes) = real_ntdll() else { return };
    let img = NtdllImage::load(&bytes, 0x1_8000_0000).unwrap();
    let d = NativeSyscallDispatcher::new(img.service_table());
    let mut ks = build_services();
    // Execute the real NtOpenKey stub (its own eax=0x0F drives the dispatch) → registry handle.
    let open = img.invoke(&d, "NtOpenKey", &[0, 0, 0], &origin(), &mut ks);
    assert_eq!(open.status, STATUS_SUCCESS);
    let kh = u64::from_le_bytes(open.output[..8].try_into().unwrap());
    // Real NtQueryValueKey stub (eax=0x14) → Answer == 42.
    let q = img.invoke(&d, "NtQueryValueKey", &[kh, 0, 0, 0], &origin(), &mut ks);
    assert_eq!(u32::from_le_bytes(q.output[..4].try_into().unwrap()), 42);
    // Real NtQuerySystemInformation stub (eax=0x33) → NumberOfProcessors, and it reached the
    // service keyed by that real number.
    let si = img.invoke(
        &d,
        "NtQuerySystemInformation",
        &[0, 0, 0, 0],
        &origin(),
        &mut ks,
    );
    assert_eq!(u32::from_le_bytes(si.output[..4].try_into().unwrap()), 1);
    assert_eq!(
        ks.last_service(),
        Some(NativeService::NtQuerySystemInformation)
    );
}
