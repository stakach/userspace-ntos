use super::*;
use alloc::string::String;
use alloc::vec;
use nt_config_manager::{ConfigManager, RegistryValueType};
use nt_fs::{FileSystem, MemFs};
use nt_syscall::{
    NativeService, NativeServiceTable, NativeSyscallDispatcher, ProcessorMode, SyscallOrigin,
    STATUS_SUCCESS,
};

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
    let paths = vec![reg_path, String::from(r"\??\C:\Temp\hosted.bin")];
    let mut ks = KernelServices::new(WindowsProfile::windows11_23h2(), cm, fs, paths);
    ks.system_time_100ns = 0x01DA_0000_0000_0000;
    ks
}

fn origin() -> SyscallOrigin {
    SyscallOrigin::new(4, 4, ProcessorMode::UserMode)
}

#[test]
fn peb_teb_layout() {
    let profile = WindowsProfile::windows11_23h2();
    let peb = build_peb(&profile, 0x1_4000_0000, 0xAAAA, 0xBBBB, 0xCCCC);
    // Version + pointer fields land at their real x64 offsets.
    assert_eq!(read_u64(&peb, peb_off::IMAGE_BASE_ADDRESS), 0x1_4000_0000);
    assert_eq!(read_u32(&peb, peb_off::OS_MAJOR_VERSION), 10);
    assert_eq!(read_u32(&peb, peb_off::OS_BUILD_NUMBER), 22631);
    let teb = build_teb(0x1_0001_0000, 0x1_0000_0000, 0x20_0000, 0x10_0000, 4, 8);
    assert_eq!(read_u64(&teb, teb_off::SELF), 0x1_0001_0000); // NT_TIB.Self
    assert_eq!(read_u64(&teb, teb_off::PEB), 0x1_0000_0000);
    assert_eq!(read_u64(&teb, teb_off::CLIENT_ID_PROCESS), 4);
    assert_eq!(read_u64(&teb, teb_off::CLIENT_ID_THREAD), 8);
}

#[test]
fn kuser_shared_data_version() {
    let profile = WindowsProfile::windows11_23h2();
    let k = build_kuser_shared_data(&profile, 0x1234_5678_9ABC, 100);
    assert_eq!(k.len(), kuser_off::SIZE); // one page
    assert_eq!(read_u32(&k, kuser_off::NT_MAJOR_VERSION), 10);
    assert_eq!(k[kuser_off::PRODUCT_TYPE_IS_VALID], 1);
    assert_eq!(KUSER_SHARED_DATA_VA, 0x7FFE_0000);
}

#[test]
fn host_launch_builds_process_and_structs() {
    let mut ks = build_services();
    let host = UserProcessHost::launch(&mut ks, "hosted.exe", 0x1_4000_1000);
    // The process + main thread exist in the Process Manager.
    assert!(ks.pm.process(host.process_id()).is_some());
    assert_eq!(
        ks.pm.thread(host.main_thread_id()).unwrap().start_address,
        0x1_4000_1000
    );
    // TEB.ClientId matches the created process/thread; TEB.PEB points at the PEB VA.
    assert_eq!(
        read_u64(host.teb(), teb_off::CLIENT_ID_PROCESS),
        host.process_id() as u64
    );
    assert_eq!(read_u64(host.teb(), teb_off::PEB), host.peb_va());
    assert_eq!(
        read_u32(host.kuser_shared_data(), kuser_off::NT_MAJOR_VERSION),
        10
    );
}

#[test]
fn dispatch_registry_and_memory_and_time() {
    let d = NativeSyscallDispatcher::new(NativeServiceTable::test_profile());
    let mut ks = build_services();
    // NtOpenKey → NtQueryValueKey Answer == 42 (registry subsystem).
    let open = d.dispatch_service(NativeService::NtOpenKey, &[0, 0, 0], &origin(), &mut ks);
    let key_handle = u64::from_le_bytes(open.output[..8].try_into().unwrap());
    let q = d.dispatch_service(
        NativeService::NtQueryValueKey,
        &[key_handle, 0, 0, 0],
        &origin(),
        &mut ks,
    );
    assert_eq!(u32::from_le_bytes(q.output[..4].try_into().unwrap()), 42);
    // NtAllocateVirtualMemory → a reserved base (address-space subsystem).
    let alloc = d.dispatch_service(
        NativeService::NtAllocateVirtualMemory,
        &[0, 0, 0, 0x4000, 0, 4],
        &origin(),
        &mut ks,
    );
    assert_eq!(alloc.status, STATUS_SUCCESS);
    assert!(u64::from_le_bytes(alloc.output[..8].try_into().unwrap()) >= 0x1_0000);
    // NtQuerySystemInformation(SystemBasicInformation) → NumberOfProcessors.
    let sysinfo = d.dispatch_service(
        NativeService::NtQuerySystemInformation,
        &[0, 0, 0, 0],
        &origin(),
        &mut ks,
    );
    assert_eq!(
        u32::from_le_bytes(sysinfo.output[..4].try_into().unwrap()),
        1
    );
    // NtQuerySystemTime → the KUSER time.
    let time = d.dispatch_service(NativeService::NtQuerySystemTime, &[0], &origin(), &mut ks);
    assert_eq!(
        u64::from_le_bytes(time.output[..8].try_into().unwrap()),
        0x01DA_0000_0000_0000
    );
}

#[test]
fn dispatch_file_create_write_read() {
    let d = NativeSyscallDispatcher::new(NativeServiceTable::test_profile());
    let mut ks = build_services();
    ks.write_scratch = b"hosted io".to_vec();
    // NtCreateFile(path index 1, FILE_CREATE=2 at arg7) → a file handle.
    let create = d.dispatch_service(
        NativeService::NtCreateFile,
        &[0, 0, 1, 0, 0, 0, 0, nt_fs::FILE_CREATE as u64],
        &origin(),
        &mut ks,
    );
    assert_eq!(create.status, STATUS_SUCCESS);
    let fh = u64::from_le_bytes(create.output[..8].try_into().unwrap());
    // NtWriteFile writes the scratch buffer at offset 0.
    d.dispatch_service(
        NativeService::NtWriteFile,
        &[fh, 0, 0, 0, 0, 0, 9, 0],
        &origin(),
        &mut ks,
    );
    // NtReadFile reads it back.
    let read = d.dispatch_service(
        NativeService::NtReadFile,
        &[fh, 0, 0, 0, 0, 0, 9, 0],
        &origin(),
        &mut ks,
    );
    assert_eq!(&read.output[..], b"hosted io");
}
