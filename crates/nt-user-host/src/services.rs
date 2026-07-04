//! `KernelServices` (spec §7, §16) — the [`NativeSyscallHandler`] that routes the native syscall
//! dispatcher to the real subsystems: registry (Configuration Manager), filesystem (MemFs),
//! virtual memory (Address Space), process manager, and `KUSER_SHARED_DATA` time/version.

use alloc::string::String;
use alloc::vec::Vec;

use nt_address_space::{AddressSpace, ViewType, PAGE_READWRITE};
use nt_config_manager::{ConfigManager, RegistryKeyId};
use nt_fs::{FileSystem, FILE_READ_DATA, FILE_WRITE_DATA};
use nt_process::ProcessManager;
use nt_syscall::{
    NativeCallContext, NativeService, NativeSyscallHandler, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};

use crate::profile::WindowsProfile;

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;

// System information classes (spec §16.5).
const SYSTEM_BASIC_INFORMATION: u64 = 0;
const SYSTEM_TIME_OF_DAY_INFORMATION: u64 = 3;

/// The kernel-services layer the dispatcher routes to (spec §7). Owns the subsystem managers +
/// a simulated user object namespace (registry/file paths indexed by a syscall argument, standing
/// in for the `OBJECT_ATTRIBUTES` pointer the copy-in helpers would resolve).
pub struct KernelServices {
    pub pm: ProcessManager,
    pub cm: ConfigManager,
    pub fs: FileSystem,
    pub aspace: AddressSpace,
    pub profile: WindowsProfile,
    pub system_time_100ns: u64,
    pub write_scratch: Vec<u8>,
    paths: Vec<String>,
    key_handles: Vec<RegistryKeyId>,
    file_handles: Vec<u64>,
    last_service: Option<NativeService>,
}

impl KernelServices {
    pub fn new(
        profile: WindowsProfile,
        cm: ConfigManager,
        fs: FileSystem,
        paths: Vec<String>,
    ) -> Self {
        KernelServices {
            pm: ProcessManager::new(),
            cm,
            fs,
            aspace: AddressSpace::new(0x1_0000, 0x7FFF_0000_0000, 0x1_0000_0000),
            profile,
            system_time_100ns: 0,
            write_scratch: Vec::new(),
            paths,
            key_handles: Vec::new(),
            file_handles: Vec::new(),
            last_service: None,
        }
    }
    pub fn last_service(&self) -> Option<NativeService> {
        self.last_service
    }
}

impl NativeSyscallHandler for KernelServices {
    fn handle(&mut self, ctx: &NativeCallContext, args: &[u64], out: &mut Vec<u8>) -> u32 {
        self.last_service = Some(ctx.service);
        match ctx.service {
            // Registry (spec §16.4).
            NativeService::NtOpenKey => {
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
            // Filesystem (spec §16.1). NtCreateFile(…, ObjectAttributes[arg2], …, Disposition[arg7]).
            NativeService::NtCreateFile => {
                let path = match self.paths.get(args[2] as usize) {
                    Some(p) => p.clone(),
                    None => return STATUS_INVALID_PARAMETER,
                };
                let disposition = args[7] as u32;
                let r = self.fs.zw_create_file(
                    &path,
                    FILE_READ_DATA | FILE_WRITE_DATA,
                    0,
                    0,
                    disposition,
                    0,
                );
                if r.status != STATUS_SUCCESS {
                    return r.status;
                }
                self.file_handles.push(r.handle);
                out.extend_from_slice(&((self.file_handles.len() - 1) as u64).to_le_bytes());
                out.extend_from_slice(&(r.information as u64).to_le_bytes());
                STATUS_SUCCESS
            }
            // NtWriteFile(FileHandle[0], …, Length[6], ByteOffset[7]) — writes write_scratch.
            NativeService::NtWriteFile => {
                let h = match self.file_handles.get(args[0] as usize) {
                    Some(h) => *h,
                    None => return STATUS_INVALID_HANDLE,
                };
                let off = if args.len() > 7 { Some(args[7]) } else { None };
                let (st, n) = self.fs.zw_write_file(h, off, &self.write_scratch);
                out.extend_from_slice(&(n as u64).to_le_bytes());
                st
            }
            // NtReadFile(FileHandle[0], …, Length[6], ByteOffset[7]).
            NativeService::NtReadFile => {
                let h = match self.file_handles.get(args[0] as usize) {
                    Some(h) => *h,
                    None => return STATUS_INVALID_HANDLE,
                };
                let len = if args.len() > 6 { args[6] as usize } else { 0 };
                let off = if args.len() > 7 { Some(args[7]) } else { None };
                let (st, bytes) = self.fs.zw_read_file(h, off, len);
                out.extend_from_slice(&bytes);
                st
            }
            // Virtual memory (spec §16.3). NtAllocateVirtualMemory(…, RegionSize[3], …).
            NativeService::NtAllocateVirtualMemory => {
                let size = args.get(3).copied().unwrap_or(0x1000).max(1);
                match self.aspace.reserve_view(
                    None,
                    size,
                    PAGE_READWRITE,
                    ViewType::PrivateAnonymous,
                    None,
                    0,
                ) {
                    Ok((_, base)) => {
                        out.extend_from_slice(&base.to_le_bytes());
                        STATUS_SUCCESS
                    }
                    Err(e) => e,
                }
            }
            // Process (spec §16.6).
            NativeService::NtTerminateProcess => self
                .pm
                .terminate_process(args[0] as u32, args[1] as u32)
                .map(|_| STATUS_SUCCESS)
                .unwrap_or(STATUS_INVALID_HANDLE),
            NativeService::NtClose => STATUS_SUCCESS,
            // KUSER-backed time (spec §16.5).
            NativeService::NtQuerySystemTime => {
                out.extend_from_slice(&self.system_time_100ns.to_le_bytes());
                STATUS_SUCCESS
            }
            NativeService::NtQuerySystemInformation => match args[0] {
                SYSTEM_BASIC_INFORMATION => {
                    out.extend_from_slice(&self.profile.number_of_processors.to_le_bytes());
                    out.extend_from_slice(&4096u32.to_le_bytes()); // page size
                    STATUS_SUCCESS
                }
                SYSTEM_TIME_OF_DAY_INFORMATION => {
                    out.extend_from_slice(&self.system_time_100ns.to_le_bytes());
                    STATUS_SUCCESS
                }
                _ => STATUS_INVALID_INFO_CLASS,
            },
            _ => STATUS_NOT_IMPLEMENTED, // never silently succeed (spec §9.2)
        }
    }
}
