//! # `nt-syscall` — native syscall dispatcher + userland ABI
//!
//! The kernel entry the official `ntdll.dll` reaches through (spec: NT Native Syscall + Official
//! Userland ABI): a per-[`UserlandAbiProfile`] [`NativeServiceTable`] mapping syscall numbers to
//! `Nt*` [`NativeService`]s, a [`NativeCallContext`], the [`SyscallRegisterAbi`] descriptor, a
//! [`NativeSyscallHandler`] trait the kernel-services layer implements, and a
//! [`NativeSyscallDispatcher`] that validates the service number + argument count, sets
//! `PreviousMode` (`Nt*` = `UserMode` / `Zw*` = `KernelMode`, spec §8.4), routes to the handler,
//! and rejects unknown services with `STATUS_INVALID_SYSTEM_SERVICE` (never silently succeeds,
//! spec §9.2) — plus user-buffer copyin/copyout helpers (spec §10). `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

// NTSTATUS (spec §18)
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// The processor mode a service runs on behalf of (spec §8.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessorMode {
    KernelMode,
    UserMode,
}

/// A userland ABI compatibility profile (spec §6). v0.1 ships a deterministic `Test` profile.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UserlandAbiProfile {
    /// A stable, deterministic profile for tests (sequential service numbers).
    Test,
    /// A Windows-11-shaped profile (numbers TBD from a captured ntdll).
    Windows11,
}

/// The required `Nt*` native services (spec §16). v0.1 covers the object/file/registry/memory/
/// process families the official userland needs early.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NativeService {
    // Object / handle (§16.1)
    NtClose,
    NtDuplicateObject,
    NtWaitForSingleObject,
    NtQueryObject,
    // File / I/O (§16.2)
    NtCreateFile,
    NtOpenFile,
    NtReadFile,
    NtWriteFile,
    NtDeviceIoControlFile,
    NtQueryInformationFile,
    // Registry (§16.3)
    NtOpenKey,
    NtCreateKey,
    NtQueryValueKey,
    NtSetValueKey,
    NtEnumerateKey,
    // Memory / section (§16.4)
    NtAllocateVirtualMemory,
    NtFreeVirtualMemory,
    NtCreateSection,
    NtMapViewOfSection,
    NtUnmapViewOfSection,
    // Process / thread (§16.5)
    NtCreateThreadEx,
    NtTerminateProcess,
    NtTerminateThread,
    NtQueryInformationProcess,
    // Security / token (§16.7)
    NtOpenProcessToken,
    NtAccessCheck,
    // System information (§16.5, §7.1)
    NtQuerySystemInformation,
    NtQuerySystemTime,
}

impl NativeService {
    /// The canonical `Nt*` export name.
    pub fn name(self) -> &'static str {
        use NativeService::*;
        match self {
            NtClose => "NtClose",
            NtDuplicateObject => "NtDuplicateObject",
            NtWaitForSingleObject => "NtWaitForSingleObject",
            NtQueryObject => "NtQueryObject",
            NtCreateFile => "NtCreateFile",
            NtOpenFile => "NtOpenFile",
            NtReadFile => "NtReadFile",
            NtWriteFile => "NtWriteFile",
            NtDeviceIoControlFile => "NtDeviceIoControlFile",
            NtQueryInformationFile => "NtQueryInformationFile",
            NtOpenKey => "NtOpenKey",
            NtCreateKey => "NtCreateKey",
            NtQueryValueKey => "NtQueryValueKey",
            NtSetValueKey => "NtSetValueKey",
            NtEnumerateKey => "NtEnumerateKey",
            NtAllocateVirtualMemory => "NtAllocateVirtualMemory",
            NtFreeVirtualMemory => "NtFreeVirtualMemory",
            NtCreateSection => "NtCreateSection",
            NtMapViewOfSection => "NtMapViewOfSection",
            NtUnmapViewOfSection => "NtUnmapViewOfSection",
            NtCreateThreadEx => "NtCreateThreadEx",
            NtTerminateProcess => "NtTerminateProcess",
            NtTerminateThread => "NtTerminateThread",
            NtQueryInformationProcess => "NtQueryInformationProcess",
            NtOpenProcessToken => "NtOpenProcessToken",
            NtAccessCheck => "NtAccessCheck",
            NtQuerySystemInformation => "NtQuerySystemInformation",
            NtQuerySystemTime => "NtQuerySystemTime",
        }
    }

    /// The `(min, max)` argument count for the service (spec §9.1).
    pub fn arg_count(self) -> (u8, u8) {
        use NativeService::*;
        match self {
            NtClose | NtTerminateThread | NtQuerySystemTime => (1, 1),
            NtTerminateProcess | NtUnmapViewOfSection => (2, 2),
            NtOpenKey | NtCreateKey => (3, 3),
            NtQueryValueKey => (4, 6),
            NtQuerySystemInformation => (4, 4),
            NtReadFile | NtWriteFile => (5, 9),
            NtCreateFile => (8, 11),
            _ => (0, 16), // permissive for the rest in v0.1
        }
    }

    /// The v0.1 service list, in a stable order (the `Test` profile numbers them sequentially).
    pub const ALL: &'static [NativeService] = &[
        NativeService::NtClose,
        NativeService::NtDuplicateObject,
        NativeService::NtWaitForSingleObject,
        NativeService::NtQueryObject,
        NativeService::NtCreateFile,
        NativeService::NtOpenFile,
        NativeService::NtReadFile,
        NativeService::NtWriteFile,
        NativeService::NtDeviceIoControlFile,
        NativeService::NtQueryInformationFile,
        NativeService::NtOpenKey,
        NativeService::NtCreateKey,
        NativeService::NtQueryValueKey,
        NativeService::NtSetValueKey,
        NativeService::NtEnumerateKey,
        NativeService::NtAllocateVirtualMemory,
        NativeService::NtFreeVirtualMemory,
        NativeService::NtCreateSection,
        NativeService::NtMapViewOfSection,
        NativeService::NtUnmapViewOfSection,
        NativeService::NtCreateThreadEx,
        NativeService::NtTerminateProcess,
        NativeService::NtTerminateThread,
        NativeService::NtQueryInformationProcess,
        NativeService::NtOpenProcessToken,
        NativeService::NtAccessCheck,
        NativeService::NtQuerySystemInformation,
        NativeService::NtQuerySystemTime,
    ];
}

/// One entry in the service table (spec §9.1).
#[derive(Copy, Clone, Debug)]
pub struct NativeServiceEntry {
    pub number: u32,
    pub service: NativeService,
    pub min_args: u8,
    pub max_args: u8,
}

/// The per-profile system-service table (spec §9.1).
pub struct NativeServiceTable {
    pub profile: UserlandAbiProfile,
    by_number: BTreeMap<u32, NativeServiceEntry>,
    by_service: BTreeMap<NativeService, u32>,
}

impl NativeServiceTable {
    /// Build the `Test` profile: services numbered sequentially from 0 in [`NativeService::ALL`]
    /// order (deterministic, spec §6.4).
    pub fn test_profile() -> Self {
        let mut by_number = BTreeMap::new();
        let mut by_service = BTreeMap::new();
        for (i, &service) in NativeService::ALL.iter().enumerate() {
            let number = i as u32;
            let (min_args, max_args) = service.arg_count();
            by_number.insert(
                number,
                NativeServiceEntry {
                    number,
                    service,
                    min_args,
                    max_args,
                },
            );
            by_service.insert(service, number);
        }
        NativeServiceTable {
            profile: UserlandAbiProfile::Test,
            by_number,
            by_service,
        }
    }

    pub fn lookup(&self, number: u32) -> Option<NativeServiceEntry> {
        self.by_number.get(&number).copied()
    }
    /// The syscall number a service is exported at (the `ntdll` stub's immediate).
    pub fn number_of(&self, service: NativeService) -> Option<u32> {
        self.by_service.get(&service).copied()
    }
    pub fn len(&self) -> usize {
        self.by_number.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }
}

/// The context captured for a dispatched syscall (spec §9.4).
#[derive(Clone, Debug)]
pub struct NativeCallContext {
    pub profile: UserlandAbiProfile,
    pub process_id: u32,
    pub thread_id: u32,
    pub previous_mode: ProcessorMode,
    pub syscall_number: u32,
    pub service: NativeService,
    pub user_ip: u64,
    pub user_sp: u64,
}

/// The register ABI descriptor for a profile (spec §8.3) — x64 fastcall + `r10` syscall stub.
#[derive(Clone, Debug)]
pub struct SyscallRegisterAbi {
    pub service_number_register: &'static str,
    pub arg_registers: Vec<&'static str>,
    pub return_status_register: &'static str,
}

impl SyscallRegisterAbi {
    /// The x64 native-syscall convention: `eax`=service number, `r10, rdx, r8, r9`=first 4 args
    /// (stack for the rest), `rax`=NTSTATUS (spec §8.3).
    pub fn x64() -> Self {
        SyscallRegisterAbi {
            service_number_register: "eax",
            arg_registers: alloc::vec!["r10", "rdx", "r8", "r9"],
            return_status_register: "rax",
        }
    }
}

/// The kernel-services layer the dispatcher routes to (spec §9.3). The implementer owns the
/// subsystem managers (Object/File/Registry/Memory/Process/Security) and does the real work.
pub trait NativeSyscallHandler {
    /// Handle a validated syscall. `out` collects any bytes to copy back to user buffers.
    fn handle(&mut self, ctx: &NativeCallContext, args: &[u64], out: &mut Vec<u8>) -> u32;
}

/// The result of a dispatched syscall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyscallResult {
    pub status: u32,
    pub output: Vec<u8>,
}

/// The native syscall dispatcher (spec §9.3): validates the service number + argument count, sets
/// `PreviousMode`, and routes to the [`NativeSyscallHandler`].
pub struct NativeSyscallDispatcher {
    table: NativeServiceTable,
}

impl NativeSyscallDispatcher {
    pub fn new(table: NativeServiceTable) -> Self {
        NativeSyscallDispatcher { table }
    }
    pub fn table(&self) -> &NativeServiceTable {
        &self.table
    }

    /// Dispatch a syscall by number (spec §9.3). `origin.previous_mode` distinguishes an `Nt*`
    /// user call (`UserMode`) from a `Zw*` kernel call (`KernelMode`, spec §8.4). An unknown
    /// service number returns `STATUS_INVALID_SYSTEM_SERVICE` without invoking the handler
    /// (spec §9.2).
    pub fn dispatch<H: NativeSyscallHandler>(
        &self,
        syscall_number: u32,
        args: &[u64],
        origin: &SyscallOrigin,
        handler: &mut H,
    ) -> SyscallResult {
        let entry = match self.table.lookup(syscall_number) {
            Some(e) => e,
            None => {
                return SyscallResult {
                    status: STATUS_INVALID_SYSTEM_SERVICE,
                    output: Vec::new(),
                };
            }
        };
        if (args.len() as u8) < entry.min_args || (args.len() as u8) > entry.max_args {
            return SyscallResult {
                status: STATUS_INVALID_PARAMETER,
                output: Vec::new(),
            };
        }
        let ctx = NativeCallContext {
            profile: self.table.profile,
            process_id: origin.process_id,
            thread_id: origin.thread_id,
            previous_mode: origin.previous_mode,
            syscall_number,
            service: entry.service,
            user_ip: origin.user_ip,
            user_sp: origin.user_sp,
        };
        let mut output = Vec::new();
        let status = handler.handle(&ctx, args, &mut output);
        SyscallResult { status, output }
    }

    /// Dispatch a service by identity (what an `ntdll` stub resolves to its number first).
    pub fn dispatch_service<H: NativeSyscallHandler>(
        &self,
        service: NativeService,
        args: &[u64],
        origin: &SyscallOrigin,
        handler: &mut H,
    ) -> SyscallResult {
        match self.table.number_of(service) {
            Some(n) => self.dispatch(n, args, origin, handler),
            None => SyscallResult {
                status: STATUS_INVALID_SYSTEM_SERVICE,
                output: Vec::new(),
            },
        }
    }
}

/// Where a dispatched syscall came from — the captured caller context (spec §9.3).
#[derive(Copy, Clone, Debug)]
pub struct SyscallOrigin {
    pub process_id: u32,
    pub thread_id: u32,
    pub previous_mode: ProcessorMode,
    pub user_ip: u64,
    pub user_sp: u64,
}

impl SyscallOrigin {
    /// A caller origin for a thread at a given previous mode (IP/SP unset).
    pub fn new(process_id: u32, thread_id: u32, previous_mode: ProcessorMode) -> Self {
        SyscallOrigin {
            process_id,
            thread_id,
            previous_mode,
            user_ip: 0,
            user_sp: 0,
        }
    }
}

// --- user pointer probing + copyin/copyout (spec §10) ------------------------

/// A view over a user address space's committed byte ranges, for `ProbeForRead`/`ProbeForWrite`
/// + copyin/copyout (spec §10.2). v0.1 models the address space as `[base, base+len)` ranges.
#[derive(Default)]
pub struct UserProbe {
    ranges: Vec<(u64, u64, bool)>, // (base, len, writable)
}

impl UserProbe {
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a committed, readable (and optionally writable) user range.
    pub fn add_range(&mut self, base: u64, len: u64, writable: bool) {
        self.ranges.push((base, len, writable));
    }
    fn contains(&self, addr: u64, len: u64, need_write: bool) -> bool {
        let end = match addr.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        self.ranges
            .iter()
            .any(|&(base, rlen, w)| addr >= base && end <= base + rlen && (!need_write || w))
    }
    /// `ProbeForRead` (spec §10.2): validate a user range is readable.
    pub fn probe_for_read(&self, addr: u64, len: u64) -> Result<(), u32> {
        if self.contains(addr, len, false) {
            Ok(())
        } else {
            Err(STATUS_ACCESS_VIOLATION)
        }
    }
    /// `ProbeForWrite` (spec §10.2): validate a user range is writable.
    pub fn probe_for_write(&self, addr: u64, len: u64) -> Result<(), u32> {
        if self.contains(addr, len, true) {
            Ok(())
        } else {
            Err(STATUS_ACCESS_VIOLATION)
        }
    }
}

#[cfg(test)]
mod tests;
