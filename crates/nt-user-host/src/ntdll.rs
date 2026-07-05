//! Loading + driving the **real** unmodified `ntdll.dll` (spec §13, §14). Loads the official image
//! as a PE section (`nt-pe-loader`), reads its export table, extracts the syscall number from each
//! `Nt*` stub's own instruction bytes (`mov r10,rcx; mov eax,<ssn>; syscall`), and builds the
//! Windows-7 [`NativeServiceTable`] keyed by those real numbers. [`NtdllImage::invoke`] executes a
//! real export stub the same way the CPU would: read the loaded stub, take the `eax` immediate, and
//! dispatch it.

use alloc::string::String;
use alloc::vec::Vec;

use nt_pe_loader::{PeError, PeFile};
use nt_syscall::{
    NativeService, NativeServiceTable, NativeSyscallDispatcher, NativeSyscallHandler,
    SyscallOrigin, SyscallResult, UserlandAbiProfile, STATUS_INVALID_SYSTEM_SERVICE,
};

/// One `Nt*`/`Zw*` export of `ntdll`, with the syscall number decoded from its stub (if any).
#[derive(Clone, Debug)]
pub struct NtdllExport {
    pub name: String,
    pub rva: u32,
    pub syscall_number: Option<u32>,
}

/// The official `ntdll.dll`'s syscall-stub map (spec §13, §14). v0.1 extracts what the ABI needs
/// — the `Nt*`/`Zw*` exports + their decoded syscall numbers — from the raw PE **without** eagerly
/// materialising the full ~1.7 MiB mapped image (so it fits a memory-constrained host).
pub struct NtdllImage {
    load_base: u64,
    entry_point: u64,
    size_of_image: u32,
    exports: Vec<NtdllExport>,
}

/// Decode a Windows x64 syscall stub (`mov r10,rcx; mov eax,ssn; syscall`) from its first bytes,
/// returning the syscall number. `None` if the bytes aren't that stub shape.
fn decode_syscall_number(b: &[u8]) -> Option<u32> {
    // 4C 8B D1 = mov r10, rcx ; B8 imm32 = mov eax, imm32
    if b.len() >= 8 && b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
        Some(u32::from_le_bytes([b[4], b[5], b[6], b[7]]))
    } else {
        None
    }
}

impl NtdllImage {
    /// Load the real `ntdll` PE bytes: parse the export table + decode the syscall number from each
    /// `Nt*`/`Zw*` export stub, reading the stub bytes straight from the file (no full image map).
    pub fn load(bytes: &[u8], load_base: u64) -> Result<Self, PeError> {
        let pe = PeFile::parse(bytes)?;
        let mut exports = Vec::new();
        for e in pe.exports()? {
            if e.name.starts_with("Nt") || e.name.starts_with("Zw") {
                let syscall_number = pe.bytes_at_rva(e.rva, 8).and_then(decode_syscall_number);
                exports.push(NtdllExport {
                    name: e.name,
                    rva: e.rva,
                    syscall_number,
                });
            }
        }
        Ok(NtdllImage {
            load_base,
            entry_point: load_base.wrapping_add(pe.entry_point_rva() as u64),
            size_of_image: pe.size_of_image(),
            exports,
        })
    }

    pub fn load_base(&self) -> u64 {
        self.load_base
    }
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }
    /// The number of `Nt*`/`Zw*` exports that are real syscall stubs.
    pub fn syscall_stub_count(&self) -> usize {
        self.exports
            .iter()
            .filter(|e| e.syscall_number.is_some())
            .count()
    }
    pub fn export_count(&self) -> usize {
        self.exports.len()
    }

    pub fn export(&self, name: &str) -> Option<&NtdllExport> {
        self.exports.iter().find(|e| e.name == name)
    }
    /// The real syscall number `ntdll` uses for `name` (e.g. `NtClose` → 0x0C on Win7 x64).
    pub fn syscall_number(&self, name: &str) -> Option<u32> {
        self.export(name).and_then(|e| e.syscall_number)
    }

    /// Build the Windows-7 [`NativeServiceTable`] keyed by the **real** `ntdll` syscall numbers:
    /// for each modelled [`NativeService`], look up its number by the export name.
    pub fn service_table(&self) -> NativeServiceTable {
        let mut pairs: Vec<(NativeService, u32)> = Vec::new();
        for &service in NativeService::ALL {
            if let Some(n) = self.syscall_number(service.name()) {
                pairs.push((service, n));
            }
        }
        NativeServiceTable::from_numbers(UserlandAbiProfile::Windows7, &pairs)
    }

    /// Execute the real `ntdll` export stub for `name`: dispatch the syscall number decoded from
    /// that stub's own bytes — the exact number the real instruction stream (`mov eax,<ssn>;
    /// syscall`) would trap with (spec §9.1). An export that isn't a syscall stub returns
    /// `STATUS_INVALID_SYSTEM_SERVICE`.
    pub fn invoke<H: NativeSyscallHandler>(
        &self,
        dispatcher: &NativeSyscallDispatcher,
        name: &str,
        args: &[u64],
        origin: &SyscallOrigin,
        handler: &mut H,
    ) -> SyscallResult {
        match self.export(name).and_then(|e| e.syscall_number) {
            Some(ssn) => dispatcher.dispatch(ssn, args, origin, handler),
            None => SyscallResult {
                status: STATUS_INVALID_SYSTEM_SERVICE,
                output: Vec::new(),
            },
        }
    }
}
