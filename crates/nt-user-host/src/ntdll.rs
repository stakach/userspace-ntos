//! Loading + driving the **real** unmodified `ntdll.dll` (spec §13, §14). Loads the official image
//! as a PE section (`nt-pe-loader`), reads its export table, extracts the syscall number from each
//! `Nt*` stub's own instruction bytes (`mov r10,rcx; mov eax,<ssn>; syscall`), and builds the
//! Windows-7 [`NativeServiceTable`] keyed by those real numbers. [`NtdllImage::invoke`] executes a
//! real export stub the same way the CPU would: read the loaded stub, take the `eax` immediate, and
//! dispatch it.

use alloc::string::String;
use alloc::vec::Vec;

use nt_pe_loader::{MappedImage, PeError, PeFile};
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

/// The loaded, laid-out, relocated official `ntdll.dll` (spec §14) + its syscall-stub map.
pub struct NtdllImage {
    image: MappedImage,
    exports: Vec<NtdllExport>,
}

/// Decode a Windows x64 syscall stub at `rva` in the mapped image (`mov r10,rcx; mov eax,ssn;
/// syscall`), returning the syscall number. `None` if the bytes aren't that stub shape.
fn decode_syscall_number(image: &[u8], rva: u32) -> Option<u32> {
    let o = rva as usize;
    let b = image.get(o..o + 8)?;
    // 4C 8B D1 = mov r10, rcx ; B8 imm32 = mov eax, imm32
    if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
        Some(u32::from_le_bytes([b[4], b[5], b[6], b[7]]))
    } else {
        None
    }
}

impl NtdllImage {
    /// Load the real `ntdll` PE bytes at `load_base`: lay out + relocate the image, then decode
    /// the syscall number from every `Nt*`/`Zw*` export stub.
    pub fn load(bytes: &[u8], load_base: u64) -> Result<Self, PeError> {
        let pe = PeFile::parse(bytes)?;
        let image = pe.map(load_base)?; // full section layout + base relocations
        let load_delta = load_base.wrapping_sub(pe.image_base());
        let mut exports = Vec::new();
        for e in pe.exports()? {
            if e.name.starts_with("Nt") || e.name.starts_with("Zw") {
                // The mapped image is relocated; the stub bytes live at the export RVA regardless.
                let syscall_number = decode_syscall_number(&image.bytes, e.rva);
                let _ = load_delta;
                exports.push(NtdllExport {
                    name: e.name,
                    rva: e.rva,
                    syscall_number,
                });
            }
        }
        Ok(NtdllImage { image, exports })
    }

    pub fn load_base(&self) -> u64 {
        self.image.load_base
    }
    pub fn entry_point(&self) -> u64 {
        self.image.entry_point()
    }
    pub fn image_bytes(&self) -> &[u8] {
        &self.image.bytes
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

    /// Execute the real `ntdll` export stub for `name`: read the loaded stub's own bytes, extract
    /// the syscall number `eax` would be set to, and dispatch it through `dispatcher` — the exact
    /// number the real instruction stream would trap with (spec §9.1). An export that isn't a
    /// syscall stub returns `STATUS_INVALID_SYSTEM_SERVICE`.
    pub fn invoke<H: NativeSyscallHandler>(
        &self,
        dispatcher: &NativeSyscallDispatcher,
        name: &str,
        args: &[u64],
        origin: &SyscallOrigin,
        handler: &mut H,
    ) -> SyscallResult {
        match self
            .export(name)
            .and_then(|e| decode_syscall_number(&self.image.bytes, e.rva))
        {
            Some(ssn) => dispatcher.dispatch(ssn, args, origin, handler),
            None => SyscallResult {
                status: STATUS_INVALID_SYSTEM_SERVICE,
                output: Vec::new(),
            },
        }
    }
}
