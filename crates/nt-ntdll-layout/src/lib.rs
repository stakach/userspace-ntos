//! # `nt-ntdll-layout` — byte-exact x64 PEB/TEB/LDR layout
//!
//! Hosted Windows binaries read our process/thread control structures **directly by offset** —
//! they poke `TEB+0x1258` (`StaticUnicodeString`), walk `PEB->Ldr` at `PEB+0x18`, read the NLS
//! code-page pointers at `PEB+0xA0/0xA8/0xB0`, dereference `TEB.ProcessEnvironmentBlock` at
//! `TEB+0x60`, etc. So these layouts must be **byte-for-byte** what real ntdll presents. This
//! crate is the single, statically-verified home for that layout.
//!
//! ## How the offsets are guaranteed
//!
//! Every struct is `#[repr(C)]` and every field the hosted binaries read is placed at its exact
//! x64 offset using explicit `_rsvd*` padding arrays. A block of `const _: () = assert!(...)`
//! [`core::mem::offset_of`] checks then proves each named field lands where it must. These fail at
//! **compile time** if the layout ever drifts — the cheap-now/expensive-later precision that
//! de-risks the eventual ntdll cutover.
//!
//! ## Sources (each asserted offset is traceable)
//!
//! - **ReactOS NDK** `references/reactos/sdk/include/ndk/peb_teb.h` — the authoritative x64
//!   `C_ASSERT(FIELD_OFFSET(...))` block (`_STRUCT64` branch). Cited inline per field.
//! - **ReactOS NDK** `ldrtypes.h` (`PEB_LDR_DATA`, `LDR_DATA_TABLE_ENTRY`), `rtltypes.h`
//!   (`RTL_USER_PROCESS_PARAMETERS`), `umtypes.h` (`CLIENT_ID`), `ketypes.h` (`NT_TIB`).
//! - **Live RE** (`project_smss_sec_image`): `TEB.StaticUnicodeString @ 0x1258`,
//!   `TEB.ActivationContextStackPointer @ 0x2C8`, `PEB` NLS ptrs `@ 0xA0/0xA8/0xB0`,
//!   `PEB->Ldr @ 0x18` — all confirmed by hardware-breakpoint reads.
//!
//! `no_std`, no `alloc` — pure layout.

#![no_std]
#![allow(clippy::identity_op)]

use core::mem::{offset_of, size_of};

/// `LIST_ENTRY` — a doubly-linked list node (`ntdef.h`). 16 bytes on x64.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ListEntry {
    /// Forward link.
    pub flink: u64,
    /// Backward link.
    pub blink: u64,
}

/// `UNICODE_STRING` — a counted UTF-16 string descriptor (`ntdef.h`). 16 bytes on x64 (the 4-byte
/// gap after `maximum_length` is real x64 padding before the 8-byte `buffer` pointer).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UnicodeString {
    /// Used length in **bytes** (not code units, not NUL-terminated).
    pub length: u16,
    /// Capacity in **bytes**.
    pub maximum_length: u16,
    _pad: u32,
    /// Pointer to the UTF-16 buffer.
    pub buffer: u64,
}

/// `CLIENT_ID` — `(UniqueProcess, UniqueThread)` (`umtypes.h`). 16 bytes on x64.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ClientId {
    /// Owning process id (as a `HANDLE`-width value).
    pub unique_process: u64,
    /// Thread id (as a `HANDLE`-width value).
    pub unique_thread: u64,
}

/// `NT_TIB` — the head of the TEB (`ketypes.h`). 0x38 bytes on x64.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NtTib {
    /// SEH chain head (unused on x64 — table-based SEH).
    pub exception_list: u64,
    /// Top of the thread stack.
    pub stack_base: u64,
    /// Bottom (limit) of the thread stack.
    pub stack_limit: u64,
    /// Subsystem TIB pointer.
    pub sub_system_tib: u64,
    /// `FiberData` / `Version` union.
    pub fiber_data: u64,
    /// Arbitrary user pointer.
    pub arbitrary_user_pointer: u64,
    /// Self-pointer to this TIB.
    pub self_ptr: u64,
}

/// `PEB_LDR_DATA` — the loader's per-process module bookkeeping, reached via `PEB->Ldr`
/// (`ldrtypes.h`). The three `LIST_ENTRY` module lists are what the loader / debuggers walk.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PebLdrData {
    /// Structure length.
    pub length: u32,
    /// `Initialized` boolean (+ x64 padding to the next pointer).
    pub initialized: u32,
    /// `SsHandle`.
    pub ss_handle: u64,
    /// Modules in load order (`LDR_DATA_TABLE_ENTRY.InLoadOrderLinks`).
    pub in_load_order_module_list: ListEntry,
    /// Modules in memory order (`InMemoryOrderLinks`).
    pub in_memory_order_module_list: ListEntry,
    /// Modules in init order (`InInitializationOrderLinks`).
    pub in_initialization_order_module_list: ListEntry,
    /// `EntryInProgress`.
    pub entry_in_progress: u64,
    /// `ShutdownInProgress` (Win7+; + padding).
    pub shutdown_in_progress: u32,
    _pad: u32,
    /// `ShutdownThreadId` (Win7+).
    pub shutdown_thread_id: u64,
}

/// `LDR_DATA_TABLE_ENTRY` — one loaded module (`ldrtypes.h`). The `InMemoryOrderLinks` name/offset
/// is hard-coded into WinDbg for PEB dumping, so the head layout is fixed.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LdrDataTableEntry {
    /// Load-order links.
    pub in_load_order_links: ListEntry,
    /// Memory-order links (offset 0x10 — WinDbg-hardcoded).
    pub in_memory_order_links: ListEntry,
    /// Init-order links.
    pub in_initialization_order_links: ListEntry,
    /// Image base.
    pub dll_base: u64,
    /// Entry point.
    pub entry_point: u64,
    /// `SizeOfImage` (+ x64 padding before the UNICODE_STRING).
    pub size_of_image: u32,
    _pad0: u32,
    /// Full path.
    pub full_dll_name: UnicodeString,
    /// Base name.
    pub base_dll_name: UnicodeString,
    /// `Flags`.
    pub flags: u32,
    /// `LoadCount`.
    pub load_count: u16,
    /// `TlsIndex`.
    pub tls_index: u16,
    /// `HashLinks` / `{SectionPointer, CheckSum}` union.
    pub hash_links: ListEntry,
    /// `TimeDateStamp` / `LoadedImports` union.
    pub time_date_stamp: u64,
    /// `EntryPointActivationContext`.
    pub entry_point_activation_context: u64,
    /// `PatchInformation`.
    pub patch_information: u64,
}

/// `RTL_USER_PROCESS_PARAMETERS` — the process's command line / image path / environment /
/// std handles (`rtltypes.h`). `ImagePathName`/`CommandLine`/`Environment` are the hot fields.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RtlUserProcessParameters {
    /// `MaximumLength`.
    pub maximum_length: u32,
    /// `Length`.
    pub length: u32,
    /// `Flags` (bit 0 = `RTL_USER_PROC_PARAMS_NORMALIZED`).
    pub flags: u32,
    /// `DebugFlags`.
    pub debug_flags: u32,
    /// `ConsoleHandle`.
    pub console_handle: u64,
    /// `ConsoleFlags` (+ x64 padding).
    pub console_flags: u32,
    _pad0: u32,
    /// `StandardInput`.
    pub standard_input: u64,
    /// `StandardOutput`.
    pub standard_output: u64,
    /// `StandardError`.
    pub standard_error: u64,
    /// `CurrentDirectory` (`CURDIR` = `{ UNICODE_STRING DosPath; HANDLE Handle; }`).
    pub current_directory_dospath: UnicodeString,
    /// `CurrentDirectory.Handle`.
    pub current_directory_handle: u64,
    /// `DllPath`.
    pub dll_path: UnicodeString,
    /// `ImagePathName`.
    pub image_path_name: UnicodeString,
    /// `CommandLine`.
    pub command_line: UnicodeString,
    /// `Environment` block pointer.
    pub environment: u64,
    /// `StartingX`.
    pub starting_x: u32,
    /// `StartingY`.
    pub starting_y: u32,
    /// `CountX`.
    pub count_x: u32,
    /// `CountY`.
    pub count_y: u32,
    /// `CountCharsX`.
    pub count_chars_x: u32,
    /// `CountCharsY`.
    pub count_chars_y: u32,
    /// `FillAttribute`.
    pub fill_attribute: u32,
    /// `WindowFlags`.
    pub window_flags: u32,
    /// `ShowWindowFlags`.
    pub show_window_flags: u32,
    _pad1: u32,
    /// `WindowTitle`.
    pub window_title: UnicodeString,
    /// `DesktopInfo`.
    pub desktop_info: UnicodeString,
    /// `ShellInfo`.
    pub shell_info: UnicodeString,
    /// `RuntimeData`.
    pub runtime_data: UnicodeString,
}

/// `PEB` — the Process Environment Block (`peb_teb.h`, x64). Only the fields hosted binaries read
/// by offset are named; the rest is `_rsvd*` padding sized to hold each named field at its exact
/// x64 offset (verified by the static asserts below against the NDK `C_ASSERT` block).
#[repr(C)]
pub struct Peb {
    /// `InheritedAddressSpace` / `ReadImageFileExecOptions` / `BeingDebugged` / `BitField`.
    pub flags_bytes: [u8; 4],
    _rsvd_04: [u8; 4],
    /// `Mutant` (offset 0x08).
    pub mutant: u64,
    /// `ImageBaseAddress` (offset 0x10).
    pub image_base_address: u64,
    /// `Ldr` — pointer to [`PebLdrData`] (offset 0x18).
    pub ldr: u64,
    /// `ProcessParameters` — pointer to [`RtlUserProcessParameters`] (offset 0x20).
    pub process_parameters: u64,
    /// `SubSystemData` (offset 0x28).
    pub sub_system_data: u64,
    /// `ProcessHeap` (offset 0x30).
    pub process_heap: u64,
    /// `FastPebLock` (offset 0x38).
    pub fast_peb_lock: u64,
    _rsvd_40: [u8; 0xA0 - 0x40],
    /// `AnsiCodePageData` — NLS 1252 table pointer (offset 0xA0).
    pub ansi_code_page_data: u64,
    /// `OemCodePageData` — NLS 437 table pointer (offset 0xA8).
    pub oem_code_page_data: u64,
    /// `UnicodeCaseTableData` — l_intl table pointer (offset 0xB0).
    pub unicode_case_table_data: u64,
    /// `NumberOfProcessors` (offset 0xB8).
    pub number_of_processors: u32,
    /// `NtGlobalFlag` (offset 0xBC).
    pub nt_global_flag: u32,
    _rsvd_c0: [u8; 0x2C0 - 0xC0],
    /// `SessionId` (offset 0x2C0).
    pub session_id: u32,
    _rsvd_2c4: [u8; 4],
}

/// `TEB` — the Thread Environment Block (`peb_teb.h`, x64). Named fields the hosted binaries touch
/// are placed at their exact x64 offsets via `_rsvd*` padding; the static asserts below prove each
/// against the NDK `C_ASSERT` block + the live-RE offsets.
#[repr(C)]
pub struct Teb {
    /// `NtTib` (offset 0x000).
    pub nt_tib: NtTib,
    /// `EnvironmentPointer` (offset 0x038).
    pub environment_pointer: u64,
    /// `ClientId` (offset 0x040).
    pub client_id: ClientId,
    /// `ActiveRpcHandle` (offset 0x050).
    pub active_rpc_handle: u64,
    /// `ThreadLocalStoragePointer` (offset 0x058).
    pub thread_local_storage_pointer: u64,
    /// `ProcessEnvironmentBlock` — pointer to the [`Peb`] (offset 0x060).
    pub process_environment_block: u64,
    /// `LastErrorValue` (offset 0x068).
    pub last_error_value: u32,
    /// `CountOfOwnedCriticalSections` (offset 0x06C).
    pub count_of_owned_critical_sections: u32,
    /// `CsrClientThread` (offset 0x070).
    pub csr_client_thread: u64,
    /// `Win32ThreadInfo` (offset 0x078).
    pub win32_thread_info: u64,
    _rsvd_80: [u8; 0x2C0 - 0x80],
    /// `ExceptionCode` (offset 0x2C0).
    pub exception_code: u32,
    _rsvd_2c4: [u8; 4],
    /// `ActivationContextStackPointer` (offset 0x2C8) — the `TEB+0x2C8` ActCtx pointer.
    pub activation_context_stack_pointer: u64,
    _rsvd_2d0: [u8; 0x1250 - 0x2D0],
    /// `LastStatusValue` (offset 0x1250).
    pub last_status_value: u32,
    _rsvd_1254: [u8; 4],
    /// `StaticUnicodeString` (offset 0x1258) — the descriptor whose uninitialised
    /// `MaximumLength` once caused smss's `STATUS_BUFFER_OVERFLOW`.
    pub static_unicode_string: UnicodeString,
    /// `StaticUnicodeBuffer[261]` (offset 0x1268) — 261 WCHAR.
    pub static_unicode_buffer: [u16; 261],
    _rsvd_147a: [u8; 6],
    /// `DeallocationStack` (offset 0x1478).
    pub deallocation_stack: u64,
    _rsvd_1480: [u8; 0x1690 - 0x1480],
    /// `Vdm` (offset 0x1690).
    pub vdm: u64,
    _rsvd_1698: [u8; 0x16B0 - 0x1698],
    /// `HardErrorMode` (offset 0x16B0).
    pub hard_error_mode: u32,
    _rsvd_16b4: [u8; 0x1740 - 0x16B4],
    /// `GdiBatchCount` (offset 0x1740).
    pub gdi_batch_count: u32,
    _rsvd_1744: [u8; 0x1760 - 0x1744],
    /// `WaitingOnLoaderLock` (offset 0x1760).
    pub waiting_on_loader_lock: u32,
    _rsvd_1764: [u8; 0x1780 - 0x1764],
    /// `TlsExpansionSlots` (offset 0x1780).
    pub tls_expansion_slots: u64,
    _rsvd_1788: [u8; 0x17C0 - 0x1788],
    /// `ActiveFrame` (offset 0x17C0).
    pub active_frame: u64,
    _rsvd_17c8: [u8; 8],
}

// --- STATIC offset assertions (compile-time; each cites its source) ----------------------------

// Primitive sizes.
const _: () = assert!(size_of::<ListEntry>() == 0x10);
const _: () = assert!(size_of::<UnicodeString>() == 0x10); // 4B tail pad before the 8B buffer ptr
const _: () = assert!(size_of::<ClientId>() == 0x10);
const _: () = assert!(size_of::<NtTib>() == 0x38);

// PEB — NDK peb_teb.h `_STRUCT64` C_ASSERT block + live-RE NLS/Ldr offsets.
const _: () = assert!(offset_of!(Peb, mutant) == 0x08); // C_ASSERT(... Mutant) == 0x08
const _: () = assert!(offset_of!(Peb, image_base_address) == 0x10);
const _: () = assert!(offset_of!(Peb, ldr) == 0x18); // C_ASSERT(... Ldr) == 0x18
const _: () = assert!(offset_of!(Peb, process_parameters) == 0x20);
const _: () = assert!(offset_of!(Peb, process_heap) == 0x30);
const _: () = assert!(offset_of!(Peb, fast_peb_lock) == 0x38); // C_ASSERT(... FastPebLock) == 0x038
const _: () = assert!(offset_of!(Peb, ansi_code_page_data) == 0xA0); // live-RE NLS 1252
const _: () = assert!(offset_of!(Peb, oem_code_page_data) == 0xA8); // live-RE NLS 437
const _: () = assert!(offset_of!(Peb, unicode_case_table_data) == 0xB0); // live-RE l_intl
const _: () = assert!(offset_of!(Peb, nt_global_flag) == 0xBC); // C_ASSERT(... NtGlobalFlag) == 0x0BC
const _: () = assert!(offset_of!(Peb, session_id) == 0x2C0); // C_ASSERT(... SessionId) == 0x2C0

// TEB — NDK peb_teb.h `_STRUCT64` C_ASSERT block + live-RE StaticUnicodeString/ActCtx offsets.
const _: () = assert!(offset_of!(Teb, nt_tib) == 0x000); // C_ASSERT(... NtTib) == 0x000
const _: () = assert!(offset_of!(Teb, environment_pointer) == 0x038); // C_ASSERT(...) == 0x038
const _: () = assert!(offset_of!(Teb, client_id) == 0x040);
const _: () = assert!(offset_of!(Teb, thread_local_storage_pointer) == 0x058);
const _: () = assert!(offset_of!(Teb, process_environment_block) == 0x060);
const _: () = assert!(offset_of!(Teb, last_error_value) == 0x068);
const _: () = assert!(offset_of!(Teb, exception_code) == 0x2C0); // C_ASSERT(... ExceptionCode) == 0x2C0
const _: () = assert!(offset_of!(Teb, activation_context_stack_pointer) == 0x2C8); // live-RE ActCtx
const _: () = assert!(offset_of!(Teb, last_status_value) == 0x1250); // C_ASSERT(... LastStatusValue) == 0x1250
const _: () = assert!(offset_of!(Teb, static_unicode_string) == 0x1258); // live-RE (smss overflow fix)
const _: () = assert!(offset_of!(Teb, static_unicode_buffer) == 0x1268);
const _: () = assert!(offset_of!(Teb, deallocation_stack) == 0x1478);
const _: () = assert!(offset_of!(Teb, vdm) == 0x1690); // C_ASSERT(... Vdm) == 0x1690
const _: () = assert!(offset_of!(Teb, hard_error_mode) == 0x16B0); // C_ASSERT(... HardErrorMode) == 0x16B0
const _: () = assert!(offset_of!(Teb, gdi_batch_count) == 0x1740); // C_ASSERT(... GdiBatchCount) == 0x1740
const _: () = assert!(offset_of!(Teb, waiting_on_loader_lock) == 0x1760); // C_ASSERT(...) == 0x1760
const _: () = assert!(offset_of!(Teb, tls_expansion_slots) == 0x1780); // C_ASSERT(... TlsExpansionSlots) == 0x1780
const _: () = assert!(offset_of!(Teb, active_frame) == 0x17C0); // C_ASSERT(... ActiveFrame) == 0x17C0

// PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY — ldrtypes.h.
const _: () = assert!(offset_of!(PebLdrData, in_load_order_module_list) == 0x10);
const _: () = assert!(offset_of!(PebLdrData, in_memory_order_module_list) == 0x20);
const _: () = assert!(offset_of!(PebLdrData, in_initialization_order_module_list) == 0x30);
const _: () = assert!(offset_of!(LdrDataTableEntry, in_memory_order_links) == 0x10); // WinDbg-hardcoded
const _: () = assert!(offset_of!(LdrDataTableEntry, dll_base) == 0x30);
const _: () = assert!(offset_of!(LdrDataTableEntry, entry_point) == 0x38);
const _: () = assert!(offset_of!(LdrDataTableEntry, full_dll_name) == 0x48);
const _: () = assert!(offset_of!(LdrDataTableEntry, base_dll_name) == 0x58);

// RTL_USER_PROCESS_PARAMETERS — rtltypes.h (x64).
const _: () = assert!(offset_of!(RtlUserProcessParameters, length) == 0x04);
const _: () = assert!(offset_of!(RtlUserProcessParameters, standard_input) == 0x20);
const _: () = assert!(offset_of!(RtlUserProcessParameters, current_directory_dospath) == 0x38);
const _: () = assert!(offset_of!(RtlUserProcessParameters, dll_path) == 0x50);
const _: () = assert!(offset_of!(RtlUserProcessParameters, image_path_name) == 0x60);
const _: () = assert!(offset_of!(RtlUserProcessParameters, command_line) == 0x70);
const _: () = assert!(offset_of!(RtlUserProcessParameters, environment) == 0x80);
const _: () = assert!(offset_of!(RtlUserProcessParameters, window_title) == 0xB0);

/// `RTL_USER_PROC_PARAMS_NORMALIZED` — the `Flags` bit set once process params are normalized
/// (absolute pointers). ntdll's `RtlNormalizeProcessParams` sets it; the loader keys off it.
pub const RTL_USER_PROC_PARAMS_NORMALIZED: u32 = 0x0000_0001;

#[cfg(test)]
mod tests;
