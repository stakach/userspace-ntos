//! # `nt-wdf-types` — KMDF/WDF ABI constants
//!
//! The binary ABI a KMDF driver expects (spec: NT KMDF/WDF Runtime, §20). Sourced from
//! the WDK KMDF **1.15** headers in `references/windows-kits/10/Include/wdf/kmdf/1.15/`
//! (verified against the `KmdfBasicTest.sys` binary). `no_std`, no allocation.
//!
//! ## Binding model (§20.1)
//!
//! The driver imports `WdfVersionBind`/`WdfVersionUnbind` from `WDFLDR.SYS`. Its
//! `FxDriverEntry` stub calls `WdfVersionBind(DriverObject, RegistryPath, &BindInfo,
//! &Globals)`; the runtime fills `*BindInfo.FuncTable` with a pointer to a
//! [`WDF_FUNCTION_COUNT`]-entry array of function pointers and `*Globals` with the driver
//! globals. Every WDF API is then `FuncTable[index](Globals, args…)`.

#![no_std]

// --- KMDF version + WDF_BIND_INFO (§20.3) ------------------------------------

pub const WDF_KMDF_VERSION_MAJOR: u32 = 1;
pub const WDF_KMDF_VERSION_MINOR: u32 = 15;
/// `WdfFunctionTableNumEntries` for KMDF 1.15 — the length of the function-pointer table.
pub const WDF_FUNCTION_COUNT: u32 = 444;

/// `WDF_BIND_INFO` field offsets (x64). Not a public header struct; recovered from the
/// driver + `wdfldr` internals. `Size` = 0x30.
pub mod bind_info {
    pub const SIZE: u64 = 0; // ULONG
    pub const COMPONENT: u64 = 8; // PWCHAR ("KmdfLibrary")
    pub const VERSION_MAJOR: u64 = 16; // ULONG
    pub const VERSION_MINOR: u64 = 20; // ULONG
    pub const VERSION_BUILD: u64 = 24; // ULONG
    pub const FUNC_COUNT: u64 = 28; // ULONG
    pub const FUNC_TABLE: u64 = 32; // PWDFFUNC* (out)
    pub const MODULE: u64 = 40; // PVOID
    pub const STRUCT_SIZE: u32 = 0x30;
}

// --- WDFFUNCENUM indices the runtime implements (KMDF 1.15, wdffuncenum.h) -----
//
// A WDF call compiles to `FuncTable[index](WdfDriverGlobals, args…)`; the byte offset in
// the disassembly is `index * 8`.

pub const IDX_WDF_DEVICE_WDM_GET_DEVICE_OBJECT: usize = 31;
pub const IDX_WDF_DEVICE_INIT_SET_PNP_POWER_EVENT_CALLBACKS: usize = 55;
pub const IDX_WDF_DEVICE_INIT_SET_IO_TYPE: usize = 61;
pub const IDX_WDF_DEVICE_INIT_SET_DEVICE_TYPE: usize = 66;
pub const IDX_WDF_DEVICE_CREATE: usize = 75;
pub const IDX_WDF_DEVICE_CREATE_SYMBOLIC_LINK: usize = 80;
pub const IDX_WDF_DRIVER_CREATE: usize = 116;
pub const IDX_WDF_IO_QUEUE_CREATE: usize = 152;
pub const IDX_WDF_OBJECT_GET_TYPED_CONTEXT_WORKER: usize = 202;
pub const IDX_WDF_OBJECT_DELETE: usize = 208;
pub const IDX_WDF_REQUEST_COMPLETE: usize = 263;
pub const IDX_WDF_REQUEST_COMPLETE_WITH_INFORMATION: usize = 265;
pub const IDX_WDF_REQUEST_RETRIEVE_INPUT_BUFFER: usize = 269;
pub const IDX_WDF_REQUEST_RETRIEVE_OUTPUT_BUFFER: usize = 270;
pub const IDX_WDF_CM_RESOURCE_LIST_GET_COUNT: usize = 304;
pub const IDX_WDF_CM_RESOURCE_LIST_GET_DESCRIPTOR: usize = 305;

// --- WDF_DRIVER_CONFIG (wdfdriver.h; Size 0x20) ------------------------------

pub mod driver_config {
    pub const SIZE: u64 = 0;
    pub const EVT_DRIVER_DEVICE_ADD: u64 = 8;
    pub const EVT_DRIVER_UNLOAD: u64 = 16;
    pub const DRIVER_INIT_FLAGS: u64 = 24;
    pub const DRIVER_POOL_TAG: u64 = 28;
    pub const STRUCT_SIZE: u32 = 0x20;
}

// --- WDF_OBJECT_ATTRIBUTES (wdfobject.h; Size 0x38) --------------------------

pub mod object_attributes {
    pub const SIZE: u64 = 0;
    pub const EVT_CLEANUP_CALLBACK: u64 = 8;
    pub const EVT_DESTROY_CALLBACK: u64 = 16;
    pub const EXECUTION_LEVEL: u64 = 24;
    pub const SYNCHRONIZATION_SCOPE: u64 = 28;
    pub const PARENT_OBJECT: u64 = 32;
    pub const CONTEXT_SIZE_OVERRIDE: u64 = 40;
    pub const CONTEXT_TYPE_INFO: u64 = 48;
    pub const STRUCT_SIZE: u32 = 0x38;
}

/// `WDF_OBJECT_CONTEXT_TYPE_INFO` fields the runtime reads for a context allocation.
pub mod context_type_info {
    pub const SIZE: u64 = 0; // ULONG
    pub const CONTEXT_NAME: u64 = 8; // PCHAR
    pub const CONTEXT_SIZE: u64 = 16; // size_t — the bytes to allocate
}

// --- WDF_IO_QUEUE_CONFIG (wdfio.h; Size 0x60) --------------------------------

pub mod queue_config {
    pub const SIZE: u64 = 0;
    pub const DISPATCH_TYPE: u64 = 4;
    pub const POWER_MANAGED: u64 = 8; // WDF_TRI_STATE
    pub const ALLOW_ZERO_LENGTH_REQUESTS: u64 = 12; // BOOLEAN
    pub const DEFAULT_QUEUE: u64 = 13; // BOOLEAN
    pub const EVT_IO_DEFAULT: u64 = 16;
    pub const EVT_IO_READ: u64 = 24;
    pub const EVT_IO_WRITE: u64 = 32;
    pub const EVT_IO_DEVICE_CONTROL: u64 = 40;
    pub const EVT_IO_INTERNAL_DEVICE_CONTROL: u64 = 48;
    pub const EVT_IO_STOP: u64 = 56;
    pub const EVT_IO_RESUME: u64 = 64;
    pub const EVT_IO_CANCELED_ON_QUEUE: u64 = 72;
    pub const STRUCT_SIZE: u32 = 0x60;
}

/// `WDF_IO_QUEUE_DISPATCH_TYPE` (wdfio.h).
pub const WDF_IO_QUEUE_DISPATCH_INVALID: u32 = 0;
pub const WDF_IO_QUEUE_DISPATCH_SEQUENTIAL: u32 = 1;
pub const WDF_IO_QUEUE_DISPATCH_PARALLEL: u32 = 2;
pub const WDF_IO_QUEUE_DISPATCH_MANUAL: u32 = 3;

// --- WDF_PNPPOWER_EVENT_CALLBACKS (wdfdevice.h) ------------------------------

pub mod pnp_power_callbacks {
    pub const SIZE: u64 = 0;
    pub const EVT_DEVICE_D0_ENTRY: u64 = 8;
    pub const EVT_DEVICE_D0_ENTRY_POST_INTERRUPTS_ENABLED: u64 = 16;
    pub const EVT_DEVICE_D0_EXIT: u64 = 24;
    pub const EVT_DEVICE_D0_EXIT_PRE_INTERRUPTS_DISABLED: u64 = 32;
    pub const EVT_DEVICE_PREPARE_HARDWARE: u64 = 40;
    pub const EVT_DEVICE_RELEASE_HARDWARE: u64 = 48;
}

/// `WDF_TRI_STATE` (wdftypes.h).
pub const WDF_FALSE: u32 = 0;
pub const WDF_TRUE: u32 = 1;
pub const WDF_USE_DEFAULT: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_table_size() {
        assert_eq!(WDF_KMDF_VERSION_MAJOR, 1);
        assert_eq!(WDF_KMDF_VERSION_MINOR, 15);
        assert_eq!(WDF_FUNCTION_COUNT, 444);
        assert_eq!(bind_info::STRUCT_SIZE, 0x30);
    }

    #[test]
    fn key_function_indices() {
        // The disassembly's `call [FuncTable + N*8]` byte offset / 8 = these.
        assert_eq!(IDX_WDF_DRIVER_CREATE * 8, 0x3a0); // matches the driver's [rax+0x3a0]
        assert_eq!(IDX_WDF_DEVICE_CREATE, 75);
        assert_eq!(IDX_WDF_IO_QUEUE_CREATE, 152);
        assert_eq!(IDX_WDF_REQUEST_COMPLETE_WITH_INFORMATION, 265);
    }

    #[test]
    fn config_offsets() {
        assert_eq!(driver_config::EVT_DRIVER_DEVICE_ADD, 8);
        assert_eq!(driver_config::STRUCT_SIZE, 0x20);
        assert_eq!(object_attributes::STRUCT_SIZE, 0x38);
        assert_eq!(queue_config::EVT_IO_DEVICE_CONTROL, 40);
        assert_eq!(pnp_power_callbacks::EVT_DEVICE_PREPARE_HARDWARE, 40);
    }
}
