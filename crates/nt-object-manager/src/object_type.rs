//! Real, const-constructible NT `OBJECT_TYPE`s for the win32k data-export globals.
//!
//! win32k.sys imports a handful of `POBJECT_TYPE` **data** globals from `ntoskrnl.exe`
//! (`PsProcessType`, `PsThreadType`, `PsJobType`, `MmSectionObjectType`,
//! `ExDesktopObjectType`, `ExWindowStationObjectType`, `ExEventObjectType`,
//! `LpcPortObjectType`, `IoDeviceObjectType`). Each is a pointer to an `OBJECT_TYPE` struct that
//! ntoskrnl creates at boot; win32k treats the pointed-at struct as its **type identity** and — for
//! the desktop / window-station types — *writes* its own `TypeInfo` fields into it during
//! `InitDesktopImpl` / `InitWindowStationImpl` (see the pinned LiberNT
//! `win32ss/user/ntuser/{desktop,winsta}.c`):
//!
//! ```c
//! ExDesktopObjectType->TypeInfo.DefaultNonPagedPoolCharge = sizeof(DESKTOP);
//! ExDesktopObjectType->TypeInfo.GenericMapping           = IntDesktopMapping;
//! ExDesktopObjectType->TypeInfo.ValidAccessMask          = DESKTOP_ALL_ACCESS;
//! ```
//!
//! Previously the hosted executive pointed those cells at zeroed 0x40-byte *placeholder* regions in
//! win32k's data page — arbitrary pointer values used only for identity discrimination. This module
//! replaces them with **real `OBJECT_TYPE` statics**: a `#[repr(C)]` struct laid out to the x64
//! `OBJECT_TYPE` ABI (the pinned LiberNT `sdk/include/ndk/obtypes.h`) so that (a) each type has a genuine, typed
//! identity — a real UNICODE_STRING `Name` and a unique `Index` — instead of an arbitrary cell
//! address, and (b) win32k's `->TypeInfo.*` writes land inside the struct's own storage rather than
//! spilling into adjacent memory.
//!
//! Heap-free by design: like [`win32k_ob`](crate::win32k_ob) these must be usable at win32k runtime,
//! when the executive's bump heap is spent — so they are `const`-constructible `static`s, **not** the
//! `alloc`-based [`ObjectType`](crate::types::ObjectType) / [`TypeRegistry`](crate::types) used by
//! the host-side tooling. The statics are `mut` because win32k writes into them (`->TypeInfo.*`);
//! nothing in Rust reads those bytes back — they exist so win32k's writes have valid backing store.

use core::mem::offset_of;

/// `GENERIC_MAPPING` (`references/nt5/.../winnt.h`): the four `GENERIC_*` → specific-rights maps.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GenericMapping {
    pub generic_read: u32,
    pub generic_write: u32,
    pub generic_execute: u32,
    pub generic_all: u32,
}

/// LiberNT `OBJECT_TYPE_INITIALIZER` (`sdk/include/ndk/obtypes.h`), x64 layout.
/// The bitfield union occupies one little-endian `USHORT`; keeping it as one value prevents
/// the older ReactOS byte layout from shifting every field after it.
#[repr(C)]
pub struct ObjectTypeInitializer {
    pub length: u16,
    pub object_type_flags: u16,
    pub object_type_code: u32,
    pub invalid_attributes: u32,
    pub generic_mapping: GenericMapping,
    pub valid_access_mask: u32,
    pub retain_access: u32,
    pub pool_type: u32,
    pub default_paged_pool_charge: u32,
    pub default_nonpaged_pool_charge: u32,
    /// `Dump/Open/Close/Delete/Parse/Security/QueryName/OkayToClose` procedure pointers.
    pub methods: [u64; 8],
    pub wait_object_flag_mask: u32,
    pub wait_object_flag_offset: u16,
    pub wait_object_pointer_offset: u16,
}

impl ObjectTypeInitializer {
    pub const CASE_INSENSITIVE: u16 = 1 << 0;
    pub const USE_DEFAULT_OBJECT: u16 = 1 << 2;
    pub const SECURITY_REQUIRED: u16 = 1 << 3;
    pub const MAINTAIN_HANDLE_COUNT: u16 = 1 << 4;
    pub const MAINTAIN_TYPE_LIST: u16 = 1 << 5;

    pub const fn case_insensitive(&self) -> bool {
        self.object_type_flags & Self::CASE_INSENSITIVE != 0
    }

    pub const fn use_default_object(&self) -> bool {
        self.object_type_flags & Self::USE_DEFAULT_OBJECT != 0
    }

    pub const fn security_required(&self) -> bool {
        self.object_type_flags & Self::SECURITY_REQUIRED != 0
    }

    pub const fn maintain_handle_count(&self) -> bool {
        self.object_type_flags & Self::MAINTAIN_HANDLE_COUNT != 0
    }

    pub const fn maintain_type_list(&self) -> bool {
        self.object_type_flags & Self::MAINTAIN_TYPE_LIST != 0
    }

    /// The hosted Object Manager currently owns exactly one native callback: DeleteProcedure.
    pub fn supports_hosted_delete(&self) -> bool {
        self.length as usize == core::mem::size_of::<Self>()
            && self.object_type_flags & !(Self::USE_DEFAULT_OBJECT | Self::SECURITY_REQUIRED) == 0
            && self.object_type_code == 0
            && self.retain_access == 0
            && self.default_paged_pool_charge == 0
            && self.wait_object_flag_mask == 0
            && self.wait_object_flag_offset == 0
            && self.wait_object_pointer_offset == 0
            && self.methods[3] != 0
            && self.methods.iter().enumerate().all(|(index, method)| index == 3 || *method == 0)
    }

    const fn zeroed() -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u16,
            object_type_flags: 0,
            object_type_code: 0,
            invalid_attributes: 0,
            generic_mapping: GenericMapping {
                generic_read: 0,
                generic_write: 0,
                generic_execute: 0,
                generic_all: 0,
            },
            valid_access_mask: 0,
            retain_access: 0,
            pool_type: 0,
            default_paged_pool_charge: 0,
            default_nonpaged_pool_charge: 0,
            methods: [0; 8],
            wait_object_flag_mask: 0,
            wait_object_flag_offset: 0,
            wait_object_pointer_offset: 0,
        }
    }
}

/// A `UNICODE_STRING` (`Length`/`MaximumLength` in bytes + a code-unit `Buffer` pointer), x64 layout.
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    _pad: u32,
    pub buffer: *const u16,
}

/// LiberNT's x64 `OBJECT_TYPE`. Opaque list, lock and counter storage preserves the entire
/// published structure; the name, index and initializer are the fields used by hosted binaries.
#[repr(C)]
pub struct ObjectType {
    _type_list: [u8; 0x10], // LIST_ENTRY
    pub name: UnicodeString,
    pub default_object: u64,
    pub index: u8,
    _index_pad: [u8; 3],
    _counters: [u32; 4], // Total/HighWater Objects+Handles
    _type_info_pad: u32,
    pub type_info: ObjectTypeInitializer,
    _type_lock: u64, // EX_PUSH_LOCK
    pub key: u32,
    _callback_list_pad: u32,
    _callback_list: [u8; 0x10],
    _se_mandatory_label_mask: u32,
    _se_trust_constraint_mask: u32,
}

// These offsets are load-bearing for released LiberNT binaries and native type publication.
const _: () = {
    assert!(core::mem::size_of::<ObjectTypeInitializer>() == 0x78);
    assert!(offset_of!(ObjectTypeInitializer, object_type_flags) == 0x02);
    assert!(offset_of!(ObjectTypeInitializer, generic_mapping) == 0x0C);
    assert!(offset_of!(ObjectTypeInitializer, methods) == 0x30);
    assert!(offset_of!(ObjectTypeInitializer, wait_object_flag_mask) == 0x70);
    assert!(offset_of!(ObjectType, name) == 0x10);
    assert!(offset_of!(ObjectType, index) == 0x28);
    assert!(offset_of!(ObjectType, type_info) == 0x40);
    assert!(offset_of!(ObjectType, key) == 0xC0);
    assert!(core::mem::size_of::<ObjectType>() == 0xE0);
};

impl ObjectType {
    /// Construct a type with a real `Name` (UTF-16 code units) and a unique `Index`.
    pub const fn new(name: &'static [u16], index: u32) -> Self {
        assert!(index <= u8::MAX as u32);
        let name_bytes = (name.len() * 2) as u16;
        Self {
            _type_list: [0; 0x10],
            name: UnicodeString {
                length: name_bytes,
                maximum_length: name_bytes,
                _pad: 0,
                buffer: name.as_ptr(),
            },
            default_object: 0,
            index: index as u8,
            _index_pad: [0; 3],
            _counters: [0; 4],
            _type_info_pad: 0,
            type_info: ObjectTypeInitializer::zeroed(),
            _type_lock: 0,
            key: 0,
            _callback_list_pad: 0,
            _callback_list: [0; 0x10],
            _se_mandatory_label_mask: 0,
            _se_trust_constraint_mask: 0,
        }
    }

    /// This type's `Index` (unique per registered type).
    pub fn index(&self) -> u32 {
        self.index as u32
    }

    /// This type's `Name` as UTF-16 code units.
    pub fn name_units(&self) -> &[u16] {
        // SAFETY: `buffer`/`length` were set from a `&'static [u16]` in `new`.
        unsafe { core::slice::from_raw_parts(self.name.buffer, (self.name.length / 2) as usize) }
    }
}

// Type indices — stable, unique, in the same order ntoskrnl would register them. (Directory=2 and
// SymbolicLink=3 are the classic ntoskrnl indices; the win32k-visible types get the next slots.)
/// `PsProcessType` index.
pub const INDEX_PROCESS: u32 = 7;
/// `PsThreadType` index.
pub const INDEX_THREAD: u32 = 8;
/// `ExEventObjectType` index.
pub const INDEX_EVENT: u32 = 12;
/// `LpcPortObjectType` index.
pub const INDEX_PORT: u32 = 21;
/// `MmSectionObjectType` index in this native descriptor catalog.
pub const INDEX_SECTION: u32 = 22;
/// `PsJobType` index in this native descriptor catalog.
pub const INDEX_JOB: u32 = 23;
/// `ExDesktopObjectType` index.
pub const INDEX_DESKTOP: u32 = 24;
/// `ExWindowStationObjectType` index.
pub const INDEX_WINDOW_STATION: u32 = 25;
/// Device projection type index in this native descriptor catalog. NT type indices are not a
/// portable ABI; this value is distinct from the already published native type identities.
pub const INDEX_DEVICE: u32 = 26;

// UTF-16 type names (const, no alloc).
static NAME_PROCESS: [u16; 7] = [
    b'P' as u16,
    b'r' as u16,
    b'o' as u16,
    b'c' as u16,
    b'e' as u16,
    b's' as u16,
    b's' as u16,
];
static NAME_THREAD: [u16; 6] = [
    b'T' as u16,
    b'h' as u16,
    b'r' as u16,
    b'e' as u16,
    b'a' as u16,
    b'd' as u16,
];
static NAME_EVENT: [u16; 5] = [
    b'E' as u16,
    b'v' as u16,
    b'e' as u16,
    b'n' as u16,
    b't' as u16,
];
static NAME_PORT: [u16; 4] = [b'P' as u16, b'o' as u16, b'r' as u16, b't' as u16];
static NAME_SECTION: [u16; 7] = [
    b'S' as u16,
    b'e' as u16,
    b'c' as u16,
    b't' as u16,
    b'i' as u16,
    b'o' as u16,
    b'n' as u16,
];
static NAME_JOB: [u16; 3] = [b'J' as u16, b'o' as u16, b'b' as u16];
static NAME_DEVICE: [u16; 6] = [
    b'D' as u16,
    b'e' as u16,
    b'v' as u16,
    b'i' as u16,
    b'c' as u16,
    b'e' as u16,
];
static NAME_DESKTOP: [u16; 7] = [
    b'D' as u16,
    b'e' as u16,
    b's' as u16,
    b'k' as u16,
    b't' as u16,
    b'o' as u16,
    b'p' as u16,
];
static NAME_WINSTA: [u16; 13] = [
    b'W' as u16,
    b'i' as u16,
    b'n' as u16,
    b'd' as u16,
    b'o' as u16,
    b'w' as u16,
    b'S' as u16,
    b't' as u16,
    b'a' as u16,
    b't' as u16,
    b'i' as u16,
    b'o' as u16,
    b'n' as u16,
];

// The real OBJECT_TYPE statics. `mut` because win32k writes `->TypeInfo.*` into the desktop /
// window-station types (nothing in Rust reads those bytes back). Addresses are taken via
// `*_object_type_addr()` — never construct a shared reference to a `static mut`.
/// `PsProcessType` — the process object type.
pub static mut PROCESS_OBJECT_TYPE: ObjectType = ObjectType::new(&NAME_PROCESS, INDEX_PROCESS);
/// `PsThreadType` — the thread object type.
pub static mut THREAD_OBJECT_TYPE: ObjectType = ObjectType::new(&NAME_THREAD, INDEX_THREAD);
/// `ExEventObjectType` — the executive event object type.
pub static mut EVENT_OBJECT_TYPE: ObjectType = ObjectType::new(&NAME_EVENT, INDEX_EVENT);
/// `LpcPortObjectType` — the LPC port object type.
pub static mut PORT_OBJECT_TYPE: ObjectType = ObjectType::new(&NAME_PORT, INDEX_PORT);
/// `MmSectionObjectType` — the section object type identity and access policy.
pub static mut SECTION_OBJECT_TYPE: ObjectType = section_object_type();
/// `PsJobType` — the job object type identity and access policy.
pub static mut JOB_OBJECT_TYPE: ObjectType = job_object_type();
/// `ExDesktopObjectType` — the win32k desktop object type.
pub static mut DESKTOP_OBJECT_TYPE: ObjectType = ObjectType::new(&NAME_DESKTOP, INDEX_DESKTOP);
/// `ExWindowStationObjectType` — the win32k window-station object type.
pub static mut WINDOW_STATION_OBJECT_TYPE: ObjectType =
    ObjectType::new(&NAME_WINSTA, INDEX_WINDOW_STATION);

/// `IoDeviceObjectType` identity and scalar policy from the NT object manager.
///
/// The native broker owns device lifetime; this descriptor does not provide callable NT
/// IopDeleteDevice/IopParseDevice/IopGetSetSecurityObject entry points. Its method slots remain
/// unset, and publishing its identity does not implement generic Ob creation, parsing or security.
pub static mut DEVICE_OBJECT_TYPE: ObjectType = device_object_type();

const fn section_object_type() -> ObjectType {
    let mut object_type = ObjectType::new(&NAME_SECTION, INDEX_SECTION);
    let info = &mut object_type.type_info;
    info.object_type_flags |= ObjectTypeInitializer::USE_DEFAULT_OBJECT;
    info.invalid_attributes = 0x0000_0100; // OBJ_OPENLINK
    info.generic_mapping = GenericMapping {
        generic_read: 0x0002_0005,    // STANDARD_RIGHTS_READ | SECTION_MAP_READ | SECTION_QUERY
        generic_write: 0x0002_0002,   // STANDARD_RIGHTS_WRITE | SECTION_MAP_WRITE
        generic_execute: 0x0002_0008, // STANDARD_RIGHTS_EXECUTE | SECTION_MAP_EXECUTE
        generic_all: 0x000F_001F,     // SECTION_ALL_ACCESS
    };
    info.valid_access_mask = 0x000F_001F;
    info.pool_type = 1; // PagedPool
    object_type
}

const fn job_object_type() -> ObjectType {
    let mut object_type = ObjectType::new(&NAME_JOB, INDEX_JOB);
    let info = &mut object_type.type_info;
    info.generic_mapping = GenericMapping {
        generic_read: 0x0002_0004,    // STANDARD_RIGHTS_READ | JOB_OBJECT_QUERY
        generic_write: 0x0002_000B,   // STANDARD_RIGHTS_WRITE | assign | set | terminate
        generic_execute: 0x0012_0000, // STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE
        generic_all: 0x001F_001F,     // JOB_OBJECT_ALL_ACCESS
    };
    info.valid_access_mask = 0x001F_001F;
    object_type
}

const fn device_object_type() -> ObjectType {
    let mut object_type = ObjectType::new(&NAME_DEVICE, INDEX_DEVICE);
    let info = &mut object_type.type_info;
    info.object_type_flags |= ObjectTypeInitializer::USE_DEFAULT_OBJECT
        | ObjectTypeInitializer::CASE_INSENSITIVE;
    info.invalid_attributes = 0x0000_0100; // OBJ_OPENLINK
                                           // IopFileMapping: STANDARD_RIGHTS_{READ,WRITE,EXECUTE}, SYNCHRONIZE, file rights.
    info.generic_mapping = GenericMapping {
        generic_read: 0x0012_0089,
        generic_write: 0x0012_0116,
        generic_execute: 0x0012_00A0,
        generic_all: 0x001F_01FF,
    };
    info.valid_access_mask = 0x001F_01FF; // FILE_ALL_ACCESS
    info.pool_type = 0; // NonPagedPool
    info.default_nonpaged_pool_charge = 0x150; // Native x64 DEVICE_OBJECT layout.
    object_type
}

/// Address of the [`PsProcessType`](PROCESS_OBJECT_TYPE) static (the value its data-export cell holds).
pub fn process_object_type_addr() -> u64 {
    core::ptr::addr_of!(PROCESS_OBJECT_TYPE) as u64
}
/// Address of the [`PsThreadType`](THREAD_OBJECT_TYPE) static.
pub fn thread_object_type_addr() -> u64 {
    core::ptr::addr_of!(THREAD_OBJECT_TYPE) as u64
}
/// Address of the [`ExEventObjectType`](EVENT_OBJECT_TYPE) static.
pub fn event_object_type_addr() -> u64 {
    core::ptr::addr_of!(EVENT_OBJECT_TYPE) as u64
}
/// Address of the [`LpcPortObjectType`](PORT_OBJECT_TYPE) static.
pub fn port_object_type_addr() -> u64 {
    core::ptr::addr_of!(PORT_OBJECT_TYPE) as u64
}
/// Address of the [`MmSectionObjectType`](SECTION_OBJECT_TYPE) static.
pub fn section_object_type_addr() -> u64 {
    core::ptr::addr_of!(SECTION_OBJECT_TYPE) as u64
}
/// Address of the [`PsJobType`](JOB_OBJECT_TYPE) static.
pub fn job_object_type_addr() -> u64 {
    core::ptr::addr_of!(JOB_OBJECT_TYPE) as u64
}
/// Address of the [`ExDesktopObjectType`](DESKTOP_OBJECT_TYPE) static.
pub fn desktop_object_type_addr() -> u64 {
    core::ptr::addr_of!(DESKTOP_OBJECT_TYPE) as u64
}
/// Address of the [`ExWindowStationObjectType`](WINDOW_STATION_OBJECT_TYPE) static.
pub fn window_station_object_type_addr() -> u64 {
    core::ptr::addr_of!(WINDOW_STATION_OBJECT_TYPE) as u64
}
/// Address of the [`IoDeviceObjectType`](DEVICE_OBJECT_TYPE) native descriptor.
pub fn device_object_type_addr() -> u64 {
    core::ptr::addr_of!(DEVICE_OBJECT_TYPE) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_indices_are_real_and_unique() {
        // SAFETY: single-threaded test; we only read the const-initialized identity fields.
        unsafe {
            assert_eq!(
                (*core::ptr::addr_of!(DESKTOP_OBJECT_TYPE)).name_units(),
                &NAME_DESKTOP
            );
            assert_eq!(
                (*core::ptr::addr_of!(WINDOW_STATION_OBJECT_TYPE)).index(),
                INDEX_WINDOW_STATION
            );
        }
        let indices = [
            INDEX_PROCESS,
            INDEX_THREAD,
            INDEX_EVENT,
            INDEX_PORT,
            INDEX_SECTION,
            INDEX_JOB,
            INDEX_DESKTOP,
            INDEX_WINDOW_STATION,
            INDEX_DEVICE,
        ];
        for (i, a) in indices.iter().enumerate() {
            for b in &indices[i + 1..] {
                assert_ne!(a, b, "type indices must be unique");
            }
        }
    }

    #[test]
    fn statics_have_distinct_addresses() {
        let addrs = [
            process_object_type_addr(),
            thread_object_type_addr(),
            event_object_type_addr(),
            port_object_type_addr(),
            section_object_type_addr(),
            job_object_type_addr(),
            desktop_object_type_addr(),
            window_station_object_type_addr(),
            device_object_type_addr(),
        ];
        for (i, a) in addrs.iter().enumerate() {
            assert_ne!(*a, 0);
            for b in &addrs[i + 1..] {
                assert_ne!(a, b, "each type must be a distinct object");
            }
        }
    }

    #[test]
    fn section_and_job_data_exports_have_distinct_real_type_identities() {
        let section = section_object_type_addr();
        let job = job_object_type_addr();
        assert_ne!(section, 0);
        assert_ne!(job, 0);
        assert_ne!(section, job);
        for existing in [
            process_object_type_addr(),
            thread_object_type_addr(),
            event_object_type_addr(),
            port_object_type_addr(),
            desktop_object_type_addr(),
            window_station_object_type_addr(),
            device_object_type_addr(),
        ] {
            assert_ne!(section, existing);
            assert_ne!(job, existing);
        }
        // SAFETY: the statics are const-initialized; the test reads identity fields only.
        unsafe {
            let section = &*(section as *const ObjectType);
            let job = &*(job as *const ObjectType);
            assert_eq!(section.name_units(), &['S' as u16, 'e' as u16, 'c' as u16, 't' as u16, 'i' as u16, 'o' as u16, 'n' as u16]);
            assert_eq!(job.name_units(), &['J' as u16, 'o' as u16, 'b' as u16]);
            assert_eq!(section.index(), INDEX_SECTION);
            assert_eq!(job.index(), INDEX_JOB);
            assert_ne!(section.index(), job.index());
            assert!(section.type_info.use_default_object());
            assert_eq!(section.type_info.invalid_attributes, 0x100);
            assert_eq!(section.type_info.valid_access_mask, 0x000F_001F);
            assert_eq!(section.type_info.generic_mapping.generic_all, 0x000F_001F);
            assert_eq!(job.type_info.valid_access_mask, 0x001F_001F);
            assert_eq!(job.type_info.generic_mapping.generic_all, 0x001F_001F);
        }
    }

    #[test]
    fn device_descriptor_retains_scalar_initialization() {
        let device = device_object_type();
        assert_eq!(device.name_units(), &NAME_DEVICE);
        assert_eq!(device.index(), INDEX_DEVICE);
        let info = &device.type_info;
        assert_eq!(
            info.length as usize,
            core::mem::size_of::<ObjectTypeInitializer>()
        );
        assert!(info.use_default_object());
        assert!(info.case_insensitive());
        assert_eq!(info.invalid_attributes, 0x100);
        let standard_read = 0x0002_0000;
        let synchronize = 0x0010_0000;
        assert_eq!(
            info.generic_mapping.generic_read,
            standard_read | synchronize | 1 | 8 | 0x80
        );
        assert_eq!(
            info.generic_mapping.generic_write,
            standard_read | synchronize | 2 | 4 | 0x10 | 0x100
        );
        assert_eq!(
            info.generic_mapping.generic_execute,
            standard_read | synchronize | 0x20 | 0x80
        );
        assert_eq!(info.generic_mapping.generic_all, 0x001F_0000 | 0x1FF);
        assert_eq!(info.valid_access_mask, info.generic_mapping.generic_all);
        assert_eq!(info.pool_type, 0);
        assert_eq!(info.default_nonpaged_pool_charge, 0x150);
        assert_eq!(info.default_paged_pool_charge, 0);
        assert!(!info.security_required());
        assert!(!info.maintain_handle_count());
        assert!(!info.maintain_type_list());
        assert_eq!(info.methods, [0; 8]);
    }

    #[test]
    fn win32k_typeinfo_writes_land_in_struct() {
        // Simulate InitDesktopImpl's three writes at LiberNT's ABI offsets and confirm they stay
        // inside the static's storage (do not run off the end / corrupt a neighbour).
        let base = desktop_object_type_addr();
        let size = core::mem::size_of::<ObjectType>() as u64;
        for off in [0x4cu64, 0x5c, 0x6c] {
            assert!(
                off + 4 <= size,
                "win32k write at +0x{off:x} escapes the struct"
            );
        }
        // The GENERIC_MAPPING write is 16 bytes wide.
        assert!(0x4c + 16 <= size);
        let _ = base;
    }
}
