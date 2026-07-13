//! Real, const-constructible NT `OBJECT_TYPE`s for the win32k data-export globals.
//!
//! win32k.sys imports a handful of `POBJECT_TYPE` **data** globals from `ntoskrnl.exe`
//! (`PsProcessType`, `PsThreadType`, `ExDesktopObjectType`, `ExWindowStationObjectType`,
//! `ExEventObjectType`, `LpcPortObjectType`). Each is a pointer to an `OBJECT_TYPE` struct that
//! ntoskrnl creates at boot; win32k treats the pointed-at struct as its **type identity** and — for
//! the desktop / window-station types — *writes* its own `TypeInfo` fields into it during
//! `InitDesktopImpl` / `InitWindowStationImpl` (see
//! `references/reactos/win32ss/user/ntuser/{desktop,winsta}.c`):
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
//! `OBJECT_TYPE` ABI (`references/nt5/base/ntos/inc/ob.h`,
//! `references/reactos/sdk/include/ndk/obtypes.h`) so that (a) each type has a genuine, typed
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

/// `OBJECT_TYPE_INITIALIZER` (`obtypes.h`), x64 layout. win32k writes `generic_mapping` (+0x08),
/// `valid_access_mask` (+0x18) and `default_nonpaged_pool_charge` (+0x28) here; the rest is backing
/// store for a genuine initializer that a fuller ntoskrnl would populate.
#[repr(C)]
pub struct ObjectTypeInitializer {
    pub length: u16,
    pub use_default_object: u8,
    pub case_insensitive: u8,
    pub invalid_attributes: u32,
    pub generic_mapping: GenericMapping,
    pub valid_access_mask: u32,
    pub security_required: u8,
    pub maintain_handle_count: u8,
    pub maintain_type_list: u8,
    _pad0: u8,
    pub pool_type: u32,
    pub default_paged_pool_charge: u32,
    pub default_nonpaged_pool_charge: u32,
    _pad1: u32,
    /// `Dump/Open/Close/Delete/Parse/Security/QueryName/OkayToClose` procedure pointers.
    pub methods: [u64; 8],
}

impl ObjectTypeInitializer {
    const fn zeroed() -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u16,
            use_default_object: 0,
            case_insensitive: 0,
            invalid_attributes: 0,
            generic_mapping: GenericMapping {
                generic_read: 0,
                generic_write: 0,
                generic_execute: 0,
                generic_all: 0,
            },
            valid_access_mask: 0,
            security_required: 0,
            maintain_handle_count: 0,
            maintain_type_list: 0,
            _pad0: 0,
            pool_type: 0,
            default_paged_pool_charge: 0,
            default_nonpaged_pool_charge: 0,
            _pad1: 0,
            methods: [0; 8],
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

/// A real NT `OBJECT_TYPE`, `#[repr(C)]` to the x64 ABI through `TypeInfo` + `Key`.
///
/// The leading `ERESOURCE Mutex`, `LIST_ENTRY TypeList` and object counters are opaque backing store
/// (win32k never reads them); [`name`](Self::name) and [`index`](Self::index) carry the real typed
/// identity; [`type_info`](Self::type_info) is where win32k writes its `TypeInfo` fields. A trailing
/// pad gives headroom past `Key` so any over-write stays in-struct. Not the full struct (the
/// `ObjectLocks[4]` tail is elided — win32k never touches it) but ABI-accurate for every field win32k
/// or a hosted binary reaches.
#[repr(C, align(16))]
pub struct ObjectType {
    _mutex: [u8; 0x68],   // ERESOURCE
    _type_list: [u8; 0x10], // LIST_ENTRY
    pub name: UnicodeString,
    pub default_object: u64,
    pub index: u32,
    _counters: [u32; 4], // Total/HighWater Objects+Handles
    _pad: u32,
    pub type_info: ObjectTypeInitializer,
    pub key: u32,
    _tail: [u8; 0x1C],
}

// Compile-time proof the layout matches the x64 OBJECT_TYPE ABI: win32k's machine code writes at
// these exact byte offsets, so they are load-bearing.
const _: () = {
    assert!(offset_of!(ObjectType, name) == 0x78);
    assert!(offset_of!(ObjectType, index) == 0x90);
    assert!(offset_of!(ObjectType, type_info) == 0xA8);
    assert!(offset_of!(ObjectType, key) == 0x118);
    // TypeInfo sub-fields win32k writes (offsets relative to the OBJECT_TYPE base).
    assert!(0xA8 + offset_of!(ObjectTypeInitializer, generic_mapping) == 0xB0);
    assert!(0xA8 + offset_of!(ObjectTypeInitializer, valid_access_mask) == 0xC0);
    assert!(0xA8 + offset_of!(ObjectTypeInitializer, default_nonpaged_pool_charge) == 0xD0);
    // The struct must be large enough to absorb every win32k write (through +0xD4) in-struct.
    assert!(core::mem::size_of::<ObjectType>() >= 0x11C);
};

impl ObjectType {
    /// Construct a type with a real `Name` (UTF-16 code units) and a unique `Index`.
    pub const fn new(name: &'static [u16], index: u32) -> Self {
        let name_bytes = (name.len() * 2) as u16;
        Self {
            _mutex: [0; 0x68],
            _type_list: [0; 0x10],
            name: UnicodeString {
                length: name_bytes,
                maximum_length: name_bytes,
                _pad: 0,
                buffer: name.as_ptr(),
            },
            default_object: 0,
            index,
            _counters: [0; 4],
            _pad: 0,
            type_info: ObjectTypeInitializer::zeroed(),
            key: 0,
            _tail: [0; 0x1C],
        }
    }

    /// This type's `Index` (unique per registered type).
    pub fn index(&self) -> u32 {
        self.index
    }

    /// This type's `Name` as UTF-16 code units.
    pub fn name_units(&self) -> &[u16] {
        // SAFETY: `buffer`/`length` were set from a `&'static [u16]` in `new`.
        unsafe {
            core::slice::from_raw_parts(self.name.buffer, (self.name.length / 2) as usize)
        }
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
/// `ExDesktopObjectType` index.
pub const INDEX_DESKTOP: u32 = 24;
/// `ExWindowStationObjectType` index.
pub const INDEX_WINDOW_STATION: u32 = 25;

// UTF-16 type names (const, no alloc).
static NAME_PROCESS: [u16; 7] = [b'P' as u16, b'r' as u16, b'o' as u16, b'c' as u16, b'e' as u16, b's' as u16, b's' as u16];
static NAME_THREAD: [u16; 6] = [b'T' as u16, b'h' as u16, b'r' as u16, b'e' as u16, b'a' as u16, b'd' as u16];
static NAME_EVENT: [u16; 5] = [b'E' as u16, b'v' as u16, b'e' as u16, b'n' as u16, b't' as u16];
static NAME_PORT: [u16; 4] = [b'P' as u16, b'o' as u16, b'r' as u16, b't' as u16];
static NAME_DESKTOP: [u16; 7] = [b'D' as u16, b'e' as u16, b's' as u16, b'k' as u16, b't' as u16, b'o' as u16, b'p' as u16];
static NAME_WINSTA: [u16; 13] = [
    b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16, b'o' as u16, b'w' as u16, b'S' as u16,
    b't' as u16, b'a' as u16, b't' as u16, b'i' as u16, b'o' as u16, b'n' as u16,
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
/// `ExDesktopObjectType` — the win32k desktop object type.
pub static mut DESKTOP_OBJECT_TYPE: ObjectType = ObjectType::new(&NAME_DESKTOP, INDEX_DESKTOP);
/// `ExWindowStationObjectType` — the win32k window-station object type.
pub static mut WINDOW_STATION_OBJECT_TYPE: ObjectType =
    ObjectType::new(&NAME_WINSTA, INDEX_WINDOW_STATION);

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
/// Address of the [`ExDesktopObjectType`](DESKTOP_OBJECT_TYPE) static.
pub fn desktop_object_type_addr() -> u64 {
    core::ptr::addr_of!(DESKTOP_OBJECT_TYPE) as u64
}
/// Address of the [`ExWindowStationObjectType`](WINDOW_STATION_OBJECT_TYPE) static.
pub fn window_station_object_type_addr() -> u64 {
    core::ptr::addr_of!(WINDOW_STATION_OBJECT_TYPE) as u64
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
            INDEX_DESKTOP,
            INDEX_WINDOW_STATION,
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
            desktop_object_type_addr(),
            window_station_object_type_addr(),
        ];
        for (i, a) in addrs.iter().enumerate() {
            assert_ne!(*a, 0);
            for b in &addrs[i + 1..] {
                assert_ne!(a, b, "each type must be a distinct object");
            }
        }
    }

    #[test]
    fn win32k_typeinfo_writes_land_in_struct() {
        // Simulate InitDesktopImpl's three writes at their ABI offsets and confirm they stay inside
        // the static's storage (do not run off the end / corrupt a neighbour).
        let base = desktop_object_type_addr();
        let size = core::mem::size_of::<ObjectType>() as u64;
        for off in [0xB0u64, 0xC0, 0xD0] {
            assert!(off + 4 <= size, "win32k write at +0x{off:x} escapes the struct");
        }
        // The GENERIC_MAPPING write is 16 bytes wide.
        assert!(0xB0 + 16 <= size);
        let _ = base;
    }
}
