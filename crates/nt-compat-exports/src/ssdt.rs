//! `KeAddSystemServiceTable` recorder.
//!
//! At init, `win32k.sys` calls `KeAddSystemServiceTable(Base, Count, Number,
//! ArgumentTable, Index)` to register its **NtUser/NtGdi** service table as SSDT
//! **shadow** slot index **1** (base service numbers `0x1000`). We record the
//! `(index, base, count, number_table, argument_table)` tuple so Phase 2 can
//! route a caller's `SSN >= 0x1000` (`UnknownSyscall` in the executive) to the
//! win32k service function it names.
//!
//! Windows SSDT layout: service number `n` in shadow table `i` selects
//! `base[n - 0x1000]` (the win32k functions live at descriptor index 1). We keep
//! this a recording stub — the actual dispatch is Phase 2's job; here we prove
//! the table is captured correctly.

use alloc::vec::Vec;

/// win32k registers its table at descriptor **index 1** (the "shadow" SSDT).
pub const WIN32K_SERVICE_TABLE_INDEX: u32 = 1;

/// The base service number of the first win32k (NtUser/NtGdi) syscall. Service
/// numbers `< 0x1000` are native ntoskrnl; `>= 0x1000` are win32k.
pub const WIN32K_SERVICE_BASE: u32 = 0x1000;

/// ReactOS/NT5 x64 service parameter tables store the argument byte count,
/// not the register-width argument count.
pub const X64_SERVICE_ARGUMENT_GRANULARITY: u32 = core::mem::size_of::<u64>() as u32;

/// Decode one x64 SSPT/KiArgumentTable byte into a pointer-width argument count.
pub const fn x64_argument_count_from_sspt_byte(argument_bytes: u8) -> u32 {
    (argument_bytes as u32) / X64_SERVICE_ARGUMENT_GRANULARITY
}

/// Encode a pointer-width argument count into the x64 SSPT byte form.
pub const fn x64_sspt_byte_from_argument_count(argument_count: u32) -> Option<u8> {
    let Some(argument_bytes) = argument_count.checked_mul(X64_SERVICE_ARGUMENT_GRANULARITY) else {
        return None;
    };
    if argument_bytes > u8::MAX as u32 {
        None
    } else {
        Some(argument_bytes as u8)
    }
}

/// One recorded `KeAddSystemServiceTable` registration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ServiceTable {
    /// The SSDT descriptor index (`1` for win32k).
    pub index: u32,
    /// Pointer to the service function table (`KiServiceTable`-style).
    pub base: u64,
    /// Number of services in the table.
    pub count: u32,
    /// Pointer to the per-service argument-byte table (`KiArgumentTable`-style).
    pub argument_table: u64,
}

impl ServiceTable {
    /// The first service number owned by this descriptor.
    pub fn service_base(&self) -> u32 {
        if self.index == WIN32K_SERVICE_TABLE_INDEX {
            WIN32K_SERVICE_BASE
        } else {
            0
        }
    }

    /// The descriptor-relative service index for `ssn`, if in range.
    pub fn service_index(&self, ssn: u32) -> Option<u32> {
        let index = ssn.checked_sub(self.service_base())?;
        if index < self.count {
            Some(index)
        } else {
            None
        }
    }

    /// True if `ssn` falls within this table's service-number range.
    /// win32k's table starts at [`WIN32K_SERVICE_BASE`]; native tables at 0.
    pub fn contains(&self, ssn: u32) -> bool {
        self.service_index(ssn).is_some()
    }

    /// The service-function pointer for `ssn` (`base + (ssn - start) * 8`),
    /// or `None` if out of range. Phase 2 uses this to locate the target.
    pub fn function_ptr(&self, ssn: u32) -> Option<u64> {
        let index = self.service_index(ssn)?;
        self.base.checked_add(u64::from(index).checked_mul(8)?)
    }

    /// Pointer to the one-byte argument metadata for `ssn`, if the provider
    /// registered an SSPT/KiArgumentTable and `ssn` is in range.
    pub fn argument_byte_ptr(&self, ssn: u32) -> Option<u64> {
        if self.argument_table == 0 {
            return None;
        }
        let index = self.service_index(ssn)?;
        self.argument_table.checked_add(u64::from(index))
    }
}

/// Records the SSDT registrations made via `KeAddSystemServiceTable`.
#[derive(Default)]
pub struct ServiceTableRegistry {
    tables: Vec<ServiceTable>,
}

impl ServiceTableRegistry {
    pub fn new() -> Self {
        Self { tables: Vec::new() }
    }

    /// `KeAddSystemServiceTable`: record a registration. Returns `false` if the
    /// index is already occupied (Windows rejects a double-add), matching the
    /// real semantics win32k relies on (it adds index 1 exactly once).
    pub fn add(&mut self, index: u32, base: u64, count: u32, argument_table: u64) -> bool {
        if self.tables.iter().any(|t| t.index == index) {
            return false;
        }
        self.tables.push(ServiceTable {
            index,
            base,
            count,
            argument_table,
        });
        true
    }

    /// The recorded table for a descriptor index, if any.
    pub fn table(&self, index: u32) -> Option<&ServiceTable> {
        self.tables.iter().find(|t| t.index == index)
    }

    /// The recorded win32k (shadow, index 1) table, if registered.
    pub fn win32k(&self) -> Option<&ServiceTable> {
        self.table(WIN32K_SERVICE_TABLE_INDEX)
    }

    /// Resolve a caller's service number to a `(table, function_ptr)` pair — the
    /// Phase 2 dispatch hook for `SSN >= 0x1000`.
    pub fn resolve(&self, ssn: u32) -> Option<(&ServiceTable, u64)> {
        self.tables
            .iter()
            .find_map(|t| t.function_ptr(ssn).map(|p| (t, p)))
    }

    pub fn len(&self) -> usize {
        self.tables.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn records_win32k_table() {
        let mut reg = ServiceTableRegistry::new();
        assert!(reg.win32k().is_none());
        // win32k registers ~600 NtUser+NtGdi services at index 1.
        assert!(reg.add(
            WIN32K_SERVICE_TABLE_INDEX,
            0xFFFF_F800_0010_0000,
            600,
            0xFFFF_F800_0011_0000
        ));
        let t = reg.win32k().expect("registered");
        assert_eq!(t.count, 600);
        assert_eq!(t.base, 0xFFFF_F800_0010_0000);
        assert_eq!(t.argument_table, 0xFFFF_F800_0011_0000);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn double_add_rejected() {
        let mut reg = ServiceTableRegistry::new();
        assert!(reg.add(WIN32K_SERVICE_TABLE_INDEX, 0x1000, 10, 0x2000));
        assert!(!reg.add(WIN32K_SERVICE_TABLE_INDEX, 0x9999, 5, 0x3000));
        assert_eq!(reg.len(), 1);
        // The first registration is untouched.
        assert_eq!(reg.win32k().unwrap().count, 10);
    }

    #[test]
    fn service_number_range_and_resolution() {
        let mut reg = ServiceTableRegistry::new();
        let base = 0xFFFF_F800_0010_0000;
        reg.add(WIN32K_SERVICE_TABLE_INDEX, base, 600, 0);
        let t = reg.win32k().unwrap();
        // Just below the win32k base is not ours.
        assert!(!t.contains(0x0FFF));
        // 0x1000 is the first NtUser/NtGdi service.
        assert!(t.contains(0x1000));
        assert_eq!(t.service_index(0x1000), Some(0));
        assert_eq!(t.function_ptr(0x1000), Some(base));
        // 0x10FA (the SSN csrss/winsrv stops on) resolves to base + 0xFA*8.
        assert!(t.contains(0x10FA));
        assert_eq!(t.service_index(0x10FA), Some(0xFA));
        assert_eq!(t.function_ptr(0x10FA), Some(base + 0xFA * 8));
        // Past the end of the table is out of range.
        assert!(!t.contains(0x1000 + 600));
        assert_eq!(t.service_index(0x1000 + 600), None);
        assert_eq!(t.function_ptr(0x1000 + 600), None);

        let (rt, ptr) = reg.resolve(0x10FA).expect("resolved");
        assert_eq!(rt.index, WIN32K_SERVICE_TABLE_INDEX);
        assert_eq!(ptr, base + 0xFA * 8);
        // A native SSN with no registered native table does not resolve.
        assert!(reg.resolve(0x0055).is_none());
    }

    #[test]
    fn native_table_uses_zero_base() {
        let mut reg = ServiceTableRegistry::new();
        reg.add(0, 0xAAAA_0000, 400, 0); // native ntoskrnl SSDT
        let t = reg.table(0).unwrap();
        assert!(t.contains(0x0055));
        assert_eq!(t.function_ptr(0x0055), Some(0xAAAA_0000 + 0x55 * 8));
        assert!(!t.contains(0x1000)); // win32k range is not in the native table
    }

    #[test]
    fn service_table_exposes_argument_metadata_addresses() {
        let table = ServiceTable {
            index: WIN32K_SERVICE_TABLE_INDEX,
            base: 0xFFFF_F800_0010_0000,
            count: 600,
            argument_table: 0xFFFF_F800_0011_0000,
        };

        assert_eq!(
            table.argument_byte_ptr(WIN32K_SERVICE_BASE),
            Some(table.argument_table)
        );
        assert_eq!(
            table.argument_byte_ptr(WIN32K_SERVICE_BASE + 0xFA),
            Some(table.argument_table + 0xFA)
        );
        assert_eq!(table.argument_byte_ptr(WIN32K_SERVICE_BASE + 600), None);

        let no_metadata = ServiceTable {
            argument_table: 0,
            ..table
        };
        assert_eq!(no_metadata.argument_byte_ptr(WIN32K_SERVICE_BASE), None);
    }

    #[test]
    fn x64_argument_count_decodes_sspt_bytes() {
        assert_eq!(x64_argument_count_from_sspt_byte(0), 0);
        assert_eq!(x64_argument_count_from_sspt_byte(32), 4);
        assert_eq!(x64_argument_count_from_sspt_byte(40), 5);
        assert_eq!(x64_argument_count_from_sspt_byte(120), 15);
        assert_eq!(x64_sspt_byte_from_argument_count(15), Some(120));
        assert_eq!(x64_sspt_byte_from_argument_count(32), None);
    }
}
