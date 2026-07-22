//! Process-local AMD64 dynamic unwind-table registrations.
//!
//! The public node prefix matches ReactOS/Windows `DYNAMIC_FUNCTION_TABLE`; storage and locking are
//! internal. Fixed registrations retain the caller's original (possibly unaligned) function-table
//! pointer. Callback registrations copy the optional out-of-process DLL name and invoke user code
//! only after releasing the registry lock.

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::marker::PhantomPinned;
use core::mem::{align_of, size_of};
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use super::exception::RuntimeFunction;

const RF_UNSORTED: u32 = 1;
const RF_CALLBACK: u32 = 2;

/// `LIST_ENTRY`, exposed by `RtlGetFunctionTableListHead`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

/// The x64 dynamic function-table descriptor used by ntdll's public list.
#[repr(C)]
pub struct DynamicFunctionTable {
    pub list_entry: ListEntry,
    pub function_table: *mut RuntimeFunction,
    pub timestamp: i64,
    pub minimum_address: u64,
    pub maximum_address: u64,
    pub base_address: u64,
    pub callback: Option<RuntimeFunctionCallback>,
    pub context: *mut c_void,
    pub out_of_process_callback_dll: *mut u16,
    pub table_type: u32,
    pub entry_count: u32,
}

/// `GET_RUNTIME_FUNCTION_CALLBACK`.
pub type RuntimeFunctionCallback =
    unsafe extern "system" fn(control_pc: u64, context: *mut c_void) -> *mut RuntimeFunction;

#[repr(C)]
struct OwnedDynamicFunctionTable {
    public: DynamicFunctionTable,
    allocation_size: usize,
}

struct RegistryState {
    head: ListEntry,
    initialized: bool,
}

/// Locked intrusive registry. Operations require a pinned reference because the circular list
/// stores the sentinel's address.
pub struct DynamicFunctionTables {
    locked: AtomicBool,
    state: UnsafeCell<RegistryState>,
    _pin: PhantomPinned,
}

unsafe impl Sync for DynamicFunctionTables {}

struct RegistryGuard<'a> {
    tables: &'a DynamicFunctionTables,
}

impl Drop for RegistryGuard<'_> {
    fn drop(&mut self) {
        self.tables.locked.store(false, Ordering::Release);
    }
}

impl Default for DynamicFunctionTables {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicFunctionTables {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            state: UnsafeCell::new(RegistryState {
                head: ListEntry {
                    flink: ptr::null_mut(),
                    blink: ptr::null_mut(),
                },
                initialized: false,
            }),
            _pin: PhantomPinned,
        }
    }

    fn lock(&self) -> RegistryGuard<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        RegistryGuard { tables: self }
    }

    unsafe fn state_and_head(&self) -> (&mut RegistryState, *mut ListEntry) {
        let state = unsafe { &mut *self.state.get() };
        let head = ptr::addr_of_mut!(state.head);
        if !state.initialized {
            state.head.flink = head;
            state.head.blink = head;
            state.initialized = true;
        }
        (state, head)
    }

    /// Return the actual circular-list sentinel.
    pub fn list_head(self: Pin<&Self>) -> *mut ListEntry {
        let this = self.get_ref();
        let _guard = this.lock();
        // SAFETY: the registry lock serializes sentinel initialization.
        unsafe { this.state_and_head().1 }
    }

    /// Register a caller-owned, unsorted runtime-function table.
    ///
    /// # Safety
    /// `function_table` must name `entry_count` readable `RUNTIME_FUNCTION` rows.
    pub unsafe fn add(
        self: Pin<&Self>,
        function_table: *mut RuntimeFunction,
        entry_count: u32,
        base_address: u64,
    ) -> bool {
        let mut minimum = u64::MAX;
        let mut maximum = 0u64;
        for index in 0..entry_count as usize {
            // SAFETY: caller contract; byte arithmetic preserves support for unaligned tables.
            let row = unsafe {
                ptr::read_unaligned(
                    function_table
                        .cast::<u8>()
                        .add(index * size_of::<RuntimeFunction>())
                        .cast::<RuntimeFunction>(),
                )
            };
            minimum = minimum.min(row.begin as u64);
            maximum = maximum.max(row.end as u64);
        }

        let Some(node) = (unsafe {
            allocate_node(
                function_table,
                entry_count,
                base_address.wrapping_add(minimum),
                base_address.wrapping_add(maximum),
                base_address,
                None,
                ptr::null_mut(),
                RF_UNSORTED,
                &[],
            )
        }) else {
            return false;
        };
        self.insert_tail(node);
        true
    }

    /// Register a callback-backed table for `[base_address, base_address + length)`.
    ///
    /// # Safety
    /// `out_of_process_dll`, when non-null, must be readable through its UTF-16 NUL terminator.
    pub unsafe fn install_callback(
        self: Pin<&Self>,
        table_identifier: u64,
        base_address: u64,
        length: u32,
        callback: Option<RuntimeFunctionCallback>,
        context: *mut c_void,
        out_of_process_dll: *const u16,
    ) -> bool {
        if table_identifier & 3 != 3 {
            return false;
        }
        let mut dll_len = 0usize;
        if !out_of_process_dll.is_null() {
            loop {
                let Some(next) = dll_len.checked_add(1) else {
                    return false;
                };
                // SAFETY: caller contract.
                let ch = unsafe { ptr::read(out_of_process_dll.add(dll_len)) };
                dll_len = next;
                if ch == 0 {
                    break;
                }
            }
        }
        let dll = if dll_len == 0 {
            &[]
        } else {
            // SAFETY: the loop above established the readable length including NUL.
            unsafe { core::slice::from_raw_parts(out_of_process_dll, dll_len) }
        };
        let Some(node) = (unsafe {
            allocate_node(
                table_identifier as *mut RuntimeFunction,
                0,
                base_address,
                base_address.wrapping_add(length as u64),
                base_address,
                callback,
                context,
                RF_CALLBACK,
                dll,
            )
        }) else {
            return false;
        };
        self.insert_tail(node);
        true
    }

    fn insert_tail(self: Pin<&Self>, node: *mut OwnedDynamicFunctionTable) {
        let this = self.get_ref();
        let _guard = this.lock();
        // SAFETY: node is uniquely owned; list mutations are serialized by the registry lock.
        unsafe {
            let (_, head) = this.state_and_head();
            let entry = ptr::addr_of_mut!((*node).public.list_entry);
            let tail = (*head).blink;
            (*entry).flink = head;
            (*entry).blink = tail;
            (*tail).flink = entry;
            (*head).blink = entry;
        }
    }

    /// Delete the first registration whose original table pointer/identifier matches exactly.
    pub fn delete(self: Pin<&Self>, function_table: *mut RuntimeFunction) -> bool {
        let this = self.get_ref();
        let guard = this.lock();
        let removed = unsafe {
            let (_, head) = this.state_and_head();
            let mut link = (*head).flink;
            let mut found = ptr::null_mut();
            while link != head {
                let node = link.cast::<OwnedDynamicFunctionTable>();
                if (*node).public.function_table == function_table {
                    let previous = (*link).blink;
                    let next = (*link).flink;
                    (*previous).flink = next;
                    (*next).blink = previous;
                    found = node;
                    break;
                }
                link = (*link).flink;
            }
            found
        };
        drop(guard);
        if removed.is_null() {
            return false;
        }
        // SAFETY: the node was unlinked under the lock and no registry traversal can reach it now.
        unsafe { free_node(removed) };
        true
    }

    /// Resolve one dynamic registration in insertion order.
    ///
    /// # Safety
    /// `image_base_out` must be null or writable. Caller-owned table rows must remain readable.
    pub unsafe fn lookup(
        self: Pin<&Self>,
        control_pc: u64,
        image_base_out: *mut u64,
    ) -> *mut RuntimeFunction {
        let this = self.get_ref();
        let guard = this.lock();
        let mut callback = None;
        let mut callback_context = ptr::null_mut();
        let mut callback_base = 0u64;
        // SAFETY: registry traversal is protected by `guard`.
        let fixed = unsafe {
            let (_, head) = this.state_and_head();
            let mut link = (*head).flink;
            let mut found = ptr::null_mut();
            while link != head {
                let node = link.cast::<OwnedDynamicFunctionTable>();
                let table = &(*node).public;
                if control_pc >= table.minimum_address && control_pc < table.maximum_address {
                    if table.table_type == RF_CALLBACK {
                        if table.callback.is_some() {
                            callback = table.callback;
                            callback_context = table.context;
                            callback_base = table.base_address;
                            break;
                        }
                    }
                    let offset = control_pc.wrapping_sub(table.base_address);
                    for index in 0..table.entry_count as usize {
                        let row = table
                            .function_table
                            .cast::<u8>()
                            .add(index * size_of::<RuntimeFunction>())
                            .cast::<RuntimeFunction>();
                        let value = ptr::read_unaligned(row);
                        if offset >= value.begin as u64 && offset < value.end as u64 {
                            if !image_base_out.is_null() {
                                *image_base_out = table.base_address;
                            }
                            found = row;
                            break;
                        }
                    }
                    if !found.is_null() {
                        break;
                    }
                }
                link = (*link).flink;
            }
            found
        };
        if !fixed.is_null() {
            return fixed;
        }
        if let Some(callback) = callback {
            if !image_base_out.is_null() {
                // SAFETY: caller contract.
                unsafe { *image_base_out = callback_base };
            }
            drop(guard);
            // SAFETY: registered callback ABI and context are caller-owned.
            return unsafe { callback(control_pc, callback_context) };
        }
        ptr::null_mut()
    }
}

impl Drop for DynamicFunctionTables {
    fn drop(&mut self) {
        // SAFETY: `&mut self` excludes concurrent access. Free each remaining intrusive node.
        unsafe {
            let state = &mut *self.state.get();
            if !state.initialized {
                return;
            }
            let head = ptr::addr_of_mut!(state.head);
            let mut link = (*head).flink;
            while link != head {
                let node = link.cast::<OwnedDynamicFunctionTable>();
                link = (*link).flink;
                free_node(node);
            }
        }
    }
}

unsafe fn allocate_node(
    function_table: *mut RuntimeFunction,
    entry_count: u32,
    minimum_address: u64,
    maximum_address: u64,
    base_address: u64,
    callback: Option<RuntimeFunctionCallback>,
    context: *mut c_void,
    table_type: u32,
    dll: &[u16],
) -> Option<*mut OwnedDynamicFunctionTable> {
    let dll_bytes = dll.len().checked_mul(size_of::<u16>())?;
    let allocation_size = size_of::<OwnedDynamicFunctionTable>().checked_add(dll_bytes)?;
    let layout =
        Layout::from_size_align(allocation_size, align_of::<OwnedDynamicFunctionTable>()).ok()?;
    // SAFETY: valid nonzero layout; null reports allocator exhaustion.
    let node = unsafe { alloc(layout) }.cast::<OwnedDynamicFunctionTable>();
    if node.is_null() {
        return None;
    }
    let dll_out = if dll.is_empty() {
        ptr::null_mut()
    } else {
        // SAFETY: the flexible suffix is part of this allocation and sized for `dll`.
        let output = unsafe {
            node.cast::<u8>()
                .add(size_of::<OwnedDynamicFunctionTable>())
                .cast::<u16>()
        };
        unsafe { ptr::copy_nonoverlapping(dll.as_ptr(), output, dll.len()) };
        output
    };
    // SAFETY: `node` is fresh, aligned, and large enough for the private header.
    unsafe {
        ptr::write(
            node,
            OwnedDynamicFunctionTable {
                public: DynamicFunctionTable {
                    list_entry: ListEntry {
                        flink: ptr::null_mut(),
                        blink: ptr::null_mut(),
                    },
                    function_table,
                    timestamp: 0,
                    minimum_address,
                    maximum_address,
                    base_address,
                    callback,
                    context,
                    out_of_process_callback_dll: dll_out,
                    table_type,
                    entry_count,
                },
                allocation_size,
            },
        )
    };
    Some(node)
}

unsafe fn free_node(node: *mut OwnedDynamicFunctionTable) {
    // SAFETY: node was allocated by `allocate_node` and is no longer linked.
    let allocation_size = unsafe { (*node).allocation_size };
    let layout = Layout::from_size_align(allocation_size, align_of::<OwnedDynamicFunctionTable>())
        .expect("stored dynamic function table layout");
    unsafe { dealloc(node.cast::<u8>(), layout) };
}

/// The process-global registry used by the DLL exports and live unwinder.
static DYNAMIC_FUNCTION_TABLES: DynamicFunctionTables = DynamicFunctionTables::new();

/// Pin the process-global registry at its static address.
pub fn dynamic_function_tables() -> Pin<&'static DynamicFunctionTables> {
    // SAFETY: statics never move.
    unsafe { Pin::new_unchecked(&DYNAMIC_FUNCTION_TABLES) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use core::mem::{offset_of, size_of};

    fn registry() -> Pin<Box<DynamicFunctionTables>> {
        Box::pin(DynamicFunctionTables::new())
    }

    #[test]
    fn native_layout_matches_amd64_abi() {
        assert_eq!(size_of::<RuntimeFunction>(), 12);
        assert_eq!(size_of::<ListEntry>(), 16);
        assert_eq!(size_of::<DynamicFunctionTable>(), 88);
        assert_eq!(align_of::<DynamicFunctionTable>(), 8);
        assert_eq!(offset_of!(DynamicFunctionTable, function_table), 16);
        assert_eq!(offset_of!(DynamicFunctionTable, minimum_address), 32);
        assert_eq!(offset_of!(DynamicFunctionTable, callback), 56);
        assert_eq!(offset_of!(DynamicFunctionTable, table_type), 80);
    }

    #[test]
    fn unsorted_table_uses_original_rows_and_exact_boundaries() {
        let tables = registry();
        let mut rows = [
            RuntimeFunction {
                begin: 0x300,
                end: 0x380,
                unwind_info: 0x900,
            },
            RuntimeFunction {
                begin: 0x100,
                end: 0x180,
                unwind_info: 0x800,
            },
        ];
        assert!(unsafe { tables.as_ref().add(rows.as_mut_ptr(), 2, 0x1_0000) });
        let mut base = 0;
        assert_eq!(
            unsafe { tables.as_ref().lookup(0x1_0100, &mut base) },
            ptr::addr_of_mut!(rows[1])
        );
        assert_eq!(base, 0x1_0000);
        assert!(unsafe { tables.as_ref().lookup(0x1_0180, &mut base) }.is_null());
        assert_eq!(
            unsafe { tables.as_ref().lookup(0x1_037f, &mut base) },
            ptr::addr_of_mut!(rows[0])
        );
        assert!(unsafe { tables.as_ref().lookup(0x1_0380, &mut base) }.is_null());
    }

    #[test]
    fn unaligned_function_table_is_supported() {
        let tables = registry();
        let mut storage = [0u8; size_of::<RuntimeFunction>() + 1];
        let row = storage[1..].as_mut_ptr().cast::<RuntimeFunction>();
        unsafe {
            ptr::write_unaligned(
                row,
                RuntimeFunction {
                    begin: 0x10,
                    end: 0x20,
                    unwind_info: 0x30,
                },
            );
        }
        assert!(unsafe { tables.as_ref().add(row, 1, 0x4000) });
        assert_eq!(
            unsafe { tables.as_ref().lookup(0x4010, ptr::null_mut()) },
            row
        );
    }

    #[test]
    fn duplicate_registration_deletes_one_at_a_time() {
        let tables = registry();
        let mut row = RuntimeFunction {
            begin: 0x10,
            end: 0x20,
            unwind_info: 0x30,
        };
        assert!(unsafe { tables.as_ref().add(&mut row, 1, 0x1000) });
        assert!(unsafe { tables.as_ref().add(&mut row, 1, 0x1000) });
        assert!(tables.as_ref().delete(&mut row));
        assert_eq!(
            unsafe { tables.as_ref().lookup(0x1010, ptr::null_mut()) },
            ptr::addr_of_mut!(row)
        );
        assert!(tables.as_ref().delete(&mut row));
        assert!(!tables.as_ref().delete(&mut row));
    }

    #[test]
    fn empty_table_is_linked_and_deletable() {
        let tables = registry();
        let marker = 0x1234usize as *mut RuntimeFunction;
        assert!(unsafe { tables.as_ref().add(marker, 0, 0x1000) });
        let head = tables.as_ref().list_head();
        assert_ne!(unsafe { (*head).flink }, head);
        assert!(tables.as_ref().delete(marker));
        assert_eq!(unsafe { (*head).flink }, head);
        assert_eq!(unsafe { (*head).blink }, head);
    }

    #[test]
    fn lookup_miss_preserves_image_base_output() {
        let tables = registry();
        let mut base = 0xDEAD_BEEF;
        assert!(unsafe { tables.as_ref().lookup(0x1234, &mut base) }.is_null());
        assert_eq!(base, 0xDEAD_BEEF);
    }

    static mut CALLBACK_ROW: RuntimeFunction = RuntimeFunction {
        begin: 0x20,
        end: 0x40,
        unwind_info: 0x60,
    };

    unsafe extern "system" fn callback(pc: u64, context: *mut c_void) -> *mut RuntimeFunction {
        assert_eq!(context as usize, 0xCAFE);
        if pc == 0x2020 {
            ptr::addr_of_mut!(CALLBACK_ROW)
        } else {
            ptr::null_mut()
        }
    }

    struct ReentrantCallback {
        tables: *const DynamicFunctionTables,
        identifier: *mut RuntimeFunction,
    }

    unsafe extern "system" fn deleting_callback(
        _pc: u64,
        context: *mut c_void,
    ) -> *mut RuntimeFunction {
        let state = unsafe { &*(context.cast::<ReentrantCallback>()) };
        let tables = unsafe { Pin::new_unchecked(&*state.tables) };
        assert!(tables.delete(state.identifier));
        ptr::addr_of_mut!(CALLBACK_ROW)
    }

    #[test]
    fn callback_validation_range_context_and_delete() {
        let tables = registry();
        assert!(!unsafe {
            tables.as_ref().install_callback(
                0x1000,
                0x2000,
                0x100,
                Some(callback),
                ptr::null_mut(),
                ptr::null(),
            )
        });
        let dll = [b'j' as u16, b'i' as u16, b't' as u16, 0];
        assert!(unsafe {
            tables.as_ref().install_callback(
                0x1003,
                0x2000,
                0x100,
                Some(callback),
                0xCAFEusize as *mut c_void,
                dll.as_ptr(),
            )
        });
        let mut base = 0;
        assert!(unsafe { tables.as_ref().lookup(0x2000, &mut base) }.is_null());
        assert_eq!(base, 0x2000);
        assert_eq!(
            unsafe { tables.as_ref().lookup(0x2020, &mut base) },
            ptr::addr_of_mut!(CALLBACK_ROW)
        );
        assert_eq!(base, 0x2000);
        assert!(unsafe { tables.as_ref().lookup(0x2100, &mut base) }.is_null());
        assert!(tables.as_ref().delete(0x1003usize as *mut RuntimeFunction));
    }

    #[test]
    fn callback_dll_name_is_owned_by_registration() {
        let tables = registry();
        let mut dll = [b'j' as u16, b'i' as u16, b't' as u16, 0];
        assert!(unsafe {
            tables.as_ref().install_callback(
                0x3003,
                0x5000,
                0x100,
                None,
                ptr::null_mut(),
                dll.as_ptr(),
            )
        });
        dll[0] = b'x' as u16;
        assert_eq!(dll[0], b'x' as u16);
        let head = tables.as_ref().list_head();
        let node = unsafe { (*head).flink.cast::<DynamicFunctionTable>() };
        let copied = unsafe { core::slice::from_raw_parts((*node).out_of_process_callback_dll, 4) };
        assert_eq!(copied, &[b'j' as u16, b'i' as u16, b't' as u16, 0]);
    }

    #[test]
    fn callback_can_delete_its_registration() {
        let tables = registry();
        let identifier = 0x4003usize as *mut RuntimeFunction;
        let mut state = ReentrantCallback {
            tables: tables.as_ref().get_ref(),
            identifier,
        };
        assert!(unsafe {
            tables.as_ref().install_callback(
                identifier as u64,
                0x6000,
                0x100,
                Some(deleting_callback),
                ptr::addr_of_mut!(state).cast(),
                ptr::null(),
            )
        });
        assert_eq!(
            unsafe { tables.as_ref().lookup(0x6020, ptr::null_mut()) },
            ptr::addr_of_mut!(CALLBACK_ROW)
        );
        assert!(!tables.as_ref().delete(identifier));
    }

    #[test]
    fn null_callback_does_not_hide_later_fixed_registration() {
        let tables = registry();
        assert!(unsafe {
            tables.as_ref().install_callback(
                0x6003,
                0x7000,
                0x100,
                None,
                ptr::null_mut(),
                ptr::null(),
            )
        });
        let mut row = RuntimeFunction {
            begin: 0x20,
            end: 0x40,
            unwind_info: 0x80,
        };
        assert!(unsafe { tables.as_ref().add(&mut row, 1, 0x7000) });
        assert_eq!(
            unsafe { tables.as_ref().lookup(0x7020, ptr::null_mut()) },
            ptr::addr_of_mut!(row)
        );
    }
}
