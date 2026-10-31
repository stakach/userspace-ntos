//! The canonical global atom table exists before win32k DriverEntry and moves once to runtime.

use nt_kernel_exec::rtl_atom::OwnedAtomTable;
use nt_user_host::bootstrap_store::BootstrapStore;

use crate::GLOBAL_ATOM_CAPACITY;

static mut BOOTSTRAP: BootstrapStore<OwnedAtomTable> = BootstrapStore::new();

/// Called by the serialized executive bootstrap, before any provider can start.
pub(crate) unsafe fn initialize() -> Result<(), u32> {
    let _durable = crate::allocator::enter_durable();
    let table = OwnedAtomTable::with_capacity(GLOBAL_ATOM_CAPACITY)
        .ok_or(nt_kernel_exec::rtl_atom::status::NO_MEMORY)?;
    (&mut *core::ptr::addr_of_mut!(BOOTSTRAP))
        .initialize(table)
        .map_err(|_| nt_kernel_exec::rtl_atom::status::INVALID_PARAMETER)
}

/// Memory-only operation after ingress has authenticated the exact physical provider and
/// root-issued kernel activation. A callback must not retain the table borrow across IPC.
pub(crate) unsafe fn add_kernel_atom(integer: Option<u16>, name: &[u16]) -> Result<u16, u32> {
    (&mut *core::ptr::addr_of_mut!(BOOTSTRAP))
        .with_mut(|table| match integer {
            Some(atom) => table.add_integer(atom),
            None => table.add_name(name),
        })
        .map_err(|_| 0xC000_00A3u32)?
}

/// Transfers the original allocation, including all atom values and reference counts.
pub(crate) unsafe fn take() -> OwnedAtomTable {
    (&mut *core::ptr::addr_of_mut!(BOOTSTRAP))
        .take()
        .expect("global atom table must transfer exactly once")
}
