//! Hosted driver imports for the native WMI GUID-object boundary.
//!
//! No WMI data provider is registered in this driver component. An absent GUID
//! is an ordinary `STATUS_WMI_GUID_NOT_FOUND`, not a fabricated successful open.
//! A future provider broker must own returned object pointers and route its
//! query/completion before this adapter can publish a successful open.

use core::ptr::{read_unaligned, write_unaligned};
use core::sync::atomic::{AtomicBool, Ordering};
use nt_wmi::{
    WmiGuid, WmiProviderId, WmiProviderOwner, WmiRegistry, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_HANDLE,
};

const STATUS_ACCESS_VIOLATION: i32 = 0xc000_0005u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xc000_00bbu32 as i32;

static BUSY: AtomicBool = AtomicBool::new(false);
static mut REGISTRY: WmiRegistry = WmiRegistry::new();

struct RegistryGuard;

impl RegistryGuard {
    fn acquire() -> Result<Self, u32> {
        BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
    }
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

/// Called only after the executive authenticates an exact provider incarnation.
/// Registration alone does not activate a driver-visible WMI object; the provider
/// query IPC and object-reference retirement boundary must be wired first.
#[allow(dead_code)]
pub(crate) fn register_provider(
    owner: WmiProviderOwner,
    guid: WmiGuid,
    access: u32,
) -> Result<WmiProviderId, u32> {
    let _guard = RegistryGuard::acquire()?;
    unsafe { (&mut *core::ptr::addr_of_mut!(REGISTRY)).register_provider(owner, guid, access) }
}

#[allow(dead_code)]
pub(crate) fn unregister_provider(owner: WmiProviderOwner, id: WmiProviderId) -> Result<(), u32> {
    let _guard = RegistryGuard::acquire()?;
    unsafe { (&mut *core::ptr::addr_of_mut!(REGISTRY)).unregister_provider(owner, id) }
}

/// `IoWMIOpenBlock(LPCGUID, ACCESS_MASK, PVOID*)`.
pub(super) extern "win64" fn open_block(
    guid: *const [u8; 16],
    desired_access: u32,
    object_out: *mut u64,
) -> i32 {
    if object_out.is_null() {
        return STATUS_ACCESS_VIOLATION;
    }
    // SAFETY: the output is a driver-owned kernel-mode pointer. Clearing it
    // before any admission failure matches the WMI object-creation contract.
    unsafe { write_unaligned(object_out, 0) };
    if guid.is_null() {
        return STATUS_ACCESS_VIOLATION;
    }
    // SAFETY: the caller passes a kernel-mode GUID pointer. Unaligned reads are
    // supported because neither the ABI nor this adapter grants pointer authority.
    let guid = WmiGuid(unsafe { read_unaligned(guid) });
    let _guard = match RegistryGuard::acquire() {
        Ok(guard) => guard,
        Err(status) => return status as i32,
    };
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(REGISTRY) };
    match registry.open_block(guid, desired_access) {
        Err(status) => status as i32,
        Ok(object) => {
            // This adapter cannot publish a pointer until a broker owns both
            // the WmiGuid object and its reference/dereference lifetime.
            let _ = registry.dereference_block(object);
            STATUS_NOT_SUPPORTED
        }
    }
}

/// `IoWMIQueryAllData(PVOID, PULONG, PVOID)` accepts only an object returned by
/// the live broker. As no object can currently be published, every pointer is
/// unowned and must fail instead of fabricating SMBIOS bytes.
pub(super) extern "win64" fn query_all_data(
    _object: u64,
    size_in_out: *mut u32,
    _buffer: u64,
) -> i32 {
    if size_in_out.is_null() {
        return STATUS_ACCESS_VIOLATION;
    }
    STATUS_INVALID_HANDLE as i32
}
