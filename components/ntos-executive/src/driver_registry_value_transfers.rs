//! Bounded value uploads retain canonical table scope and target identity between chunks.

use super::*;
use nt_process::native_handle::{NativeHandleCaller, NativeHandleScope};

struct Transfer {
    caller: NativeHandleCaller,
    owner: nt_process::ProcessId,
    handle: nt_process::Handle,
    token: u64,
    target: DriverRegistryHandleTarget,
    name: String,
    value_type: u32,
    upload: nt_config_client::SystemHiveValueUpload,
}

static mut TRANSFERS: Vec<Transfer> = Vec::new();
static NEXT: AtomicU64 = AtomicU64::new(1);

unsafe fn scope(
    caller: NativeHandleCaller,
    handle: u64,
) -> Result<(nt_process::ProcessId, nt_process::Handle), i32> {
    crate::with_provider_process_manager(|pm| match pm.decode_native_handle(caller, handle)? {
        NativeHandleScope::Table { owner, handle, .. } => Ok((owner, handle)),
        _ => Err(nt_process::STATUS_INVALID_HANDLE),
    })
    .map_err(|status| status as i32)
}

fn same_target(first: DriverRegistryHandleTarget, second: DriverRegistryHandleTarget) -> bool {
    match (first, second) {
        (
            DriverRegistryHandleTarget::System { lease: a, .. },
            DriverRegistryHandleTarget::System { lease: b, .. },
        ) => a == b,
        (
            DriverRegistryHandleTarget::Hosted { key: a, .. },
            DriverRegistryHandleTarget::Hosted { key: b, .. },
        ) => a == b,
        (
            DriverRegistryHandleTarget::Generic { key: a, .. },
            DriverRegistryHandleTarget::Generic { key: b, .. },
        ) => a == b,
        _ => false,
    }
}

unsafe fn index(
    caller: NativeHandleCaller,
    handle: u64,
    token: u64,
    total: usize,
) -> Result<usize, i32> {
    let (owner, raw) = scope(caller, handle)?;
    let target = driver_registry_handle_slot(caller, handle, 2)?.target;
    (&*core::ptr::addr_of!(TRANSFERS))
        .iter()
        .position(|row| {
            row.caller == caller
                && row.owner == owner
                && row.handle == raw
                && row.token == token
                && row.upload.expected_len() == total
                && same_target(row.target, target)
        })
        .ok_or(STATUS_INVALID_HANDLE)
}

pub(crate) unsafe fn begin(
    caller: NativeHandleCaller,
    handle: u64,
    target: DriverRegistryHandleTarget,
    name: &str,
    value_type: u32,
    total: usize,
) -> Result<u64, i32> {
    let _durable = crate::allocator::enter_durable();
    let (owner, raw) = scope(caller, handle)?;
    if !same_target(
        driver_registry_handle_slot(caller, handle, 2)?.target,
        target,
    ) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let upload = nt_config_client::SystemHiveValueUpload::new(total)?;
    let token = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let rows = &mut *core::ptr::addr_of_mut!(TRANSFERS);
    rows.try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    rows.push(Transfer {
        caller,
        owner,
        handle: raw,
        token,
        target,
        name: String::from(name),
        value_type,
        upload,
    });
    Ok(token)
}

pub(crate) unsafe fn append(
    caller: NativeHandleCaller,
    handle: u64,
    token: u64,
    total: usize,
    offset: usize,
    data: &[u8],
) -> Result<(), i32> {
    let index = index(caller, handle, token, total)?;
    (&mut *core::ptr::addr_of_mut!(TRANSFERS))[index]
        .upload
        .append(offset, data)
}

pub(crate) unsafe fn commit(
    caller: NativeHandleCaller,
    handle: u64,
    token: u64,
    total: usize,
) -> Result<(), i32> {
    let index = index(caller, handle, token, total)?;
    // An incomplete upload remains owned for explicit abort. Removal precedes provider effects;
    // an uncertain durable commit is never replayed under the same upload token.
    (&*core::ptr::addr_of!(TRANSFERS))[index]
        .upload
        .complete_data()?;
    let row = (&mut *core::ptr::addr_of_mut!(TRANSFERS)).swap_remove(index);
    driver_registry_operations::set_value(
        row.target,
        &row.name,
        row.value_type,
        row.upload.complete_data()?,
    )
}

pub(crate) unsafe fn abort(
    caller: NativeHandleCaller,
    handle: u64,
    token: u64,
    total: usize,
) -> Result<(), i32> {
    let index = index(caller, handle, token, total)?;
    (&mut *core::ptr::addr_of_mut!(TRANSFERS)).swap_remove(index);
    Ok(())
}

pub(crate) unsafe fn close(caller: NativeHandleCaller, handle: u64) -> Result<(), i32> {
    let (owner, raw) = scope(caller, handle)?;
    // A different thread may close this table entry. Application tag bits cannot preserve a
    // stale transfer through close/reuse, nor can a matching value in another table cancel it.
    cancel_closed_handle(owner, raw);
    Ok(())
}

/// Called only after canonical PM removal, before any target-release IPC or slot reuse.
pub(crate) unsafe fn cancel_closed_handle(
    owner: nt_process::ProcessId,
    handle: nt_process::Handle,
) {
    let raw = handle & !3;
    (&mut *core::ptr::addr_of_mut!(TRANSFERS))
        .retain(|row| row.owner != owner || row.handle != raw);
}

/// Process close-all owns every entry in this table, regardless of originating thread.
pub(crate) unsafe fn cancel_process(owner: nt_process::ProcessId) {
    (&mut *core::ptr::addr_of_mut!(TRANSFERS)).retain(|row| row.owner != owner);
}
