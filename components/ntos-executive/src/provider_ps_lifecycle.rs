//! Canonical execution identity for provider lifecycle callouts, independent of THREADINFO.

use nt_kernel_abi::ps_reactos_x64 as abi;

const INVALID_CID: u32 = 0xc000_000b;

fn field_address(body: u64, offset: usize) -> Result<u64, u32> {
    if body == 0 || body & 7 != 0 {
        return Err(INVALID_CID);
    }
    let address = body.checked_add(offset as u64).ok_or(INVALID_CID)?;
    address.checked_add(8).ok_or(INVALID_CID)?;
    Ok(address)
}

/// # Safety
/// Root has authenticated the current thread incarnation and granted its retained canonical body
/// before publishing this request. These memory-only checks do not grant pointer authority.
pub(super) unsafe fn validate_ps_provider_execution_thread(
    pid: u64,
    tid: u64,
    eprocess: u64,
    ethread: u64,
) -> Result<(), u32> {
    if pid == 0 || tid == 0 || eprocess == 0 || eprocess & 7 != 0 {
        return Err(INVALID_CID);
    }
    let process_id = field_address(ethread, abi::ETHREAD_CLIENT_ID_PROCESS)?;
    let thread_id = field_address(ethread, abi::ETHREAD_CLIENT_ID_THREAD)?;
    let process_body = field_address(ethread, abi::ETHREAD_THREADS_PROCESS)?;
    if core::ptr::read_volatile(ethread as *const u8) != 6
        || core::ptr::read_volatile(process_id as *const u64) != pid
        || core::ptr::read_volatile(thread_id as *const u64) != tid
        || core::ptr::read_volatile(process_body as *const u64) != eprocess
    {
        return Err(INVALID_CID);
    }
    Ok(())
}

/// # Safety
/// The canonical execution identity has been validated under the same retained root request.
/// Used only without a GUI context: GUI bodies retain their separate callout TEB mirror.
pub(super) unsafe fn read_ps_provider_execution_teb(
    ethread: u64,
    supplied_teb: u64,
) -> Result<u64, u32> {
    if supplied_teb == 0 {
        return Err(INVALID_CID);
    }
    let field = field_address(ethread, abi::KTHREAD_TEB)?;
    let canonical_teb = core::ptr::read_volatile(field as *const u64);
    if canonical_teb != supplied_teb {
        return Err(INVALID_CID);
    }
    Ok(canonical_teb)
}
