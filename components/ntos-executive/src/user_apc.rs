//! Checked APC frame preparation shared by retained hosted wait continuations.

use crate::*;
use nt_thread_start::amd64_context::{
    prepare_user_apc, LegacyContextRestore, UserApcContinuation, UserApcPayload,
};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

/// Copy a prepared frame without consuming the APC or installing target registers.
/// The caller must retain its exact APC/continuation owner across copyout, then revalidate that
/// owner before checked register installation and exact queue commit without intervening reentry.
pub(crate) unsafe fn stage_frame(
    handler: &mut ExecNtHandler,
    caller: ProviderLogicalCaller,
    payload: nt_process::UserApc,
    continuation: UserApcContinuation,
    return_status: u32,
) -> Result<LegacyContextRestore, u32> {
    if !handler.validate_provider_logical_caller(caller) {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let live = thread_context::LegacyThreadContext::read(caller.tcb())
        .map_err(|_| nt_status::NtStatus::UNSUCCESSFUL.raw() as u32)?;
    let rva = img_spawn::OUR_KI_USER_APC_DISPATCHER_RVA.load(Ordering::Relaxed);
    if rva == 0 {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    let dispatcher = NTDLL_BASE
        .checked_add(rva)
        .ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
    let prepared = prepare_user_apc(
        &live.registers,
        &live.floating_point,
        continuation,
        dispatcher,
        UserApcPayload {
            routine: payload.routine,
            normal_context: payload.normal_context,
            system_argument1: payload.system_argument1,
            system_argument2: payload.system_argument2,
        },
        return_status,
        exec_handler::HIGHEST_USER_ADDRESS,
    )
    .map_err(|error| error.status())?;
    handler
        .process_memory_write_checked(caller.pi(), prepared.frame_va, &prepared.frame)
        .map_err(|failure| failure.status())?;
    // Copyout may reenter. Neither a replacement runtime nor changed execution state may inherit
    // the old frame; a definite refusal leaves queue consumption and register installation undone.
    if !handler.validate_provider_logical_caller(caller) {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let current = thread_context::LegacyThreadContext::read(caller.tcb())
        .map_err(|_| nt_status::NtStatus::UNSUCCESSFUL.raw() as u32)?;
    if current.registers != live.registers || current.floating_point != live.floating_point {
        return Err(nt_process::STATUS_DEVICE_BUSY);
    }
    Ok(prepared.install)
}
