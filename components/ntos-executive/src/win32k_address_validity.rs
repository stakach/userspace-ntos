//! Exact win32k page-presence query through its authenticated physical lane.

use super::*;

pub(crate) unsafe fn query_page(vspace: u64, address: u64) -> Result<bool, i32> {
    let info: u64;
    let present: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_CALL as u64,
        inout("rdi") vspace => _,
        inout("rsi") (sel4_rt::LBL_X86_VSPACE_QUERY_PAGE << 12) | 1 => info,
        inout("r10") address => present,
        in("r8") 0u64,
        in("r9") 0u64,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    if info != 1 || present > 1 {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    Ok(present != 0)
}

pub(crate) unsafe fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    address: u64,
) -> Result<bool, i32> {
    let _ = super::win32k_device_consumer::authenticate_channel(ch, reply_cap)?;
    // Bootstrap dispatch precedes WIN32K_HOST_PML4 publication. The consumer
    // registration already pins and checks this exact physical PML4.
    if ch.pml4 == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    query_page(ch.pml4, address)
}

/// BOOLEAN NTAPI MmIsAddressValid(PVOID VirtualAddress).
pub(crate) extern "win64" fn mm_is_address_valid(address: u64) -> u8 {
    let (info, status, present, _, _) = unsafe {
        crate::driver_launch::call_on4_raw(
            (crate::win32k_subsystem::W32_MM_QUERY_PAGE_LABEL << 12) | 1,
            address,
            0,
            0,
            0,
        )
    };
    if info != 2 || status as i32 != STATUS_SUCCESS || present > 1 {
        panic!("executive win32k page-presence query failed: info={info:#x} status={status:#x}");
    }
    present as u8
}
