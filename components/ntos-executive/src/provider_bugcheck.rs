//! Terminal provider reports. No reply, callback unwind, or resource reuse follows acceptance.
use super::*;
pub(crate) use nt_kernel_exec::provider_bugcheck::BUGCHECK_LABEL;
use nt_kernel_exec::provider_bugcheck::{FatalReport, FatalState, ProviderChannel, ReportError};

// Only the serialized executive receiver accesses this state. Provider exports send scalar IPC.
static mut FATAL: FatalState = FatalState::new();

pub(crate) extern "win64" fn ke_bug_check(code: u32) -> ! {
    unsafe { report(code, [0; 4]) }
}

pub(crate) extern "win64" fn ke_bug_check_ex(
    code: u32,
    parameter1: u64,
    parameter2: u64,
    parameter3: u64,
    parameter4: u64,
) -> ! {
    unsafe { report(code, [parameter1, parameter2, parameter3, parameter4]) }
}

/// Kernel ABI adapters delegate here; an unexpected reply is itself a nonreturning protocol fault.
pub(crate) unsafe fn report(code: u32, parameters: [u64; 4]) -> ! {
    let _ = driver_launch::call_on5(
        nt_kernel_exec::provider_bugcheck::BUGCHECK_MESSAGE_INFO,
        u64::from(code),
        parameters[0],
        parameters[1],
        parameters[2],
        parameters[3],
    );
    core::arch::asm!("ud2", options(noreturn));
}

pub(crate) unsafe fn accept(
    channel: &spawn_hosts::PumpChannel,
    reply_object: u64,
    badge: u64,
    message_info: u64,
    words: [u64; 5],
) -> Result<FatalReport, ReportError> {
    // Ordinary component channels grant an unbadged CT_FAULT cap to exactly this executor.
    // Timer/IRQ notifications and private badged IRQ lanes are not this report authority.
    let report = FatalReport::decode(
        ProviderChannel {
            endpoint: channel.fault_ep,
            tcb: channel.tcb,
            vspace: channel.pml4,
            reply_object,
            expected_badge: 0,
        },
        badge,
        message_info,
        words,
    )?;
    Ok((&mut *core::ptr::addr_of_mut!(FATAL)).record(report))
}

pub(crate) unsafe fn stop_if_pending() {
    if let Some(report) = (&*core::ptr::addr_of!(FATAL)).first() {
        stop(report);
    }
}

pub(crate) unsafe fn stop(report: FatalReport) -> ! {
    let channel = report.channel();
    print_str(b"[provider-bugcheck] code=0x");
    print_hex(report.code());
    for parameter in report.parameters() {
        print_str(b" parameter=0x");
        print_hex_u64(parameter);
    }
    print_str(b"\n[provider-bugcheck] endpoint=0x");
    print_hex_u64(channel.endpoint);
    print_str(b" tcb=0x");
    print_hex_u64(channel.tcb);
    print_str(b" vspace=0x");
    print_hex_u64(channel.vspace);
    print_str(b" reply=0x");
    print_hex_u64(channel.reply_object);
    print_str(b"\n");

    // The reporting executor is already blocked in its unreplied Call. Suspend it explicitly and
    // fence every registered sibling sharing its provider VSpace, including parked continuations.
    let suspend_error = tcb_suspend_r(channel.tcb);
    print_str(b"[provider-bugcheck] reporting-tcb-suspend=");
    print_u64(suspend_error);
    print_str(b"\n");
    win32k_glue::retire_bugchecked_vspace(channel.vspace, channel.tcb);
    print_str(b"[provider-bugcheck] terminal\n");
    park()
}
