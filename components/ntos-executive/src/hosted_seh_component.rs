//! Component-side, nonreturning SEH exchange on the interrupted hosted-driver thread.

use core::{
    mem::{offset_of, MaybeUninit},
    ptr,
};
use nt_unwind::{
    raw_exception::RawExceptionRecord,
    seh_handler_packet::SehHandlerPacket,
    seh_transport::{SehCall, SehCommand},
    Disposition, EXCEPTION_UNWIND,
};

use super::call_on4_raw;

fn exchange(call: SehCall) -> SehCommand {
    let (info, words) = call.encode();
    let (reply_info, m0, m1, m2, m3) =
        unsafe { call_on4_raw(info, words[0], words[1], words[2], words[3]) };
    SehCommand::parse(reply_info, [m0, m1, m2, m3])
        .expect("hosted SEH transport received an unexpected command")
}

fn packet_field(packet_va: u64, offset: usize) -> u64 {
    unsafe { ptr::read_volatile((packet_va + offset as u64) as *const u64) }
}

fn invoke(packet_va: u64, token: u64) -> i32 {
    if packet_field(packet_va, offset_of!(SehHandlerPacket, token)) != token {
        panic!("hosted SEH invoked a different packet token");
    }
    let packet = packet_va as *const SehHandlerPacket;
    let exception_va = packet_va + offset_of!(SehHandlerPacket, exception) as u64;
    let context_va = packet_va + offset_of!(SehHandlerPacket, original_context) as u64;
    let dispatcher_va = packet_va + offset_of!(SehHandlerPacket, dispatcher) as u64;
    let frame =
        unsafe { ptr::read_volatile(ptr::addr_of!((*packet).dispatcher.establisher_frame)) };
    let flags = unsafe { ptr::read_volatile(ptr::addr_of!((*packet).exception.flags)) };
    let wrapper_offset = if flags & EXCEPTION_UNWIND == 0 {
        offset_of!(SehHandlerPacket, search_wrapper)
    } else {
        offset_of!(SehHandlerPacket, unwind_wrapper)
    };
    let wrapper = packet_field(packet_va, wrapper_offset);
    if wrapper == 0 {
        panic!("hosted SEH handler wrapper is unbound");
    }
    let wrapper: unsafe extern "win64" fn(u64, u64, u64, u64) -> i32 =
        unsafe { core::mem::transmute(wrapper as usize) };
    let disposition = unsafe { wrapper(exception_va, frame, context_va, dispatcher_va) };
    if Disposition::try_from_raw(disposition).is_none() {
        panic!("hosted SEH language handler returned an invalid disposition");
    }
    disposition
}

fn restore(packet_va: u64, token: u64, context_va: u64) -> ! {
    if packet_field(packet_va, offset_of!(SehHandlerPacket, token)) != token {
        panic!("hosted SEH restore token does not own this packet");
    }
    let original = packet_va + offset_of!(SehHandlerPacket, original_context) as u64;
    let unwound = packet_va + offset_of!(SehHandlerPacket, unwound_context) as u64;
    if context_va != original && context_va != unwound {
        panic!("hosted SEH restore context is outside the owned packet");
    }
    let resume = packet_field(packet_va, offset_of!(SehHandlerPacket, resume_va));
    if resume == 0 {
        panic!("hosted SEH resume entry is unbound");
    }
    let resume: unsafe extern "win64" fn(u64) -> ! =
        unsafe { core::mem::transmute(resume as usize) };
    unsafe { resume(context_va) }
}

fn command_loop(mut command: SehCommand, packet_va: u64) -> ! {
    let mut prepared = None;
    loop {
        command = match command {
            SehCommand::Prepare { token } => {
                if prepared.is_some() {
                    panic!("hosted SEH prepared a second handler before Invoke");
                }
                prepared = Some(token);
                exchange(SehCall::Prepare { token, packet_va })
            }
            SehCommand::Invoke { token } => {
                if prepared.take() != Some(token) {
                    panic!("hosted SEH Invoke does not match its Prepare");
                }
                let disposition = invoke(packet_va, token);
                exchange(SehCall::HandlerResult {
                    token,
                    packet_va,
                    disposition,
                })
            }
            SehCommand::Restore { token, context_va } => restore(packet_va, token, context_va),
            SehCommand::SecondChance { code, address, .. } => unsafe {
                crate::provider_bugcheck::report(0x1e, [u64::from(code), address, 0, 0])
            },
        };
    }
}

/// Bound per instance into the support PE's initially zero `SehRaiseDispatch` slot. The component
/// never returns to `SehRaiseStatus`: it is either restored through the support PE or contained.
#[inline(never)]
pub(super) extern "win64" fn raise_dispatch(context_va: u64, status: u32) -> ! {
    let mut packet = MaybeUninit::<SehHandlerPacket>::uninit();
    let packet_va = packet.as_mut_ptr() as u64;
    let command = exchange(SehCall::Raise { context_va, status });
    command_loop(command, packet_va)
}

/// Bound into the instance's admitted `SehUnwindDispatch` slot. A target unwind restores from
/// this packet even when there is no intervening language handler to prepare one.
#[inline(never)]
pub(super) extern "win64" fn unwind_dispatch(request_va: u64) -> ! {
    let mut packet = MaybeUninit::<SehHandlerPacket>::uninit();
    let packet_va = packet.as_mut_ptr() as u64;
    let record_va = unsafe { ptr::read_volatile((request_va + 0x10) as *const u64) };
    if record_va != 0 {
        unsafe {
            ptr::copy_nonoverlapping(
                record_va as *const u8,
                ptr::addr_of_mut!((*packet.as_mut_ptr()).exception).cast::<u8>(),
                core::mem::size_of::<RawExceptionRecord>(),
            );
        }
    }
    let command = exchange(SehCall::BeginUnwind {
        request_va,
        packet_va,
    });
    command_loop(command, packet_va)
}

/// Entered once by a fault Reply after the executive has retained the original CPU snapshot.
/// The token is not authority on its own: the owning pump also matches the physical route and
/// dispatch before it reads this packet or advances the saved exception walk.
#[inline(never)]
pub(super) extern "win64" fn fault_dispatch(token: u64) -> ! {
    let mut packet = MaybeUninit::<SehHandlerPacket>::uninit();
    let packet_va = packet.as_mut_ptr() as u64;
    let command = exchange(SehCall::FaultBegin { token, packet_va });
    command_loop(command, packet_va)
}

/// Enter target unwind while the search-handler wrapper frame remains suspended. A status Reply
/// here would return into an `__except` branch that has not executed.
#[inline(never)]
pub(super) fn unwind_request(packet_va: u64, target_frame: u64, target_ip: u64) -> ! {
    let token = packet_field(packet_va, offset_of!(SehHandlerPacket, token));
    if token == 0 {
        panic!("hosted SEH unwind lacks an owned handler token");
    }
    let command = exchange(SehCall::UnwindRequest {
        token,
        target_frame,
        target_ip,
        packet_va,
    });
    command_loop(command, packet_va)
}
