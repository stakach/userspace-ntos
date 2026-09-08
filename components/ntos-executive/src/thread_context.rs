//! Checked snapshots of the microkernel's legacy AMD64 execution state.

use crate::*;
use sel4_rt::legacy_context::{
    FX_BYTES, FX_MASK, READ_WORDS, REGISTER_WORDS, RESTART_MASK, WRITE_WORDS,
};

pub(crate) struct LegacyThreadContext {
    pub(crate) registers: [u64; REGISTER_WORDS],
    pub(crate) floating_point: [u8; FX_BYTES],
}

/// Rejected installations leave both the target state and its bound reply unchanged.
pub(crate) unsafe fn continue_thread(
    tcb: u64,
    context: &nt_thread_start::amd64_context::LegacyContextRestore,
) -> Result<(), u64> {
    write(tcb, context, true)
}

/// Install selected state before first publication, or resume a parked caller atomically.
/// With `restart == false`, installation does not make a suspended target runnable.
pub(crate) unsafe fn write(
    tcb: u64,
    context: &nt_thread_start::amd64_context::LegacyContextRestore,
    restart: bool,
) -> Result<(), u64> {
    let mut words = [0u64; WRITE_WORDS];
    words[0] = context.register_mask | if restart { RESTART_MASK } else { 0 };
    words[1..1 + REGISTER_WORDS].copy_from_slice(&context.registers);
    if let Some(image) = &context.floating_point {
        words[0] |= FX_MASK;
        for (word, bytes) in words[1 + REGISTER_WORDS..]
            .iter_mut()
            .zip(image.chunks_exact(8))
        {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
    }
    for (index, word) in words.iter().enumerate().skip(4) {
        set_reply_mr(index, *word);
    }
    let info: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") (sel4_rt::LBL_TCB_WRITE_LEGACY_CONTEXT << 12) | WRITE_WORDS as u64 => info,
        inout("r10") words[0] => _, inout("r8") words[1] => _,
        inout("r9") words[2] => _, inout("r15") words[3] => _,
        in("r12") 0u64, in("r13") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    if info >> 12 != 0 {
        return Err(info >> 12);
    }
    // A malformed success may already have restarted the thread. It cannot become an NT error
    // reply to the now-unbound invocation.
    assert_eq!(
        info, 0,
        "legacy context write returned a malformed success envelope"
    );
    Ok(())
}

impl LegacyThreadContext {
    /// General and floating-point state are sampled during one target quiescence interval.
    pub(crate) unsafe fn read(tcb: u64) -> Result<Self, u64> {
        let info: u64;
        let (r0, r1, r2, r3): (u64, u64, u64, u64);
        core::arch::asm!(
            "syscall",
            inout("rdx") SYS_CALL as u64 => _,
            inout("rdi") tcb => _,
            inout("rsi") sel4_rt::LBL_TCB_READ_LEGACY_CONTEXT << 12 => info,
            lateout("r10") r0, lateout("r8") r1,
            lateout("r9") r2, lateout("r15") r3,
            in("r12") 0u64, in("r13") 0u64,
            lateout("rax") _, lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        if info >> 12 != 0 {
            return Err(info >> 12);
        }
        if info != READ_WORDS as u64 {
            return Err(u64::MAX);
        }
        let mut context = Self {
            registers: [0; REGISTER_WORDS],
            floating_point: [0; FX_BYTES],
        };
        context.registers[..4].copy_from_slice(&[r0, r1, r2, r3]);
        for index in 4..REGISTER_WORDS {
            context.registers[index] = get_recv_mr(index);
        }
        for (index, bytes) in context.floating_point.chunks_exact_mut(8).enumerate() {
            bytes.copy_from_slice(&get_recv_mr(REGISTER_WORDS + index).to_le_bytes());
        }
        Ok(context)
    }
}
