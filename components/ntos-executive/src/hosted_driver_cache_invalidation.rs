//! Coherent x86 cache invalidation for driver-visible virtual ranges.

use super::*;

/// `VOID KeInvalidateRangeAllCaches(PVOID BaseAddress, ULONG Length)`.
pub(super) extern "win64" fn invalidate(base: u64, length: u32) {
    if length == 0 { return; }
    if base == 0 || unsafe { hosted_current_irql() } > DISPATCH_LEVEL {
        unsafe { crate::provider_bugcheck::report(0xc4, [base, u64::from(length), 1, 0]); }
    }
    // CLFLUSH writes back dirty data and broadcasts invalidation through the
    // CPU coherence domain, including other processors and physical aliases.
    let cpu = unsafe { core::arch::x86_64::__cpuid(1) };
    if cpu.edx & (1 << 19) == 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [base, u64::from(length), 2, 0]); }
    }
    let line_size = u64::from((cpu.ebx >> 8) & 0xff) * 8;
    let Some(lines) = nt_kernel_exec::cache_invalidation::cache_lines(base, length, line_size) else {
        unsafe { crate::provider_bugcheck::report(0xc4, [base, u64::from(length), line_size, 3]); }
    };
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
        for line in lines {
            core::arch::asm!("clflush [{address}]", address = in(reg) line, options(nostack, preserves_flags));
        }
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}
