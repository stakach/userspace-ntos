//! Shared native Win64 entry capture for hosted kernel image frame walks.
//!
//! The captured address is a packet on the calling component's stack. Only the broker holding
//! that exact paused physical lane may interpret or write it. The opaque output pointer remains
//! in the component and is never translated into executive space.

use nt_unwind::kernel_frame_ingress::{
    KernelFrameIngressPacket, FRAME_INGRESS_WORDS, FRAME_RESULT_OFFSET,
};

pub(crate) fn dispatch_captured_frame(
    packet: *const u64,
    bridge: unsafe extern "win64" fn(u64) -> u32,
) -> u32 {
    // The pointer names the shim's fixed stack allocation, not caller-controlled memory.
    let words = unsafe { core::slice::from_raw_parts(packet, FRAME_INGRESS_WORDS) };
    let flags = (words[3] >> 32) as u32;
    if flags & 0xfe != 0 {
        crate::print_str(b"[kernel-frame] unsupported low flags; terminal\n");
        unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [0x4b46_5231, u64::from(flags), words[1], words[3] as u32 as u64],
            )
        }
    }
    let Some(request) = KernelFrameIngressPacket::from_words(words) else {
        crate::print_str(b"[kernel-frame] malformed or unbounded ingress\n");
        return 0;
    };
    if request.walk_capacity() == 0 {
        return 0;
    }
    let count = unsafe { bridge(packet as u64) };
    let Some(result_count) = request.published_result_count(count) else {
        crate::print_str(b"[kernel-frame] broker returned an impossible count\n");
        return 0;
    };
    if result_count != 0 {
        // Copy only after the retained broker returned. Its staging suffix was written under the
        // exact lane lease; the executive never dereferences the opaque caller output pointer.
        unsafe {
            core::ptr::copy(
                packet.cast::<u8>().add(FRAME_RESULT_OFFSET).cast::<u64>(),
                request.callers() as *mut u64,
                result_count,
            );
        }
    }
    count
}

/// Emit a naked Win64 entry that captures the caller's return slot and all nonvolatile state.
/// The 0x528-byte frame reserves shadow space, a 0x100-byte packet and 0x400-byte result suffix.
/// The packet layout has one authority in `nt_unwind::kernel_frame_ingress`.
macro_rules! kernel_frame_capture_entry {
    ($name:ident, $dispatch:ident) => {
        #[unsafe(naked)]
        pub(crate) unsafe extern "win64" fn $name(
            _callers: *mut u64,
            _count: u32,
            _flags: u32,
        ) -> u32 {
            core::arch::naked_asm!(
                "sub rsp, 0x528",
                "mov r9, {magic}",
                "mov [rsp + 0x20], r9",
                "lea r9, [rsp + 0x528]",
                "mov [rsp + 0x28], r9",
                "mov [rsp + 0x30], rcx",
                "mov r9d, r8d",
                "shl r9, 32",
                "mov r10d, edx",
                "or r9, r10",
                "mov [rsp + 0x38], r9",
                "mov [rsp + 0x40], rbx",
                "mov [rsp + 0x48], rbp",
                "mov [rsp + 0x50], rsi",
                "mov [rsp + 0x58], rdi",
                "mov [rsp + 0x60], r12",
                "mov [rsp + 0x68], r13",
                "mov [rsp + 0x70], r14",
                "mov [rsp + 0x78], r15",
                "movdqu [rsp + 0x80], xmm6",
                "movdqu [rsp + 0x90], xmm7",
                "movdqu [rsp + 0xa0], xmm8",
                "movdqu [rsp + 0xb0], xmm9",
                "movdqu [rsp + 0xc0], xmm10",
                "movdqu [rsp + 0xd0], xmm11",
                "movdqu [rsp + 0xe0], xmm12",
                "movdqu [rsp + 0xf0], xmm13",
                "movdqu [rsp + 0x100], xmm14",
                "movdqu [rsp + 0x110], xmm15",
                "lea rcx, [rsp + 0x20]",
                "call {dispatch}",
                "add rsp, 0x528",
                "ret",
                magic = const nt_unwind::kernel_frame_ingress::FRAME_INGRESS_MAGIC,
                dispatch = sym $dispatch,
            );
        }
    };
}

pub(crate) use kernel_frame_capture_entry;
