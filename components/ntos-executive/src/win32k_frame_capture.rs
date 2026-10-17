//! Native Win64 RtlWalkFrameChain entry capture for an isolated win32k lane.
//!
//! The shim owns only capture. The broker named below must authenticate the exact paused lane,
//! copy this packet through that lane's stack reader, admit the return PC and image catalog, and
//! bound output publication before it returns a count. The output VA in the packet is opaque to
//! the executive; it is never a permission to dereference the same number in executive space.

use nt_unwind::kernel_frame_ingress::{
    KernelFrameIngressPacket, FRAME_INGRESS_MAGIC, FRAME_INGRESS_WORDS, FRAME_RESULT_OFFSET,
};

// Supplied by the native frame-chain bridge when the provider and executive dispatch are wired.
// An unresolved symbol is intentional: capture must not be bound as an import without its owner.
unsafe extern "win64" {
    fn win32k_native_frame_chain_bridge(packet_va: u64) -> u32;
}

extern "win64" fn dispatch_captured_frame(packet: *const u64) -> u32 {
    // The pointer names this shim's own fixed stack allocation, not caller-controlled memory.
    let words = unsafe { core::slice::from_raw_parts(packet, FRAME_INGRESS_WORDS) };
    let flags = (words[3] >> 32) as u32;
    if flags & 0xfe != 0 {
        crate::print_str(b"[win32k-frame] unsupported low flags; terminal\n");
        unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [0x4b46_5231, u64::from(flags), words[1], words[3] as u32 as u64],
            )
        }
    }
    let Some(request) = KernelFrameIngressPacket::from_words(words) else {
        crate::print_str(b"[win32k-frame] malformed or unbounded ingress\n");
        return 0;
    };
    if request.walk_capacity() == 0 {
        return 0;
    }
    // The bridge's reply includes skipped frames and must be checked under the retained dispatch. An
    // uncertain write or reply never permits replay on another stack or lane.
    let count = unsafe { win32k_native_frame_chain_bridge(packet as u64) };
    let Some(result_count) = request.published_result_count(count) else {
        crate::print_str(b"[win32k-frame] broker returned an impossible count\n");
        return 0;
    };
    if result_count != 0 {
        // This runs back in the originating component. The executive only writes the staging
        // suffix under its exact lane lease; it never dereferences the opaque caller pointer.
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

/// Capture the caller's Win64 nonvolatile register state before any Rust prologue changes RSP.
///
/// Entry RSP points to the return PC; the post-call context begins at RSP+8. The 0x528-byte frame
/// leaves 32 bytes of Win64 shadow space, a 16-byte-aligned 0x100-byte capture header, 0x400
/// bytes of bounded result staging, and alignment padding. XMM6–XMM15 are retained because
/// unwind codes may restore their prior values.
#[unsafe(naked)]
pub(crate) unsafe extern "win64" fn rtl_walk_frame_chain(
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
        magic = const FRAME_INGRESS_MAGIC,
        dispatch = sym dispatch_captured_frame,
    );
}
