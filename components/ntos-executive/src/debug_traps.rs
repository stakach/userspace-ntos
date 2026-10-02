//! NT AMD64 debugger entry leaves. A continued breakpoint returns to its caller.

core::arch::global_asm!(r#"
    .text
    .globl DbgBreakPoint
    .type DbgBreakPoint,@function
DbgBreakPoint:
    int3
    ret
    .size DbgBreakPoint,.-DbgBreakPoint

    .globl DbgBreakPointWithStatus
    .globl RtlpBreakWithStatusInstruction
    .type DbgBreakPointWithStatus,@function
    .type RtlpBreakWithStatusInstruction,@function
DbgBreakPointWithStatus:
RtlpBreakWithStatusInstruction:
    int3
    ret
    .size DbgBreakPointWithStatus,.-DbgBreakPointWithStatus
    .size RtlpBreakWithStatusInstruction,.-RtlpBreakWithStatusInstruction
"#);

unsafe extern "win64" {
    pub(crate) fn DbgBreakPoint();
    // The leaf preserves ECX so the debugger sees the caller's status.
    pub(crate) fn DbgBreakPointWithStatus(status: u32);
}
