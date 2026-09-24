/* No language handler: prove a target restore without a Prepare exchange. */
    .text
    .globl BareTargetUnwind
    .seh_proc BareTargetUnwind
BareTargetUnwind:
    pushq %rbp
    .seh_pushreg %rbp
    subq $0x500, %rsp
    .seh_stackalloc 0x500
    leaq 0x80(%rsp), %rbp
    .seh_setframe %rbp, 0x80
    .seh_endprologue

    leaq 0x30(%rsp), %rax
    movq %rax, 0x20(%rsp)
    movq $0, 0x28(%rsp)
    leaq -0x80(%rbp), %rcx
    leaq .Ltarget(%rip), %rdx
    xorl %r8d, %r8d
    movl $0x5678, %r9d
    callq *__imp_RtlUnwindEx(%rip)
    incl SehFixtureEvidence+36(%rip)
.Ltarget:
    incl SehFixtureEvidence+40(%rip)
    addq $0x500, %rsp
    popq %rbp
    retq
    .seh_endproc
