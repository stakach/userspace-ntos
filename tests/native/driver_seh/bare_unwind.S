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

/* The compiler's outlined ?fin$ helper has no pdata even when it allocates a frame.
   Keep both the C scope and the nested finalizer in explicitly unwindable COFF frames. */
    .globl CollidedTargetUnwind
    .seh_proc CollidedTargetUnwind
CollidedTargetUnwind:
    pushq %rbp
    .seh_pushreg %rbp
    subq $0x500, %rsp
    .seh_stackalloc 0x500
    leaq 0x80(%rsp), %rbp
    .seh_setframe %rbp, 0x80
    .seh_handler __C_specific_handler, @except, @unwind
    .seh_endprologue
    .seh_handlerdata
    .long 1
    .rva .Lcollision_try_begin, .Lcollision_try_end, CollisionFinalizer
    .long 0
    .text

    leaq 0x30(%rsp), %rax
    movq %rax, 0x20(%rsp)
    movq $0, 0x28(%rsp)
    leaq -0x80(%rbp), %rcx
    leaq .Lcollision_target(%rip), %rdx
    xorl %r8d, %r8d
    movl $0x9abc, %r9d
.Lcollision_try_begin:
    callq *__imp_RtlUnwindEx(%rip)
    incl SehFixtureEvidence+52(%rip)
.Lcollision_try_end:
.Lcollision_target:
    incl SehFixtureEvidence+56(%rip)
    addq $0x500, %rsp
    popq %rbp
    retq
    .seh_endproc

/* __C_specific_handler calls this with (AbnormalTermination, EstablisherFrame).
   The second RtlUnwindEx crosses the active SehCallFinally wrapper and obtains
   ExceptionCollidedUnwind from that wrapper's real language handler. */
    .globl CollisionFinalizer
    .seh_proc CollisionFinalizer
CollisionFinalizer:
    pushq %rbp
    .seh_pushreg %rbp
    subq $0x500, %rsp
    .seh_stackalloc 0x500
    leaq 0x80(%rsp), %rbp
    .seh_setframe %rbp, 0x80
    .seh_endprologue

    incl SehFixtureEvidence+44(%rip)
    leaq 0x30(%rsp), %rax
    movq %rax, 0x20(%rsp)
    movq $0, 0x28(%rsp)
    movq %rdx, %rcx
    leaq .Lcollision_target(%rip), %rdx
    xorl %r8d, %r8d
    movl $0x9abc, %r9d
    callq *__imp_RtlUnwindEx(%rip)
    incl SehFixtureEvidence+48(%rip)
    addq $0x500, %rsp
    popq %rbp
    retq
    .seh_endproc
