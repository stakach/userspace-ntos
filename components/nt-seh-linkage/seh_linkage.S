/*
 * Win64 call frames for C SEH callbacks and language handlers. These frames have real COFF
 * unwind metadata. The language-handler frames are not bound to a native dispatcher yet.
 * No kernel import is needed here.
 *
 * int32_t SehCallFilter(int32_t (*filter)(void *, void *), void *exception_pointers,
 *                       void *establisher_frame, void *dispatcher_context);
 * void SehCallFinally(void (*finally)(unsigned char, void *), void *establisher_frame,
 *                     void *dispatcher_context);
 * int32_t SehExecuteHandlerForException(void *exception_record, void *establisher_frame,
 *                                       void *context_record, void *dispatcher_context);
 * int32_t SehExecuteHandlerForUnwind(void *exception_record, void *establisher_frame,
 *                                    void *context_record, void *dispatcher_context);
 * void SehRaiseStatus(uint32_t status);  // not bound until native dispatch and restore exist
 * void SehResumeContext(void *validated_raw_context);  // does not return
 */

    .text
    .globl SehRaiseStatus
    .seh_proc SehRaiseStatus
SehRaiseStatus:
    pushfq
    .seh_stackalloc 8
    subq $0x4f0, %rsp
    .seh_stackalloc 0x4f0
    .seh_endprologue

    /* RSP is aligned; [RSP, RSP+0x20) is outgoing Win64 shadow space and
       the complete 16-byte-aligned NT CONTEXT starts at RSP+0x20. */
    movq %rax, 0x98(%rsp)
    movq %rcx, 0xa0(%rsp)
    movq %rdx, 0xa8(%rsp)
    movq %rbx, 0xb0(%rsp)
    movq %rbp, 0xc0(%rsp)
    movq %rsi, 0xc8(%rsp)
    movq %rdi, 0xd0(%rsp)
    movq %r8, 0xd8(%rsp)
    movq %r9, 0xe0(%rsp)
    movq %r10, 0xe8(%rsp)
    movq %r11, 0xf0(%rsp)
    movq %r12, 0xf8(%rsp)
    movq %r13, 0x100(%rsp)
    movq %r14, 0x108(%rsp)
    movq %r15, 0x110(%rsp)

    leaq 0x4f8(%rsp), %rax
    movq %rax, 0xb8(%rsp)
    leaq SehRaiseStatus(%rip), %rax
    movq %rax, 0x118(%rsp)

    /* Clear unmodeled and FXSAVE-reserved bytes before the dispatcher can inspect them. */
    cld
    xorl %eax, %eax
    leaq 0x20(%rsp), %rdi
    movl $15, %ecx
    rep stosq
    leaq 0x320(%rsp), %rdi
    movl $58, %ecx
    rep stosq
    leaq 0x120(%rsp), %rdi
    movl $64, %ecx
    rep stosq
    fxsave 0x120(%rsp)

    movl $0x0010000f, 0x50(%rsp)
    movl 0x138(%rsp), %eax
    movl %eax, 0x54(%rsp)
    movw %cs, 0x58(%rsp)
    movw %ds, 0x5a(%rsp)
    movw %es, 0x5c(%rsp)
    movw %fs, 0x5e(%rsp)
    movw %gs, 0x60(%rsp)
    movw %ss, 0x62(%rsp)
    movq 0x4f0(%rsp), %rax
    movl %eax, 0x64(%rsp)

    movq SehRaiseDispatch(%rip), %rax
    testq %rax, %rax
    jz .Lraise_unbound
    leaq 0x20(%rsp), %rcx
    movl 0xa0(%rsp), %edx
    callq *%rax
.Lraise_unbound:
    ud2
    .seh_endproc

    .globl SehResumeContext
    .seh_proc SehResumeContext
SehResumeContext:
    subq $8, %rsp
    .seh_stackalloc 8
    .seh_endprologue
    testq %rcx, %rcx
    jz .Lresume_invalid
    testq $15, %rcx
    jnz .Lresume_invalid

    /* The caller already authenticated this owned CONTEXT, its destination stack
       and the target PC. Preserve the pointer until the final register load. */
    movq %rcx, %r11
    movq 0x98(%r11), %rdx
    movq 0x88(%r11), %r9
    movq %r9, -32(%rdx)
    movl 0x44(%r11), %eax
    movq %rax, -24(%rdx)
    movq 0xf8(%r11), %r8
    movq %r8, -16(%rdx)

    fxrstor 0x100(%r11)
    movq 0x90(%r11), %rbx
    movq 0xa0(%r11), %rbp
    movq 0xa8(%r11), %rsi
    movq 0xb0(%r11), %rdi
    movq 0xb8(%r11), %r8
    movq 0xc0(%r11), %r9
    movq 0xc8(%r11), %r10
    movq 0xd8(%r11), %r12
    movq 0xe0(%r11), %r13
    movq 0xe8(%r11), %r14
    movq 0xf0(%r11), %r15
    movq 0x78(%r11), %rax
    movq 0x80(%r11), %rcx
    movq 0xd0(%r11), %r11
    leaq -32(%rdx), %rsp
    popq %rdx
    popfq
    retq $8
.Lresume_invalid:
    ud2
    .seh_endproc

    .globl SehCallFilter
    .seh_proc SehCallFilter
SehCallFilter:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_handler SehNestedExceptionHandler, @except
    .seh_endprologue
    movq %r9, 32(%rsp)
    movq %rcx, %rax
    movq %rdx, %rcx
    movq %r8, %rdx
    callq *%rax
    nop
    addq $40, %rsp
    retq
    .seh_endproc

    .globl SehExecuteHandlerForException
    .seh_proc SehExecuteHandlerForException
SehExecuteHandlerForException:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_handler SehNestedExceptionHandler, @except
    .seh_endprologue
    movq %r9, 32(%rsp)
    callq *48(%r9)
    nop
    addq $40, %rsp
    retq
    .seh_endproc

    .globl SehExecuteHandlerForUnwind
    .seh_proc SehExecuteHandlerForUnwind
SehExecuteHandlerForUnwind:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_handler SehCollidedUnwindHandler, @unwind
    .seh_endprologue
    movq %r9, 32(%rsp)
    callq *48(%r9)
    nop
    addq $40, %rsp
    retq
    .seh_endproc

/* The establisher frame is the wrapper's post-prologue RSP. */
SehNestedExceptionHandler:
    movl $1, %eax
    testl $0x66, 4(%rcx)
    jnz 1f
    movq 32(%rdx), %rax
    movq 24(%rax), %rax
    movq %rax, 24(%r9)
    movl $2, %eax
1:  retq

SehCollidedUnwindHandler:
    movq 32(%rdx), %rax
    movq 0(%rax), %r10
    movq %r10, 0(%r9)
    movq 8(%rax), %r10
    movq %r10, 8(%r9)
    movq 16(%rax), %r10
    movq %r10, 16(%r9)
    movq 24(%rax), %r10
    movq %r10, 24(%r9)
    movq 40(%rax), %r10
    movq %r10, 40(%r9)
    movq 48(%rax), %r10
    movq %r10, 48(%r9)
    movq 56(%rax), %r10
    movq %r10, 56(%r9)
    movq 64(%rax), %r10
    movq %r10, 64(%r9)
    movl 72(%rax), %r10d
    movl %r10d, 72(%r9)
    movl $3, %eax
    retq

    .globl SehCallFinally
    .seh_proc SehCallFinally
SehCallFinally:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_handler SehCollidedUnwindHandler, @unwind
    .seh_endprologue
    movq %r8, 32(%rsp)
    movq %rcx, %rax
    movl $1, %ecx
    callq *%rax
    nop
    addq $40, %rsp
    retq
    .seh_endproc

    .section .rdata,"dr"
    .p2align 3
    .globl SehRaiseDispatch
SehRaiseDispatch:
    .quad 0
