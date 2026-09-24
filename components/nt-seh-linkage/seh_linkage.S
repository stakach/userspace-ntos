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
 */

    .text
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
