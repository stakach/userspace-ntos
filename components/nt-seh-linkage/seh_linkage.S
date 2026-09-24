/*
 * Win64 call frames for C SEH callbacks. These frames have real COFF unwind metadata, but no
 * language handler yet: nested exceptions and collided unwinds must fail closed until the
 * dispatcher and linkage-handler contract is implemented. No kernel import is needed here.
 *
 * int32_t SehCallFilter(int32_t (*filter)(void *, void *), void *exception_pointers,
 *                       void *establisher_frame);
 * void SehCallFinally(void (*finally)(unsigned char, void *), void *establisher_frame);
 */

    .text
    .globl SehCallFilter
    .seh_proc SehCallFilter
SehCallFilter:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq %rcx, %rax
    movq %rdx, %rcx
    movq %r8, %rdx
    callq *%rax
    addq $40, %rsp
    retq
    .seh_endproc

    .globl SehCallFinally
    .seh_proc SehCallFinally
SehCallFinally:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq %rcx, %rax
    movl $1, %ecx
    callq *%rax
    addq $40, %rsp
    retq
    .seh_endproc
