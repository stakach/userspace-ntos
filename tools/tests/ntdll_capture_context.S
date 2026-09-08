#if !defined(__x86_64__)
#error This artifact probe requires an x86-64 executable.
#endif

.text
.globl _capture_artifact_probe
_capture_artifact_probe:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $72, %rsp
    // Win64 shadow space is [rsp, rsp+32); retain harness pointers above it.
    movq %rdi, 32(%rsp)
    movq %rsi, 40(%rsp)
    movq %rdx, 48(%rsp)
    fxsave64 1024(%rdx)
    fxrstor (%rdx)
    fxsave 512(%rdx)
    movq %rsp, 1536(%rdx)
    leaq Lcaptured(%rip), %rax
    movq %rax, 1544(%rdx)
    movw %cs, 1560(%rdx)
    movw %ds, 1562(%rdx)
    movw %es, 1564(%rdx)
    movw %fs, 1566(%rdx)
    movw %gs, 1568(%rdx)
    movw %ss, 1570(%rdx)
    pushq $0x246
    popfq
    pushfq
    popq 1552(%rdx)
    movq 40(%rsp), %rcx
    movabsq $0x1111000000000000, %rax
    movabsq $0x1111000000000002, %rdx
    movabsq $0x1111000000000003, %rbx
    movabsq $0x1111000000000005, %rbp
    movabsq $0x1111000000000006, %rsi
    movabsq $0x1111000000000007, %rdi
    movabsq $0x1111000000000008, %r8
    movabsq $0x1111000000000009, %r9
    movabsq $0x111100000000000a, %r10
    movabsq $0x111100000000000b, %r11
    movabsq $0x111100000000000c, %r12
    movabsq $0x111100000000000d, %r13
    movabsq $0x111100000000000e, %r14
    movabsq $0x111100000000000f, %r15
    callq *32(%rsp)
Lcaptured:
    movq 48(%rsp), %rax
    fxrstor64 1024(%rax)
    addq $72, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
