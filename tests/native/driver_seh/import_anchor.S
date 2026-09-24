/* Build-only trap exports for producing ntoskrnl.lib where llvm-dlltool is unavailable. */
    .text
    .globl ExRaiseStatus
ExRaiseStatus:
    ud2
    .globl RtlUnwindEx
RtlUnwindEx:
    ud2
    .globl DbgPrint
DbgPrint:
    ud2
    .globl __C_specific_handler
__C_specific_handler:
    ud2
