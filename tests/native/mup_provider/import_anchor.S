/* Build-only trap exports used to create an import library without llvm-dlltool. */
.text
.globl IoCreateDevice
IoCreateDevice:
    ud2
.globl IoDeleteDevice
IoDeleteDevice:
    ud2
.globl IofCompleteRequest
IofCompleteRequest:
    ud2
.globl ZwCreateFile
ZwCreateFile:
    ud2
.globl ZwFsControlFile
ZwFsControlFile:
    ud2
.globl ZwWaitForSingleObject
ZwWaitForSingleObject:
    ud2
.globl ZwClose
ZwClose:
    ud2
.globl DbgPrint
DbgPrint:
    ud2
