/* Build-only trap exports used to create an import library without llvm-dlltool. */
.text
.globl IoCreateDevice
IoCreateDevice:
    ud2
.globl IoDeleteDevice
IoDeleteDevice:
    ud2
.globl IoAllocateIrp
IoAllocateIrp:
    ud2
.globl IoFreeIrp
IoFreeIrp:
    ud2
.globl IoGetNextIrpStackLocation
IoGetNextIrpStackLocation:
    ud2
.globl IoGetRelatedDeviceObject
IoGetRelatedDeviceObject:
    ud2
.globl IofCallDriver
IofCallDriver:
    ud2
.globl IofCompleteRequest
IofCompleteRequest:
    ud2
.globl ExAllocatePoolWithTag
ExAllocatePoolWithTag:
    ud2
.globl ExFreePoolWithTag
ExFreePoolWithTag:
    ud2
.globl ObReferenceObjectByHandle
ObReferenceObjectByHandle:
    ud2
.globl ObfDereferenceObject
ObfDereferenceObject:
    ud2
.globl KeDelayExecutionThread
KeDelayExecutionThread:
    ud2
.globl KeInitializeEvent
KeInitializeEvent:
    ud2
.globl KeWaitForSingleObject
KeWaitForSingleObject:
    ud2
.globl KeSetEvent
KeSetEvent:
    ud2
.globl ZwCreateFile
ZwCreateFile:
    ud2
.globl ZwQueryInformationFile
ZwQueryInformationFile:
    ud2
.globl ZwReadFile
ZwReadFile:
    ud2
.globl ZwWriteFile
ZwWriteFile:
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
.globl PsCreateSystemThread
PsCreateSystemThread:
    ud2
.globl PsTerminateSystemThread
PsTerminateSystemThread:
    ud2
.globl DbgPrint
DbgPrint:
    ud2
