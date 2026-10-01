.text
.macro IMPORT_ANCHOR name
.globl \name
\name:
    ud2
    ret
.endm
IMPORT_ANCHOR DbgPrint
IMPORT_ANCHOR KeInitializeEvent
IMPORT_ANCHOR KeWaitForSingleObject
IMPORT_ANCHOR KeSetEvent
IMPORT_ANCHOR IoCreateDevice
IMPORT_ANCHOR IoDeleteDevice
IMPORT_ANCHOR IofCompleteRequest
IMPORT_ANCHOR PsCreateSystemThread
IMPORT_ANCHOR PsTerminateSystemThread
IMPORT_ANCHOR ZwWaitForSingleObject
IMPORT_ANCHOR ZwClose
IMPORT_ANCHOR IoBuildSynchronousFsdRequest
IMPORT_ANCHOR IoBuildDeviceIoControlRequest
IMPORT_ANCHOR IofCallDriver
