/* A real fileless WDM target. Success requires exact buffers and actual IRP completion. */
#include "contract.h"

__declspec(dllimport) NTSTATUS __stdcall IoCreateDevice(DRIVER_OBJECT *, uint32_t,
    UNICODE_STRING *, uint32_t, uint32_t, uint8_t, DEVICE_OBJECT **);
__declspec(dllimport) void __stdcall IoDeleteDevice(DEVICE_OBJECT *);
__declspec(dllimport) void __stdcall IofCompleteRequest(IRP *, int8_t);
__declspec(dllimport) NTSTATUS __stdcall PsCreateSystemThread(HANDLE *, uint32_t,
    void *, HANDLE, void *, void (__stdcall *)(void *), void *);
__declspec(dllimport) void __stdcall PsTerminateSystemThread(NTSTATUS);
__declspec(dllimport) NTSTATUS __stdcall ZwWaitForSingleObject(HANDLE, uint8_t, int64_t *);
__declspec(dllimport) NTSTATUS __stdcall ZwClose(HANDLE);

struct SourceIrpTargetEvidence {
    uint32_t completed[2][6];
    uint32_t rejected;
};
__declspec(dllexport) volatile struct SourceIrpTargetEvidence SourceIrpTargetEvidence;
static DEVICE_OBJECT *TargetDevice;
static HANDLE WorkerHandle;
static uint64_t PendingEvent[3];
static IRP *PendingIrp;
static uint32_t Stopping;
static uint16_t TargetName[] = {
    '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'S', 'o', 'u', 'r', 'c', 'e',
    'I', 'r', 'p', 'P', 'r', 'o', 'b', 'e', 0
};

static NTSTATUS Complete(IRP *irp)
{
    IO_STACK_LOCATION *stack = irp->CurrentStackLocation;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    uint32_t mode = 0, operation = 0;
    uint8_t *destination = NULL;
    if (stack == NULL || stack->FileObject != NULL || irp->OriginalFileObject != NULL)
        goto done;
    if (stack->MajorFunction == IRP_MJ_READ || stack->MajorFunction == IRP_MJ_WRITE) {
        if (stack->Parameters.ReadWrite.Length != PROBE_BYTES ||
            stack->Parameters.ReadWrite.ByteOffset < 0 ||
            stack->Parameters.ReadWrite.ByteOffset > 1 ||
            irp->MdlAddress != NULL || irp->AssociatedSystemBuffer == NULL) goto done;
        mode = (uint32_t)stack->Parameters.ReadWrite.ByteOffset;
        operation = stack->MajorFunction == IRP_MJ_READ ? 0 : 1;
        if (operation == 1) {
            if (!ProbeMatches(irp->AssociatedSystemBuffer, ProbeInput)) goto done;
        } else destination = irp->AssociatedSystemBuffer;
    } else if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        uint32_t code = stack->Parameters.DeviceIoControl.IoControlCode;
        uint32_t method = code & 3;
        mode = ((code >> 2) & 0xfff) - 0x880;
        operation = method + 2;
        if (mode > 1 || code != PROBE_IOCTL(mode, method) ||
            stack->Parameters.DeviceIoControl.InputBufferLength != PROBE_BYTES ||
            stack->Parameters.DeviceIoControl.OutputBufferLength != PROBE_BYTES) {
            DbgPrint("[source-irp-reject] control lengths or code\n");
            goto done;
        }
        const uint8_t *input;
        if (method == METHOD_NEITHER) {
            if (irp->MdlAddress != NULL || irp->AssociatedSystemBuffer != NULL) goto done;
            input = stack->Parameters.DeviceIoControl.Type3InputBuffer;
            destination = irp->UserBuffer;
        } else {
            input = irp->AssociatedSystemBuffer;
            if (stack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
                DbgPrint("[source-irp-reject] unexpected Type3InputBuffer\n");
                goto done;
            }
            if (method == METHOD_BUFFERED) {
                if (irp->MdlAddress != NULL) goto done;
                destination = irp->AssociatedSystemBuffer;
            } else {
                MDL *mdl = irp->MdlAddress;
                if (mdl == NULL || mdl->Next != NULL || mdl->Size < (int16_t)sizeof(MDL) ||
                    mdl->ByteCount != PROBE_BYTES || mdl->MappedSystemVa == NULL ||
                    (mdl->MdlFlags & 3) != 3 || mdl->ByteOffset >= 4096 ||
                    (uintptr_t)mdl->StartVa + mdl->ByteOffset != (uintptr_t)mdl->MappedSystemVa)
                {
                    DbgPrint("[source-irp-reject] MDL layout or mapping\n");
                    goto done;
                }
                if (method == METHOD_IN_DIRECT) {
                    if (!ProbeMatches(mdl->MappedSystemVa, ProbeSeed)) {
                        DbgPrint("[source-irp-reject] IN_DIRECT second-buffer contents\n");
                        goto done;
                    }
                } else destination = mdl->MappedSystemVa;
            }
        }
        if (!ProbeMatches(input, ProbeInput)) {
            DbgPrint("[source-irp-reject] control input contents\n");
            goto done;
        }
        if (method != METHOD_IN_DIRECT && destination == NULL) goto done;
    } else goto done;
    if (destination != NULL)
        for (uint32_t i = 0; i < PROBE_BYTES; i++) destination[i] = ProbeOutput(i);
    status = STATUS_SUCCESS;
done:
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = status == STATUS_SUCCESS ? PROBE_BYTES : 0;
    if (status == STATUS_SUCCESS) SourceIrpTargetEvidence.completed[mode][operation]++;
    else SourceIrpTargetEvidence.rejected++;
    IofCompleteRequest(irp, 0);
    return status;
}

static void __stdcall CompletionWorker(void *context)
{
    (void)context;
    for (;;) {
        NTSTATUS status = KeWaitForSingleObject(PendingEvent, 0, 0, 0, NULL);
        if (status != STATUS_SUCCESS) PsTerminateSystemThread(status);
        IRP *irp = __atomic_exchange_n(&PendingIrp, NULL, __ATOMIC_ACQ_REL);
        if (irp != NULL) Complete(irp);
        if (__atomic_load_n(&Stopping, __ATOMIC_ACQUIRE)) break;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS __stdcall Dispatch(DEVICE_OBJECT *device, IRP *irp)
{
    if (device != TargetDevice || irp == NULL) return STATUS_INVALID_PARAMETER;
    IO_STACK_LOCATION *stack = irp->CurrentStackLocation;
    if (stack == NULL) return Complete(irp);
    uint32_t pending = stack->MajorFunction == IRP_MJ_DEVICE_CONTROL ?
        (((stack->Parameters.DeviceIoControl.IoControlCode >> 2) & 0xfff) == 0x881) :
        ((stack->MajorFunction == IRP_MJ_READ || stack->MajorFunction == IRP_MJ_WRITE) &&
         stack->Parameters.ReadWrite.ByteOffset == 1);
    if (!pending) return Complete(irp);
    IRP *empty = NULL;
    /* No worker may complete before the pending marker is part of the native IRP. */
    stack->Control |= 1;
    if (!__atomic_compare_exchange_n(&PendingIrp, &empty, irp, 0,
                                     __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
        irp->IoStatus.Status = STATUS_DEVICE_BUSY;
        irp->IoStatus.Information = 0;
        IofCompleteRequest(irp, 0);
        return STATUS_DEVICE_BUSY;
    }
    KeSetEvent(PendingEvent, 0, 0);
    return STATUS_PENDING;
}

static void __stdcall Unload(DRIVER_OBJECT *driver)
{
    (void)driver;
    if (WorkerHandle != NULL) {
        __atomic_store_n(&Stopping, 1, __ATOMIC_RELEASE);
        KeSetEvent(PendingEvent, 0, 0);
        /* Do not delete backing if the real worker has not terminated. */
        if (ZwWaitForSingleObject(WorkerHandle, 0, NULL) != STATUS_SUCCESS) return;
        ZwClose(WorkerHandle);
        WorkerHandle = NULL;
    }
    if (TargetDevice != NULL) { IoDeleteDevice(TargetDevice); TargetDevice = NULL; }
}

NTSTATUS __stdcall DriverEntry(DRIVER_OBJECT *driver, UNICODE_STRING *registry_path)
{
    (void)registry_path;
    UNICODE_STRING name = { sizeof(TargetName) - 2, sizeof(TargetName), TargetName };
    NTSTATUS status = IoCreateDevice(driver, 0, &name, 0x22, 0, 0, &TargetDevice);
    if (status != STATUS_SUCCESS) return status;
    KeInitializeEvent(PendingEvent, 1, 0);
    status = PsCreateSystemThread(&WorkerHandle, 0, NULL, NULL, NULL, CompletionWorker, NULL);
    if (status != STATUS_SUCCESS) { IoDeleteDevice(TargetDevice); TargetDevice = NULL; return status; }
    for (uint32_t i = 0; i < 28; i++) driver->MajorFunction[i] = Dispatch;
    driver->DriverUnload = Unload;
    TargetDevice->Flags = (TargetDevice->Flags | DO_BUFFERED_IO) & ~DO_DEVICE_INITIALIZING;
    DbgPrint("[source-irp-target-ready] buffered-device=1 worker=1\n");
    return STATUS_SUCCESS;
}
