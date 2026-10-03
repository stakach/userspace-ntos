/* A separate native driver domain that forwards one buffered READ IRP. */
#include <stddef.h>
#include <stdint.h>
#include "failure_receipts.h"

typedef int32_t NTSTATUS;
typedef uint16_t WCHAR;
typedef void *HANDLE;

#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001u)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009au)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034u)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xc000003au)
#define STATUS_IO_DEVICE_ERROR ((NTSTATUS)0xc0000185u)
#define STATUS_TIMEOUT ((NTSTATUS)0x102)
#define STATUS_MORE_PROCESSING_REQUIRED ((NTSTATUS)0xc0000016u)
#define NT_SUCCESS(status) ((status) >= 0)
#define IRP_MJ_CREATE 0x00
#define IRP_MJ_CLOSE 0x02
#define IRP_MJ_READ 0x03
#define IRP_MJ_WRITE 0x04
#define IRP_MJ_FLUSH_BUFFERS 0x09
#define IRP_MJ_QUERY_INFORMATION 0x05
#define IRP_MJ_CLEANUP 0x12
#define IRP_MJ_MAXIMUM_FUNCTION 0x1b
#define DO_BUFFERED_IO 0x04
#define DO_DEVICE_INITIALIZING 0x80
#define FileStandardInformation 5
#define FileInternalInformation 6
#define IRP_BUFFERED_IO 0x10
#define IRP_DEALLOCATE_BUFFER 0x20
#define IRP_INPUT_OPERATION 0x40
#define SL_INVOKE_ON_SUCCESS 0x40
#define FILE_READ_DATA 0x01
#define FILE_SHARE_READ 0x01
#define FILE_SHARE_WRITE 0x02
#define FILE_OPEN 0x01
#define OBJ_CASE_INSENSITIVE 0x40
#define PagedPool 1

typedef struct {
    uint16_t Length;
    uint16_t MaximumLength;
    WCHAR *Buffer;
} UNICODE_STRING;

typedef struct {
    uint32_t Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    uint32_t Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct {
    NTSTATUS Status;
    uint32_t Reserved;
    uintptr_t Information;
} IO_STATUS_BLOCK;

typedef struct {
    int64_t AllocationSize;
    int64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
    uint8_t Reserved[2];
} FILE_STANDARD_INFORMATION;

typedef struct {
    uint8_t Reserved[0x30];
    uint32_t Flags;
    uint8_t Reserved34[0x18];
    uint8_t StackSize;
} DEVICE_OBJECT;

typedef struct {
    uint8_t MajorFunction;
    uint8_t MinorFunction;
    uint8_t Flags;
    uint8_t Control;
    uint32_t Reserved;
    union {
        struct {
            uint32_t Length;
            uint32_t Reserved0;
            uint32_t Key;
            uint32_t Reserved1;
            int64_t ByteOffset;
            uint64_t Reserved2;
        } Read;
        struct {
            uint32_t Length;
            uint32_t Reserved0;
            uint32_t Key;
            uint32_t Reserved1;
            int64_t ByteOffset;
            uint64_t Reserved2;
        } Write;
        struct {
            uint32_t Length;
            uint32_t Reserved0;
            uint32_t FileInformationClass;
            uint8_t Reserved[20];
        } QueryFile;
    } Parameters;
    DEVICE_OBJECT *DeviceObject;
    void *FileObject;
    void *CompletionRoutine;
    void *Context;
} IO_STACK_LOCATION;
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.QueryFile.FileInformationClass) == 16,
               "QueryFile class must use NT pointer alignment");

typedef struct {
    uint8_t Reserved0[0x10];
    uint32_t Flags;
    uint32_t Reserved14;
    void *AssociatedSystemBuffer;
    uint8_t Reserved20[0x10];
    IO_STATUS_BLOCK IoStatus;
    uint8_t Reserved40[0x08];
    IO_STATUS_BLOCK *UserIosb;
    void *UserEvent;
    uint8_t Reserved58[0x18];
    void *UserBuffer;
    uint8_t Reserved78[0x40];
    IO_STACK_LOCATION *CurrentStackLocation;
    void *OriginalFileObject;
} IRP;

typedef void (__stdcall *DRIVER_UNLOAD)(void *);
typedef NTSTATUS (__stdcall *DRIVER_DISPATCH)(DEVICE_OBJECT *, IRP *);
typedef struct {
    uint8_t Reserved0[0x68];
    DRIVER_UNLOAD DriverUnload;
    DRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT;

_Static_assert(sizeof(UNICODE_STRING) == 16, "UNICODE_STRING x64 ABI");
_Static_assert(sizeof(OBJECT_ATTRIBUTES) == 48, "OBJECT_ATTRIBUTES x64 ABI");
_Static_assert(sizeof(IO_STATUS_BLOCK) == 16, "IO_STATUS_BLOCK x64 ABI");
_Static_assert(sizeof(FILE_STANDARD_INFORMATION) == 24, "FILE_STANDARD_INFORMATION x64 ABI");
_Static_assert(offsetof(DEVICE_OBJECT, StackSize) == 0x4c, "device stack x64 ABI");
_Static_assert(offsetof(DEVICE_OBJECT, Flags) == 0x30, "device flags x64 ABI");
_Static_assert(sizeof(IO_STACK_LOCATION) == 0x48, "IO stack x64 ABI");
_Static_assert(offsetof(IRP, Flags) == 0x10, "IRP flags x64 ABI");
_Static_assert(offsetof(IRP, AssociatedSystemBuffer) == 0x18, "IRP buffer x64 ABI");
_Static_assert(offsetof(IRP, UserIosb) == 0x48, "IRP user IOSB x64 ABI");
_Static_assert(offsetof(IRP, UserBuffer) == 0x70, "IRP user buffer x64 ABI");
_Static_assert(offsetof(IRP, CurrentStackLocation) == 0xb8, "IRP stack x64 ABI");
_Static_assert(offsetof(IRP, OriginalFileObject) == 0xc0, "IRP original File x64 ABI");
_Static_assert(offsetof(DRIVER_OBJECT, DriverUnload) == 0x68, "driver unload x64 ABI");
_Static_assert(offsetof(DRIVER_OBJECT, MajorFunction) == 0x70, "driver dispatch x64 ABI");

__declspec(dllimport) NTSTATUS __stdcall ZwCreateFile(HANDLE *, uint32_t,
    OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, int64_t *, uint32_t, uint32_t,
    uint32_t, uint32_t, void *, uint32_t);
__declspec(dllimport) NTSTATUS __stdcall ZwQueryInformationFile(HANDLE, IO_STATUS_BLOCK *,
    void *, uint32_t, uint32_t);
__declspec(dllimport) NTSTATUS __stdcall ZwReadFile(HANDLE, HANDLE, void *, void *,
    IO_STATUS_BLOCK *, void *, uint32_t, int64_t *, uint32_t *);
__declspec(dllimport) NTSTATUS __stdcall ZwClose(HANDLE);
__declspec(dllimport) NTSTATUS __stdcall ObReferenceObjectByHandle(HANDLE, uint32_t,
    void *, uint8_t, void **, void *);
__declspec(dllimport) void __stdcall ObfDereferenceObject(void *);
__declspec(dllimport) DEVICE_OBJECT *__stdcall IoGetRelatedDeviceObject(void *);
__declspec(dllimport) IRP *__stdcall IoAllocateIrp(uint8_t, uint8_t);
__declspec(dllimport) void __stdcall IoFreeIrp(IRP *);
__declspec(dllimport) IO_STACK_LOCATION *__stdcall IoGetNextIrpStackLocation(IRP *);
__declspec(dllimport) NTSTATUS __stdcall IofCallDriver(DEVICE_OBJECT *, IRP *);
__declspec(dllimport) void __stdcall IofCompleteRequest(IRP *, uint8_t);
__declspec(dllimport) NTSTATUS __stdcall IoCreateDevice(DRIVER_OBJECT *, uint32_t,
    UNICODE_STRING *, uint32_t, uint32_t, uint8_t, DEVICE_OBJECT **);
__declspec(dllimport) void __stdcall IoDeleteDevice(DEVICE_OBJECT *);
__declspec(dllimport) void *__stdcall ExAllocatePoolWithTag(uint32_t, size_t, uint32_t);
__declspec(dllimport) void __stdcall ExFreePoolWithTag(void *, uint32_t);
__declspec(dllimport) NTSTATUS __stdcall KeDelayExecutionThread(uint8_t, uint8_t, int64_t *);
__declspec(dllimport) void __stdcall KeInitializeEvent(void *, uint32_t, uint8_t);
__declspec(dllimport) NTSTATUS __stdcall KeWaitForSingleObject(void *, uint32_t, uint32_t,
    uint8_t, int64_t *);
__declspec(dllimport) NTSTATUS __stdcall PsCreateSystemThread(HANDLE *, uint32_t,
    OBJECT_ATTRIBUTES *, HANDLE, void *, void (__stdcall *)(void *), void *);
__declspec(dllimport) void __stdcall PsTerminateSystemThread(NTSTATUS);
__declspec(dllimport) int __cdecl DbgPrint(const char *, ...);

static WCHAR ProviderName[] = {
    '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 't', 'o', 's', 'U', 'n', 'c', 'P',
    'r', 'o', 'b', 'e', 0
};
static WCHAR SectionName[] = {
    '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'M', 'u', 'p',
    '\\', 'n', 't', 'o', 's', '-', 'p', 'r', 'o', 'b', 'e',
    '\\', 's', 'e', 'c', 't', 'i', 'o', 'n', 0
};
static const uint8_t ExpectedBytes[] = {'n', 't', 'o', 's', '-', 'r', 'e', 'a', 'd', '!'};
static const FILE_STANDARD_INFORMATION ExpectedStandardInfo = {
    0x1122334455667788ll, 0x0102030405060708ll, 0x13579bdfu, 1, 0, {0, 0}
};
static const FILE_STANDARD_INFORMATION ExpectedSectionStandardInfo = {
    4096, 4096, 1, 0, 0, {0, 0}
};
static const uint64_t ExpectedSectionInternalIndex = 0x53656374696f6e31ull;
static WCHAR PrimaryProbeName[] = {
    '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 't', 'o', 's', 'F', 'o', 'r',
    'w', 'a', 'r', 'd', 'P', 'r', 'o', 'b', 'e', 0
};
static DEVICE_OBJECT *PrimaryProbeDevice;
static uint32_t PrimaryProbeEntered;

typedef struct {
    uint32_t Count;
} INLINE_MPR_CONTEXT;

static _Noreturn void ParkUnknownInlineMpr(void)
{
    DbgPrint("[read-forward-fail] inline-mpr uncertain dispatch; retained stack owner\n");
    for (;;) {
        int64_t delay = -10000000;
        KeDelayExecutionThread(0, 0, &delay);
    }
}

static NTSTATUS __stdcall HoldInlineRead(DEVICE_OBJECT *device, IRP *irp, void *context)
{
    (void)device;
    (void)irp;
    INLINE_MPR_CONTEXT *held = context;
    uint32_t count = __atomic_add_fetch(&held->Count, 1, __ATOMIC_ACQ_REL);
    DbgPrint("[inline-mpr-held] count=%u\n", count);
    return count == 1 ? STATUS_MORE_PROCESSING_REQUIRED : STATUS_SUCCESS;
}

static NTSTATUS CheckInlineMpr(void *file, DEVICE_OBJECT *device)
{
    uint8_t output[sizeof(ExpectedBytes)];
    for (uint32_t i = 0; i < sizeof(output); ++i) output[i] = 0xcc;
    void *buffer = ExAllocatePoolWithTag(PagedPool, sizeof(output), 0x4d706e74);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    for (uint32_t i = 0; i < sizeof(output); ++i) ((uint8_t *)buffer)[i] = 0xa5;
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        ExFreePoolWithTag(buffer, 0x4d706e74);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp);
        ExFreePoolWithTag(buffer, 0x4d706e74);
        return STATUS_UNSUCCESSFUL;
    }
    INLINE_MPR_CONTEXT context = {0};
    IO_STATUS_BLOCK iosb = {STATUS_UNSUCCESSFUL, 0, 0x12345678};
    uint64_t event[3] = {0};
    KeInitializeEvent(event, 1, 0);
    irp->Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
    irp->AssociatedSystemBuffer = buffer;
    irp->UserBuffer = output;
    irp->UserIosb = &iosb;
    irp->UserEvent = event;
    irp->OriginalFileObject = file;
    stack->MajorFunction = IRP_MJ_READ;
    stack->Parameters.Read.Length = sizeof(output);
    stack->Parameters.Read.ByteOffset = 0;
    stack->DeviceObject = device;
    stack->FileObject = file;
    stack->CompletionRoutine = (void *)HoldInlineRead;
    stack->Context = &context;
    stack->Control = SL_INVOKE_ON_SUCCESS;
    DbgPrint("[inline-mpr-begin]\n");
    NTSTATUS call = IofCallDriver(device, irp);
    int64_t zero_timeout = 0;
    NTSTATUS event_status = KeWaitForSingleObject(event, 0, 0, 0, &zero_timeout);
    uint32_t count = __atomic_load_n(&context.Count, __ATOMIC_ACQUIRE);
    uint32_t unchanged = iosb.Status == STATUS_UNSUCCESSFUL && iosb.Information == 0x12345678;
    for (uint32_t i = 0; i < sizeof(output); ++i) unchanged &= output[i] == 0xcc;
    DbgPrint("[inline-mpr-dispatch-return] call=0x%08x event=0x%08x iosb-and-output-unchanged=%u count=%u\n",
             (uint32_t)call, (uint32_t)event_status, unchanged, count);
    // ReactOS IofCompleteRequest advances the cursor before an MPR callback (irp.c:1442).
    // Only the witnessed held IRP may be completed again; unknown outcomes are not replayed.
    if (call != STATUS_SUCCESS || count != 1) ParkUnknownInlineMpr();
    uint32_t held_valid = event_status == STATUS_TIMEOUT && unchanged;
    DbgPrint("[inline-mpr-resume] count=%u\n", count);
    IofCompleteRequest(irp, 0);
    NTSTATUS wait = KeWaitForSingleObject(event, 0, 0, 0, NULL);
    uint32_t bytes_match = 1;
    for (uint32_t i = 0; i < sizeof(output); ++i) bytes_match &= output[i] == ExpectedBytes[i];
    count = __atomic_load_n(&context.Count, __ATOMIC_ACQUIRE);
    DbgPrint("[inline-mpr-terminal] wait=0x%08x iosb=0x%08x info=%u bytes-match=%u count=%u\n",
             (uint32_t)wait, (uint32_t)iosb.Status, (uint32_t)iosb.Information, bytes_match, count);
    // Real terminal completion owns buffer and IRP reclamation, not this caller.
    return held_valid && wait == STATUS_SUCCESS && iosb.Status == STATUS_SUCCESS &&
        iosb.Information == sizeof(output) && bytes_match && count == 1
        ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static NTSTATUS ForwardOnce(void *file, DEVICE_OBJECT *device, int64_t offset)
{
    uint8_t output[sizeof(ExpectedBytes)];
    for (uint32_t i = 0; i < sizeof(output); i++) output[i] = 0xcc;
    void *system_buffer = ExAllocatePoolWithTag(PagedPool, sizeof(output), 0x52646e74);
    if (system_buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    for (uint32_t i = 0; i < sizeof(output); i++) ((uint8_t *)system_buffer)[i] = 0xa5;
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        ExFreePoolWithTag(system_buffer, 0x52646e74);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp);
        ExFreePoolWithTag(system_buffer, 0x52646e74);
        return STATUS_UNSUCCESSFUL;
    }
    IO_STATUS_BLOCK read_iosb = {0};
    uint64_t completion_event[3] = {0};
    KeInitializeEvent(completion_event, 1, 0);
    irp->Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
    irp->AssociatedSystemBuffer = system_buffer;
    irp->UserBuffer = output;
    irp->UserIosb = &read_iosb;
    irp->UserEvent = completion_event;
    irp->OriginalFileObject = file;
    stack->MajorFunction = IRP_MJ_READ;
    stack->Parameters.Read.Length = sizeof(output);
    stack->Parameters.Read.ByteOffset = offset;
    stack->DeviceObject = device;
    stack->FileObject = file;
    DbgPrint("[read-forward-stage] offset=%u dispatching buffered IRP through IofCallDriver\n",
             (uint32_t)offset);
    NTSTATUS call_status = IofCallDriver(device, irp);
    NTSTATUS wait_status = STATUS_UNSUCCESSFUL;
    if (call_status == STATUS_SUCCESS || call_status == STATUS_PENDING)
        wait_status = KeWaitForSingleObject(completion_event, 0, 0, 0, NULL);
    NTSTATUS status = call_status == (offset == 0 ? STATUS_SUCCESS : STATUS_PENDING) &&
                      wait_status == STATUS_SUCCESS &&
                      read_iosb.Status == STATUS_SUCCESS &&
                      read_iosb.Information == sizeof(output) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    if (status == STATUS_SUCCESS) {
        for (uint32_t i = 0; i < sizeof(output); i++) {
            if (output[i] != ExpectedBytes[i]) {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    DbgPrint("[read-forward-result] offset=%u call=0x%08x wait=0x%08x status=0x%08x iosb=0x%08x info=%u bytes-match=%u\n",
             (uint32_t)offset, (uint32_t)call_status, (uint32_t)wait_status,
             (uint32_t)status, (uint32_t)read_iosb.Status,
             (uint32_t)read_iosb.Information, status == STATUS_SUCCESS);
    if (status == STATUS_SUCCESS)
        DbgPrint("[read-forward-verified-%u]\n", (uint32_t)offset);
    return status;
}

static NTSTATUS FlushOnce(void *file, DEVICE_OBJECT *device, uint32_t ordinal)
{
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp);
        return STATUS_UNSUCCESSFUL;
    }
    IO_STATUS_BLOCK flush_iosb = {0};
    uint64_t completion_event[3] = {0};
    KeInitializeEvent(completion_event, 1, 0);
    irp->UserIosb = &flush_iosb;
    irp->UserEvent = completion_event;
    irp->OriginalFileObject = file;
    stack->MajorFunction = IRP_MJ_FLUSH_BUFFERS;
    stack->DeviceObject = device;
    stack->FileObject = file;
    DbgPrint("[flush-forward-stage] ordinal=%u dispatching IRP through IofCallDriver\n",
             ordinal);
    NTSTATUS call_status = IofCallDriver(device, irp);
    NTSTATUS wait_status = STATUS_UNSUCCESSFUL;
    if (call_status == STATUS_SUCCESS || call_status == STATUS_PENDING)
        wait_status = KeWaitForSingleObject(completion_event, 0, 0, 0, NULL);
    NTSTATUS status = call_status == (ordinal == 0 ? STATUS_SUCCESS : STATUS_PENDING) &&
                      wait_status == STATUS_SUCCESS &&
                      flush_iosb.Status == STATUS_SUCCESS &&
                      flush_iosb.Information == 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    DbgPrint("[flush-forward-result] ordinal=%u call=0x%08x wait=0x%08x status=0x%08x iosb=0x%08x info=%u\n",
             ordinal, (uint32_t)call_status, (uint32_t)wait_status,
             (uint32_t)status, (uint32_t)flush_iosb.Status,
             (uint32_t)flush_iosb.Information);
    if (status == STATUS_SUCCESS)
        DbgPrint("[flush-forward-verified-%u]\n", ordinal);
    return status;
}

static NTSTATUS QueryOnce(void *file, DEVICE_OBJECT *device, uint32_t ordinal)
{
    FILE_STANDARD_INFORMATION output;
    uint8_t *output_bytes = (uint8_t *)&output;
    for (uint32_t i = 0; i < sizeof(output); i++) output_bytes[i] = 0xcc;
    void *system_buffer = ExAllocatePoolWithTag(PagedPool, sizeof(output), 0x516e746e);
    if (system_buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    for (uint32_t i = 0; i < sizeof(output); i++) ((uint8_t *)system_buffer)[i] = 0xa5;
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        ExFreePoolWithTag(system_buffer, 0x516e746e);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp);
        ExFreePoolWithTag(system_buffer, 0x516e746e);
        return STATUS_UNSUCCESSFUL;
    }
    IO_STATUS_BLOCK query_iosb = {0};
    uint64_t completion_event[3] = {0};
    KeInitializeEvent(completion_event, 1, 0);
    irp->Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
    irp->AssociatedSystemBuffer = system_buffer;
    irp->UserBuffer = &output;
    irp->UserIosb = &query_iosb;
    irp->UserEvent = completion_event;
    irp->OriginalFileObject = file;
    stack->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    stack->Parameters.QueryFile.Length = sizeof(output);
    stack->Parameters.QueryFile.FileInformationClass = FileStandardInformation;
    stack->DeviceObject = device;
    stack->FileObject = file;
    DbgPrint("[query-forward-stage] ordinal=%u class=5 bytes=24\n", ordinal);
    NTSTATUS call_status = IofCallDriver(device, irp);
    NTSTATUS wait_status = STATUS_UNSUCCESSFUL;
    if (call_status == STATUS_SUCCESS || call_status == STATUS_PENDING)
        wait_status = KeWaitForSingleObject(completion_event, 0, 0, 0, NULL);
    NTSTATUS status = call_status == (ordinal == 0 ? STATUS_SUCCESS : STATUS_PENDING) &&
                      wait_status == STATUS_SUCCESS &&
                      query_iosb.Status == STATUS_SUCCESS &&
                      query_iosb.Information == sizeof(output) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    if (status == STATUS_SUCCESS) {
        const uint8_t *expected = (const uint8_t *)&ExpectedStandardInfo;
        for (uint32_t i = 0; i < sizeof(output); i++) {
            if (output_bytes[i] != expected[i]) {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    DbgPrint("[query-forward-result] ordinal=%u call=0x%08x wait=0x%08x status=0x%08x iosb=0x%08x info=%u bytes-match=%u\n",
             ordinal, (uint32_t)call_status, (uint32_t)wait_status,
             (uint32_t)status, (uint32_t)query_iosb.Status,
             (uint32_t)query_iosb.Information, status == STATUS_SUCCESS);
    if (status == STATUS_SUCCESS)
        DbgPrint("[query-forward-verified-%u]\n", ordinal);
    return status;
}

static NTSTATUS QueryThroughZw(HANDLE handle)
{
    FILE_STANDARD_INFORMATION output;
    uint8_t *output_bytes = (uint8_t *)&output;
    for (uint32_t i = 0; i < sizeof(output); i++) output_bytes[i] = 0xcc;
    IO_STATUS_BLOCK iosb = {0};
    NTSTATUS call_status = ZwQueryInformationFile(handle, &iosb, &output,
                                                  sizeof(output), FileStandardInformation);
    NTSTATUS status = call_status == STATUS_SUCCESS && iosb.Status == STATUS_SUCCESS &&
                      iosb.Information == sizeof(output) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    if (status == STATUS_SUCCESS) {
        const uint8_t *expected = (const uint8_t *)&ExpectedStandardInfo;
        for (uint32_t i = 0; i < sizeof(output); i++) {
            if (output_bytes[i] != expected[i]) {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    DbgPrint("[zw-query-file-result] call=0x%08x iosb=0x%08x info=%u bytes-match=%u\n",
             (uint32_t)call_status, (uint32_t)iosb.Status,
             (uint32_t)iosb.Information, status == STATUS_SUCCESS);
    if (status == STATUS_SUCCESS) DbgPrint("[zw-query-file-verified]\n");
    return status;
}

static NTSTATUS ReadThroughZw(HANDLE handle)
{
    uint8_t output[sizeof(ExpectedBytes)];
    for (uint32_t i = 0; i < sizeof(output); i++) output[i] = 0xcc;
    IO_STATUS_BLOCK iosb = {0};
    int64_t offset = 0;
    NTSTATUS call_status = ZwReadFile(handle, NULL, NULL, NULL, &iosb, output,
                                      sizeof(output), &offset, NULL);
    NTSTATUS status = call_status == STATUS_SUCCESS && iosb.Status == STATUS_SUCCESS &&
                      iosb.Information == sizeof(output) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    if (status == STATUS_SUCCESS) {
        for (uint32_t i = 0; i < sizeof(output); i++) {
            if (output[i] != ExpectedBytes[i]) {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    DbgPrint("[zw-read-file-result] call=0x%08x iosb=0x%08x info=%u bytes-match=%u\n",
             (uint32_t)call_status, (uint32_t)iosb.Status,
             (uint32_t)iosb.Information, status == STATUS_SUCCESS);
    if (status == STATUS_SUCCESS) DbgPrint("[zw-read-file-verified]\n");
    return status;
}

static NTSTATUS SectionQueryOnce(void *file, DEVICE_OBJECT *device, uint32_t info_class)
{
    const uint32_t length = info_class == FileStandardInformation
        ? sizeof(ExpectedSectionStandardInfo) : sizeof(ExpectedSectionInternalIndex);
    uint8_t output[sizeof(ExpectedSectionStandardInfo)];
    for (uint32_t i = 0; i < sizeof(output); i++) output[i] = 0xcc;
    void *system_buffer = ExAllocatePoolWithTag(PagedPool, length, 0x53716e74);
    if (system_buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    for (uint32_t i = 0; i < length; i++) ((uint8_t *)system_buffer)[i] = 0xa5;
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        ExFreePoolWithTag(system_buffer, 0x53716e74);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp);
        ExFreePoolWithTag(system_buffer, 0x53716e74);
        return STATUS_UNSUCCESSFUL;
    }
    IO_STATUS_BLOCK iosb = {0};
    uint64_t completion_event[3] = {0};
    KeInitializeEvent(completion_event, 1, 0);
    irp->Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
    irp->AssociatedSystemBuffer = system_buffer;
    irp->UserBuffer = output;
    irp->UserIosb = &iosb;
    irp->UserEvent = completion_event;
    irp->OriginalFileObject = file;
    stack->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    stack->Parameters.QueryFile.Length = length;
    stack->Parameters.QueryFile.FileInformationClass = info_class;
    stack->DeviceObject = device;
    stack->FileObject = file;
    NTSTATUS call = IofCallDriver(device, irp);
    NTSTATUS wait = call == STATUS_SUCCESS || call == STATUS_PENDING
        ? KeWaitForSingleObject(completion_event, 0, 0, 0, NULL) : STATUS_UNSUCCESSFUL;
    NTSTATUS status = call == (info_class == FileStandardInformation ? STATUS_PENDING : STATUS_SUCCESS) &&
                      wait == STATUS_SUCCESS && iosb.Status == STATUS_SUCCESS &&
                      iosb.Information == length ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    const uint8_t *expected = info_class == FileStandardInformation
        ? (const uint8_t *)&ExpectedSectionStandardInfo
        : (const uint8_t *)&ExpectedSectionInternalIndex;
    if (status == STATUS_SUCCESS) {
        for (uint32_t i = 0; i < length; i++) {
            if (output[i] != expected[i]) { status = STATUS_UNSUCCESSFUL; break; }
        }
    }
    DbgPrint("[section-query-result] class=%u call=0x%08x wait=0x%08x iosb=0x%08x info=%u match=%u\n",
             info_class, (uint32_t)call, (uint32_t)wait, (uint32_t)iosb.Status,
             (uint32_t)iosb.Information, status == STATUS_SUCCESS);
    if (status == STATUS_SUCCESS) DbgPrint("[section-query-verified-%u]\n", info_class);
    return status;
}

static NTSTATUS SectionReadOnce(void *file, DEVICE_OBJECT *device)
{
    uint8_t *output = ExAllocatePoolWithTag(PagedPool, 4096, 0x53726e74);
    if (output == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    for (uint32_t i = 0; i < 4096; i++) output[i] = 0xcc;
    void *system_buffer = ExAllocatePoolWithTag(PagedPool, 4096, 0x53736e74);
    if (system_buffer == NULL) {
        ExFreePoolWithTag(output, 0x53726e74);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (uint32_t i = 0; i < 4096; i++) ((uint8_t *)system_buffer)[i] = 0xa5;
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        ExFreePoolWithTag(system_buffer, 0x53736e74);
        ExFreePoolWithTag(output, 0x53726e74);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp);
        ExFreePoolWithTag(system_buffer, 0x53736e74);
        ExFreePoolWithTag(output, 0x53726e74);
        return STATUS_UNSUCCESSFUL;
    }
    IO_STATUS_BLOCK iosb = {0};
    uint64_t completion_event[3] = {0};
    KeInitializeEvent(completion_event, 1, 0);
    irp->Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
    irp->AssociatedSystemBuffer = system_buffer;
    irp->UserBuffer = output;
    irp->UserIosb = &iosb;
    irp->UserEvent = completion_event;
    irp->OriginalFileObject = file;
    stack->MajorFunction = IRP_MJ_READ;
    stack->Parameters.Read.Length = 4096;
    stack->Parameters.Read.ByteOffset = 0;
    stack->DeviceObject = device;
    stack->FileObject = file;
    NTSTATUS call = IofCallDriver(device, irp);
    NTSTATUS wait = call == STATUS_PENDING
        ? KeWaitForSingleObject(completion_event, 0, 0, 0, NULL) : STATUS_UNSUCCESSFUL;
    NTSTATUS status = call == STATUS_PENDING && wait == STATUS_SUCCESS &&
                      iosb.Status == STATUS_SUCCESS && iosb.Information == 4096
        ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    if (status == STATUS_SUCCESS) {
        for (uint32_t i = 0; i < 4096; i++) {
            if (output[i] != (uint8_t)i) { status = STATUS_UNSUCCESSFUL; break; }
        }
    }
    DbgPrint("[section-read-result] call=0x%08x wait=0x%08x iosb=0x%08x info=%u match=%u\n",
             (uint32_t)call, (uint32_t)wait, (uint32_t)iosb.Status,
             (uint32_t)iosb.Information, status == STATUS_SUCCESS);
    if (status == STATUS_SUCCESS) DbgPrint("[section-read-verified]\n");
    ExFreePoolWithTag(output, 0x53726e74);
    return status;
}

static NTSTATUS CheckSectionFile(void)
{
    UNICODE_STRING name = {
        (uint16_t)(sizeof(SectionName) - sizeof(WCHAR)),
        (uint16_t)sizeof(SectionName), SectionName
    };
    OBJECT_ATTRIBUTES attrs = {sizeof(attrs), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL};
    HANDLE handle = NULL;
    IO_STATUS_BLOCK open_iosb = {0};
    NTSTATUS status = ZwCreateFile(&handle, FILE_READ_DATA, &attrs, &open_iosb, NULL, 0,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
    if (NT_SUCCESS(status)) status = open_iosb.Status;
    if (!NT_SUCCESS(status) || handle == NULL) return STATUS_UNSUCCESSFUL;
    void *file = NULL;
    status = ObReferenceObjectByHandle(handle, FILE_READ_DATA, NULL, 0, &file, NULL);
    if (!NT_SUCCESS(status) || file == NULL) goto close;
    DEVICE_OBJECT *device = IoGetRelatedDeviceObject(file);
    if (device == NULL || device->StackSize == 0 || device->StackSize > 32) {
        status = STATUS_UNSUCCESSFUL;
        goto dereference;
    }
    status = SectionQueryOnce(file, device, FileStandardInformation);
    if (status == STATUS_SUCCESS) status = SectionQueryOnce(file, device, FileInternalInformation);
    if (status == STATUS_SUCCESS) status = SectionReadOnce(file, device);
dereference:
    ObfDereferenceObject(file);
close:
    ZwClose(handle);
    return status;
}

static NTSTATUS QueryFailureIdentity(void *file, DEVICE_OBJECT *device, uint64_t *generation)
{
    uint64_t output = 0;
    void *buffer = ExAllocatePoolWithTag(PagedPool, sizeof(output), 0x466e746e);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        ExFreePoolWithTag(buffer, 0x466e746e);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp); ExFreePoolWithTag(buffer, 0x466e746e);
        return STATUS_UNSUCCESSFUL;
    }
    IO_STATUS_BLOCK iosb = {STATUS_UNSUCCESSFUL, 0, 0};
    uint64_t event[3] = {0};
    KeInitializeEvent(event, 1, 0);
    irp->Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
    irp->AssociatedSystemBuffer = buffer;
    irp->UserBuffer = &output;
    irp->UserIosb = &iosb;
    irp->UserEvent = event;
    irp->OriginalFileObject = file;
    stack->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    stack->Parameters.QueryFile.Length = sizeof(output);
    stack->Parameters.QueryFile.FileInformationClass = FileInternalInformation;
    stack->DeviceObject = device;
    stack->FileObject = file;
    NTSTATUS call = IofCallDriver(device, irp);
    NTSTATUS wait = call == STATUS_SUCCESS || call == STATUS_PENDING
        ? KeWaitForSingleObject(event, 0, 0, 0, NULL) : STATUS_UNSUCCESSFUL;
    if (call != STATUS_SUCCESS || wait != STATUS_SUCCESS || iosb.Status != STATUS_SUCCESS ||
        iosb.Information != sizeof(output) || output == 0)
        return STATUS_UNSUCCESSFUL;
    *generation = output;
    DbgPrint("[terminal-failure-identity] " FAILURE_ID_FORMAT
             " call=0x%08x wait=0x%08x iosb=0x%08x info=%u\n",
             FAILURE_ID_ARGS(file, output), (uint32_t)call, (uint32_t)wait,
             (uint32_t)iosb.Status, (uint32_t)iosb.Information);
    return STATUS_SUCCESS;
}

static NTSTATUS ReleaseTerminalFailure(void *file, DEVICE_OBJECT *device, uint32_t operation)
{
    uint8_t *buffer = ExAllocatePoolWithTag(PagedPool, 2, 0x466e746e);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    buffer[0] = 0xa7; buffer[1] = (uint8_t)operation;
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        ExFreePoolWithTag(buffer, 0x466e746e);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp); ExFreePoolWithTag(buffer, 0x466e746e);
        return STATUS_UNSUCCESSFUL;
    }
    IO_STATUS_BLOCK iosb = {STATUS_UNSUCCESSFUL, 0, 0};
    uint64_t event[3] = {0};
    KeInitializeEvent(event, 1, 0);
    irp->Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
    irp->AssociatedSystemBuffer = buffer;
    irp->UserIosb = &iosb;
    irp->UserEvent = event;
    irp->OriginalFileObject = file;
    stack->MajorFunction = IRP_MJ_WRITE;
    stack->Parameters.Write.Length = 2;
    stack->Parameters.Write.ByteOffset = 0;
    stack->DeviceObject = device;
    stack->FileObject = file;
    NTSTATUS call = IofCallDriver(device, irp);
    NTSTATUS wait = call == STATUS_SUCCESS || call == STATUS_PENDING
        ? KeWaitForSingleObject(event, 0, 0, 0, NULL) : STATUS_UNSUCCESSFUL;
    return call == STATUS_SUCCESS && wait == STATUS_SUCCESS &&
        iosb.Status == STATUS_SUCCESS && iosb.Information == 2 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static NTSTATUS TerminalFailureOnce(void *file, DEVICE_OBJECT *device, uint64_t generation, uint32_t operation)
{
    uint8_t output[32];
    for (uint32_t i = 0; i < sizeof(output); ++i) output[i] = 0xcc;
    const uint32_t length = operation == 0 ? sizeof(ExpectedBytes) : sizeof(FILE_STANDARD_INFORMATION);
    void *buffer = NULL;
    if (operation != 1) {
        buffer = ExAllocatePoolWithTag(PagedPool, length, 0x466e746e);
        if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        for (uint32_t i = 0; i < length; ++i) ((uint8_t *)buffer)[i] = 0xa5;
    }
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        if (buffer != NULL) ExFreePoolWithTag(buffer, 0x466e746e);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp);
        if (buffer != NULL) ExFreePoolWithTag(buffer, 0x466e746e);
        return STATUS_UNSUCCESSFUL;
    }
    IO_STATUS_BLOCK iosb = {STATUS_UNSUCCESSFUL, 0, 0x12345678};
    uint64_t event[3] = {0};
    KeInitializeEvent(event, 1, 0);
    irp->UserIosb = &iosb;
    irp->UserEvent = event;
    irp->OriginalFileObject = file;
    stack->DeviceObject = device;
    stack->FileObject = file;
    if (operation != 1) {
        irp->Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
        irp->AssociatedSystemBuffer = buffer;
        irp->UserBuffer = output + 4;
    }
    if (operation == 0) {
        stack->MajorFunction = IRP_MJ_READ;
        stack->Parameters.Read.Length = length;
        stack->Parameters.Read.ByteOffset = 0;
    } else if (operation == 1) {
        stack->MajorFunction = IRP_MJ_FLUSH_BUFFERS;
    } else {
        stack->MajorFunction = IRP_MJ_QUERY_INFORMATION;
        stack->Parameters.QueryFile.Length = length;
        stack->Parameters.QueryFile.FileInformationClass = FileStandardInformation;
    }
    NTSTATUS call = IofCallDriver(device, irp);
    NTSTATUS wait = STATUS_UNSUCCESSFUL;
    int before_unchanged = iosb.Status == STATUS_UNSUCCESSFUL && iosb.Information == 0x12345678;
    for (uint32_t i = 0; i < sizeof(output); ++i)
        if (output[i] != 0xcc) before_unchanged = 0;
    int64_t zero = 0;
    NTSTATUS pending_event = call == STATUS_PENDING
        ? KeWaitForSingleObject(event, 0, 0, 0, &zero) : STATUS_UNSUCCESSFUL;
    DbgPrint("[terminal-failure-retained] operation=%u " FAILURE_ID_FORMAT
             " event=0x%08x iosb-and-output-unchanged=%u\n",
             operation, FAILURE_ID_ARGS(file, generation), (uint32_t)pending_event, before_unchanged);
    // Release even after an assertion mismatch: a live pending IRP still owns stack storage.
    NTSTATUS release = call == STATUS_PENDING
        ? ReleaseTerminalFailure(file, device, operation) : STATUS_UNSUCCESSFUL;
    // Keep the File reference, stack IOSB, Event and output alive through actual completion.
    if (call == STATUS_PENDING) wait = KeWaitForSingleObject(event, 0, 0, 0, NULL);
    int untouched = 1;
    for (uint32_t i = 0; i < sizeof(output); ++i)
        if (output[i] != 0xcc) untouched = 0;
    NTSTATUS result = call == STATUS_PENDING && wait == STATUS_SUCCESS &&
        release == STATUS_SUCCESS && pending_event == STATUS_TIMEOUT && before_unchanged &&
        iosb.Status == STATUS_IO_DEVICE_ERROR && iosb.Information == 0 && untouched
        ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    DbgPrint("[terminal-failure-result] operation=%u " FAILURE_ID_FORMAT
             " call=0x%08x release=0x%08x wait=0x%08x iosb=0x%08x info=%u output-unchanged=%u\n",
             operation, FAILURE_ID_ARGS(file, generation), (uint32_t)call, (uint32_t)release,
             (uint32_t)wait, (uint32_t)iosb.Status,
             (uint32_t)iosb.Information, untouched);
    if (result == STATUS_SUCCESS)
        DbgPrint("[terminal-failure-verified] operation=%u " FAILURE_ID_FORMAT "\n",
                 operation, FAILURE_ID_ARGS(file, generation));
    return result;
}

static NTSTATUS CheckTerminalFailures(void)
{
    static WCHAR path[] = {
        '\\','D','e','v','i','c','e','\\','M','u','p','\\','n','t','o','s','-','p','r','o','b','e',
        '\\','t','e','r','m','i','n','a','l','-','f','a','i','l','u','r','e',0
    };
    UNICODE_STRING name = {sizeof(path) - sizeof(WCHAR), sizeof(path), path};
    OBJECT_ATTRIBUTES attrs = {sizeof(attrs), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL};
    IO_STATUS_BLOCK open_iosb = {0};
    HANDLE handle = NULL;
    NTSTATUS result = ZwCreateFile(&handle, FILE_READ_DATA, &attrs, &open_iosb, NULL, 0,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
    if (NT_SUCCESS(result)) result = open_iosb.Status;
    if (!NT_SUCCESS(result) || handle == NULL) return STATUS_UNSUCCESSFUL;
    void *file = NULL;
    result = ObReferenceObjectByHandle(handle, FILE_READ_DATA, NULL, 0, &file, NULL);
    if (NT_SUCCESS(result) && file != NULL) {
        DEVICE_OBJECT *device = IoGetRelatedDeviceObject(file);
        uint64_t generation = 0;
        if (device == NULL || device->StackSize == 0 || device->StackSize > 32)
            result = STATUS_UNSUCCESSFUL;
        else {
            result = QueryFailureIdentity(file, device, &generation);
            for (uint32_t operation = 0; operation < 3 && NT_SUCCESS(result); ++operation)
                result = TerminalFailureOnce(file, device, generation, operation);
        }
        // Closing the handle must deliver CLEANUP but not CLOSE while this pointer is retained.
        if (generation != 0)
            DbgPrint("[terminal-failure-handle-close-begin] " FAILURE_ID_FORMAT "\n",
                     FAILURE_ID_ARGS(file, generation));
        NTSTATUS close = ZwClose(handle);
        handle = NULL;
        if (generation != 0)
            DbgPrint("[terminal-failure-handle-close-return] " FAILURE_ID_FORMAT " status=0x%08x\n",
                     FAILURE_ID_ARGS(file, generation), (uint32_t)close);
        if (!NT_SUCCESS(close)) result = close;
        if (generation != 0)
            DbgPrint("[terminal-failure-pointer-release-begin] " FAILURE_ID_FORMAT "\n",
                     FAILURE_ID_ARGS(file, generation));
        ObfDereferenceObject(file);
        if (generation != 0)
            DbgPrint("[terminal-failure-pointer-release-return] " FAILURE_ID_FORMAT "\n",
                     FAILURE_ID_ARGS(file, generation));
    } else result = STATUS_UNSUCCESSFUL;
    if (handle != NULL) {
        NTSTATUS close = ZwClose(handle);
        if (!NT_SUCCESS(close)) result = close;
    }
    return result;
}

static NTSTATUS CompletePrimaryProbe(IRP *irp, NTSTATUS status)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IofCompleteRequest(irp, 0);
    return status;
}

static NTSTATUS __stdcall PrimaryProbeLifecycle(DEVICE_OBJECT *device, IRP *irp)
{
    (void)device;
    return CompletePrimaryProbe(irp, STATUS_SUCCESS);
}

static NTSTATUS __stdcall PrimaryProbeRead(DEVICE_OBJECT *device, IRP *irp)
{
    (void)device;
    if (__atomic_exchange_n(&PrimaryProbeEntered, 1, __ATOMIC_ACQ_REL) != 0)
        return CompletePrimaryProbe(irp, STATUS_UNSUCCESSFUL);
    DbgPrint("[source-primary-probe] entered\n");
    // A real primary dispatch waits on lower completions. Its own lane cannot deliver them.
    NTSTATUS status = CheckTerminalFailures();
    DbgPrint("[source-primary-probe] terminal-intent status=0x%08x\n", (uint32_t)status);
    return CompletePrimaryProbe(irp, status);
}

static NTSTATUS CheckPrimaryTerminalFailures(void)
{
    UNICODE_STRING name = {sizeof(PrimaryProbeName) - sizeof(WCHAR),
                           sizeof(PrimaryProbeName), PrimaryProbeName};
    OBJECT_ATTRIBUTES attrs = {sizeof(attrs), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL};
    HANDLE handle = NULL;
    IO_STATUS_BLOCK iosb = {STATUS_UNSUCCESSFUL, 0, 0x12345678};
    NTSTATUS status = ZwCreateFile(&handle, FILE_READ_DATA, &attrs, &iosb, NULL, 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
    if (!NT_SUCCESS(status) || !NT_SUCCESS(iosb.Status) || handle == NULL)
        return STATUS_UNSUCCESSFUL;
    uint8_t output = 0xcc;
    int64_t offset = 0;
    iosb.Status = STATUS_UNSUCCESSFUL;
    iosb.Information = 0x12345678;
    NTSTATUS call = ZwReadFile(handle, NULL, NULL, NULL, &iosb, &output, 1, &offset, NULL);
    DbgPrint("[source-primary-probe] delivered call=0x%08x iosb=0x%08x info=%u output-unchanged=%u\n",
             (uint32_t)call, (uint32_t)iosb.Status, (uint32_t)iosb.Information, output == 0xcc);
    NTSTATUS close = ZwClose(handle);
    return call == STATUS_SUCCESS && iosb.Status == STATUS_SUCCESS &&
        iosb.Information == 0 && output == 0xcc && close == STATUS_SUCCESS
        ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static void __stdcall ReadWorker(void *context)
{
    (void)context;
    UNICODE_STRING name = {
        (uint16_t)(sizeof(ProviderName) - sizeof(WCHAR)),
        (uint16_t)sizeof(ProviderName), ProviderName
    };
    OBJECT_ATTRIBUTES attrs = {sizeof(attrs), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL};
    HANDLE handle = NULL;
    IO_STATUS_BLOCK open_iosb = {0};
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;
    for (uint32_t attempt = 0; attempt < 100; attempt++) {
        status = ZwCreateFile(&handle, FILE_READ_DATA, &attrs, &open_iosb, NULL, 0,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
        if (NT_SUCCESS(status)) break;
        if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND)
            break;
        int64_t delay = -1000000; /* 100 ms in 100-ns units. */
        KeDelayExecutionThread(0, 0, &delay);
    }
    if (NT_SUCCESS(status)) status = open_iosb.Status;
    if (!NT_SUCCESS(status) || handle == NULL) goto fail;

    void *file = NULL;
    status = ObReferenceObjectByHandle(handle, FILE_READ_DATA, NULL, 0, &file, NULL);
    if (!NT_SUCCESS(status) || file == NULL) goto close;
    DEVICE_OBJECT *device = IoGetRelatedDeviceObject(file);
    if (device == NULL || device->StackSize == 0 || device->StackSize > 32) {
        status = STATUS_UNSUCCESSFUL;
        goto dereference;
    }

    status = CheckInlineMpr(file, device);
    if (status == STATUS_SUCCESS) status = ForwardOnce(file, device, 0);
    if (status == STATUS_SUCCESS) status = ForwardOnce(file, device, 1);
    if (status == STATUS_SUCCESS) status = FlushOnce(file, device, 0);
    if (status == STATUS_SUCCESS) status = FlushOnce(file, device, 1);
    if (status == STATUS_SUCCESS) status = QueryOnce(file, device, 0);
    if (status == STATUS_SUCCESS) status = QueryOnce(file, device, 1);
    if (status == STATUS_SUCCESS) status = QueryThroughZw(handle);
    if (status == STATUS_SUCCESS) status = ReadThroughZw(handle);
dereference:
    ObfDereferenceObject(file);
close:
    ZwClose(handle);
    if (status == STATUS_SUCCESS) status = CheckPrimaryTerminalFailures();
    if (status == STATUS_SUCCESS) status = CheckSectionFile();
fail:
    if (!NT_SUCCESS(status))
        DbgPrint("[read-forward-fail] status=0x%08x\n", (uint32_t)status);
    PsTerminateSystemThread(status);
}

NTSTATUS __stdcall DriverEntry(DRIVER_OBJECT *driver, UNICODE_STRING *registry_path)
{
    (void)registry_path;
    UNICODE_STRING name = {sizeof(PrimaryProbeName) - sizeof(WCHAR),
                           sizeof(PrimaryProbeName), PrimaryProbeName};
    NTSTATUS status = IoCreateDevice(driver, 0, &name, 0x22, 0, 0, &PrimaryProbeDevice);
    if (!NT_SUCCESS(status)) return status;
    driver->MajorFunction[IRP_MJ_CREATE] = PrimaryProbeLifecycle;
    driver->MajorFunction[IRP_MJ_CLEANUP] = PrimaryProbeLifecycle;
    driver->MajorFunction[IRP_MJ_CLOSE] = PrimaryProbeLifecycle;
    driver->MajorFunction[IRP_MJ_READ] = PrimaryProbeRead;
    PrimaryProbeDevice->Flags = (PrimaryProbeDevice->Flags | DO_BUFFERED_IO) & ~DO_DEVICE_INITIALIZING;
    HANDLE worker = NULL;
    status = PsCreateSystemThread(&worker, 0, NULL, NULL, NULL, ReadWorker, NULL);
    if (NT_SUCCESS(status) && worker != NULL) ZwClose(worker);
    if (!NT_SUCCESS(status)) IoDeleteDevice(PrimaryProbeDevice);
    DbgPrint("[read-forward-entry] worker=0x%08x\n", (uint32_t)status);
    return status;
}
