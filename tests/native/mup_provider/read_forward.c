/* A separate native driver domain that forwards one buffered READ IRP. */
#include <stddef.h>
#include <stdint.h>

typedef int32_t NTSTATUS;
typedef uint16_t WCHAR;
typedef void *HANDLE;

#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001u)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009au)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034u)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xc000003au)
#define NT_SUCCESS(status) ((status) >= 0)
#define IRP_MJ_READ 0x03
#define IRP_BUFFERED_IO 0x10
#define IRP_DEALLOCATE_BUFFER 0x20
#define IRP_INPUT_OPERATION 0x40
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
    uint8_t Reserved[0x4c];
    uint8_t StackSize;
} DEVICE_OBJECT;

typedef struct {
    uint8_t MajorFunction;
    uint8_t MinorFunction;
    uint8_t Flags;
    uint8_t Control;
    uint32_t Reserved;
    struct {
        uint32_t Length;
        uint32_t Reserved0;
        uint32_t Key;
        uint32_t Reserved1;
        int64_t ByteOffset;
        uint64_t Reserved2;
    } Read;
    DEVICE_OBJECT *DeviceObject;
    void *FileObject;
    void *CompletionRoutine;
    void *Context;
} IO_STACK_LOCATION;

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
typedef struct {
    uint8_t Reserved0[0x68];
    DRIVER_UNLOAD DriverUnload;
} DRIVER_OBJECT;

_Static_assert(sizeof(UNICODE_STRING) == 16, "UNICODE_STRING x64 ABI");
_Static_assert(sizeof(OBJECT_ATTRIBUTES) == 48, "OBJECT_ATTRIBUTES x64 ABI");
_Static_assert(sizeof(IO_STATUS_BLOCK) == 16, "IO_STATUS_BLOCK x64 ABI");
_Static_assert(offsetof(DEVICE_OBJECT, StackSize) == 0x4c, "device stack x64 ABI");
_Static_assert(sizeof(IO_STACK_LOCATION) == 0x48, "IO stack x64 ABI");
_Static_assert(offsetof(IRP, Flags) == 0x10, "IRP flags x64 ABI");
_Static_assert(offsetof(IRP, AssociatedSystemBuffer) == 0x18, "IRP buffer x64 ABI");
_Static_assert(offsetof(IRP, UserIosb) == 0x48, "IRP user IOSB x64 ABI");
_Static_assert(offsetof(IRP, UserBuffer) == 0x70, "IRP user buffer x64 ABI");
_Static_assert(offsetof(IRP, CurrentStackLocation) == 0xb8, "IRP stack x64 ABI");
_Static_assert(offsetof(IRP, OriginalFileObject) == 0xc0, "IRP original File x64 ABI");
_Static_assert(offsetof(DRIVER_OBJECT, DriverUnload) == 0x68, "driver unload x64 ABI");

__declspec(dllimport) NTSTATUS __stdcall ZwCreateFile(HANDLE *, uint32_t,
    OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, int64_t *, uint32_t, uint32_t,
    uint32_t, uint32_t, void *, uint32_t);
__declspec(dllimport) NTSTATUS __stdcall ZwClose(HANDLE);
__declspec(dllimport) NTSTATUS __stdcall ObReferenceObjectByHandle(HANDLE, uint32_t,
    void *, uint8_t, void **, void *);
__declspec(dllimport) void __stdcall ObfDereferenceObject(void *);
__declspec(dllimport) DEVICE_OBJECT *__stdcall IoGetRelatedDeviceObject(void *);
__declspec(dllimport) IRP *__stdcall IoAllocateIrp(uint8_t, uint8_t);
__declspec(dllimport) void __stdcall IoFreeIrp(IRP *);
__declspec(dllimport) IO_STACK_LOCATION *__stdcall IoGetNextIrpStackLocation(IRP *);
__declspec(dllimport) NTSTATUS __stdcall IofCallDriver(DEVICE_OBJECT *, IRP *);
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
static const uint8_t ExpectedBytes[] = {'n', 't', 'o', 's', '-', 'r', 'e', 'a', 'd', '!'};

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

    uint8_t output[sizeof(ExpectedBytes)];
    for (uint32_t i = 0; i < sizeof(output); i++) output[i] = 0xcc;
    void *system_buffer = ExAllocatePoolWithTag(PagedPool, sizeof(output), 0x52646e74);
    if (system_buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto dereference;
    }
    for (uint32_t i = 0; i < sizeof(output); i++) ((uint8_t *)system_buffer)[i] = 0xa5;
    IRP *irp = IoAllocateIrp(device->StackSize, 0);
    if (irp == NULL) {
        ExFreePoolWithTag(system_buffer, 0x52646e74);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto dereference;
    }
    IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
    if (stack == NULL) {
        IoFreeIrp(irp);
        ExFreePoolWithTag(system_buffer, 0x52646e74);
        status = STATUS_UNSUCCESSFUL;
        goto dereference;
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
    stack->Read.Length = sizeof(output);
    stack->Read.ByteOffset = 0;
    stack->DeviceObject = device;
    stack->FileObject = file;
    DbgPrint("[read-forward-stage] dispatching buffered IRP through IofCallDriver\n");
    NTSTATUS call_status = IofCallDriver(device, irp);
    NTSTATUS wait_status = KeWaitForSingleObject(completion_event, 0, 0, 0, NULL);
    status = (call_status == STATUS_SUCCESS || call_status == STATUS_PENDING) &&
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
    DbgPrint("[read-forward-result] call=0x%08x wait=0x%08x status=0x%08x iosb=0x%08x info=%u bytes-match=%u\n",
             (uint32_t)call_status, (uint32_t)wait_status, (uint32_t)status,
             (uint32_t)read_iosb.Status,
             (uint32_t)read_iosb.Information, status == STATUS_SUCCESS);

dereference:
    ObfDereferenceObject(file);
close:
    ZwClose(handle);
fail:
    if (!NT_SUCCESS(status))
        DbgPrint("[read-forward-fail] status=0x%08x\n", (uint32_t)status);
    PsTerminateSystemThread(status);
}

NTSTATUS __stdcall DriverEntry(DRIVER_OBJECT *driver, UNICODE_STRING *registry_path)
{
    (void)driver;
    (void)registry_path;
    HANDLE worker = NULL;
    NTSTATUS status = PsCreateSystemThread(&worker, 0, NULL, NULL, NULL, ReadWorker, NULL);
    if (NT_SUCCESS(status) && worker != NULL) ZwClose(worker);
    DbgPrint("[read-forward-entry] worker=0x%08x\n", (uint32_t)status);
    return status;
}
