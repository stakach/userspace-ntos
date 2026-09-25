/* Native AMD64 WDM fixture for Mup provider registration and query forwarding. */
#include <stddef.h>
#include <stdint.h>

typedef int32_t NTSTATUS;
typedef uint16_t WCHAR;
typedef void *HANDLE;

#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xc0000010u)
#define STATUS_BAD_NETWORK_NAME ((NTSTATUS)0xc00000ccu)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000du)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001u)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0xc000009eu)
#define NT_SUCCESS(status) ((status) >= 0)

#define IRP_MJ_CREATE 0x00
#define IRP_MJ_CLOSE 0x02
#define IRP_MJ_READ 0x03
#define IRP_MJ_WRITE 0x04
#define IRP_MJ_DEVICE_CONTROL 0x0e
#define IRP_MJ_CLEANUP 0x12
#define IRP_MJ_MAXIMUM_FUNCTION 0x1b
#define SL_PENDING_RETURNED 0x01
#define DO_DEVICE_INITIALIZING 0x80
#define DO_BUFFERED_IO 0x04
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x14
#define FILE_DEVICE_MULTI_UNC_PROVIDER 0x10
#define FILE_TRAVERSE 0x20
#define FILE_WRITE_DATA 0x02
#define SYNCHRONIZE 0x00100000
#define FILE_SHARE_READ 0x01
#define FILE_SHARE_WRITE 0x02
#define FILE_OPEN 0x01
#define FILE_DIRECTORY_FILE 0x01
#define OBJ_CASE_INSENSITIVE 0x40
#define CTL_CODE(device, function, method, access) \
    (((device) << 16) | ((access) << 14) | ((function) << 2) | (method))
#define FSCTL_MUP_REGISTER_PROVIDER CTL_CODE(FILE_DEVICE_MULTI_UNC_PROVIDER, 1, 0, 0)
#define IOCTL_REDIR_QUERY_PATH CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 99, 3, 0)

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

typedef struct _DEVICE_OBJECT {
    uint8_t Reserved[0x30];
    uint32_t Flags;
} DEVICE_OBJECT;

typedef struct {
    uint8_t Reserved0[0x18];
    void *FsContext;
    uint8_t Reserved1[0x38];
    UNICODE_STRING FileName;
} FILE_OBJECT;

typedef struct _IRP {
    uint8_t Reserved0[0x18];
    void *AssociatedSystemBuffer;
    uint8_t Reserved1[0x10];
    IO_STATUS_BLOCK IoStatus;
    uint8_t Reserved2[0x30];
    void *UserBuffer;
    uint8_t Reserved3[0x40];
    struct _IO_STACK_LOCATION *CurrentStackLocation;
} IRP;

typedef struct _IO_STACK_LOCATION {
    uint8_t MajorFunction;
    uint8_t MinorFunction;
    uint8_t Flags;
    uint8_t Control;
    uint32_t Reserved;
    union {
        struct {
            uint32_t OutputBufferLength;
            uint32_t Reserved0;
            uint32_t InputBufferLength;
            uint32_t Reserved1;
            uint32_t IoControlCode;
            uint32_t Reserved2;
            void *Type3InputBuffer;
        } DeviceIoControl;
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
            uint32_t Key;
            uint32_t Reserved1;
            int64_t ByteOffset;
            uint64_t Reserved2;
        } Read;
        uint8_t Bytes[32];
    } Parameters;
    DEVICE_OBJECT *DeviceObject;
    void *FileObject;
    void *CompletionRoutine;
    void *Context;
} IO_STACK_LOCATION;

typedef NTSTATUS (__stdcall *DRIVER_DISPATCH)(DEVICE_OBJECT *, IRP *);
typedef void (__stdcall *DRIVER_UNLOAD)(void *);
typedef struct {
    uint8_t Reserved0[8];
    DEVICE_OBJECT *DeviceObject;
    uint8_t Reserved1[0x58];
    DRIVER_UNLOAD DriverUnload;
    DRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT;

typedef struct {
    uint32_t RedirectorDeviceNameOffset;
    uint32_t RedirectorDeviceNameLength;
    uint32_t Reserved[2];
    uint8_t MailslotsSupported;
} MUP_PROVIDER_REGISTRATION_INFO;

typedef struct {
    uint32_t PathNameLength;
    uint32_t Reserved;
    void *SecurityContext;
    WCHAR FilePathName[1];
} QUERY_PATH_REQUEST;

typedef struct {
    uint32_t LengthAccepted;
} QUERY_PATH_RESPONSE;

_Static_assert(sizeof(UNICODE_STRING) == 16, "UNICODE_STRING x64 ABI");
_Static_assert(sizeof(OBJECT_ATTRIBUTES) == 48, "OBJECT_ATTRIBUTES x64 ABI");
_Static_assert(sizeof(IRP) == 0xc0, "IRP prefix x64 ABI");
_Static_assert(offsetof(IRP, IoStatus) == 0x30, "IRP IoStatus x64 ABI");
_Static_assert(offsetof(IRP, AssociatedSystemBuffer) == 0x18, "IRP system buffer x64 ABI");
_Static_assert(offsetof(IRP, UserBuffer) == 0x70, "IRP UserBuffer x64 ABI");
_Static_assert(offsetof(IRP, CurrentStackLocation) == 0xb8, "IRP stack x64 ABI");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters) == 8, "IO stack params x64 ABI");
_Static_assert(sizeof(IO_STACK_LOCATION) == 0x48, "IO stack x64 ABI");
_Static_assert(offsetof(DRIVER_OBJECT, DriverUnload) == 0x68, "driver unload x64 ABI");
_Static_assert(offsetof(DRIVER_OBJECT, MajorFunction) == 0x70, "driver dispatch x64 ABI");
_Static_assert(offsetof(DEVICE_OBJECT, Flags) == 0x30, "device flags x64 ABI");
_Static_assert(offsetof(FILE_OBJECT, FileName) == 0x58, "file name x64 ABI");
_Static_assert(offsetof(FILE_OBJECT, FsContext) == 0x18, "file context x64 ABI");
_Static_assert(sizeof(MUP_PROVIDER_REGISTRATION_INFO) == 20, "Mup registration ABI");
_Static_assert(offsetof(QUERY_PATH_REQUEST, FilePathName) == 16, "query path ABI");

__declspec(dllimport) NTSTATUS __stdcall IoCreateDevice(DRIVER_OBJECT *, uint32_t,
    UNICODE_STRING *, uint32_t, uint32_t, uint8_t, DEVICE_OBJECT **);
__declspec(dllimport) void __stdcall IoDeleteDevice(DEVICE_OBJECT *);
__declspec(dllimport) void __stdcall IofCompleteRequest(IRP *, int8_t);
__declspec(dllimport) NTSTATUS __stdcall ZwCreateFile(HANDLE *, uint32_t,
    OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, int64_t *, uint32_t, uint32_t,
    uint32_t, uint32_t, void *, uint32_t);
__declspec(dllimport) NTSTATUS __stdcall ZwFsControlFile(HANDLE, HANDLE, void *, void *,
    IO_STATUS_BLOCK *, uint32_t, void *, uint32_t, void *, uint32_t);
__declspec(dllimport) NTSTATUS __stdcall ZwWriteFile(HANDLE, HANDLE, void *, void *,
    IO_STATUS_BLOCK *, void *, uint32_t, int64_t *, uint32_t *);
__declspec(dllimport) NTSTATUS __stdcall ZwWaitForSingleObject(HANDLE, uint8_t, int64_t *);
__declspec(dllimport) NTSTATUS __stdcall ZwClose(HANDLE);
__declspec(dllimport) NTSTATUS __stdcall PsCreateSystemThread(HANDLE *, uint32_t,
    OBJECT_ATTRIBUTES *, HANDLE, void *, void (__stdcall *)(void *), void *);
__declspec(dllimport) void __stdcall PsTerminateSystemThread(NTSTATUS);
__declspec(dllimport) NTSTATUS __stdcall KeDelayExecutionThread(uint8_t, uint8_t, int64_t *);
__declspec(dllimport) int __cdecl DbgPrint(const char *, ...);

struct MupProviderEvidence {
    uint32_t driver_entry;
    uint32_t device_created;
    uint32_t registration_worker_created;
    uint32_t mup_opened;
    uint32_t registration_sent;
    uint32_t registration_status;
    uint32_t probe_attempted;
    uint32_t probe_status;
    uint32_t create_count;
    uint32_t cleanup_count;
    uint32_t close_count;
    uint32_t probe_file_created;
    uint32_t probe_file_cleaned;
    uint32_t probe_file_closed;
    uint32_t probe_write_count;
    uint32_t probe_write_bytes;
    uint32_t probe_read_count;
    uint32_t probe_read_bytes;
    uint32_t query_count;
    uint32_t query_accepted;
    uint32_t query_rejected;
    uint32_t last_path_bytes;
    uint32_t last_security_context_present;
    uint32_t unload_count;
};

volatile struct MupProviderEvidence MupProviderEvidence;
static DEVICE_OBJECT *ProviderDevice;
static HANDLE MupRegistrationHandle;
static HANDLE RegistrationWorkerHandle;

static WCHAR ProviderName[] = {
    '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 't', 'o', 's', 'U', 'n', 'c', 'P',
    'r', 'o', 'b', 'e', 0
};
static WCHAR MupName[] = {
    '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'M', 'u', 'p', 0
};
static WCHAR ProbeName[] = {
    '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'M', 'u', 'p',
    '\\', 'n', 't', 'o', 's', '-', 'p', 'r', 'o', 'b', 'e',
    '\\', 's', 'h', 'a', 'r', 'e', 0
};
/* Mup's FileObject name begins with one backslash; include the server only. */
static const WCHAR AcceptedPrefix[] = {
    '\\', 'n', 't', 'o', 's', '-', 'p', 'r', 'o', 'b', 'e'
};
static const WCHAR ProbeRelativeName[] = {
    '\\', 'n', 't', 'o', 's', '-', 'p', 'r', 'o', 'b', 'e',
    '\\', 's', 'h', 'a', 'r', 'e'
};
static const uint8_t ProbeWriteBytes[] = {'n', 't', 'o', 's', '-', 'w', 'r', 'i', 't', 'e'};
static const uint8_t ProbeReadBytes[] = {'n', 't', 'o', 's', '-', 'r', 'e', 'a', 'd', '!'};
static IRP *PendingReadIrp;

static int IsProbeFileName(const UNICODE_STRING *name)
{
    if (name->Length != sizeof(ProbeRelativeName) || name->Buffer == NULL) return 0;
    for (uint32_t i = 0; i < sizeof(ProbeRelativeName) / sizeof(WCHAR); i++) {
        WCHAR c = name->Buffer[i];
        if (c >= 'A' && c <= 'Z') c = (WCHAR)(c + ('a' - 'A'));
        if (c != ProbeRelativeName[i]) return 0;
    }
    return 1;
}

static NTSTATUS Complete(IRP *irp, NTSTATUS status, uintptr_t information)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IofCompleteRequest(irp, 0);
    return status;
}

static NTSTATUS __stdcall ProviderCreate(DEVICE_OBJECT *device, IRP *irp)
{
    (void)device;
    MupProviderEvidence.create_count++;
    IO_STACK_LOCATION *stack = irp->CurrentStackLocation;
    if (stack == NULL || stack->FileObject == NULL) {
        return Complete(irp, STATUS_BAD_NETWORK_NAME, 0);
    }
    FILE_OBJECT *file = (FILE_OBJECT *)stack->FileObject;
    if (file->FileName.Length == 0) return Complete(irp, STATUS_SUCCESS, 1);
    if (!IsProbeFileName(&file->FileName)) {
        return Complete(irp, STATUS_BAD_NETWORK_NAME, 0);
    }
    file->FsContext = file;
    MupProviderEvidence.probe_file_created++;
    DbgPrint("[mup-provider-create] probe-file created=%u\n",
             MupProviderEvidence.probe_file_created);
    return Complete(irp, STATUS_SUCCESS, 1);
}

static NTSTATUS __stdcall ProviderCleanup(DEVICE_OBJECT *device, IRP *irp)
{
    (void)device;
    MupProviderEvidence.cleanup_count++;
    IO_STACK_LOCATION *stack = irp->CurrentStackLocation;
    if (stack != NULL && stack->FileObject != NULL) {
        FILE_OBJECT *file = (FILE_OBJECT *)stack->FileObject;
        if (file->FsContext == file) {
            MupProviderEvidence.probe_file_cleaned++;
            DbgPrint("[mup-provider-cleanup] probe-file cleaned=%u\n",
                     MupProviderEvidence.probe_file_cleaned);
        }
    }
    return Complete(irp, STATUS_SUCCESS, 0);
}

static NTSTATUS __stdcall ProviderClose(DEVICE_OBJECT *device, IRP *irp)
{
    (void)device;
    MupProviderEvidence.close_count++;
    IO_STACK_LOCATION *stack = irp->CurrentStackLocation;
    if (stack != NULL && stack->FileObject != NULL) {
        FILE_OBJECT *file = (FILE_OBJECT *)stack->FileObject;
        if (file->FsContext == file) {
            file->FsContext = NULL;
            MupProviderEvidence.probe_file_closed++;
            DbgPrint("[mup-provider-close] probe-file closed=%u\n",
                     MupProviderEvidence.probe_file_closed);
        }
    }
    return Complete(irp, STATUS_SUCCESS, 0);
}

static NTSTATUS __stdcall ProviderWrite(DEVICE_OBJECT *device, IRP *irp)
{
    (void)device;
    IO_STACK_LOCATION *stack = irp->CurrentStackLocation;
    if (stack == NULL || stack->FileObject == NULL ||
        ((FILE_OBJECT *)stack->FileObject)->FsContext != stack->FileObject ||
        stack->Parameters.Write.Length != sizeof(ProbeWriteBytes) ||
        irp->AssociatedSystemBuffer == NULL) {
        return Complete(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const uint8_t *bytes = (const uint8_t *)irp->AssociatedSystemBuffer;
    for (uint32_t i = 0; i < sizeof(ProbeWriteBytes); i++) {
        if (bytes[i] != ProbeWriteBytes[i]) return Complete(irp, STATUS_INVALID_PARAMETER, 0);
    }
    MupProviderEvidence.probe_write_count++;
    MupProviderEvidence.probe_write_bytes += sizeof(ProbeWriteBytes);
    DbgPrint("[mup-provider-write] count=%u bytes=%u\n",
             MupProviderEvidence.probe_write_count,
             MupProviderEvidence.probe_write_bytes);
    return Complete(irp, STATUS_SUCCESS, sizeof(ProbeWriteBytes));
}

static void FillRead(IRP *irp)
{
    uint8_t *bytes = (uint8_t *)irp->AssociatedSystemBuffer;
    for (uint32_t i = 0; i < sizeof(ProbeReadBytes); i++) bytes[i] = ProbeReadBytes[i];
    MupProviderEvidence.probe_read_count++;
    MupProviderEvidence.probe_read_bytes += sizeof(ProbeReadBytes);
}

static NTSTATUS __stdcall ProviderRead(DEVICE_OBJECT *device, IRP *irp)
{
    (void)device;
    IO_STACK_LOCATION *stack = irp->CurrentStackLocation;
    if (stack == NULL || stack->FileObject == NULL ||
        stack->Parameters.Read.Length != sizeof(ProbeReadBytes) ||
        (stack->Parameters.Read.ByteOffset != 0 &&
         stack->Parameters.Read.ByteOffset != 1) ||
        irp->AssociatedSystemBuffer == NULL) {
        return Complete(irp, STATUS_INVALID_PARAMETER, 0);
    }
    if (stack->Parameters.Read.ByteOffset == 1) {
        IRP *empty = NULL;
        stack->Control |= SL_PENDING_RETURNED;
        if (!__atomic_compare_exchange_n(&PendingReadIrp, &empty, irp, 0,
                                         __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
            stack->Control &= (uint8_t)~SL_PENDING_RETURNED;
            return Complete(irp, STATUS_DEVICE_BUSY, 0);
        }
        DbgPrint("[mup-provider-read-pending-dispatch] status=0x%08x\n",
                 (uint32_t)STATUS_PENDING);
        return STATUS_PENDING;
    }
    FillRead(irp);
    DbgPrint("[mup-provider-read] count=%u bytes=%u\n",
             MupProviderEvidence.probe_read_count,
             MupProviderEvidence.probe_read_bytes);
    return Complete(irp, STATUS_SUCCESS, sizeof(ProbeReadBytes));
}

static NTSTATUS __stdcall ProviderDeviceControl(DEVICE_OBJECT *device, IRP *irp)
{
    (void)device;
    IO_STACK_LOCATION *stack = irp->CurrentStackLocation;
    if (stack == NULL || stack->MajorFunction != IRP_MJ_DEVICE_CONTROL ||
        stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_REDIR_QUERY_PATH) {
        return Complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }

    MupProviderEvidence.query_count++;
    const uint32_t input_bytes = stack->Parameters.DeviceIoControl.InputBufferLength;
    const uint32_t output_bytes = stack->Parameters.DeviceIoControl.OutputBufferLength;
    const QUERY_PATH_REQUEST *request =
        (const QUERY_PATH_REQUEST *)stack->Parameters.DeviceIoControl.Type3InputBuffer;
    /* METHOD_NEITHER passes the output pointer in IRP.UserBuffer. */
    QUERY_PATH_RESPONSE *response = (QUERY_PATH_RESPONSE *)irp->UserBuffer;
    if (request == NULL || response == NULL || output_bytes < sizeof(*response) ||
        input_bytes < offsetof(QUERY_PATH_REQUEST, FilePathName) ||
        request->PathNameLength > input_bytes - offsetof(QUERY_PATH_REQUEST, FilePathName) ||
        (request->PathNameLength & 1) != 0) {
        MupProviderEvidence.query_rejected++;
        return Complete(irp, STATUS_INVALID_PARAMETER, 0);
    }

    MupProviderEvidence.last_path_bytes = request->PathNameLength;
    MupProviderEvidence.last_security_context_present = request->SecurityContext != NULL;
    if (request->SecurityContext == NULL) {
        MupProviderEvidence.query_rejected++;
        return Complete(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const uint32_t prefix_bytes = sizeof(AcceptedPrefix);
    if (request->PathNameLength < prefix_bytes ||
        (request->PathNameLength > prefix_bytes &&
         request->FilePathName[prefix_bytes / sizeof(WCHAR)] != '\\')) {
        MupProviderEvidence.query_rejected++;
        return Complete(irp, STATUS_BAD_NETWORK_NAME, 0);
    }
    for (uint32_t i = 0; i < prefix_bytes / sizeof(WCHAR); i++) {
        WCHAR c = request->FilePathName[i];
        if (c >= 'A' && c <= 'Z') c = (WCHAR)(c + ('a' - 'A'));
        if (c != AcceptedPrefix[i]) {
            MupProviderEvidence.query_rejected++;
            return Complete(irp, STATUS_BAD_NETWORK_NAME, 0);
        }
    }

    response->LengthAccepted = prefix_bytes;
    MupProviderEvidence.query_accepted++;
    DbgPrint("[mup-provider-query] count=%u accepted=%u path-bytes=%u security=%u\n",
             MupProviderEvidence.query_count, MupProviderEvidence.query_accepted,
             MupProviderEvidence.last_path_bytes,
             MupProviderEvidence.last_security_context_present);
    return Complete(irp, STATUS_SUCCESS, sizeof(*response));
}

static void __stdcall ProviderUnload(void *driver_object)
{
    (void)driver_object;
    MupProviderEvidence.unload_count++;
    if (MupRegistrationHandle != NULL) {
        ZwClose(MupRegistrationHandle);
        MupRegistrationHandle = NULL;
    }
    if (ProviderDevice != NULL) {
        IoDeleteDevice(ProviderDevice);
        ProviderDevice = NULL;
    }
}

static void __stdcall RegistrationWorker(void *context)
{
    (void)context;
    DbgPrint("[mup-provider-stage] opening-mup\n");

    UNICODE_STRING mup_name = {
        (uint16_t)(sizeof(MupName) - sizeof(WCHAR)),
        (uint16_t)sizeof(MupName), MupName
    };
    OBJECT_ATTRIBUTES attrs = {sizeof(attrs), NULL, &mup_name,
                                OBJ_CASE_INSENSITIVE, NULL, NULL};
    IO_STATUS_BLOCK iosb = {0};
    NTSTATUS status = ZwCreateFile(&MupRegistrationHandle, FILE_TRAVERSE | SYNCHRONIZE, &attrs, &iosb,
                          NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0);
    DbgPrint("[mup-provider-stage] open-mup status=0x%08x\n", (uint32_t)status);
    if (!NT_SUCCESS(status)) goto fail;
    MupProviderEvidence.mup_opened++;
    UNICODE_STRING provider_name = {
        (uint16_t)(sizeof(ProviderName) - sizeof(WCHAR)),
        (uint16_t)sizeof(ProviderName), ProviderName
    };

    struct {
        MUP_PROVIDER_REGISTRATION_INFO Info;
        WCHAR Name[sizeof(ProviderName) / sizeof(WCHAR) - 1];
    } registration = {0};
    registration.Info.RedirectorDeviceNameOffset = sizeof(registration.Info);
    registration.Info.RedirectorDeviceNameLength = provider_name.Length;
    for (uint32_t i = 0; i < provider_name.Length / sizeof(WCHAR); i++) {
        registration.Name[i] = ProviderName[i];
    }
    MupProviderEvidence.registration_sent++;
    DbgPrint("[mup-provider-stage] registering\n");
    status = ZwFsControlFile(MupRegistrationHandle, NULL, NULL, NULL, &iosb,
                             FSCTL_MUP_REGISTER_PROVIDER, &registration,
                             sizeof(registration), NULL, 0);
    DbgPrint("[mup-provider-stage] register-return status=0x%08x\n", (uint32_t)status);
    if (status == STATUS_PENDING) {
        status = ZwWaitForSingleObject(MupRegistrationHandle, 0, NULL);
    }
    if (NT_SUCCESS(status)) status = iosb.Status;
    MupProviderEvidence.registration_status = (uint32_t)status;
    DbgPrint("[mup-provider-register] status=0x%08x device=%u open=%u sent=%u\n",
             (uint32_t)status, MupProviderEvidence.device_created,
             MupProviderEvidence.mup_opened,
             MupProviderEvidence.registration_sent);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING probe_name = {
            (uint16_t)(sizeof(ProbeName) - sizeof(WCHAR)),
            (uint16_t)sizeof(ProbeName), ProbeName
        };
        OBJECT_ATTRIBUTES probe_attrs = {sizeof(probe_attrs), NULL, &probe_name,
                                          OBJ_CASE_INSENSITIVE, NULL, NULL};
        HANDLE probe_handle = NULL;
        IO_STATUS_BLOCK probe_iosb = {0};
        MupProviderEvidence.probe_attempted++;
        NTSTATUS probe_status = ZwCreateFile(&probe_handle,
                                              FILE_TRAVERSE | FILE_WRITE_DATA | SYNCHRONIZE,
                                              &probe_attrs, &probe_iosb, NULL, 0,
                                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                                              FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0);
        if (NT_SUCCESS(probe_status)) {
            probe_status = probe_iosb.Status;
            if (NT_SUCCESS(probe_status) && probe_handle != NULL) {
                IO_STATUS_BLOCK write_iosb = {0};
                int64_t write_offset = 0;
                NTSTATUS write_status = ZwWriteFile(probe_handle, NULL, NULL, NULL,
                    &write_iosb, (void *)ProbeWriteBytes, sizeof(ProbeWriteBytes),
                    &write_offset, NULL);
                if (NT_SUCCESS(write_status)) write_status = write_iosb.Status;
                if (NT_SUCCESS(write_status) && write_iosb.Information != sizeof(ProbeWriteBytes))
                    write_status = STATUS_UNSUCCESSFUL;
                DbgPrint("[mup-provider-write-result] status=0x%08x info=%u\n",
                         (uint32_t)write_status, (uint32_t)write_iosb.Information);
                if (!NT_SUCCESS(write_status)) probe_status = write_status;
            }
            if (probe_handle != NULL) ZwClose(probe_handle);
        }
        MupProviderEvidence.probe_status = (uint32_t)probe_status;
        DbgPrint("[mup-provider-probe] status=0x%08x queries=%u accepted=%u file-created=%u cleaned=%u closed=%u\n",
                 (uint32_t)probe_status, MupProviderEvidence.query_count,
                 MupProviderEvidence.query_accepted,
                 MupProviderEvidence.probe_file_created,
                 MupProviderEvidence.probe_file_cleaned,
                 MupProviderEvidence.probe_file_closed);
        for (uint32_t attempt = 0; attempt < 100; attempt++) {
            IRP *pending = __atomic_exchange_n(&PendingReadIrp, NULL, __ATOMIC_ACQ_REL);
            if (pending != NULL) {
                int64_t delay = -1000000;
                KeDelayExecutionThread(0, 0, &delay);
                FillRead(pending);
                DbgPrint("[mup-provider-read-pending-complete] count=%u bytes=%u\n",
                         MupProviderEvidence.probe_read_count,
                         MupProviderEvidence.probe_read_bytes);
                Complete(pending, STATUS_SUCCESS, sizeof(ProbeReadBytes));
                break;
            }
            int64_t delay = -1000000;
            KeDelayExecutionThread(0, 0, &delay);
        }
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

fail:
    DbgPrint("[mup-provider-stage] registration-failed status=0x%08x\n", (uint32_t)status);
    PsTerminateSystemThread(status);
}

NTSTATUS __stdcall DriverEntry(DRIVER_OBJECT *driver, UNICODE_STRING *registry_path)
{
    (void)registry_path;
    MupProviderEvidence.driver_entry++;
    DbgPrint("[mup-provider-stage] entry\n");
    UNICODE_STRING provider_name = {
        (uint16_t)(sizeof(ProviderName) - sizeof(WCHAR)),
        (uint16_t)sizeof(ProviderName), ProviderName
    };
    NTSTATUS status = IoCreateDevice(driver, 0, &provider_name,
                                     FILE_DEVICE_NETWORK_FILE_SYSTEM, 0, 0,
                                     &ProviderDevice);
    DbgPrint("[mup-provider-stage] create-device status=0x%08x\n", (uint32_t)status);
    if (!NT_SUCCESS(status)) return status;
    MupProviderEvidence.device_created++;
    driver->MajorFunction[IRP_MJ_CREATE] = ProviderCreate;
    driver->MajorFunction[IRP_MJ_CLEANUP] = ProviderCleanup;
    driver->MajorFunction[IRP_MJ_CLOSE] = ProviderClose;
    driver->MajorFunction[IRP_MJ_READ] = ProviderRead;
    driver->MajorFunction[IRP_MJ_WRITE] = ProviderWrite;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProviderDeviceControl;
    driver->DriverUnload = ProviderUnload;
    ProviderDevice->Flags = (ProviderDevice->Flags | DO_BUFFERED_IO) & ~DO_DEVICE_INITIALIZING;
    status = PsCreateSystemThread(&RegistrationWorkerHandle, 0, NULL, NULL, NULL,
                                  RegistrationWorker, NULL);
    if (!NT_SUCCESS(status)) {
        ProviderUnload(driver);
        return status;
    }
    MupProviderEvidence.registration_worker_created++;
    DbgPrint("[mup-provider-stage] worker-started status=0x%08x\n", (uint32_t)status);
    return STATUS_SUCCESS;
}
