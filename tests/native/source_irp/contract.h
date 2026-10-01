/* NT AMD64 WDM prefixes: ReactOS sdk/include/xdk/iotypes.h and ketypes.h. */
#ifndef SOURCE_IRP_CONTRACT_H
#define SOURCE_IRP_CONTRACT_H
#include <stddef.h>
#include <stdint.h>

typedef int32_t NTSTATUS;
typedef void *HANDLE;
typedef struct { uint16_t Length, MaximumLength; uint16_t *Buffer; } UNICODE_STRING;
typedef struct { NTSTATUS Status; uint32_t Reserved; uintptr_t Information; } IO_STATUS_BLOCK;
typedef struct DEVICE_OBJECT {
    uint8_t Reserved0[0x30];
    uint32_t Flags;
    uint8_t Reserved34[0x18];
    uint8_t StackSize;
} DEVICE_OBJECT;
typedef struct MDL {
    struct MDL *Next;
    int16_t Size, MdlFlags;
    uint32_t Reserved;
    void *Process, *MappedSystemVa, *StartVa;
    uint32_t ByteCount, ByteOffset;
} MDL;
typedef struct IO_STACK_LOCATION {
    uint8_t MajorFunction, MinorFunction, Flags, Control;
    uint32_t Reserved;
    union {
        struct { uint32_t Length, Pad0, Key, Pad1; int64_t ByteOffset; uint64_t Pad2; } ReadWrite;
        struct {
            uint32_t OutputBufferLength, Pad0, InputBufferLength, Pad1, IoControlCode, Pad2;
            void *Type3InputBuffer;
        } DeviceIoControl;
    } Parameters;
    DEVICE_OBJECT *DeviceObject;
    void *FileObject, *CompletionRoutine, *Context;
} IO_STACK_LOCATION;
typedef struct IRP {
    uint8_t Reserved0[8];
    MDL *MdlAddress;
    uint32_t Flags, Reserved14;
    void *AssociatedSystemBuffer;
    uint8_t Reserved20[0x10];
    IO_STATUS_BLOCK IoStatus;
    uint8_t Reserved40[8];
    IO_STATUS_BLOCK *UserIosb;
    void *UserEvent;
    uint8_t Reserved58[0x18];
    void *UserBuffer;
    uint8_t Reserved78[0x40];
    IO_STACK_LOCATION *CurrentStackLocation;
    void *OriginalFileObject;
} IRP;
typedef NTSTATUS (__stdcall *DRIVER_DISPATCH)(DEVICE_OBJECT *, IRP *);
typedef struct DRIVER_OBJECT {
    uint8_t Reserved0[8];
    DEVICE_OBJECT *DeviceObject;
    uint8_t Reserved10[0x58];
    void (__stdcall *DriverUnload)(struct DRIVER_OBJECT *);
    DRIVER_DISPATCH MajorFunction[28];
} DRIVER_OBJECT;

typedef struct {
    NTSTATUS call, wait, iosb_status;
    uint32_t bytes_valid;
    uint64_t information;
} SOURCE_IRP_OBSERVATION;
typedef struct {
    uint32_t attempts[2][6];
    uint32_t completed[2][6];
    uint32_t failed;
    SOURCE_IRP_OBSERVATION observations[2][6];
} SOURCE_IRP_EVIDENCE;
_Static_assert(sizeof(SOURCE_IRP_OBSERVATION) == 24, "observation ABI");
_Static_assert(offsetof(SOURCE_IRP_OBSERVATION, information) == 16, "observation Information ABI");
_Static_assert(offsetof(SOURCE_IRP_EVIDENCE, completed) == 48, "completed counters ABI");
_Static_assert(offsetof(SOURCE_IRP_EVIDENCE, failed) == 96, "failure counter ABI");
_Static_assert(offsetof(SOURCE_IRP_EVIDENCE, observations) == 104, "observation array ABI");
_Static_assert(sizeof(SOURCE_IRP_EVIDENCE) == 392, "source evidence ABI");

_Static_assert(sizeof(UNICODE_STRING) == 16, "UNICODE_STRING x64");
_Static_assert(sizeof(IO_STATUS_BLOCK) == 16, "IOSB x64");
_Static_assert(offsetof(DEVICE_OBJECT, Flags) == 0x30, "device flags x64");
_Static_assert(offsetof(DEVICE_OBJECT, StackSize) == 0x4c, "device stack x64");
_Static_assert(sizeof(MDL) == 0x30, "MDL x64");
_Static_assert(offsetof(MDL, MappedSystemVa) == 0x18, "MDL mapping x64");
_Static_assert(sizeof(IO_STACK_LOCATION) == 0x48, "IO stack x64");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.DeviceIoControl.InputBufferLength) == 0x10,
               "input length is pointer aligned");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.DeviceIoControl.IoControlCode) == 0x18,
               "control code is pointer aligned");
_Static_assert(offsetof(IO_STACK_LOCATION, FileObject) == 0x30, "stack File x64");
_Static_assert(offsetof(IRP, MdlAddress) == 8, "IRP MDL x64");
_Static_assert(offsetof(IRP, IoStatus) == 0x30, "IRP IOSB x64");
_Static_assert(offsetof(IRP, UserBuffer) == 0x70, "IRP output x64");
_Static_assert(offsetof(IRP, CurrentStackLocation) == 0xb8, "IRP stack x64");
_Static_assert(offsetof(IRP, OriginalFileObject) == 0xc0, "IRP File x64");
_Static_assert(offsetof(DRIVER_OBJECT, MajorFunction) == 0x70, "driver dispatch x64");

#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000du)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001u)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0xc000009eu)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009au)
#define IRP_MJ_READ 3
#define IRP_MJ_WRITE 4
#define IRP_MJ_DEVICE_CONTROL 14
#define DO_BUFFERED_IO 4
#define DO_DEVICE_INITIALIZING 0x80
#define METHOD_BUFFERED 0
#define METHOD_IN_DIRECT 1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER 3
#define PROBE_BYTES 16
#define PROBE_IOCTL(mode, method) ((0x22u << 16) | ((0x880u + (mode)) << 2) | (method))

/* Unequal input/output and seed patterns detect direction and copy-bound errors. */
static inline uint8_t ProbeInput(uint32_t index) { return (uint8_t)(0x31u + index * 7u); }
static inline uint8_t ProbeOutput(uint32_t index) { return (uint8_t)(0xd2u - index * 5u); }
static inline uint8_t ProbeSeed(uint32_t index) { return (uint8_t)(0x85u ^ index); }
static inline int ProbeMatches(const uint8_t *bytes, uint8_t (*pattern)(uint32_t)) {
    if (bytes == NULL) return 0;
    for (uint32_t i = 0; i < PROBE_BYTES; i++) if (bytes[i] != pattern(i)) return 0;
    return 1;
}

__declspec(dllimport) int __cdecl DbgPrint(const char *, ...);
__declspec(dllimport) void __stdcall KeInitializeEvent(void *, uint32_t, uint8_t);
__declspec(dllimport) NTSTATUS __stdcall KeWaitForSingleObject(void *, uint32_t, uint32_t,
                                                            uint8_t, int64_t *);
__declspec(dllimport) int32_t __stdcall KeSetEvent(void *, int32_t, uint8_t);
#endif
