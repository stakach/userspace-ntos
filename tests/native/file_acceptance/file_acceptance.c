/* Native user-mode File acceptance. All effects go through public ntdll exports. */
#include <stddef.h>
#include <stdint.h>

typedef int32_t NTSTATUS;
typedef void *HANDLE;
typedef struct { uint16_t Length, MaximumLength; uint16_t *Buffer; } UNICODE_STRING;
typedef struct {
    uint32_t Length; HANDLE RootDirectory; UNICODE_STRING *ObjectName;
    uint32_t Attributes; void *SecurityDescriptor; void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef struct { uintptr_t Status; uintptr_t Information; } IO_STATUS_BLOCK;
typedef struct { HANDLE UniqueProcess, UniqueThread; } CLIENT_ID;
typedef struct {
    NTSTATUS ExitStatus; void *PebBaseAddress; uintptr_t AffinityMask;
    int32_t BasePriority; uintptr_t UniqueProcessId, InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef NTSTATUS (*THREAD_START)(void *);
#define IMPORT __declspec(dllimport)
IMPORT NTSTATUS NtCreateFile(HANDLE *, uint32_t, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *,
                            int64_t *, uint32_t, uint32_t, uint32_t, uint32_t, void *, uint32_t);
IMPORT NTSTATUS NtOpenFile(HANDLE *, uint32_t, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, uint32_t, uint32_t);
IMPORT NTSTATUS NtReadFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, uint32_t, int64_t *, uint32_t *);
IMPORT NTSTATUS NtWriteFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, uint32_t, int64_t *, uint32_t *);
IMPORT NTSTATUS NtQueryInformationFile(HANDLE, IO_STATUS_BLOCK *, void *, uint32_t, uint32_t);
IMPORT NTSTATUS NtSetInformationFile(HANDLE, IO_STATUS_BLOCK *, void *, uint32_t, uint32_t);
IMPORT NTSTATUS NtDuplicateObject(HANDLE, HANDLE, HANDLE, HANDLE *, uint32_t, uint32_t, uint32_t);
IMPORT NTSTATUS NtAllocateVirtualMemory(HANDLE, void **, uintptr_t, size_t *, uint32_t, uint32_t);
IMPORT NTSTATUS NtProtectVirtualMemory(HANDLE, void **, size_t *, uint32_t, uint32_t *);
IMPORT NTSTATUS NtFreeVirtualMemory(HANDLE, void **, size_t *, uint32_t);
IMPORT NTSTATUS NtCreateEvent(HANDLE *, uint32_t, OBJECT_ATTRIBUTES *, uint32_t, uint8_t);
IMPORT NTSTATUS NtWaitForSingleObject(HANDLE, uint8_t, int64_t *);
IMPORT NTSTATUS NtClose(HANDLE);
IMPORT NTSTATUS NtDisplayString(UNICODE_STRING *);
IMPORT NTSTATUS NtTerminateProcess(HANDLE, NTSTATUS);
IMPORT NTSTATUS NtTerminateThread(HANDLE, NTSTATUS);
IMPORT NTSTATUS RtlCreateUserThread(HANDLE, void *, uint8_t, uint32_t, size_t, size_t,
                                  THREAD_START, void *, HANDLE *, CLIENT_ID *);
IMPORT NTSTATUS NtOpenKey(HANDLE *, uint32_t, OBJECT_ATTRIBUTES *);
IMPORT NTSTATUS NtQueryKey(HANDLE, uint32_t, void *, uint32_t, uint32_t *);
IMPORT NTSTATUS NtQueryInformationProcess(HANDLE, uint32_t, void *, uint32_t, uint32_t *);

_Static_assert(sizeof(OBJECT_ATTRIBUTES) == 48, "AMD64 OBJECT_ATTRIBUTES");
_Static_assert(sizeof(IO_STATUS_BLOCK) == 16, "AMD64 IOSB");
_Static_assert(offsetof(IO_STATUS_BLOCK, Information) == 8, "IOSB Information");
_Static_assert(sizeof(UNICODE_STRING) == 16, "AMD64 string");
_Static_assert(sizeof(CLIENT_ID) == 16, "AMD64 CLIENT_ID");
_Static_assert(sizeof(PROCESS_BASIC_INFORMATION) == 48, "AMD64 process basic information");
_Static_assert(offsetof(PROCESS_BASIC_INFORMATION, UniqueProcessId) == 32, "AMD64 process PID");
#define CURRENT_PROCESS ((HANDLE)(intptr_t)-1)
#define CURRENT_THREAD ((HANDLE)(intptr_t)-2)
#define SUCCESS ((NTSTATUS)0)
#define AV ((NTSTATUS)0xc0000005u)
#define GUARD ((NTSTATUS)0x80000001u)
#define BAD_HANDLE ((NTSTATUS)0xc0000008u)
#define BAD_CLASS ((NTSTATUS)0xc0000003u)
#define BAD_LENGTH ((NTSTATUS)0xc0000004u)
#define ACCESS_DENIED ((NTSTATUS)0xc0000022u)
#define NOT_DIRECTORY ((NTSTATUS)0xc0000103u)
#define TIMEOUT ((NTSTATUS)0x102)
#define SENTINEL ((uintptr_t)0xababababababababu)
#define SYNC 0x00100000u
#define DIRECTORY 1u
#define NON_DIRECTORY 0x40u
#define SYNC_NONALERT 0x20u
#define DELETE_ON_CLOSE 0x1000u
#define PAGE_RW 4u
#define PAGE_NOACCESS 1u
#define PAGE_GUARD 0x100u

static unsigned completed;
static unsigned registry_completed;
static const unsigned char payload[16] = "native-file-io!";

static void emit(const char *case_name, const char *field, uint64_t actual, uint64_t expected)
{
    uint16_t buffer[256]; size_t n = 0;
    const char *parts[] = {"[file-acceptance] case=", case_name, " field=", field, " actual=0x"};
    const char digits[] = "0123456789abcdef";
    for (unsigned p = 0; p != 5; ++p)
        for (const char *s = parts[p]; *s && n < 180; ++s) buffer[n++] = (uint8_t)*s;
    for (int i = 15; i >= 0; --i) buffer[n++] = digits[(actual >> (i * 4)) & 15u];
    const char *suffix = " expected=0x";
    while (*suffix) buffer[n++] = (uint8_t)*suffix++;
    for (int i = 15; i >= 0; --i) buffer[n++] = digits[(expected >> (i * 4)) & 15u];
    buffer[n++] = '\n';
    UNICODE_STRING text = {(uint16_t)(n * 2), (uint16_t)(n * 2), buffer};
    (void)NtDisplayString(&text);
}

__attribute__((noreturn)) static void fail(void)
{
    emit("FAIL", "completed", completed, UINT32_MAX);
    (void)NtTerminateProcess(CURRENT_PROCESS, (NTSTATUS)0xc0000001u);
    __builtin_trap();
}
static void eq(const char *name, const char *field, uint64_t actual, uint64_t expected)
{
    emit(name, field, actual, expected);
    if (actual != expected) fail();
}
static void status(const char *name, NTSTATUS actual, NTSTATUS expected)
{ eq(name, "status", (uint32_t)actual, (uint32_t)expected); }
static void fill(void *data, size_t bytes, unsigned char value)
{ for (size_t i = 0; i < bytes; ++i) ((unsigned char *)data)[i] = value; }
static int same(const void *a, const void *b, size_t bytes)
{
    for (size_t i = 0; i < bytes; ++i)
        if (((const unsigned char *)a)[i] != ((const unsigned char *)b)[i]) return 0;
    return 1;
}
static uint64_t u64(const unsigned char *p)
{ uint64_t v = 0; for (unsigned i = 0; i != 8; ++i) v |= (uint64_t)p[i] << (i * 8); return v; }
static uint32_t u32(const unsigned char *p)
{ uint32_t v = 0; for (unsigned i = 0; i != 4; ++i) v |= (uint32_t)p[i] << (i * 8); return v; }
static int name_ends_with(const unsigned char *name, size_t bytes, const char *suffix)
{
    size_t units = 0; while (suffix[units]) ++units;
    if ((bytes & 1u) || bytes / 2 < units) return 0;
    size_t offset = bytes - units * 2;
    for (size_t i = 0; i < units; ++i) {
        uint16_t actual = (uint16_t)name[offset + i * 2] |
                          (uint16_t)name[offset + i * 2 + 1] << 8;
        uint16_t expected = (uint8_t)suffix[i];
        if (actual >= 'A' && actual <= 'Z') actual += 'a' - 'A';
        if (expected >= 'A' && expected <= 'Z') expected += 'a' - 'A';
        if (actual != expected) return 0;
    }
    return 1;
}
static IO_STATUS_BLOCK untouched(void)
{ IO_STATUS_BLOCK v = {SENTINEL, SENTINEL}; return v; }
static UNICODE_STRING string(const char *name, uint16_t *buffer)
{
    size_t n = 0; while (*name) buffer[n++] = (uint8_t)*name++;
    UNICODE_STRING result = {(uint16_t)(n * 2), (uint16_t)(n * 2), buffer}; return result;
}
static OBJECT_ATTRIBUTES attributes(HANDLE root, UNICODE_STRING *name)
{ OBJECT_ATTRIBUTES result = {48, root, name, 0x40, 0, 0}; return result; }
static void close_handle(HANDLE handle)
{ status("close", NtClose(handle), SUCCESS); }
static void query_position(HANDLE file, uint64_t expected)
{
    uint64_t position = UINT64_MAX; IO_STATUS_BLOCK iosb = untouched();
    status("position", NtQueryInformationFile(file, &iosb, &position, 8, 14), SUCCESS);
    eq("position", "information", iosb.Information, 8);
    eq("position", "offset", position, expected);
}
static uint32_t protect(void *page, uint32_t protection)
{
    size_t bytes = 4096; uint32_t old = 0;
    status("protect", NtProtectVirtualMemory(CURRENT_PROCESS, &page, &bytes, protection, &old), SUCCESS);
    return old;
}
static void nonsignaled(HANDLE event)
{
    int64_t poll = 0; status("event", NtWaitForSingleObject(event, 0, &poll), TIMEOUT);
}

static void query_cases(HANDLE file)
{
    _Alignas(8) unsigned char storage[512];
    IO_STATUS_BLOCK iosb = untouched(); fill(storage, sizeof(storage), 0xa5);
    status("file-all", NtQueryInformationFile(file, &iosb, storage + 8, 488, 18), SUCCESS);
    eq("file-all", "iosb-status", (uint32_t)iosb.Status, 0);
    eq("file-all", "iosb-padding", iosb.Status >> 32, 0xababababu);
    uint32_t name_bytes = u32(storage + 8 + 96);
    eq("file-all", "name-even", name_bytes & 1u, 0);
    emit("file-all", "name-bytes", name_bytes, name_bytes);
    uint64_t required = 100ull + name_bytes;
    if (required > 488 || name_bytes == 0 || (name_bytes & 1u)) fail();
    eq("file-all", "information", iosb.Information, required);
    eq("file-all", "name-suffix", name_ends_with(storage + 8 + 100, name_bytes,
           "\\ntos-file-acceptance.tmp"), 1);
    eq("file-all", "eof", u64(storage + 8 + 48), sizeof(payload));
    eq("file-all", "position", u64(storage + 8 + 80), sizeof(payload));
    eq("file-all", "mode", u32(storage + 8 + 88), SYNC_NONALERT | DELETE_ON_CLOSE);
    for (size_t i = 0; i < 8; ++i) if (storage[i] != 0xa5) fail();
    for (size_t i = 496; i < sizeof(storage); ++i) if (storage[i] != 0xa5) fail();
    emit("file-all", "boundary-canaries", 1, 1); ++completed;

    iosb = untouched(); fill(storage, sizeof(storage), 0xa5);
    status("short-standard", NtQueryInformationFile(file, &iosb, storage + 8, 23, 5), BAD_LENGTH);
    eq("short-standard", "iosb-status", iosb.Status, SENTINEL);
    for (size_t i = 0; i < sizeof(storage); ++i) if (storage[i] != 0xa5) fail();
    ++completed;

    iosb = untouched();
    status("query-class-before-probe", NtQueryInformationFile((HANDLE)0x12345678, 0, 0, 24, 0), BAD_CLASS);
    status("query-length-before-probe", NtQueryInformationFile((HANDLE)0x12345678, 0, 0, 1, 5), BAD_LENGTH);
    status("query-probe-before-handle", NtQueryInformationFile((HANDLE)0x12345678, 0, storage, 24, 5), AV);
    status("read-handle-before-probe", NtReadFile((HANDLE)0x12345678, 0, 0, 0, 0, 0, 8, 0, 0), BAD_HANDLE);
    status("write-handle-before-probe", NtWriteFile((HANDLE)0x12345678, 0, 0, 0, 0, 0, 8, 0, 0), BAD_HANDLE);
    ++completed;
}

static void fault_cases(HANDLE file)
{
    void *allocation = 0; size_t bytes = 8192;
    status("allocate", NtAllocateVirtualMemory(CURRENT_PROCESS, &allocation, 0, &bytes, 0x3000, PAGE_RW), SUCCESS);
    eq("allocate", "size", bytes, 8192);
    unsigned char *base = allocation;
    fill(base, 8192, 0xcc);
    HANDLE event = 0;
    status("event-create", NtCreateEvent(&event, 0x001f0003, 0, 0, 0), SUCCESS);
    int64_t offset = 0;
    for (unsigned iosb_fault = 0; iosb_fault != 2; ++iosb_fault) {
        const char *name = iosb_fault ? "open-iosb-before-attributes" : "open-handle-before-iosb";
        HANDLE handle = (HANDLE)SENTINEL;
        fill(base + 4096, 16, 0xab);
        protect(base + 4096, PAGE_RW | PAGE_GUARD);
        status(name, NtOpenFile(iosb_fault ? &handle : (HANDLE *)(base + 4096),
               SYNC | 1, 0, iosb_fault ? (IO_STATUS_BLOCK *)(base + 4096) : 0,
               7, NON_DIRECTORY | SYNC_NONALERT), GUARD);
        eq(name, "old-protection", protect(base + 4096, PAGE_RW), PAGE_RW);
        eq(name, "handle-unchanged", iosb_fault ? (uintptr_t)handle : u64(base + 4096), SENTINEL);
        eq(name, "protected-output-unchanged", u64(base + 4104), SENTINEL);
    }
    {
        HANDLE handle = (HANDLE)SENTINEL;
        IO_STATUS_BLOCK iosb = untouched();
        protect(base + 4096, PAGE_NOACCESS);
        status("open-attributes-after-outputs", NtOpenFile(&handle, SYNC | 1,
               (OBJECT_ATTRIBUTES *)(base + 4096), &iosb, 7, NON_DIRECTORY | SYNC_NONALERT), AV);
        eq("open-attributes-after-outputs", "handle-unchanged", (uintptr_t)handle, SENTINEL);
        eq("open-attributes-after-outputs", "iosb-status", iosb.Status, SENTINEL);
        eq("open-attributes-after-outputs", "iosb-information", iosb.Information, SENTINEL);
        eq("open-attributes-after-outputs", "old-protection", protect(base + 4096, PAGE_RW), PAGE_NOACCESS);
    }
    fill(base + 4096, 16, 0xcc);
    for (unsigned guard = 0; guard != 2; ++guard) {
        NTSTATUS expected = guard ? GUARD : AV;
        const char *name = guard ? "guard-query-output" : "noaccess-query-output";
        protect(base + 4096, guard ? PAGE_RW | PAGE_GUARD : PAGE_NOACCESS);
        IO_STATUS_BLOCK iosb = untouched();
        status(name, NtQueryInformationFile(file, &iosb, base + 4088, 24, 5), expected);
        eq(name, "iosb-status", iosb.Status, SENTINEL);
        eq(name, "iosb-information", iosb.Information, SENTINEL);
        uint32_t old = protect(base + 4096, PAGE_RW);
        eq(name, "old-protection", old, guard ? PAGE_RW : PAGE_NOACCESS);
        for (size_t i = 4088; i < 4112; ++i) if (base[i] != 0xcc) fail();
        emit(name, "output-unchanged", 1, 1);
        query_position(file, sizeof(payload)); nonsignaled(event); ++completed;
    }

    /* The four-byte scalar is readable, but NT captures the complete supplied Length
       after acquiring the synchronous File. A trailing refusal must not change mode. */
    for (unsigned guard = 0; guard != 2; ++guard) {
        const char *name = guard ? "mode-guard-span" : "mode-noaccess-span";
        uint32_t *requested = (uint32_t *)(base + 4092);
        *requested = 0x10; /* would switch the shared File to synchronous alertable */
        protect(base + 4096, guard ? PAGE_RW | PAGE_GUARD : PAGE_NOACCESS);
        IO_STATUS_BLOCK iosb = untouched();
        status(name, NtSetInformationFile(file, &iosb, requested, 8, 16), guard ? GUARD : AV);
        eq(name, "iosb-status", iosb.Status, SENTINEL);
        eq(name, "iosb-information", iosb.Information, SENTINEL);
        eq(name, "input-scalar", *requested, 0x10);
        protect(base + 4096, PAGE_RW);
        uint32_t mode = UINT32_MAX;
        status(guard ? "mode-guard-span-query" : "mode-noaccess-span-query",
               NtQueryInformationFile(file, &iosb, &mode, 4, 16), SUCCESS);
        eq(name, "mode", mode, DELETE_ON_CLOSE | SYNC_NONALERT);
        query_position(file, sizeof(payload));
        ++completed;
    }

    protect(base + 4096, PAGE_NOACCESS);
    IO_STATUS_BLOCK iosb = untouched();
    status("read-output-crossing", NtReadFile(file, event, 0, 0, &iosb, base + 4088, 16, &offset, 0), AV);
    eq("read-output-crossing", "iosb-status", iosb.Status, SENTINEL);
    eq("read-output-crossing", "iosb-information", iosb.Information, SENTINEL);
    int64_t poll = 0;
    status("read-output-fault-file-wait", NtWaitForSingleObject(file, 0, &poll), SUCCESS);
    query_position(file, sizeof(payload)); nonsignaled(event); ++completed;

    HANDLE write_event = 0;
    status("write-fault-event-create", NtCreateEvent(&write_event, 0x001f0003, 0, 0, 1), SUCCESS);
    status("write-input-crossing", NtWriteFile(file, write_event, 0, 0, &iosb, base + 4088, 16, &offset, 0), AV);
    eq("write-input-crossing", "iosb-status", iosb.Status, SENTINEL);
    eq("write-input-crossing", "iosb-information", iosb.Information, SENTINEL);
    status("write-input-fault-file-wait", NtWaitForSingleObject(file, 0, &poll), TIMEOUT);
    query_position(file, sizeof(payload)); nonsignaled(write_event);
    status("write-fault-event-close", NtClose(write_event), SUCCESS);

    protect(base + 4096, PAGE_RW | PAGE_GUARD);
    iosb = untouched(); write_event = 0;
    status("write-guard-event-create", NtCreateEvent(&write_event, 0x001f0003, 0, 0, 1), SUCCESS);
    status("write-input-guard", NtWriteFile(file, write_event, 0, 0, &iosb,
           base + 4088, 16, &offset, 0), GUARD);
    eq("write-input-guard", "iosb-status", iosb.Status, SENTINEL);
    eq("write-input-guard", "iosb-information", iosb.Information, SENTINEL);
    status("write-input-guard-file-wait", NtWaitForSingleObject(file, 0, &poll), TIMEOUT);
    status("write-input-guard-event-wait", NtWaitForSingleObject(write_event, 0, &poll), TIMEOUT);
    eq("write-input-guard", "old-protection", protect(base + 4096, PAGE_RW), PAGE_RW);
    uint64_t position = UINT64_MAX; IO_STATUS_BLOCK position_iosb = untouched();
    status("write-input-guard-position", NtQueryInformationFile(file, &position_iosb,
           &position, sizeof(position), 14), SUCCESS);
    eq("write-input-guard", "position", position, sizeof(payload));
    status("write-guard-event-close", NtClose(write_event), SUCCESS);

    /* Optional scalar pointers fault before the initially signaled Event is reset. */
    for (unsigned key_case = 0; key_case != 2; ++key_case) {
        const char *name = key_case ? "write-key-guard" : "write-offset-noaccess";
        fill(base + 4088, 16, 0);
        protect(base + 4096, key_case ? PAGE_RW | PAGE_GUARD : PAGE_NOACCESS);
        HANDLE scalar_event = 0;
        status(key_case ? "write-key-event-create" : "write-offset-event-create",
               NtCreateEvent(&scalar_event, 0x001f0003, 0, 0, 1), SUCCESS);
        iosb = untouched();
        status(name, NtWriteFile(file, scalar_event, 0, 0, &iosb, (void *)payload,
               sizeof(payload), key_case ? &offset : (int64_t *)(base + 4092),
               key_case ? (uint32_t *)(base + 4096) : 0), key_case ? GUARD : AV);
        eq(name, "iosb-status", iosb.Status, SENTINEL);
        eq(name, "iosb-information", iosb.Information, SENTINEL);
        status(key_case ? "write-key-event-wait" : "write-offset-event-wait",
               NtWaitForSingleObject(scalar_event, 0, &poll), SUCCESS);
        status(key_case ? "write-key-file-wait" : "write-offset-file-wait",
               NtWaitForSingleObject(file, 0, &poll), SUCCESS);
        eq(name, "old-protection", protect(base + 4096, PAGE_RW),
           key_case ? PAGE_RW : PAGE_NOACCESS);
        position = UINT64_MAX; position_iosb = untouched();
        status(key_case ? "write-key-position" : "write-offset-position",
               NtQueryInformationFile(file, &position_iosb, &position, sizeof(position), 14), SUCCESS);
        eq(name, "position", position, sizeof(payload));
        status(key_case ? "write-key-event-close" : "write-offset-event-close",
               NtClose(scalar_event), SUCCESS);
    }
    ++completed;
    protect(base + 4096, PAGE_NOACCESS);

    /* IOSB probe spans both words before provider entry; no terminal IOSB publication occurs. */
    uintptr_t *partial = (uintptr_t *)(base + 4088); *partial = SENTINEL;
    status("read-iosb-crossing", NtReadFile(file, event, 0, 0, (IO_STATUS_BLOCK *)partial,
           base, 16, &offset, 0), AV);
    eq("read-iosb-crossing", "status-word", *partial, SENTINEL);
    query_position(file, sizeof(payload)); nonsignaled(event); ++completed;
    protect(base + 4096, PAGE_RW);

    unsigned char readback[16]; iosb = untouched();
    status("content-after-faults", NtReadFile(file, 0, 0, 0, &iosb, readback, 16, &offset, 0), SUCCESS);
    eq("content-after-faults", "information", iosb.Information, sizeof(payload));
    eq("content-after-faults", "unchanged", same(readback, payload, sizeof(payload)), 1);
    ++completed;
    close_handle(event);
    bytes = 0; status("free", NtFreeVirtualMemory(CURRENT_PROCESS, &allocation, &bytes, 0x8000), SUCCESS);
}

static void mode_cases(HANDLE file)
{
    HANDLE duplicate = 0;
    status("mode-duplicate", NtDuplicateObject(CURRENT_PROCESS, file, CURRENT_PROCESS,
           &duplicate, 0, 0, 2), SUCCESS);
    uint32_t requested = 0x16; /* write-through, sequential, synchronous alertable */
    IO_STATUS_BLOCK iosb = untouched();
    status("mode-set", NtSetInformationFile(file, &iosb, &requested, 4, 16), SUCCESS);
    eq("mode-set", "information", iosb.Information, 0);
    eq("mode-set", "padding", iosb.Status >> 32, 0xababababu);
    uint32_t queried = UINT32_MAX;
    status("mode-query-duplicate", NtQueryInformationFile(duplicate, &iosb, &queried, 4, 16), SUCCESS);
    eq("mode-query-duplicate", "mode", queried, DELETE_ON_CLOSE | requested);
    _Alignas(8) unsigned char all[512]; fill(all, sizeof(all), 0xa5);
    status("mode-all-duplicate", NtQueryInformationFile(duplicate, &iosb, all, sizeof(all), 18), SUCCESS);
    eq("mode-all-duplicate", "mode", u32(all + 88), DELETE_ON_CLOSE | requested);
    eq("mode-all-duplicate", "position", u64(all + 80), sizeof(payload));
    ++completed;

    requested = 0x30; /* mutually exclusive synchronous flags */
    status("mode-reject", NtSetInformationFile(duplicate, &iosb, &requested, 4, 16), (NTSTATUS)0xc000000du);
    status("mode-reject-query", NtQueryInformationFile(file, &iosb, &queried, 4, 16), SUCCESS);
    eq("mode-reject-query", "mode", queried, DELETE_ON_CLOSE | 0x16);
    requested = SYNC_NONALERT;
    status("mode-restore", NtSetInformationFile(duplicate, &iosb, &requested, 4, 16), SUCCESS);
    status("mode-restore-query", NtQueryInformationFile(file, &iosb, &queried, 4, 16), SUCCESS);
    eq("mode-restore-query", "mode", queried, DELETE_ON_CLOSE | SYNC_NONALERT);
    close_handle(duplicate);
    ++completed;
}

static NTSTATUS registry_worker(void *context)
{
    (void)context;
    uint16_t units[128];
    UNICODE_STRING name = string("\\Registry\\Machine\\Software\\Classes", units);
    OBJECT_ATTRIBUTES attrs = attributes(0, &name);
    HANDLE key = 0;
    status("registry-worker-open", NtOpenKey(&key, 1, &attrs), SUCCESS);
    /* ResultLength is an actual local on the independently registered worker stack. */
    uint32_t required = UINT32_MAX;
    status("registry-worker-size", NtQueryKey(key, 3, 0, 0, &required), (NTSTATUS)0xc0000023u);
    eq("registry-worker-size", "required", required, 4u + name.Length);
    _Alignas(8) unsigned char storage[256]; fill(storage, sizeof(storage), 0xa5);
    if (required > sizeof(storage) - 16) fail();
    uint32_t returned = UINT32_MAX;
    status("registry-worker-name", NtQueryKey(key, 3, storage + 8, required, &returned), SUCCESS);
    eq("registry-worker-name", "required", returned, required);
    eq("registry-worker-name", "name-length", u32(storage + 8), name.Length);
    for (size_t i = 0; i < name.Length / 2; ++i) {
        uint16_t actual = (uint16_t)storage[12 + i * 2] | (uint16_t)storage[13 + i * 2] << 8;
        uint16_t expected = units[i];
        if (actual >= 'A' && actual <= 'Z') actual += 'a' - 'A';
        if (expected >= 'A' && expected <= 'Z') expected += 'a' - 'A';
        if (actual != expected) { eq("registry-worker-name", "unit", actual, expected); fail(); }
    }
    for (size_t i = 0; i < 8; ++i) if (storage[i] != 0xa5) fail();
    for (size_t i = 8 + required; i < sizeof(storage); ++i) if (storage[i] != 0xa5) fail();
    emit("registry-worker-name", "name-and-canaries", 1, 1);
    close_handle(key);
    __atomic_store_n(&registry_completed, 1, __ATOMIC_RELEASE);
    NTSTATUS returned_status = NtTerminateThread(CURRENT_THREAD, SUCCESS);
    emit("FAIL-THREAD-EXIT-RETURNED", "status", (uint32_t)returned_status, UINT32_MAX);
    fail();
}

static void registry_case(void)
{
    HANDLE worker = 0; CLIENT_ID id = {0, 0};
    status("registry-worker-create", RtlCreateUserThread(CURRENT_PROCESS, 0, 0, 0,
           0, 0, registry_worker, 0, &worker, &id), SUCCESS);
    if (worker == 0 || id.UniqueThread == 0) fail();
    int64_t timeout = -100000000ll;
    status("registry-worker-wait", NtWaitForSingleObject(worker, 0, &timeout), SUCCESS);
    eq("registry-worker-wait", "completed", __atomic_load_n(&registry_completed, __ATOMIC_ACQUIRE), 1);
    close_handle(worker); ++completed;
}

void NtProcessStartup(void *peb)
{
    (void)peb;
    emit("BEGIN", "version", 1, 1);
    PROCESS_BASIC_INFORMATION process = {0}; uint32_t process_bytes = 0;
    status("identity", NtQueryInformationProcess(CURRENT_PROCESS, 0, &process,
           sizeof(process), &process_bytes), SUCCESS);
    eq("identity", "bytes", process_bytes, sizeof(process));
    if (process.UniqueProcessId == 0) fail();
    emit("identity", "pid", process.UniqueProcessId, process.UniqueProcessId);
    uint16_t parent_units[128], child_units[128];
    UNICODE_STRING parent_name = string("\\SystemRoot\\Fonts", parent_units);
    UNICODE_STRING child_name = string("ntos-file-acceptance.tmp", child_units);
    OBJECT_ATTRIBUTES parent_attrs = attributes(0, &parent_name);
    IO_STATUS_BLOCK iosb = untouched(); HANDLE parent = 0;
    status("parent-open", NtOpenFile(&parent, 0x81 | SYNC, &parent_attrs, &iosb, 7,
           DIRECTORY | SYNC_NONALERT), SUCCESS);
    {
        uint16_t missing_units[128];
        UNICODE_STRING missing_name = string("ntos-file-acceptance-absent.tmp", missing_units);
        OBJECT_ATTRIBUTES missing_attrs = attributes(parent, &missing_name);
        HANDLE missing = (HANDLE)SENTINEL;
        IO_STATUS_BLOCK missing_iosb = untouched();
        status("open-missing-child", NtOpenFile(&missing, 0x81 | SYNC, &missing_attrs,
               &missing_iosb, 7, NON_DIRECTORY | SYNC_NONALERT), (NTSTATUS)0xc0000034u);
        eq("open-missing-child", "handle-unchanged", (uintptr_t)missing, SENTINEL);
        eq("open-missing-child", "iosb-status", missing_iosb.Status, SENTINEL);
        eq("open-missing-child", "iosb-information", missing_iosb.Information, SENTINEL);
    }
    OBJECT_ATTRIBUTES child_attrs = attributes(parent, &child_name); HANDLE child = 0;
    status("relative-create", NtCreateFile(&child, 0x00110183, &child_attrs, &iosb,
           0, 0, 7, 2, NON_DIRECTORY | SYNC_NONALERT | DELETE_ON_CLOSE, 0, 0), SUCCESS);
    eq("relative-create", "information", iosb.Information, 2); ++completed;
    int64_t offset = 0;
    status("write", NtWriteFile(child, 0, 0, 0, &iosb, (void *)payload, sizeof(payload), &offset, 0), SUCCESS);
    eq("write", "information", iosb.Information, sizeof(payload));
    HANDLE reopened = 0;
    status("relative-reopen", NtOpenFile(&reopened, 0x81 | SYNC, &child_attrs, &iosb, 7,
           NON_DIRECTORY | SYNC_NONALERT), SUCCESS);
    unsigned char readback[16];
    status("relative-read", NtReadFile(reopened, 0, 0, 0, &iosb, readback, 16, &offset, 0), SUCCESS);
    eq("relative-read", "bytes", same(readback, payload, sizeof(payload)), 1);
    ++completed;

    /* A valid read-only File handle cannot grant write access. */
    status("write-readonly-handle", NtWriteFile(reopened, 0, 0, 0, &iosb,
           (void *)payload, sizeof(payload), &offset, 0), ACCESS_DENIED);
    status("write-access-before-probe", NtWriteFile(reopened, 0, 0, 0, 0,
           0, sizeof(payload), (int64_t *)1, (uint32_t *)1), ACCESS_DENIED); ++completed;
    OBJECT_ATTRIBUTES wrong_root = attributes(child, &child_name); HANDLE denied = 0;
    status("nondirectory-root", NtOpenFile(&denied, 0x81 | SYNC, &wrong_root, &iosb, 7,
           NON_DIRECTORY | SYNC_NONALERT), NOT_DIRECTORY); ++completed;
    close_handle(parent); close_handle(reopened);
    query_position(child, sizeof(payload)); ++completed;
    query_cases(child); mode_cases(child); fault_cases(child);
    close_handle(child);
    registry_case();
    eq("PASS", "cases", completed, 19);
    emit("EXIT-REQUEST", "status", 0, 0);
    NTSTATUS returned = NtTerminateProcess(CURRENT_PROCESS, SUCCESS);
    emit("FAIL-EXIT-RETURNED", "status", (uint32_t)returned, UINT32_MAX);
    fail();
}
