#ifndef FONT_CLEANUP_FIXTURE_H
#define FONT_CLEANUP_FIXTURE_H

typedef unsigned short WCHAR;
typedef unsigned int ULONG;
typedef unsigned long long ULONG_PTR;
typedef int NTSTATUS;
typedef void *HANDLE;
#define IMPORT __declspec(dllimport)
#define NTAPI __stdcall
#define CURRENT_PROCESS ((HANDLE)(long long)-1)

typedef struct {
    unsigned short Length, MaximumLength;
    WCHAR *Buffer;
} UNICODE_STRING;
typedef struct {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    ULONG Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef struct {
    NTSTATUS ExitStatus;
    void *PebBaseAddress;
    ULONG_PTR AffinityMask;
    int BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

_Static_assert(sizeof(UNICODE_STRING) == 16, "NT AMD64 UNICODE_STRING");
_Static_assert(sizeof(OBJECT_ATTRIBUTES) == 48, "NT AMD64 OBJECT_ATTRIBUTES");
_Static_assert(sizeof(PROCESS_BASIC_INFORMATION) == 48, "NT AMD64 process basic information");
_Static_assert(__builtin_offsetof(PROCESS_BASIC_INFORMATION, UniqueProcessId) == 32, "PID offset");

IMPORT NTSTATUS NTAPI NtDisplayString(UNICODE_STRING *);
IMPORT NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, ULONG, void *, ULONG, ULONG *);
IMPORT NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);

static void emit(const char *text) {
    WCHAR buffer[256];
    ULONG count = 0;
    while (text[count] && count < 254) { buffer[count] = (unsigned char)text[count]; ++count; }
    buffer[count++] = '\n';
    UNICODE_STRING string = {(unsigned short)(count * 2), (unsigned short)(count * 2), buffer};
    (void)NtDisplayString(&string);
}

static char *append(char *cursor, const char *text) {
    while (*text) *cursor++ = *text++;
    return cursor;
}

static char *hex32(char *cursor, ULONG value) {
    static const char digits[] = "0123456789abcdef";
    cursor = append(cursor, "0x");
    for (int shift = 28; shift >= 0; shift -= 4) *cursor++ = digits[(value >> shift) & 15];
    return cursor;
}

static char *decimal(char *cursor, ULONG_PTR value) {
    char digits[20];
    ULONG count = 0;
    do { digits[count++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (count) *cursor++ = digits[--count];
    return cursor;
}

static void observation(const char *fixture, const char *stage, NTSTATUS actual, NTSTATUS expected) {
    char line[256], *cursor = append(line, fixture);
    cursor = append(cursor, " "); cursor = append(cursor, stage);
    cursor = append(cursor, " actual="); cursor = hex32(cursor, (ULONG)actual);
    cursor = append(cursor, " expected="); cursor = hex32(cursor, (ULONG)expected);
    *cursor = 0; emit(line);
}

static NTSTATUS begin(const char *fixture) {
    PROCESS_BASIC_INFORMATION info = {0};
    ULONG returned = 0;
    NTSTATUS status = NtQueryInformationProcess(CURRENT_PROCESS, 0, &info, sizeof(info), &returned);
    observation(fixture, "PID-QUERY", status, 0);
    if (status != 0 || info.UniqueProcessId == 0 || returned != sizeof(info)) return (NTSTATUS)0xc0000001;
    char line[256], *cursor = append(line, fixture);
    cursor = append(cursor, " BEGIN pid="); cursor = decimal(cursor, info.UniqueProcessId);
    *cursor = 0; emit(line);
    return 0;
}

static void terminate(const char *fixture, NTSTATUS status) {
    char line[256], *cursor = append(line, fixture);
    cursor = append(cursor, " EXIT-REQUEST status="); cursor = hex32(cursor, (ULONG)status);
    *cursor = 0; emit(line);
    NTSTATUS returned = NtTerminateProcess(CURRENT_PROCESS, status);
    observation(fixture, "TERMINATE-RETURNED", returned, (NTSTATUS)0xc0000001);
    __builtin_trap();
}

#endif
