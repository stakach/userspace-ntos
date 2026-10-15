#include "fixture.h"

IMPORT NTSTATUS NTAPI NtCreateKey(HANDLE *, ULONG, OBJECT_ATTRIBUTES *, ULONG, UNICODE_STRING *, ULONG, ULONG *);
IMPORT NTSTATUS NTAPI NtSetValueKey(HANDLE, UNICODE_STRING *, ULONG, ULONG, const void *, ULONG);
IMPORT NTSTATUS NTAPI NtQueryValueKey(HANDLE, UNICODE_STRING *, ULONG, void *, ULONG, ULONG *);
IMPORT NTSTATUS NTAPI NtClose(HANDLE);

void NtProcessStartup(void *reserved) {
    (void)reserved;
    const char *fixture = "[font-setup]";
    NTSTATUS status = begin(fixture);
    if (status != 0) { emit("[font-setup] FAIL PID"); terminate(fixture, status); }
    static WCHAR path[] = L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    static WCHAR value[] = L"NtosFontAcceptance";
    static WCHAR command[] = L"%SystemRoot%\\System32\\font_acceptance.exe";
    UNICODE_STRING key_name = {sizeof(path) - 2, sizeof(path), path};
    UNICODE_STRING value_name = {sizeof(value) - 2, sizeof(value), value};
    OBJECT_ATTRIBUTES attributes = {sizeof(attributes), 0, &key_name, 0x40, 0, 0};
    HANDLE key = 0;
    ULONG disposition = 0;
    status = NtCreateKey(&key, 3, &attributes, 0, 0, 0, &disposition);
    observation(fixture, "CREATE-RUN", status, 0);
    if (status != 0) { emit("[font-setup] FAIL CREATE"); terminate(fixture, status); }
    status = NtSetValueKey(key, &value_name, 0, 2, command, sizeof(command)); /* REG_EXPAND_SZ */
    observation(fixture, "SET-RUN", status, 0);
    if (status != 0) { (void)NtClose(key); emit("[font-setup] FAIL SET"); terminate(fixture, status); }
    union { ULONG_PTR alignment; unsigned char bytes[512]; } result;
    ULONG required = 0;
    status = NtQueryValueKey(key, &value_name, 2, result.bytes, sizeof(result.bytes), &required);
    observation(fixture, "READBACK-RUN", status, 0);
    int valid = status == 0 && required == 12 + sizeof(command);
    if (valid) {
        ULONG *header = (ULONG *)result.bytes;
        valid = header[1] == 2 && header[2] == sizeof(command);
        for (ULONG index = 0; valid && index < sizeof(command); ++index)
            valid = result.bytes[12 + index] == ((unsigned char *)command)[index];
    }
    NTSTATUS closed = NtClose(key);
    observation(fixture, "CLOSE-RUN", closed, 0);
    if (!valid || closed != 0) {
        emit("[font-setup] FAIL READBACK"); terminate(fixture, (NTSTATUS)0xc0000001);
    }
    emit("[font-setup] PASS RUN-REGISTERED");
    terminate(fixture, 0);
}
