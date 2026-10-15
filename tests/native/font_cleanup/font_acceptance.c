#include "fixture.h"

IMPORT ULONG NTAPI GetWindowsDirectoryW(WCHAR *, ULONG);
IMPORT ULONG NTAPI GetLastError(void);
IMPORT int NTAPI AddFontResourceExW(const WCHAR *, ULONG, void *);

void WinMainCRTStartup(void) {
    const char *fixture = "[font-acceptance]";
    NTSTATUS status = begin(fixture);
    if (status != 0) { emit("[font-acceptance] FAIL PID"); terminate(fixture, status); }
    WCHAR path[512];
    ULONG length = GetWindowsDirectoryW(path, 512);
    static const WCHAR suffix[] = L"\\Fonts\\FreeSans.ttf";
    ULONG suffix_length = sizeof(suffix) / sizeof(suffix[0]);
    if (length == 0 || length + suffix_length > 512) {
        observation(fixture, "WINDOWS-DIRECTORY-ERROR", (NTSTATUS)GetLastError(), 0);
        emit("[font-acceptance] FAIL PATH"); terminate(fixture, (NTSTATUS)0xc0000001);
    }
    for (ULONG index = 0; index < suffix_length; ++index) path[length + index] = suffix[index];
    int count = AddFontResourceExW(path, 0x10, 0); /* FR_PRIVATE */
    char line[256], *cursor = append(line, "[font-acceptance] ADDED fonts=");
    cursor = decimal(cursor, count > 0 ? (ULONG)count : 0);
    cursor = append(cursor, " flags=0x00000010"); *cursor = 0; emit(line);
    if (count <= 0) {
        observation(fixture, "ADD-ERROR", (NTSTATUS)GetLastError(), 0);
        emit("[font-acceptance] FAIL ADD"); terminate(fixture, (NTSTATUS)0xc0000001);
    }
    emit("[font-acceptance] PASS PRIVATE-FONT-LOADED");
    /* Intentionally no RemoveFontResourceEx: real process deletion must retire the font. */
    terminate(fixture, 0);
}
