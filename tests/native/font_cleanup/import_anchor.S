.text
.macro IMPORT_ANCHOR name
.globl \name
\name:
    ud2
    ret
.endm
IMPORT_ANCHOR NtDisplayString
IMPORT_ANCHOR NtQueryInformationProcess
IMPORT_ANCHOR NtTerminateProcess
IMPORT_ANCHOR NtCreateKey
IMPORT_ANCHOR NtSetValueKey
IMPORT_ANCHOR NtQueryValueKey
IMPORT_ANCHOR NtClose
IMPORT_ANCHOR GetWindowsDirectoryW
IMPORT_ANCHOR GetLastError
IMPORT_ANCHOR AddFontResourceExW
