/* Native AMD64 kernel-driver SEH acceptance fixture. No CRT or private executive ABI. */
#include <stdint.h>

typedef int32_t NTSTATUS;

#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001u)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022u)
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0

__declspec(dllimport) void __stdcall ExRaiseStatus(NTSTATUS status);
__declspec(dllimport) int __cdecl DbgPrint(const char *format, ...);

struct SehFixtureEvidence {
    uint32_t entered;
    uint32_t after_raise;
    uint32_t finally_calls;
    uint32_t caught;
    uint32_t caught_code;
    uint32_t driver_entry_returned;
};

volatile struct SehFixtureEvidence SehFixtureEvidence;

__declspec(noinline) static void RaiseWithFinally(void)
{
    __try {
        SehFixtureEvidence.entered++;
        ExRaiseStatus(STATUS_ACCESS_DENIED);
        SehFixtureEvidence.after_raise++;
    } __finally {
        SehFixtureEvidence.finally_calls++;
    }
}

NTSTATUS __stdcall DriverEntry(void *driver_object, void *registry_path)
{
    (void)driver_object;
    (void)registry_path;

    __try {
        RaiseWithFinally();
        SehFixtureEvidence.driver_entry_returned++;
    } __except (__exception_code() == (uint32_t)STATUS_ACCESS_DENIED
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        SehFixtureEvidence.caught++;
        SehFixtureEvidence.caught_code = __exception_code();
    }

    NTSTATUS status = STATUS_SUCCESS;
    if (SehFixtureEvidence.entered != 1 || SehFixtureEvidence.after_raise != 0 ||
        SehFixtureEvidence.finally_calls != 1 || SehFixtureEvidence.caught != 1 ||
        SehFixtureEvidence.caught_code != (uint32_t)STATUS_ACCESS_DENIED ||
        SehFixtureEvidence.driver_entry_returned != 0) {
        status = STATUS_UNSUCCESSFUL;
    }
    DbgPrint("[seh-native-proof] status=0x%08x entered=%u after-raise=%u finally=%u caught=%u caught-code=0x%08x returned-before-catch=%u\n",
             (uint32_t)status, SehFixtureEvidence.entered,
             SehFixtureEvidence.after_raise, SehFixtureEvidence.finally_calls,
             SehFixtureEvidence.caught, SehFixtureEvidence.caught_code,
             SehFixtureEvidence.driver_entry_returned);
    if (status == STATUS_SUCCESS) {
        DbgPrint("[seh-native-proof-complete]\n");
    }
    return status;
}
