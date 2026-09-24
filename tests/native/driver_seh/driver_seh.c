/* Native AMD64 kernel-driver SEH acceptance fixture. No CRT or private executive ABI. */
#include <stdint.h>

typedef int32_t NTSTATUS;

#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001u)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022u)
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0

__declspec(dllimport) void __stdcall ExRaiseStatus(NTSTATUS status);

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

    if (SehFixtureEvidence.entered != 1 || SehFixtureEvidence.after_raise != 0 ||
        SehFixtureEvidence.finally_calls != 1 || SehFixtureEvidence.caught != 1 ||
        SehFixtureEvidence.caught_code != (uint32_t)STATUS_ACCESS_DENIED ||
        SehFixtureEvidence.driver_entry_returned != 0) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}
