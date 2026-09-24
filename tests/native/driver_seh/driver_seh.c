/* Native AMD64 kernel-driver SEH acceptance fixture. No CRT or private executive ABI. */
#include <stdint.h>

typedef int32_t NTSTATUS;

#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001u)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022u)
#define STATUS_ILLEGAL_INSTRUCTION ((NTSTATUS)0xc000001du)
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0

#if (defined(SEH_TERMINAL_UNHANDLED) + defined(SEH_TERMINAL_EXIT) + defined(SEH_FAULT_UD2)) > 1
#error "select exactly one native SEH case"
#endif

__declspec(dllimport) void __stdcall ExRaiseStatus(NTSTATUS status);
__declspec(dllimport) void __stdcall RtlUnwindEx(void *target_frame, void *target_ip,
    void *exception_record, void *return_value, void *context_record, void *history_table);
__declspec(dllimport) int __cdecl DbgPrint(const char *format, ...);

struct SehFixtureEvidence {
    uint32_t entered;
    uint32_t after_raise;
    uint32_t finally_calls;
    uint32_t caught;
    uint32_t caught_code;
    uint32_t driver_entry_returned;
    uint32_t unwind_finally;
    uint32_t unwind_after_call;
    uint32_t unwind_landed;
    uint32_t bare_unwind_after_call;
    uint32_t bare_unwind_landed;
    uint32_t collided_finally;
    uint32_t collided_inner_after;
    uint32_t collided_outer_after;
    uint32_t collided_landed;
    uint32_t fault_entered;
    uint32_t fault_after_instruction;
    uint32_t fault_caught;
    uint32_t fault_code;
};

volatile struct SehFixtureEvidence SehFixtureEvidence;

struct NativeExceptionRecord {
    uint32_t code;
    uint32_t flags;
    uint64_t chained;
    uint64_t address;
    uint32_t parameter_count;
    uint32_t alignment;
    uint64_t information[15];
};
_Static_assert(sizeof(struct NativeExceptionRecord) == 0x98, "NT exception record ABI");

static const struct NativeExceptionRecord UnwindRecord = {
    .code = 0xc0000027u,
};

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

__declspec(noinline) static void ExplicitTargetUnwind(void)
{
    __declspec(align(16)) unsigned char context[0x4d0];
    void *frame = __builtin_frame_address(0);
    void *target = &&unwind_target;
    __try {
        RtlUnwindEx(frame, target, (void *)&UnwindRecord,
                    (void *)(uintptr_t)0x1234, context, 0);
        SehFixtureEvidence.unwind_after_call++;
    } __finally {
        SehFixtureEvidence.unwind_finally++;
    }
unwind_target:
    SehFixtureEvidence.unwind_landed++;
}

void BareTargetUnwind(void);
void CollidedTargetUnwind(void);

#if defined(SEH_FAULT_UD2)
__declspec(noinline) static void CatchIllegalInstruction(void)
{
    __try {
        SehFixtureEvidence.fault_entered++;
        __asm__ __volatile__("ud2");
        SehFixtureEvidence.fault_after_instruction++;
    } __except (__exception_code() == (uint32_t)STATUS_ILLEGAL_INSTRUCTION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        SehFixtureEvidence.fault_caught++;
        SehFixtureEvidence.fault_code = __exception_code();
    }
}
#endif

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

    ExplicitTargetUnwind();
    BareTargetUnwind();
    CollidedTargetUnwind();

    NTSTATUS status = STATUS_SUCCESS;
    if (SehFixtureEvidence.entered != 1 || SehFixtureEvidence.after_raise != 0 ||
        SehFixtureEvidence.finally_calls != 1 || SehFixtureEvidence.caught != 1 ||
        SehFixtureEvidence.caught_code != (uint32_t)STATUS_ACCESS_DENIED ||
        SehFixtureEvidence.driver_entry_returned != 0 ||
        SehFixtureEvidence.unwind_finally != 1 ||
        SehFixtureEvidence.unwind_after_call != 0 ||
        SehFixtureEvidence.unwind_landed != 1 ||
        SehFixtureEvidence.bare_unwind_after_call != 0 ||
        SehFixtureEvidence.bare_unwind_landed != 1 ||
        SehFixtureEvidence.collided_finally != 1 ||
        SehFixtureEvidence.collided_inner_after != 0 ||
        SehFixtureEvidence.collided_outer_after != 0 ||
        SehFixtureEvidence.collided_landed != 1) {
        status = STATUS_UNSUCCESSFUL;
    }
    DbgPrint("[seh-native-proof] status=0x%08x entered=%u after-raise=%u finally=%u caught=%u caught-code=0x%08x returned-before-catch=%u\n",
             (uint32_t)status, SehFixtureEvidence.entered,
             SehFixtureEvidence.after_raise, SehFixtureEvidence.finally_calls,
             SehFixtureEvidence.caught, SehFixtureEvidence.caught_code,
             SehFixtureEvidence.driver_entry_returned);
    if (status == STATUS_SUCCESS) {
        DbgPrint("[seh-unwind-proof] finally=%u after-call=%u landed=%u bare-after=%u bare-landed=%u\n",
                 SehFixtureEvidence.unwind_finally, SehFixtureEvidence.unwind_after_call,
                 SehFixtureEvidence.unwind_landed, SehFixtureEvidence.bare_unwind_after_call,
                 SehFixtureEvidence.bare_unwind_landed);
        DbgPrint("[seh-collision-proof] finally=%u inner-after=%u outer-after=%u landed=%u\n",
                 SehFixtureEvidence.collided_finally, SehFixtureEvidence.collided_inner_after,
                 SehFixtureEvidence.collided_outer_after, SehFixtureEvidence.collided_landed);
#if defined(SEH_TERMINAL_UNHANDLED)
        DbgPrint("[seh-terminal-trigger] kind=unhandled code=0xc0000022\n");
        ExRaiseStatus(STATUS_ACCESS_DENIED);
        DbgPrint("[seh-terminal-unexpected-return]\n");
        return STATUS_UNSUCCESSFUL;
#elif defined(SEH_TERMINAL_EXIT)
        __declspec(align(16)) unsigned char exit_context[0x4d0];
        DbgPrint("[seh-terminal-trigger] kind=exit code=0xc0000027\n");
        RtlUnwindEx(0, 0, (void *)&UnwindRecord, 0, exit_context, 0);
        DbgPrint("[seh-terminal-unexpected-return]\n");
        return STATUS_UNSUCCESSFUL;
#elif defined(SEH_FAULT_UD2)
        DbgPrint("[seh-fault-trigger] kind=ud2\n");
        CatchIllegalInstruction();
        if (SehFixtureEvidence.fault_entered != 1 ||
            SehFixtureEvidence.fault_after_instruction != 0 ||
            SehFixtureEvidence.fault_caught != 1 ||
            SehFixtureEvidence.fault_code != (uint32_t)STATUS_ILLEGAL_INSTRUCTION) {
            DbgPrint("[seh-fault-failed] kind=ud2 entered=%u after=%u caught=%u code=0x%08x\n",
                     SehFixtureEvidence.fault_entered,
                     SehFixtureEvidence.fault_after_instruction,
                     SehFixtureEvidence.fault_caught, SehFixtureEvidence.fault_code);
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("[seh-fault-proof] kind=ud2 entered=1 after=0 caught=1 code=0xc000001d\n");
#else
        DbgPrint("[seh-native-proof-complete]\n");
#endif
    }
    return status;
}
