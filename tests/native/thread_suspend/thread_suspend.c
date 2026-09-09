/* Native-subsystem acceptance fixture. No CRT or private executive protocol. */
#include <stddef.h>
#include <stdint.h>

typedef int32_t NTSTATUS;
typedef void *HANDLE;
typedef uint8_t BOOLEAN;
typedef uint32_t ULONG;
typedef int64_t LARGE_INTEGER;
typedef struct {
    uint16_t Length;
    uint16_t MaximumLength;
    uint16_t *Buffer;
} UNICODE_STRING;
typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef NTSTATUS (*THREAD_START)(void *);

_Static_assert(sizeof(void *) == 8, "AMD64 only");
_Static_assert(sizeof(UNICODE_STRING) == 16, "NT string ABI");
_Static_assert(offsetof(UNICODE_STRING, Buffer) == 8, "NT string pointer ABI");
_Static_assert(sizeof(CLIENT_ID) == 16, "NT client ID ABI");

#define IMPORT __declspec(dllimport)
IMPORT NTSTATUS RtlCreateUserThread(HANDLE, void *, BOOLEAN, ULONG, size_t,
                                   size_t, THREAD_START, void *, HANDLE *, CLIENT_ID *);
IMPORT NTSTATUS NtCreateEvent(HANDLE *, ULONG, void *, ULONG, BOOLEAN);
IMPORT NTSTATUS NtSuspendThread(HANDLE, ULONG *);
IMPORT NTSTATUS NtResumeThread(HANDLE, ULONG *);
IMPORT NTSTATUS NtWaitForSingleObject(HANDLE, BOOLEAN, LARGE_INTEGER *);
IMPORT NTSTATUS NtSignalAndWaitForSingleObject(HANDLE, HANDLE, BOOLEAN, LARGE_INTEGER *);
IMPORT NTSTATUS NtSetEvent(HANDLE, int32_t *);
IMPORT NTSTATUS NtDelayExecution(BOOLEAN, LARGE_INTEGER *);
IMPORT NTSTATUS NtClose(HANDLE);
IMPORT NTSTATUS NtDisplayString(UNICODE_STRING *);
IMPORT NTSTATUS NtTerminateThread(HANDLE, NTSTATUS);
IMPORT NTSTATUS NtTerminateProcess(HANDLE, NTSTATUS);

#define CURRENT_PROCESS ((HANDLE)(intptr_t)-1)
#define CURRENT_THREAD ((HANDLE)(intptr_t)-2)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_TIMEOUT ((NTSTATUS)0x102)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001u)
#define UNWRITTEN 0xdeadbeefu
#define EVENT_ALL_ACCESS 0x001f0003u
#define SYNCHRONIZATION_EVENT 1u
#define WAIT_10_SECONDS (-100000000ll)

typedef struct {
    HANDLE ready;
    HANDLE target;
    HANDLE done;
    HANDLE thread;
    ULONG entered;
    ULONG returned;
    volatile ULONG previous;
    NTSTATUS status;
} PROBE;

static PROBE probe;

static void report(const char *text, uint32_t value)
{
    static const char digits[] = "0123456789abcdef";
    uint16_t buffer[192];
    size_t n = 0;
    while (*text && n < 170) {
        buffer[n++] = (uint8_t)*text++;
    }
    buffer[n++] = ' ';
    buffer[n++] = '0';
    buffer[n++] = 'x';
    for (int i = 7; i >= 0; --i) {
        buffer[n++] = (uint16_t)digits[(value >> (i * 4)) & 15u];
    }
    buffer[n++] = '\r';
    buffer[n++] = '\n';
    UNICODE_STRING string = {(uint16_t)(n * 2), (uint16_t)(n * 2), buffer};
    (void)NtDisplayString(&string);
}

__attribute__((noreturn)) static void fail(const char *phase, NTSTATUS actual)
{
    report("[thread-suspend] FAIL", (uint32_t)STATUS_UNSUCCESSFUL);
    report(phase, (uint32_t)actual);
    (void)NtTerminateProcess(CURRENT_PROCESS, STATUS_UNSUCCESSFUL);
    __builtin_trap();
}

static void expect(const char *phase, NTSTATUS actual, NTSTATUS expected)
{
    if (actual != expected) {
        fail(phase, actual);
    }
}

static void count(const char *phase, ULONG actual, ULONG expected)
{
    if (actual != expected) {
        fail(phase, (NTSTATUS)actual);
    }
}

static ULONG load(ULONG *value)
{
    return __atomic_load_n(value, __ATOMIC_SEQ_CST);
}

static void create_event(HANDLE *event)
{
    expect("NtCreateEvent", NtCreateEvent(event, EVENT_ALL_ACCESS, 0,
           SYNCHRONIZATION_EVENT, 0), STATUS_SUCCESS);
}

static void wait_done(HANDLE object, const char *phase)
{
    LARGE_INTEGER timeout = WAIT_10_SECONDS;
    expect(phase, NtWaitForSingleObject(object, 0, &timeout), STATUS_SUCCESS);
}

static void delay(void)
{
    LARGE_INTEGER interval = -10000; /* One millisecond, bounded by caller. */
    expect("NtDelayExecution", NtDelayExecution(0, &interval), STATUS_SUCCESS);
}

static void suspend_expect(ULONG expected)
{
    ULONG previous = UNWRITTEN;
    expect("NtSuspendThread", NtSuspendThread(probe.thread, &previous), STATUS_SUCCESS);
    count("suspend previous count", previous, expected);
}

static void resume_expect(ULONG expected)
{
    ULONG previous = UNWRITTEN;
    expect("NtResumeThread", NtResumeThread(probe.thread, &previous), STATUS_SUCCESS);
    count("resume previous count", previous, expected);
}

static void still_held(void)
{
    for (unsigned i = 0; i < 25; ++i) {
        delay();
        count("returned before final resume", load(&probe.returned), 0);
    }
    LARGE_INTEGER zero = 0;
    expect("done signaled while held", NtWaitForSingleObject(probe.done, 0, &zero),
           STATUS_TIMEOUT);
}

__attribute__((noreturn)) static void worker_done(NTSTATUS status)
{
    probe.status = status;
    __atomic_fetch_add(&probe.returned, 1, __ATOMIC_SEQ_CST);
    expect("worker NtSetEvent", NtSetEvent(probe.done, 0), STATUS_SUCCESS);
    (void)NtTerminateThread(CURRENT_THREAD, STATUS_SUCCESS);
    fail("NtTerminateThread returned", STATUS_UNSUCCESSFUL);
}

static NTSTATUS self_worker(void *parameter)
{
    (void)parameter;
    __atomic_fetch_add(&probe.entered, 1, __ATOMIC_SEQ_CST);
    NTSTATUS status = NtSuspendThread(CURRENT_THREAD, (ULONG *)&probe.previous);
    worker_done(status);
}

static NTSTATUS wait_worker(void *parameter)
{
    (void)parameter;
    __atomic_fetch_add(&probe.entered, 1, __ATOMIC_SEQ_CST);
    LARGE_INTEGER timeout = WAIT_10_SECONDS;
    NTSTATUS status = NtSignalAndWaitForSingleObject(probe.ready, probe.target, 0, &timeout);
    worker_done(status);
}

static void start(THREAD_START worker)
{
    CLIENT_ID client;
    probe.entered = 0;
    probe.returned = 0;
    probe.previous = UNWRITTEN;
    probe.status = STATUS_UNSUCCESSFUL;
    create_event(&probe.done);
    expect("RtlCreateUserThread", RtlCreateUserThread(CURRENT_PROCESS, 0, 1, 0,
           0, 0, worker, 0, &probe.thread, &client), STATUS_SUCCESS);
    count("CREATE_SUSPENDED entered", load(&probe.entered), 0);
    count("CREATE_SUSPENDED returned", load(&probe.returned), 0);
    resume_expect(1);
}

static void join(void)
{
    wait_done(probe.done, "worker done timeout");
    wait_done(probe.thread, "worker termination timeout");
    count("worker entered exactly once", load(&probe.entered), 1);
    count("worker returned exactly once", load(&probe.returned), 1);
    expect("original native call status", probe.status, STATUS_SUCCESS);
    expect("close thread", NtClose(probe.thread), STATUS_SUCCESS);
    expect("close done", NtClose(probe.done), STATUS_SUCCESS);
}

static void test_self_suspend(void)
{
    start(self_worker);
    /* The real adapter publishes PreviousSuspendCount only after the hold ACK. */
    unsigned attempts;
    for (attempts = 0; attempts < 10000 && probe.previous == UNWRITTEN; ++attempts) {
        delay();
    }
    if (probe.previous == UNWRITTEN) {
        fail("self-suspend admission timeout", STATUS_TIMEOUT);
    }
    count("self-suspend previous count", probe.previous, 0);
    suspend_expect(1);
    resume_expect(2);
    still_held();
    resume_expect(1);
    join();
    count("self-suspend output retained", probe.previous, 0);
    report("[thread-suspend] PASS self original Reply, nested counts, one return", 1);
}

static void test_object_wait(BOOLEAN complete_while_held)
{
    create_event(&probe.ready);
    create_event(&probe.target);
    start(wait_worker);
    wait_done(probe.ready, "atomic signal-and-wait handshake timeout");
    resume_expect(0);
    still_held();
    suspend_expect(0);
    if (complete_while_held) {
        suspend_expect(1);
    } else {
        resume_expect(1);
        still_held();
    }
    int32_t previous = -1;
    expect("signal held waiter", NtSetEvent(probe.target, &previous), STATUS_SUCCESS);
    count("target was nonsignaled", (ULONG)previous, 0);
    /* The original waiter must consume the auto-reset signal, held or released. */
    LARGE_INTEGER zero = 0;
    expect("held wait did not consume signal", NtWaitForSingleObject(probe.target, 0, &zero),
           STATUS_TIMEOUT);
    if (complete_while_held) {
        resume_expect(2);
        still_held();
        resume_expect(1);
    }
    join();
    expect("close ready", NtClose(probe.ready), STATUS_SUCCESS);
    expect("close target", NtClose(probe.target), STATUS_SUCCESS);
    report(complete_while_held
           ? "[thread-suspend] PASS object completed while held, one return"
           : "[thread-suspend] PASS final resume preserved pending object wait", 1);
}

__attribute__((noreturn)) void NtProcessStartup(void *peb)
{
    (void)peb;
    report("[thread-suspend] BEGIN genuine native acceptance", 1);
    test_self_suspend();
    test_object_wait(1);
    test_object_wait(0);
    report("[thread-suspend] PASS all native acceptance cases", 3);
    (void)NtTerminateProcess(CURRENT_PROCESS, STATUS_SUCCESS);
    __builtin_trap();
}
