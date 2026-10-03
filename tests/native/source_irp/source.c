/* Invoked in an authenticated win32k dispatch activation, not a separate driver host. */
#include "contract.h"

__declspec(dllimport) IRP *__stdcall IoBuildSynchronousFsdRequest(uint32_t, DEVICE_OBJECT *,
    void *, uint32_t, int64_t *, void *, IO_STATUS_BLOCK *);
__declspec(dllimport) IRP *__stdcall IoBuildDeviceIoControlRequest(uint32_t, DEVICE_OBJECT *,
    void *, uint32_t, void *, uint32_t, uint8_t, void *, IO_STATUS_BLOCK *);
__declspec(dllimport) NTSTATUS __stdcall IofCallDriver(DEVICE_OBJECT *, IRP *);

__declspec(dllexport) volatile SOURCE_IRP_EVIDENCE SourceIrpEvidence;

__declspec(dllexport) NTSTATUS __stdcall SourceIrpProbe(DEVICE_OBJECT *device, uint32_t pending)
{
    if (device == NULL || device->StackSize == 0 || pending > 1) return STATUS_INVALID_PARAMETER;
    for (uint32_t operation = 0; operation < 6; operation++) {
        uint8_t input[PROBE_BYTES], output[PROBE_BYTES + 8];
        for (uint32_t i = 0; i < PROBE_BYTES; i++) input[i] = ProbeInput(i);
        for (uint32_t i = 0; i < sizeof(output); i++) output[i] = i < PROBE_BYTES ? ProbeSeed(i) : 0xe7;
        IO_STATUS_BLOCK iosb = { STATUS_UNSUCCESSFUL, 0, 0 };
        uint64_t event[3] = {0};
        KeInitializeEvent(event, 1, 0);
        IRP *irp;
        int64_t offset = pending;
        if (operation < 2) {
            irp = IoBuildSynchronousFsdRequest(operation == 0 ? IRP_MJ_READ : IRP_MJ_WRITE,
                device, operation == 0 ? output : input, PROBE_BYTES, &offset, event, &iosb);
        } else {
            irp = IoBuildDeviceIoControlRequest(PROBE_IOCTL(pending, operation - 2), device,
                input, PROBE_BYTES, output, PROBE_BYTES, 0, event, &iosb);
        }
        SourceIrpEvidence.attempts[pending][operation]++;
        volatile SOURCE_IRP_OBSERVATION *observation =
            &SourceIrpEvidence.observations[pending][operation];
        if (irp == NULL) {
            observation->call = STATUS_INSUFFICIENT_RESOURCES;
            observation->wait = STATUS_UNSUCCESSFUL;
            observation->iosb_status = iosb.Status;
            observation->bytes_valid = 0;
            observation->information = iosb.Information;
            SourceIrpEvidence.failed++;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NTSTATUS call = IofCallDriver(device, irp);
        NTSTATUS wait = STATUS_UNSUCCESSFUL;
        /* The runner bounds boot; this wait must retain stack storage until real completion. */
        if (call == STATUS_SUCCESS || call == STATUS_PENDING)
            wait = KeWaitForSingleObject(event, 0, 0, 0, NULL);
        int valid = call == (pending ? STATUS_PENDING : STATUS_SUCCESS) &&
                    wait == STATUS_SUCCESS && iosb.Status == STATUS_SUCCESS &&
                    iosb.Information == PROBE_BYTES;
        if (operation == 1) valid &= ProbeMatches(input, ProbeInput);
        else valid &= ProbeMatches(output, operation == 3 ? ProbeSeed : ProbeOutput);
        for (uint32_t i = PROBE_BYTES; i < sizeof(output); i++) valid &= output[i] == 0xe7;
        observation->call = call;
        observation->wait = wait;
        observation->iosb_status = iosb.Status;
        observation->bytes_valid = (uint32_t)valid;
        observation->information = iosb.Information;
        DbgPrint("[source-irp-proof] mode=%u op=%u call=0x%08x wait=0x%08x iosb=0x%08x info=%u bytes=%u\n",
            pending, operation, (uint32_t)call, (uint32_t)wait, (uint32_t)iosb.Status,
            (uint32_t)iosb.Information, (uint32_t)valid);
        if (!valid) {
            SourceIrpEvidence.failed++;
            return STATUS_UNSUCCESSFUL;
        }
        SourceIrpEvidence.completed[pending][operation]++;
    }
    DbgPrint("[source-irp-proof-complete] mode=%u operations=6\n", pending);
    return STATUS_SUCCESS;
}
