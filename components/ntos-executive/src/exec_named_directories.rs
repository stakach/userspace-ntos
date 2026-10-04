//! Native named Directory service entrypoints.
use super::*;

impl ExecNtHandler {
    pub(super) unsafe fn nt_named_directory_service(
        &mut self,
        args: &[u64],
        previous_mode: nt_syscall::ProcessorMode,
        create: bool,
    ) -> u32 {
        let out = args[0]; // R10 = *Handle
        let desired_access = nt_ulong_arg(args[1]);
        let oa = args[2]; // R8 = *OBJECT_ATTRIBUTES
        if out == 0 {
            return 0xC000_0005; // STATUS_ACCESS_VIOLATION
        }
        if out & 7 != 0 {
            return 0x8000_0002; // STATUS_DATATYPE_MISALIGNMENT
        }
        if !self.probe_event_output(out, 8) {
            return 0xC000_0005;
        }
        let captured = match self.capture_named_object_attributes(oa) {
            Ok(captured) => captured,
            Err(status) => return status,
        };
        if captured.path().is_none() {
            return 0xC000_0033; // STATUS_OBJECT_NAME_INVALID
        }
        let caller = match self.native_handle_caller(previous_mode) {
            Ok(caller) => caller,
            Err(status) => return status,
        };
        let mut staged = match self.stage_native_directory_object_open(
            &captured,
            caller,
            desired_access,
            create,
        ) {
            Ok(staged) => staged,
            Err(status) => return status,
        };
        if !self.xas_write_u64(out, staged.publication.value()) {
            self.abort_staged_directory_object_open(&mut staged);
            return 0xC000_0005;
        }
        if let Err(status) = staged.publication.publish(&mut self.pm) {
            self.abort_staged_directory_object_open(&mut staged);
            return status;
        }
        self.record_process_handle_insert(
            staged.publication.process_id(),
            staged.cap_before,
        );
        staged.status
    }
}
