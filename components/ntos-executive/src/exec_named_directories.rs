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
        if let Err(status) = self.probe_copy_output(self.pi, out, 8) {
            return status;
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
        if let Err(status) = staged.publication.publish(&mut self.pm) {
            self.abort_staged_directory_object_open(&mut staged);
            return status;
        }
        self.record_process_handle_insert(staged.publication.process_id(), staged.cap_before);
        self.release_directory_object_security(&mut staged.security);
        if let Err(failure) = self.process_memory_write_checked(
            self.pi,
            out,
            &staged.publication.value().to_le_bytes(),
        ) {
            return failure.status();
        }
        staged.status
    }
}
