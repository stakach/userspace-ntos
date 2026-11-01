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
        if self.pending_native_directory_open_transfer.is_some() {
            return nt_status::NtStatus::DEVICE_BUSY.raw() as u32;
        }
        let mut reference = match self.pm.reference_native_syscall_requestor(caller) {
            Ok(reference) => reference,
            Err(status) => return status,
        };
        let reserved = match self.reserve_native_directory_object_open(
            &captured,
            caller,
            desired_access,
            create,
        ) {
            Ok(reserved) => reserved,
            Err(status) => {
                if self.pi == 0 {
                    print_str(b"[native-directory-denied] stage=security path=");
                    print_str(captured.path().unwrap_or(b""));
                    print_str(b" access=0x"); print_hex(desired_access);
                    print_str(b" create="); print_u64(u64::from(create));
                    print_str(b" status=0x"); print_hex(status);
                    print_str(b"\n");
                }
                reference.release(&mut self.pm)
                    .expect("unsubmitted directory requestor reference");
                return status;
            }
        };
        self.pending_native_directory_open_transfer = Some(
            crate::native_directory_open_work::PendingNativeDirectoryOpen::new(
                reserved, reference, caller, self.pi, self.current_tid,
                self.current_badge, out,
            ),
        );
        STATUS_PENDING
    }
}
