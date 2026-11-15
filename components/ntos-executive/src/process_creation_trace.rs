//! The process-creation failure trace: one line for each distinct native service that fails (or
//! is not served at all) while a process is being created. The selection and the bound live in
//! `nt_syscall_abi::process_creation_trace`; this is where the executive reports a finished
//! service to it and prints the line.

use crate::*;

impl ExecNtHandler {
    /// Report a finished native service. `args` are its arguments as issued.
    pub(crate) fn trace_process_creation_failure(
        &mut self,
        ssn: u64,
        status: u64,
        pi: usize,
        tid: u64,
        args: &[u64],
    ) {
        let Ok(ssn) = u32::try_from(ssn) else {
            return;
        };
        let Some(service) =
            self.process_creation_failures.observe(ssn, status as u32, pi as u32, args)
        else {
            return;
        };
        print_str(b"[process-create-failed] service=");
        print_str(service.as_bytes());
        print_str(b" status=0x");
        print_hex(status as u32);
        print_str(b" pi=");
        print_u64(pi as u64);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b"\n");
    }
}
