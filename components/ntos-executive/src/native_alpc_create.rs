//! Native ALPC create ingress binding. No port-service effect occurs here.

pub(crate) struct PreparedCreatePort {
    pub(crate) process_id: u64,
    pub(crate) thread_id: u64,
    pub(crate) process_generation: u64,
    pub(crate) captured: nt_alpc_native_capture::CapturedCreatePort,
}

impl crate::ExecNtHandler {
    /// Bind copied arguments to the hosted thread and process incarnation
    /// admitted for this native call. RootDirectory and SecurityDescriptor
    /// policy, token ownership, and Reply retention precede any live submission.
    pub(crate) unsafe fn prepare_native_alpc_create_port(
        &mut self,
        args: [u64; 3],
    ) -> Result<PreparedCreatePort, u32> {
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        let pi = self.pi;
        let badge = self.current_badge;
        if self.hosted_thread_pi_for_badge(badge) != Some(pi) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process_id = self.pm_pid_for_pi(pi).ok_or(STATUS_INVALID_PARAMETER)? as u64;
        let thread_id = self.hosted_thread_tid_for_badge(badge)
            .filter(|tid| *tid != 0 && *tid == self.current_tid)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let process_generation = self.hosted_process_generation(pi)
            .filter(|generation| *generation != 0)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let output_valid = self.probe_user_output(args[0], 8);
        let captured = nt_alpc_native_capture::capture(
            args,
            |address, out| self.xas_read(address, out),
            |_, _| output_valid,
        )?;
        Ok(PreparedCreatePort {
            process_id,
            thread_id,
            process_generation,
            captured,
        })
    }
}
