//! `NtPowerInformation`: probe the caller's buffers and copy out one Power Manager record.

use super::*;

impl ExecNtHandler {
    /// `NtPowerInformation(Level, InputBuffer, InputLength, OutputBuffer, OutputLength)`. Both
    /// buffers are probed before the level is examined (ReactOS `ntoskrnl/po/power.c`); level
    /// admission and the records live in `nt-power-manager`.
    pub(super) unsafe fn nt_power_information(&mut self, args: &[u64]) -> u32 {
        let level = nt_ulong_arg(args[0]);
        let input = args[1];
        let input_length = nt_ulong_arg(args[2]) as usize;
        let output = args[3];
        let output_length = nt_ulong_arg(args[4]) as usize;
        if input_length != 0 && !self.probe_user_input(input, input_length) {
            return STATUS_ACCESS_VIOLATION;
        }
        if output_length != 0 {
            if output & 3 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            if !self.probe_user_output(output, output_length) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        let query = match nt_power_manager::information::plan_power_information(
            level, input != 0, output_length,
        ) {
            Ok(query) => query,
            Err(status) => return status,
        };
        let mut record = [0u8; nt_power_manager::information::SYSTEM_POWER_CAPABILITIES_SIZE];
        let Some(length) = crate::power_manager::power_information(query, &mut record) else {
            return nt_power_manager::information::STATUS_NOT_IMPLEMENTED;
        };
        if self.xas_try_write_buf(output, &record[..length]) {
            0
        } else {
            STATUS_ACCESS_VIOLATION
        }
    }
}
