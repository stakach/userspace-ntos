//! Native flush capture and writeback publication through checked process memory.

use super::virtual_memory_copy::ProcessWriteProbe;
use super::*;
use nt_address_space::native_output::{VmFlushOutput, VmRangeOutput};

impl ExecNtHandler {
    pub(super) unsafe fn nt_flush_virtual_memory(&mut self, args: &[u64]) -> u32 {
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
        let output = VmFlushOutput {
            range: VmRangeOutput {
                base_pointer: args.get(1).copied().unwrap_or(0),
                size_pointer: args.get(2).copied().unwrap_or(0),
            },
            iosb: args.get(3).copied().unwrap_or(0),
        };
        let (base, size) =
            match output.capture(&mut ProcessWriteProbe::current(self), USER_ADDRESS_LIMIT) {
                Ok(range) => range,
                Err(status) => return status,
            };
        if base > HIGHEST_USER_ADDRESS || size > HIGHEST_USER_ADDRESS - base {
            return STATUS_INVALID_PARAMETER_2;
        }
        let (target_pid, target_pi) =
            match self.resolve_process_for_access(args[0], PROCESS_VM_OPERATION) {
                Ok(target) => target,
                Err(status) => return status,
            };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            return nt_process::STATUS_PROCESS_IS_TERMINATING;
        }
        let Some(ctx) = self.loop_ctx.and_then(|ctx| ctx.for_process(target_pi)) else {
            return STATUS_INVALID_HANDLE;
        };
        let generic_sections = &mut *ctx.generic_sections;
        let plan = match generic_sections.plan_flush(target_pi, base, size) {
            Ok(plan) => plan,
            Err(status) => {
                return output.publish(
                    &mut ProcessWriteProbe::current(self),
                    base & !(nt_address_space::PAGE_SIZE - 1),
                    size,
                    status,
                    0,
                );
            }
        };
        let writeback = service_generic_section_writeback_plan(
            generic_sections,
            plan,
            ctx.scratch_base,
            Some(ctx),
        );
        if writeback.bytes_written != 0 {
            self.writable_fs_dirty = true;
        }
        output.publish(
            &mut ProcessWriteProbe::current(self),
            plan.base,
            plan.size,
            writeback.status,
            writeback.bytes_written,
        )
    }
}
