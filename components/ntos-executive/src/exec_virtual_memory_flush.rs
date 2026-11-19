//! Native flush capture and writeback publication through checked process memory.

use super::virtual_memory_copy::ProcessWriteProbe;
use super::*;
use nt_address_space::native_output::{VmFlushOutput, VmRangeOutput};

/// A captured `NtFlushVirtualMemory` request after process admission.
pub(crate) enum VmFlushRequest {
    /// The range resolved to one data-file view of `target_pi`.
    Planned {
        output: VmFlushOutput,
        target_pi: usize,
        plan: nt_memory_manager::GenericSectionFlushPlan,
    },
    /// Planning failed; the rounded range and IOSB are still published with `status`.
    Refused {
        output: VmFlushOutput,
        base: u64,
        size: u64,
        status: u32,
    },
}

impl ExecNtHandler {
    /// Capture and admit the request exactly as the service does, without any writeback effect.
    /// An `Err` is the service's immediate status.
    pub(crate) unsafe fn capture_vm_flush(&mut self, args: &[u64]) -> Result<VmFlushRequest, u32> {
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
        let output = VmFlushOutput {
            range: VmRangeOutput {
                base_pointer: args.get(1).copied().unwrap_or(0),
                size_pointer: args.get(2).copied().unwrap_or(0),
            },
            iosb: args.get(3).copied().unwrap_or(0),
        };
        let (base, size) = output.capture(&mut ProcessWriteProbe::current(self), USER_ADDRESS_LIMIT)?;
        if base > HIGHEST_USER_ADDRESS || size > HIGHEST_USER_ADDRESS - base {
            return Err(STATUS_INVALID_PARAMETER_2);
        }
        let (target_pid, target_pi) =
            self.resolve_process_for_access(args[0], PROCESS_VM_OPERATION)?;
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            return Err(nt_process::STATUS_PROCESS_IS_TERMINATING);
        }
        let ctx = self
            .loop_ctx
            .and_then(|ctx| ctx.for_process(target_pi))
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok(match (&*ctx.generic_sections).plan_flush(target_pi, base, size) {
            Ok(plan) => VmFlushRequest::Planned { output, target_pi, plan },
            Err(status) => VmFlushRequest::Refused {
                output,
                base: base & !(nt_address_space::PAGE_SIZE - 1),
                size,
                status,
            },
        })
    }

    /// Publish the flushed range and IOSB to the current caller, returning the service status.
    pub(crate) unsafe fn publish_vm_flush(
        &mut self,
        output: VmFlushOutput,
        base: u64,
        size: u64,
        status: u32,
        bytes_written: u64,
    ) -> u32 {
        output.publish(&mut ProcessWriteProbe::current(self), base, size, status, bytes_written)
    }

    pub(super) unsafe fn nt_flush_virtual_memory(&mut self, args: &[u64]) -> u32 {
        let (output, target_pi, plan) = match self.capture_vm_flush(args) {
            Err(status) => return status,
            Ok(VmFlushRequest::Refused { output, base, size, status }) => {
                return self.publish_vm_flush(output, base, size, status, 0);
            }
            Ok(VmFlushRequest::Planned { output, target_pi, plan }) => (output, target_pi, plan),
        };
        let Some(ctx) = self.loop_ctx.and_then(|ctx| ctx.for_process(target_pi)) else {
            return STATUS_INVALID_HANDLE;
        };
        let generic_sections = &mut *ctx.generic_sections;
        // Routed dirty pages are written by retained paging IRPs; the syscall ingress parks this
        // caller on them before dispatch, so the service itself only sees a clean routed range.
        assert!(
            plan.section.backing.kind != nt_memory_manager::GENERIC_SECTION_BACKING_ROUTED
                || generic_sections.prepare_writeback(plan).is_ok_and(|pages| pages.is_empty()),
            "routed flush reached the service without its retained page-write owner"
        );
        let writeback = service_generic_section_writeback_plan(
            generic_sections,
            plan,
            ctx.scratch_base,
            Some(ctx),
        );
        if writeback.bytes_written != 0 {
            self.writable_fs_dirty = true;
        }
        self.publish_vm_flush(output, plan.base, plan.size, writeback.status, writeback.bytes_written)
    }
}
