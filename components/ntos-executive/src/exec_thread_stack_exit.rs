//! NT5's explicit user-stack release request is separate from thread transport retirement.

use super::*;
use nt_user_host::thread_stack_release::{ThreadStackExitKind, ThreadStackReleaseRequest};

impl ExecNtHandler {
    /// Called after successful suspension, while the registered runtime and its TEB still exist.
    /// Failed constructors use their own retirement actor and never enter this policy path.
    pub(crate) unsafe fn capture_hosted_thread_stack_release(
        &mut self,
        tid: u64,
        tcb: u64,
    ) -> Result<Option<ThreadStackReleaseRequest>, u32> {
        let runtime = self
            .thread_runtime
            .executable_by_tid(tid)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if runtime.tcb != tcb || self.capture_process_identity(runtime.pi) != Some(runtime.process)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let thread_id = u32::try_from(tid).map_err(|_| STATUS_INVALID_HANDLE)?;
        let thread = self
            .pm
            .thread_lifetime(thread_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if thread.process_id() != runtime.process.pid {
            return Err(STATUS_INVALID_HANDLE);
        }
        let teb = self.pm.thread_teb(thread_id).filter(|teb| *teb != 0);
        match ThreadStackReleaseRequest::capture(
            runtime.process,
            thread,
            teb,
            ThreadStackExitKind::RegisteredThread,
            |address, output| self.process_memory_read_status(runtime.pi, address, output),
        ) {
            Ok(request) => Ok(request),
            Err(status) => {
                // PspExitThread catches TEB-access exceptions and still deletes the TEB. Without
                // a captured request the VAD stays process-owned; never substitute recorded bounds.
                self.trace_thread_stack_release_failure(runtime, status, b"capture");
                Ok(None)
            }
        }
    }

    pub(crate) unsafe fn release_requested_thread_user_stack(
        &mut self,
        runtime: HostedThreadRuntime,
        request: ThreadStackReleaseRequest,
    ) -> Result<(), u32> {
        let tid = u32::try_from(runtime.tid).map_err(|_| STATUS_INVALID_HANDLE)?;
        let thread = self.pm.thread_lifetime(tid).ok_or(STATUS_INVALID_HANDLE)?;
        let teb = self.pm.thread_teb(tid).ok_or(STATUS_INVALID_HANDLE)?;
        if self.capture_process_identity(runtime.pi) != Some(runtime.process)
            || !request.matches(runtime.process, thread, teb)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let vm_map = process_vm_region_map_mut(runtime.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let before = &mut *core::ptr::addr_of_mut!(VM_MAP_BEFORE);
        let after = &mut *core::ptr::addr_of_mut!(VM_MAP_AFTER);
        *before = *vm_map;
        *after = *before;
        let plan = after.free(
            request.deallocation_stack(),
            0,
            nt_address_space::MEM_RELEASE,
        )?;
        let (ownership_base, ownership_size) = plan
            .ownership_range(before)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        hosted_thread_memory_retirement_access(runtime.pi as u64, ownership_base, ownership_size)?;
        let released_commit = before
            .private_committed_bytes()
            .checked_sub(after.private_committed_bytes())
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let _ = vm_page_lock_retire_range(runtime.pi as u64, plan.base, plan.size);
        let end = plan
            .base
            .checked_add(plan.size)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let mut page = plan.base;
        while page < end {
            // A reserved page may still have a retained transition or failed backing operation.
            if !vm_unmap_private_page(runtime.pi, page) {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            page += nt_address_space::PAGE_SIZE;
        }
        self.release_process_commit(runtime.process.pid, released_commit);
        *vm_map = *after;
        USER_STACK_VAD_RELEASES.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub(crate) unsafe fn trace_thread_stack_release_failure(
        &self,
        runtime: HostedThreadRuntime,
        status: u32,
        operation: &[u8],
    ) {
        if USER_STACK_VAD_RELEASE_FAILS.fetch_add(1, Ordering::Relaxed) < 8 {
            print_str(b"[thread-term] user-stack ");
            print_str(operation);
            print_str(b" failed pi=");
            print_u64(runtime.pi as u64);
            print_str(b" tid=");
            print_u64(runtime.tid);
            print_str(b" status=0x");
            print_hex(status);
            print_str(b"\n");
        }
    }
}
