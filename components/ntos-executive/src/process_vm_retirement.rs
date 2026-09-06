//! Final process VM cleanup. The generation-exact Ps deletion candidate owns every retry.
use super::*;
use nt_memory_manager::process_retirement::{
    retire_process_vm, ProcessVmRetirement, ProcessVmRetirementIo,
};

pub(crate) unsafe fn reclaim_final_process_vm(
    candidate: nt_user_host::ProcessDeletionCandidate,
    handler: &mut ExecNtHandler,
) -> ProcessVmRetirement {
    retire_process_vm(&mut FinalProcessVm { candidate, handler })
}

struct FinalProcessVm<'a> {
    candidate: nt_user_host::ProcessDeletionCandidate,
    handler: &'a mut ExecNtHandler,
}

impl ProcessVmRetirementIo for FinalProcessVm<'_> {
    fn is_quiescent(&self) -> bool {
        let candidate = self.candidate;
        let pi = candidate.pi;
        let handler = &self.handler;
        if pi >= MAX_PI
            || candidate.phase != nt_user_host::ProcessDeletionPhase::ReclaimingVm
            || handler.process_deletion_candidates.get(pi) != Some(candidate)
            || !handler
                .process_mechanisms
                .get(pi)
                .is_some_and(|owner| candidate.matches_mechanism(owner))
            || handler.loop_ctx.is_none()
            || handler.thread_runtime.has_process(pi)
            || !handler
                .pm
                .process_object_delete_blockers(candidate.pid)
                .is_some_and(nt_process::ProcessObjectDeleteBlockers::delete_ready)
            || handler.pm.process_win32(candidate.pid).is_some()
            || handler.pm.process(candidate.pid).is_none_or(|process| {
                process
                    .threads
                    .iter()
                    .any(|tid| handler.pm.thread_win32(*tid).is_some())
            })
        {
            return false;
        }
        let root = handler.process_vspaces.get(pi).copied();
        let owner_matches = match handler.process_vspace_caps.get(pi) {
            Some(Some(owner)) => {
                owner.generation == candidate.generation
                    && owner.pml4 != 0
                    && root == Some(owner.pml4)
            }
            Some(None) => root == Some(0),
            None => false,
        };
        owner_matches
            && unsafe {
                !win32k_glue::client_has_active_callback_frames(pi as u32)
                    && !service_sec_image::client_has_vm_continuations(pi as u32)
            }
    }

    fn retire_leaves(&mut self) -> bool {
        unsafe {
            let pi = self.candidate.pi;
            let ctx = self
                .handler
                .loop_ctx
                .expect("quiescence requires the VM owner context");
            self.handler
                .secured_virtual_memory
                .retire_owner(u64::from(self.candidate.pid));
            let _ = vm_page_lock_retire_owner(pi as u64);
            revoke_process_teb_tail_alias(pi);
            // These aliases can reference any client backing, including private COW frames.
            if win32k_glue::detach_attached_client_process(pi as u64).is_err() {
                return false;
            }
            let sections = &mut *ctx.generic_sections;
            while let Some(view) = sections.first_view_for_process(pi) {
                let writeback = service_sec_image::service_generic_section_writeback_view(
                    sections,
                    view,
                    ctx.scratch_base,
                    Some(ctx),
                );
                if writeback.bytes_written != 0 {
                    self.handler.writable_fs_dirty = true;
                }
                if writeback.status != 0 {
                    print_str(b"[process-vm-reclaim] mapped-section writeback failed pi=");
                    print_u64(pi as u64);
                    print_str(b" status=0x");
                    print_hex(writeback.status);
                    print_str(b"\n");
                    return false;
                }
                if service_sec_image::service_unmap_section_view_mappings(view).is_err() {
                    return false;
                }
                sections
                    .unmap_view(pi, view.base)
                    .expect("checked mapping teardown retains its exact section view");
            }
            let (_, failures) = shared_image_mapping_unmap_process(pi as u64);
            if failures != 0 || !shared_image_mapping_process_is_empty(pi) {
                return false;
            }
            if !win32k_glue::release_win32k_client_cap_bank(pi)
                || !win32k_glue::win32k_client_cap_bank_is_empty(pi)
            {
                return false;
            }
            let _ = csrss_frame_drop_process_all(pi as u64);
            if !client_frame_registry_process_is_empty(pi as u64) {
                return false;
            }
            let (_, failures) = client_copyin_frame_drop_process(pi as u64);
            if failures != 0 || !client_copyin_frame_process_is_empty(pi as u64) {
                return false;
            }
            if !kuser_page_alias_release(pi) || kuser_page_alias_get(pi) != 0 {
                return false;
            }
            if let Some(owner) = self.handler.process_vspace_caps[pi].as_mut() {
                if !release_sec_image_vspace_leaves(owner) {
                    return false;
                }
            }
            // Metadata commit returns transition frames to this free list after every alias and
            // root is gone. Reserve now, while failure can still retain the complete VM owner.
            let Ok(transitions) =
                (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).retirement_frame_count(pi as u64)
            else {
                return false;
            };
            (&mut *core::ptr::addr_of_mut!(VM_FREE_FRAMES)).reserve(transitions)
        }
    }

    fn retire_page_tables(&mut self) -> bool {
        unsafe {
            let pi = self.candidate.pi;
            let ctx = self
                .handler
                .loop_ctx
                .expect("retirement retains the VM owner context");
            let paging = &mut *ctx.dll_arena_paging;
            let pd = paging.pd_cap(pi);
            if pd != 0 {
                if cnode_delete_recycle_r(pd) != 0 {
                    return false;
                }
                assert!(paging.clear_process_exact(pi, pd));
            }
            let (_, failures) = process_user_page_tables_release(pi, self.handler);
            failures == 0
                && (&*core::ptr::addr_of!(PROCESS_USER_PAGE_TABLES))
                    .first_for_process(pi as u64)
                    .is_none()
        }
    }

    fn retire_vspace(&mut self) -> bool {
        let pi = self.candidate.pi;
        // A process can exit before publishing a VSpace. Empty physical ownership still needs
        // logical retirement; never skip that work just because the published root is zero.
        if self.handler.process_vspace_caps[pi].is_none() {
            return self.handler.process_vspaces[pi] == 0;
        }
        unsafe { self.handler.release_hosted_process_vspace_caps(pi) }
    }

    fn commit_metadata(&mut self) {
        unsafe {
            let pi = self.candidate.pi;
            let mut ctx = self
                .handler
                .loop_ctx
                .expect("retirement retains the VM owner context");
            (&mut *ctx.reg).clear_mapped_for_pi(pi);
            process_committed_mapping_reset(pi);
            process_vm_region_map_reset(pi);
            if ctx.live_paging.is_some_and(|live| live.pi == pi) {
                ctx.live_paging = None;
            }
            if ctx.owner_pi == pi {
                ctx.pml4 = 0;
                ctx.filled_pages = &mut (&mut *ctx.pfilled)[pi];
                ctx.faults = &mut (&mut *ctx.procs)[pi].faults;
            }
            (&mut *ctx.procs)[pi] = ProcExec::empty();
            self.handler.loop_ctx = Some(ctx);
        }
    }
}
