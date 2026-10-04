//! Canonical SEC_IMAGE views, independent of loader filenames and legacy DLL handles.

use super::*;
use crate::native_image_sections::NativeImageSectionId;
use nt_memory_manager::image_section::{ImageMappedViewPhase, ImageViewRef};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeImageViewDescriptor {
    pub(crate) view: ImageViewRef,
    pub(crate) process: nt_memory_manager::ProcessIdentity,
    pub(crate) pi: usize,
    pub(crate) pml4: u64,
    pub(crate) scratch_base: u64,
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) section_offset: u64,
}

pub(crate) struct NativeImageViewOwner {
    descriptor: NativeImageViewDescriptor,
}

impl ExecNtHandler {
    fn native_image_view_is_current(&self, descriptor: NativeImageViewDescriptor) -> bool {
        self.capture_process_identity(descriptor.pi) == Some(descriptor.process)
            && self.loop_ctx.and_then(|ctx| unsafe { ctx.for_process(descriptor.pi) })
                .is_some_and(|ctx| unsafe {
                    (&*ctx.procs).get(descriptor.pi).is_some_and(|target|
                        target.pml4 == descriptor.pml4 && target.scratch_base == descriptor.scratch_base)
                })
    }

    pub(crate) fn native_image_view_for_page(
        &self, pi: usize, page: u64,
    ) -> Result<Option<NativeImageViewDescriptor>, u32> {
        let Some(row) = self.native_image_views.iter().find(|row| {
            let view = row.descriptor;
            view.pi == pi && page >= view.base && page - view.base < view.size
        }) else { return Ok(None); };
        let descriptor = row.descriptor;
        let mapping = self.image_sections.mapped_view(descriptor.view)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        if !self.native_image_view_is_current(descriptor)
            || mapping.process != descriptor.process || mapping.base != descriptor.base
            || mapping.size != descriptor.size || mapping.phase != ImageMappedViewPhase::Mapped
        {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        Ok(Some(descriptor))
    }

    pub(crate) unsafe fn service_native_image_page_residency(
        &mut self, pi: usize, page: u64, access: nt_address_space::FaultAccess,
        fault_observed: bool,
    ) -> Result<Option<()>, u32> {
        let Some(view) = self.native_image_view_for_page(pi, page)? else { return Ok(None); };
        crate::native_image_residency::service_native_image_page_residency(
            self, view, page, access, fault_observed,
        )?;
        Ok(Some(()))
    }

    pub(super) unsafe fn map_native_image_section_view(
        &mut self, args: &[u64], previous_mode: nt_syscall::ProcessorMode,
    ) -> Result<Option<u32>, u32> {
        let caller = self.native_handle_caller(previous_mode)?;
        let handle = match self.pm.lookup_native_section_handle(caller, args[0]) {
            Ok(handle) => handle,
            Err(nt_process::STATUS_INVALID_HANDLE) => return Ok(None),
            Err(status) => return Err(status),
        };
        let Some(id) = NativeImageSectionId::from_section_id(handle.section()) else { return Ok(None); };
        let requested_protection = nt_ulong_arg(args[9]);
        let required = nt_memory_manager::section_view_access::required_section_map_access(requested_protection)?;
        if caller.mode() == nt_types::AccessMode::UserMode && handle.granted_access() & required != required {
            return Err(nt_process::STATUS_ACCESS_DENIED);
        }
        if !matches!(args[7], 1 | 2) || nt_ulong_arg(args[8]) & !nt_address_space::MEM_TOP_DOWN != 0 {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        let (pid, pi) = self.resolve_process_for_access(args[1], 0x0008)?;
        let process = self.capture_process_identity(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        if self.pm.process(pid).is_none_or(|process| matches!(process.state,
            nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated))
        { return Err(nt_process::STATUS_PROCESS_IS_TERMINATING); }
        let ctx = self.loop_ctx.and_then(|ctx| ctx.for_process(pi)).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let target = (&*ctx.procs).get(pi).copied().filter(|target| target.pml4 != 0 && target.scratch_base != 0)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        // Capture pointers through the syscall caller, not the target process's VSpace.
        self.probe_copy_output(self.pi, args[2], 8)?;
        self.probe_copy_output(self.pi, args[6], 8)?;
        let mut bytes = [0; 8];
        self.process_memory_read_status(self.pi, args[2], &mut bytes)?;
        let base = u64::from_le_bytes(bytes);
        self.process_memory_read_status(self.pi, args[6], &mut bytes)?;
        let requested_size = u64::from_le_bytes(bytes);
        let offset = if args[5] != 0 {
            self.probe_copy_output(self.pi, args[5], 8)?;
            self.process_memory_read_status(self.pi, args[5], &mut bytes)?;
            u64::from_le_bytes(bytes)
        } else { 0 };
        if offset & 0xffff != 0 { return Err(0xc000_0220); } // STATUS_MAPPED_ALIGNMENT
        let source = self.image_sections.source(id).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        if !source.has_readable_image() { return Err(STATUS_NOT_SUPPORTED); }
        let pe = &source.layout;
        let remaining = u64::from(pe.size_of_image()).checked_sub(offset)
            .filter(|size| *size != 0).ok_or(0xc000_001f_u32)?;
        let size = if requested_size == 0 { remaining } else { requested_size };
        if size > remaining { return Err(0xc000_001f); }
        let size = size.checked_add(0xfff).map(|size| size & !0xfff).ok_or(0xc000_001f_u32)?;
        let preferred = pe.headers().image_base.checked_add(offset).ok_or(0xc000_007b_u32)?;
        let mut placement_request = nt_address_space::image_view_placement::ImageViewPlacementRequest {
            preferred_base: preferred, requested_base: (base != 0).then_some(base),
            alternate_base: None, image_size: size,
            highest_admitted_address: USER_ADDRESS_LIMIT - 1, zero_bits: args[3],
        };
        if base != 0 {
            // Explicit ZeroBits/range rejection precedes even the serialized VAD conflict query.
            nt_address_space::image_view_placement::plan_image_view_placement(
                placement_request, |_, _| true,
            )?;
        }
        let before = &mut *core::ptr::addr_of_mut!(VM_MAP_BEFORE);
        let after = &mut *core::ptr::addr_of_mut!(VM_MAP_AFTER);
        *before = *process_vm_region_map(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let allocation_type = nt_address_space::MEM_RESERVE | nt_address_space::MEM_COMMIT
            | (nt_ulong_arg(args[8]) & nt_address_space::MEM_TOP_DOWN);
        let candidate = if base != 0 { base } else { preferred };
        let allocation = match allocate_vad_avoiding_fixed_authorities(
            before, after, VmVadKind::Mapped, pi, Some(candidate), size,
            allocation_type, nt_address_space::PAGE_READONLY, USER_ADDRESS_LIMIT,
        ) {
            Ok(plan) => plan,
            Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES) if base == 0 =>
                allocate_vad_avoiding_fixed_authorities(before, after, VmVadKind::Mapped, pi,
                    None, size, allocation_type, nt_address_space::PAGE_READONLY, USER_ADDRESS_LIMIT)?,
            Err(status) => return Err(status),
        };
        placement_request.alternate_base = Some(allocation.base);
        let placement = nt_address_space::image_view_placement::plan_image_view_placement(
            placement_request, |candidate, extent| candidate == allocation.base && extent == allocation.size,
        )?;
        let committed = &mut *core::ptr::addr_of_mut!(COMMITTED_MAP_AFTER);
        *committed = *process_committed_mapping_table(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let mut charge_bytes = 0u64;
        let mut run = None::<nt_address_space::VmCommittedRange>;
        for relative in (0..placement.size).step_by(0x1000) {
            let rva = u32::try_from(offset + relative).map_err(|_| 0xc000_007b_u32)?;
            pe.image_page_fill_plan(rva, source.backing.file_extent).map_err(|_| 0xc000_007b_u32)?;
            let protection = img_spawn::image_protection_to_nt(pe.image_protection_at(rva));
            if matches!(protection, nt_address_space::PAGE_WRITECOPY | nt_address_space::PAGE_EXECUTE_WRITECOPY) {
                charge_bytes = charge_bytes.checked_add(0x1000).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            }
            if run.is_some_and(|run| run.protect != protection) {
                if let Some(previous) = run.take() { committed.register(previous)?; }
            }
            if let Some(run) = &mut run { run.size += 0x1000; }
            else { run = Some(nt_address_space::VmCommittedRange {
                base: placement.base + relative, size: 0x1000, allocation_base: placement.base,
                allocation_protect: nt_address_space::PAGE_EXECUTE_WRITECOPY,
                protect: protection, type_: nt_address_space::MEM_IMAGE,
            }); }
        }
        if let Some(run) = run { committed.register(run)?; }
        self.native_image_views.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let charge = self.prepare_process_commit_charge(pid, pi, charge_bytes)?;
        let view = self.image_sections.reserve_mapped_view(id, process, placement.base, placement.size)
            .map_err(image_section_create::map_image_error)?;
        let descriptor = NativeImageViewDescriptor { view, process, pi, pml4: target.pml4,
            scratch_base: target.scratch_base, base: placement.base, size: placement.size, section_offset: offset };
        if !self.native_image_view_is_current(descriptor) {
            self.image_sections.abort_prepared_mapped_view(view, process)
                .map_err(image_section_create::map_image_error)?;
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        self.native_image_views.push(NativeImageViewOwner { descriptor });
        self.image_sections.begin_mapped_view_mapping(view, process).map_err(image_section_create::map_image_error)?;
        *process_vm_region_map_mut(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)? = *after;
        *process_committed_mapping_table_mut(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)? = *committed;
        self.commit_process_commit_charge(charge);
        self.image_sections.publish_mapped_view(view).map_err(image_section_create::map_image_error)?;
        // A committed view survives late user publication faults, just as the reference NT map.
        self.process_memory_write_checked(self.pi, args[6], &placement.size.to_le_bytes())
            .map_err(nt_address_space::copy::MemoryCopyFailure::status)?;
        self.process_memory_write_checked(self.pi, args[2], &placement.base.to_le_bytes())
            .map_err(nt_address_space::copy::MemoryCopyFailure::status)?;
        if args[5] != 0 {
            self.process_memory_write_checked(self.pi, args[5], &offset.to_le_bytes())
                .map_err(nt_address_space::copy::MemoryCopyFailure::status)?;
        }
        Ok(Some(placement.status))
    }

    pub(crate) unsafe fn unmap_native_image_view(
        &mut self, pi: usize, base: u64,
    ) -> Result<bool, u32> {
        let Some(index) = self.native_image_views.iter().position(|row| row.descriptor.pi == pi
            && base >= row.descriptor.base && base - row.descriptor.base < row.descriptor.size)
        else { return Ok(false); };
        let descriptor = self.native_image_views[index].descriptor;
        if !self.native_image_view_is_current(descriptor) { return Err(nt_process::STATUS_INVALID_HANDLE); }
        if self.secured_virtual_memory.conflicts_with_delete(u64::from(descriptor.process.pid), descriptor.base, descriptor.size) {
            return Err(nt_address_space::STATUS_INVALID_PAGE_PROTECTION);
        }
        hosted_thread_memory_access(pi as u64, descriptor.base, descriptor.size)?;
        let after = &mut *core::ptr::addr_of_mut!(VM_MAP_AFTER);
        *after = *process_vm_region_map(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let removal = after.unmap_mapped(descriptor.base)?;
        if removal.base != descriptor.base || removal.size != descriptor.size { return Err(nt_process::STATUS_INVALID_HANDLE); }
        let committed = &mut *core::ptr::addr_of_mut!(COMMITTED_MAP_AFTER);
        *committed = *process_committed_mapping_table(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let charge = process_committed_allocation_commit_bytes(pi as u64, descriptor.base)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        committed.unregister_allocation_base(descriptor.base);
        self.ensure_process_commit_owner(descriptor.process.pid, pi)?;
        let receipt = self.image_sections.begin_mapped_view_retirement(descriptor.view, descriptor.process)
            .map_err(image_section_create::map_image_error)?;
        crate::native_image_residency::drain_view(self, descriptor)?;
        let _ = vm_page_lock_retire_range(pi as u64, descriptor.base, descriptor.size);
        vm_unmap_shared_image_mapping_range(pi, descriptor.process, descriptor.base,
            descriptor.base + descriptor.size, self)?;
        self.image_sections.acknowledge_mapped_view_retirement(receipt).map_err(image_section_create::map_image_error)?;
        *process_vm_region_map_mut(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)? = *after;
        *process_committed_mapping_table_mut(pi).ok_or(nt_process::STATUS_INVALID_HANDLE)? = *committed;
        self.release_process_commit(descriptor.process.pid, charge);
        self.native_image_views.swap_remove(index);
        Ok(true)
    }

    pub(crate) unsafe fn retire_native_image_views_for_process(
        &mut self, pi: usize, process: nt_memory_manager::ProcessIdentity,
    ) -> Result<(), u32> {
        while let Some(row) = self.native_image_views.iter().find(|row| row.descriptor.pi == pi) {
            let descriptor = row.descriptor;
            if descriptor.process != process { return Err(nt_process::STATUS_INVALID_HANDLE); }
            if !self.unmap_native_image_view(pi, descriptor.base)? { return Err(nt_process::STATUS_INVALID_HANDLE); }
        }
        Ok(())
    }
}
