//! Canonical image Section authority to an exact hosted process instance.

use super::*;
use crate::native_image_sections::NativeImageSectionId;
use nt_memory_manager::image_section::ImageViewRef;

const INVALID_IMAGE: u32 = 0xc000_007b;
const NOT_READY: u32 = 0xc000_00a3;

pub(crate) struct ProcessImageOwner {
    target: nt_exe_image::SpawnTarget,
    pid: Option<nt_process::ProcessId>,
    view: ImageViewRef,
    mechanism_retired: bool,
}

impl ExecNtHandler {
    pub(super) unsafe fn reserve_native_image_process(
        &mut self,
        parent: nt_process::ProcessId,
        create: nt_process::ProcessCreateInput,
        desired_access: u32,
        output: u64,
        previous_mode: nt_syscall::ProcessorMode,
    ) -> Result<Option<nt_exe_image::SpawnRequest>, u32> {
        let caller = self.native_handle_caller(previous_mode)?;
        let ctx = self.loop_ctx.ok_or(NOT_READY)?;
        let handle = match self.pm.lookup_native_section_handle(caller, create.section_handle) {
            Ok(handle) => handle,
            Err(nt_process::STATUS_INVALID_HANDLE) => return Ok(None),
            Err(status) => return Err(status),
        };
        let id = NativeImageSectionId::from_section_id(handle.section()).ok_or(INVALID_IMAGE)?;
        if caller.mode() == nt_types::AccessMode::UserMode
            && handle.granted_access() & nt_memory_manager::section_view_access::SECTION_MAP_EXECUTE == 0
        { return Err(nt_process::STATUS_ACCESS_DENIED); }
        let source = self.image_sections.source(id).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        // A Section handle alone does not imply its retained source contains the complete PE.
        if !source.has_complete_image() { return Err(STATUS_NOT_SUPPORTED); }
        let path = source.image_path.as_deref().ok_or(STATUS_NOT_SUPPORTED)?;
        let leaf = nt_exe_image::canonical_exe_leaf(path).ok_or(INVALID_IMAGE)?;
        let mut captured_leaf = [0; nt_exe_image::MAX_EXE_LEAF];
        captured_leaf[..leaf.len()].copy_from_slice(leaf);
        let leaf = &captured_leaf[..leaf.len()];
        let mut image_path = [0; nt_exe_image::MAX_NT_IMAGE_PATH];
        let (path_len, root) = dynamic_hosted_nt_image_path(path, leaf, &mut image_path)
            .ok_or(STATUS_NOT_SUPPORTED)?;
        let _durable = crate::allocator::enter_durable();
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(source.pe_header.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        bytes.extend_from_slice(&source.pe_header);
        if bytes.len() as u64 != source.backing.file_extent { return Err(INVALID_IMAGE); }
        // Preserve the canonical preferred transfer address through main-image placement.
        let pe = nt_pe_loader::PeFile::parse(&source.pe_header).map_err(|_| INVALID_IMAGE)?;
        let headers = pe.headers();
        if headers.machine != 0x8664 || !headers.is_executable() { return Err(INVALID_IMAGE); }
        let role = nt_exe_image::HostedProcessRole::for_image_subsystem(headers.subsystem)
            .ok_or(STATUS_NOT_SUPPORTED)?;
        let observation_target = source.observation_target;
        let metadata = nt_exe_image::ImageMetadata {
            pool_va: bytes.as_mut_ptr() as u64, file_size: bytes.len() as u64,
            image_size: u64::from(headers.size_of_image), entry_rva: headers.entry_point_rva,
            subsystem: headers.subsystem, subsystem_major: headers.major_subsystem_version,
            subsystem_minor: headers.minor_subsystem_version,
        };
        let layout = nt_exe_image::ProcessImageLayout::checked(
            headers.image_base, u64::from(headers.size_of_image), headers.entry_point_rva,
        ).map_err(|_| INVALID_IMAGE)?;
        let ntdll_extent = (!ctx.ntdll_pe.is_null())
            .then(|| (ctx.nt_base, image_extent(&*ctx.ntdll_pe)));
        img_spawn::validate_hosted_main_image_layout(layout, ntdll_extent, true)?;
        self.process_image_owners.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let view = self.image_sections.reference_view(id).map_err(image_section_create::map_image_error)?;
        let catalog = &mut *ctx.exe_image_catalog;
        let pi = match catalog.admit_dynamic_executable_observed(
            leaf, role, &image_path[..path_len], &image_path[..path_len], root, observation_target, MAX_PI,
        ) {
            Ok(pi) => pi,
            Err(_) => {
                self.image_sections.release_view(view).expect("unpublished process image view");
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        let image = catalog.get_by_pi(pi).expect("new exact process image registration");
        let target = nt_exe_image::SpawnTarget::from_image(image);
        if register_hosted_process_runtime_for_image(image).is_err() {
            catalog.retire_dynamic_target(target).expect("unpublished exact image registration");
            self.image_sections.release_view(view).expect("unpublished process image view");
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        if (&mut *ctx.hosted_loaded_images).register_exact_loaded(image, bytes).is_err() {
            retire_hosted_process_runtime(target).expect("unpublished exact process runtime");
            catalog.retire_dynamic_target(target).expect("unpublished exact image registration");
            self.image_sections.release_view(view).expect("unpublished process image view");
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        self.process_image_owners.push(ProcessImageOwner { target, pid: None, view, mechanism_retired: false });
        let request = match (&mut *ctx.exe_images).reserve_spawn_from_native_section(
            catalog, target, self.pi, create.section_handle, metadata, desired_access, output,
        ) {
            Ok(request) => request,
            Err(_) => {
                self.abort_native_image_process(target);
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        if let Err(status) = self.allocate_hosted_process_slot(parent, image, create.flags, create.job_member_level) {
            (&mut *ctx.exe_images).discard_native_section_spawn(request).expect("exact unentered native spawn");
            self.abort_native_image_process(target);
            return Err(status);
        }
        let pid = self.pm_pid_for_pi(pi).expect("allocated exact process image owner");
        self.process_image_owners.last_mut().expect("retained process image owner").pid = Some(pid);
        match image.observation_role() {
            nt_exe_image::HostedProcessRole::InteractiveShellBootstrap => {
                USERINIT_CREATE_PROCESS_REQUESTS.fetch_add(1, Ordering::Relaxed);
            }
            nt_exe_image::HostedProcessRole::InteractiveShell => {
                EXPLORER_CREATE_PROCESS_REQUESTS.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        Ok(Some(request))
    }

    unsafe fn abort_native_image_process(&mut self, target: nt_exe_image::SpawnTarget) {
        // A retained process construction cannot be rolled back as if it never existed.
        if let Some(pid) = self.pm_pid_for_pi(target.pi) {
            let row = self.process_image_owners.iter_mut().find(|row| row.target == target)
                .expect("retained failed process image owner");
            row.pid = Some(pid);
            return;
        }
        let index = self.process_image_owners.iter().position(|row| row.target == target)
            .expect("exact unentered native process image owner");
        let ctx = self.loop_ctx.expect("native image construction loop");
        assert!(retire_unspawned_dynamic_hosted_identity(ctx, target));
        self.process_image_owners[index].mechanism_retired = true;
        self.drain_native_process_images();
    }

    pub(super) fn release_native_process_image(&mut self, pi: usize, pid: nt_process::ProcessId, generation: u64) {
        let Some(index) = self.process_image_owners.iter().position(|row| row.target.pi == pi) else { return; };
        let row = &self.process_image_owners[index];
        assert_eq!(row.target.generation, generation);
        assert_eq!(row.pid, Some(pid));
        self.process_image_owners[index].mechanism_retired = true;
        self.drain_native_process_images();
    }

    /// Native mechanism retirement can occur inside an outer event that still reads the PE.
    /// The detached exact owner converges here only after all such readers have acknowledged.
    pub(crate) fn drain_native_process_images(&mut self) {
        let Some(ctx) = self.loop_ctx else { return; };
        let mut index = 0;
        while index < self.process_image_owners.len() {
            let row = &self.process_image_owners[index];
            if !row.mechanism_retired { index += 1; continue; }
            let bytes = match unsafe { (&mut *ctx.hosted_loaded_images).retire_exact_snapshot(row.target) } {
                Ok(bytes) => bytes,
                Err(crate::hosted_loaded_images::HostedLoadedImageRegistrationError::LiveReaders) => {
                    index += 1;
                    continue;
                }
                Err(error) => panic!("retired exact process snapshot changed: {:?}", error),
            };
            self.image_sections.release_view(row.view)
                .expect("physically retired exact process image view");
            self.process_image_owners.remove(index);
            drop(bytes);
        }
    }
}
