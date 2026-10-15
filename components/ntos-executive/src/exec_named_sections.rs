//! Named Section service entrypoints.
use super::*;

impl ExecNtHandler {
    pub(super) unsafe fn nt_open_section_service(
        &mut self,
        args: &[u64],
        previous_mode: nt_syscall::ProcessorMode,
    ) -> u32 {
        let _durable = allocator::enter_durable();
        if previous_mode != nt_syscall::ProcessorMode::KernelMode {
            if let Err(status) = self.probe_copy_scalar::<8>(args[0]) {
                return status;
            }
        }
        let captured = match self.capture_named_object_attributes(args[2]) {
            Ok(captured) => captured,
            Err(status) => return status,
        };
        let caller = match self.native_handle_caller(previous_mode) {
            Ok(caller) => caller,
            Err(status) => return status,
        };
        let Some(path) = captured.path() else {
            return STATUS_OBJECT_NAME_INVALID;
        };
        let (root, path) = match self.native_directory_root_and_path(caller, captured.root, path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        // Image descriptor/access policy remains the existing image boundary.
        if let Some(image) = self.obj_resolve(path, root).and_then(|index| {
            (self.obj_ns[index].kind == OBJ_KIND_SECTION)
                .then(|| {
                    native_image_sections::NativeImageSectionId::from_section_id(
                        self.obj_ns[index].payload as nt_process::SectionId,
                    )
                })
                .flatten()
        }) {
            let section_id = image.section_id();
            let had_handle = self
                .pm
                .handle_object_count(nt_process::HandleObject::Section(section_id))
                != 0;
            if let Err(error) = self.image_sections.ensure_handle_group(image) {
                return image_section_create::map_image_error(error);
            }
            let mut publication = match self.pm.reserve_native_section_handle(
                caller,
                captured.attributes & (nt_process::native_handle::OBJ_KERNEL_HANDLE | 0x2),
            ) {
                Ok(publication) => publication,
                Err(status) => {
                    if !had_handle {
                        self.image_sections
                            .close_handle_group(image)
                            .expect("unopened image group rollback");
                    }
                    return status;
                }
            };
            if let Err(status) = publication.bind(&mut self.pm, section_id, nt_ulong_arg(args[1])) {
                publication
                    .abort(&mut self.pm)
                    .expect("failed image open reservation");
                if !had_handle {
                    self.image_sections
                        .close_handle_group(image)
                        .expect("failed image open group rollback");
                }
                return status;
            }
            let handle = match publication.publish(&mut self.pm) {
                Ok(handle) => handle,
                Err(status) => {
                    publication
                        .abort(&mut self.pm)
                        .expect("failed image open publication");
                    if !had_handle {
                        self.image_sections
                            .close_handle_group(image)
                            .expect("failed image open group rollback");
                    }
                    return status;
                }
            };
            // NtOpenSection keeps its committed handle and original status on late user faults.
            if let Err(nt_address_space::copy::MemoryCopyFailure::Retry(status)) =
                self.process_memory_write_checked(self.pi, args[0], &handle.to_le_bytes())
            {
                crate::provider_bugcheck::report(0xc4, [handle, args[0], u64::from(status), 94]);
            }
            return 0;
        }
        let admission =
            match self.prepare_data_section_name(&captured, caller, nt_ulong_arg(args[1]), false) {
                Ok(admission) => admission,
                Err(status) => return status,
            };
        let mut admission = Some(admission);
        let mut reserved = None;
        match crate::section_metadata_work::submit_local_data(
            self,
            caller,
            args[0],
            0,
            &mut reserved,
            &mut admission,
        ) {
            Ok(()) => 0x0000_0103,
            Err(status) => {
                self.release_data_section_admission(
                    admission.as_mut().expect("unsubmitted Section admission"),
                );
                status
            }
        }
    }
}
