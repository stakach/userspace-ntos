//! Named Section service entrypoints.
use super::*;

impl ExecNtHandler {
    pub(super) unsafe fn nt_open_section_service(
        &mut self,
        args: &[u64],
        previous_mode: nt_syscall::ProcessorMode,
    ) -> u32 {
        if !self.probe_user_output(args[0], core::mem::size_of::<u64>()) {
            return STATUS_ACCESS_VIOLATION;
        }
        let captured = match self.capture_named_object_attributes(args[2]) {
            Ok(captured) => captured,
            Err(status) => return status,
        };
        let Some(path) = captured.path() else {
            return STATUS_OBJECT_NAME_INVALID;
        };
        let (root_index, path) = match self.event_root_and_path(captured.root, path) {
            Ok(resolved) => resolved,
            Err(status) => return status,
        };
        if let Some(index) = self.obj_resolve(path, root_index) {
            if self.obj_ns[index].kind != OBJ_KIND_SECTION {
                return STATUS_OBJECT_TYPE_MISMATCH;
            }
            let section_id = self.obj_ns[index].payload as nt_process::SectionId;
            let Some(image) = native_image_sections::NativeImageSectionId::from_section_id(section_id) else {
                return STATUS_INVALID_HANDLE;
            };
            let caller = match self.native_handle_caller(previous_mode) {
                Ok(caller) => caller,
                Err(status) => return status,
            };
            let had_handle = self.pm.handle_object_count(nt_process::HandleObject::Section(section_id)) != 0;
            if let Err(error) = self.image_sections.ensure_handle_group(image) {
                return image_section_create::map_image_error(error);
            }
            let mut publication = match self.pm.reserve_native_section_handle(caller, captured.attributes & (nt_process::native_handle::OBJ_KERNEL_HANDLE | 0x2)) {
                Ok(publication) => publication,
                Err(status) => {
                    if !had_handle {
                        self.image_sections.close_handle_group(image).expect("unopened image group rollback");
                    }
                    return status;
                }
            };
            if let Err(status) = publication.bind(&mut self.pm, section_id, nt_ulong_arg(args[1])) {
                publication.abort(&mut self.pm).expect("failed image open reservation");
                if !had_handle {
                    self.image_sections.close_handle_group(image).expect("failed image open group rollback");
                }
                return status;
            }
            let handle = publication.value();
            if !self.user_memory_write(SyscallUserMemory::CurrentProcess, args[0], &handle.to_le_bytes()) {
                publication.abort(&mut self.pm).expect("image open copyout rollback");
                if !had_handle {
                    self.image_sections.close_handle_group(image).expect("image open copyout group rollback");
                }
                return STATUS_ACCESS_VIOLATION;
            }
            publication.publish(&mut self.pm).expect("image Section open publication");
            return 0;
        }
        let ctx = self.loop_ctx.unwrap();
        let name16 = smss_read_objattr_name(args[2]); // R8 = *ObjectAttributes
        print_str(b"[ntos-exec] NtOpenSection name=\"");
        for &w in name16.iter().take(96) {
            debug_put_char(if (0x20..0x7f).contains(&w) {
                w as u8
            } else {
                b'?'
            });
        }
        print_str(b"\"\n");
        let mut nb = [0u8; 96];
        let mut nlen = 0;
        for &w in &name16 {
            if nlen >= nb.len() {
                break;
            }
            nb[nlen] = (w as u8).to_ascii_lowercase();
            nlen += 1;
        }
        if nb[..nlen].windows(17).any(|w| w == b"nlssectioncp20127") {
            let h = self.mint_handle();
            smss_stack_write(args[0], h); // R10 = *SectionHandle
            *ctx.nls_section_handle = h;
            print_str(b"[ntos-exec] NtOpenSection NlsCP20127 -> handle 0x");
            print_hex(*ctx.nls_section_handle as u32);
            print_str(b"\n");
            0 // STATUS_SUCCESS
        } else {
            0xC0000034 // STATUS_OBJECT_NAME_NOT_FOUND
        }
    }
}
