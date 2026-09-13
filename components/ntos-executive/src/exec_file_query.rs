//! Hosted File queries retain one authenticated identity through acquisition and delivery.

use super::*;

impl ExecNtHandler {
    unsafe fn owned_hosted_query_metadata(
        &self,
        capture: &file_capture::HostedFileCapture,
    ) -> Result<nt_fs::QueryMetadata, u32> {
        let metadata = driver_launch::owned_hosted_file_query_metadata(
            capture.route.file_id,
            capture.route.device_id,
        )?;
        Ok(nt_fs::QueryMetadata {
            access_flags: capture.granted_access,
            mode: nt_fs::file_mode_from_create_options(metadata.create_options.bits()),
            alignment_requirement: metadata.alignment_requirement,
            ..nt_fs::QueryMetadata::default()
        })
    }

    pub(super) unsafe fn query_hosted_file_information(
        &mut self,
        handle: u64,
        iosb: u64,
        output: u64,
        length: usize,
        class: u32,
        capture: &file_capture::HostedFileCapture,
    ) -> u32 {
        let route = capture.route;
        let file_id = route.file_id;
        let synchronous_file = match self.file_completion.is_synchronous(file_id) {
            Ok(synchronous) => synchronous,
            Err(status) => return status,
        };
        let inline = matches!(
            class,
            nt_fs::FILE_ACCESS_INFORMATION
                | nt_fs::FILE_MODE_INFORMATION
                | nt_fs::FILE_ALIGNMENT_INFORMATION
                | 41
        );
        if !inline
            && (REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0
                || !wait_reply_pool_has_free()
                || !self.reserve_pending_file_io_owner())
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        match self.prepare_hosted_file_io(route, handle, capture.granted_access) {
            Ok(true) => {}
            Ok(false) => return STATUS_PENDING,
            Err(status) => return status,
        }
        if let Err(status) = self.file_completion.set_signaled(file_id, false) {
            self.release_file_reference(file_id);
            return status;
        }

        if inline {
            let mut encoded = [0u8; 4];
            let result = if class == 41 {
                self.file_completion
                    .notification_modes(file_id)
                    .map(|flags| {
                        encoded.copy_from_slice(&flags.to_le_bytes());
                        4
                    })
            } else {
                self.owned_hosted_query_metadata(capture)
                    .and_then(|metadata| {
                        nt_fs::encode_query_information(class, metadata, &mut encoded)
                    })
            };
            let required = match result {
                Ok(required) => required,
                Err(status) => {
                    self.release_file_reference(file_id);
                    return status;
                }
            };
            let mut status = nt_fs::STATUS_SUCCESS;
            let mut information = required as u64;
            if !self.xas_try_write_buf(output, &encoded[..required]) {
                status = STATUS_ACCESS_VIOLATION;
                information = 0;
            }
            if !self.write_current_iosb(iosb, status, information) {
                status = STATUS_ACCESS_VIOLATION;
            }
            if synchronous_file || class == 41 {
                let _ = self.signal_file_completion(file_id, status);
            }
            self.release_file_reference(file_id);
            return status;
        }

        let mut routed_output = match try_zeroed_transfer_buffer(length) {
            Ok(output) => output,
            Err(status) => {
                self.release_file_reference(file_id);
                return status;
            }
        };
        let output_capacity = routed_output.len();
        if class == nt_fs::FILE_ALL_INFORMATION {
            let result = self
                .owned_hosted_query_metadata(capture)
                .and_then(|metadata| {
                    nt_fs::encode_file_all_io_manager_information(metadata, &mut routed_output)
                });
            if let Err(status) = result {
                self.release_file_reference(file_id);
                return status;
            }
        }

        let mut information = 0u64;
        let mut pending_irp_id = 0u64;
        let mut status = match self.dispatch_hosted_file_irp_for(
            route,
            major::IRP_MJ_QUERY_INFORMATION as u64,
            class as u64,
            &[],
            &mut routed_output,
        ) {
            Ok((driver_status, completed, irp_id)) => {
                information = completed;
                pending_irp_id = irp_id;
                driver_status as u32
            }
            Err(route_status) => route_status,
        };

        if status == STATUS_PENDING {
            if pending_irp_id == 0 {
                status = nt_io_completion::STATUS_INSUFFICIENT_RESOURCES;
                information = 0;
                if synchronous_file {
                    let _ = self.signal_file_completion(file_id, status);
                }
                self.release_file_reference(file_id);
                let mut iosb_bytes = [0u8; 16];
                iosb_bytes[..4].copy_from_slice(&status.to_le_bytes());
                if !self.xas_try_write_buf(iosb, &iosb_bytes) {
                    status = nt_syscall::STATUS_ACCESS_VIOLATION;
                }
            } else {
                self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
                    route: PendingFileRoute::Hosted(file_id),
                    irp_id: pending_irp_id,
                    major: major::IRP_MJ_QUERY_INFORMATION,
                    control_code: 0,
                    operation: nt_io_manager::PendingFileIoOperation::Transfer,
                    delivery_state: 0,
                    pi: self.pi as u32,
                    tid: self.current_tid,
                    busy: None,
                    badge: self.current_badge,
                    consumer_abandoned: false,
                    output_va: output,
                    output_len: output_capacity as u32,
                    output_offset: 0,
                    iosb_va: iosb,
                    apc_routine: 0,
                    apc_context: 0,
                    completion_port_suppressed: true,
                    signal_file: synchronous_file,
                    publish_iocp: false,
                    event_obj_idx: u64::MAX,
                    reply_cap: 0,
                    reply_required: false,
                    native_call_transport: self.current_native_call_transport,
                    resume_ip: 0,
                    resume_sp: 0,
                    resume_flags: 0,
                });
                self.pending_file_io_wait = true;
            }
        } else {
            let copy_len = information
                .min(length as u64)
                .min(routed_output.len() as u64) as usize;
            if copy_len != 0 && !self.xas_try_write_buf(output, &routed_output[..copy_len]) {
                status = nt_syscall::STATUS_ACCESS_VIOLATION;
                information = 0;
            }
            let mut iosb_bytes = [0u8; 16];
            iosb_bytes[..4].copy_from_slice(&status.to_le_bytes());
            iosb_bytes[8..16].copy_from_slice(&information.to_le_bytes());
            if !self.xas_try_write_buf(iosb, &iosb_bytes) {
                status = nt_syscall::STATUS_ACCESS_VIOLATION;
            }
            if synchronous_file {
                let _ = self.signal_file_completion(file_id, status);
            }
            self.release_file_reference(file_id);
        }
        if NT_QUERY_INFORMATION_FILE_NPFS_TRACE_N.fetch_add(1, Ordering::Relaxed) < 32 {
            print_str(b"[nt-query-info-file-npfs] pi=");
            print_u64(self.pi as u64);
            print_str(b" handle=0x");
            print_hex(handle as u32);
            print_str(b" fid=0x");
            print_hex(route.file_id as u32);
            print_str(b" dev=");
            print_u64(route.device_id);
            print_str(b" class=");
            print_u64(class as u64);
            print_str(b" length=");
            print_u64(length as u64);
            print_str(b" transport=");
            print_u64(output_capacity as u64);
            print_str(b" status=0x");
            print_hex(status);
            print_str(b" info=");
            print_u64(information);
            print_str(b"\n");
        }
        status
    }
}
