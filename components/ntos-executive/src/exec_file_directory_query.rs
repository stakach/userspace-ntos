//! Native directory query admission and completion for a canonical hosted File.

use super::*;

impl ExecNtHandler {
    pub(super) unsafe fn query_hosted_file_directory(
        &mut self,
        args: &[u64],
        length: usize,
        information_class: u32,
        return_single_entry: bool,
        restart_scan: bool,
        capture: &file_capture::HostedFileCapture,
    ) -> u32 {
        let route = capture.route;
        let file_id = route.file_id;
        let iosb = args[4];
        let output = args[5];
        let apc_routine = args[2];
        let apc_context = args[3];
        if apc_routine != 0 && self.file_completion.binding(file_id).is_some() {
            return STATUS_INVALID_PARAMETER;
        }
        let mut units = [0u16; nt_fs::MAX_DIRECTORY_NAME];
        let pattern_len = match self.read_directory_pattern(args[9], &mut units) {
            Ok(length) => length,
            Err(status) => return status,
        };
        let pattern = if args[9] == 0 {
            None
        } else {
            let mut owned = Vec::new();
            if owned.try_reserve_exact(pattern_len).is_err() {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            owned.extend_from_slice(&units[..pattern_len]);
            Some(nt_types::UnicodeString::from_owned_units(owned))
        };
        let mut routed_output = match try_zeroed_transfer_buffer(length) {
            Ok(output) => output,
            Err(status) => return status,
        };
        let synchronous = match self.file_completion.is_synchronous(file_id) {
            Ok(synchronous) => synchronous,
            Err(status) => return status,
        };
        let completion_port_suppressed =
            nt_io_completion::io_event_suppresses_completion_port(args[1]);
        let event_obj_idx = match self.prepare_io_event_for_request(args[1]) {
            Ok(Some(index)) => index as u64,
            Ok(None) => u64::MAX,
            Err(status) => return status,
        };
        if !self.reserve_pending_file_io_owner()
            || (synchronous
                && (REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0 || !wait_reply_pool_has_free()))
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        match self.prepare_hosted_file_io(route, args[0], capture.granted_access) {
            Ok(true) => {}
            Ok(false) => return STATUS_PENDING,
            Err(status) => return status,
        }
        if let Err(status) = self.file_completion.set_signaled(file_id, false) {
            self.release_file_reference(file_id);
            return status;
        }
        let mut flags = nt_io_manager::StackFlags::empty();
        if return_single_entry {
            flags |= nt_io_manager::StackFlags::RETURN_SINGLE_ENTRY;
        }
        if restart_scan {
            flags |= nt_io_manager::StackFlags::RESTART_SCAN;
        }
        let parameters = nt_io_manager::DirectoryQueryParameters {
            length: length as u32,
            information_class,
            file_index: 0,
            pattern,
        };
        let caller = match self.hosted_file_native_caller() {
            Ok(caller) => caller,
            Err(status) => {
                self.release_file_reference(file_id);
                return status;
            }
        };
        let mut information = 0u64;
        let mut pending_irp = None;
        let mut status = match driver_launch::dispatch_hosted_file_directory_query_result_exact(
            file_id,
            caller,
            parameters,
            flags,
            &mut routed_output,
        ) {
            Ok((driver_status, completed, irp_id)) => {
                information = completed;
                pending_irp = irp_id;
                driver_status as u32
            }
            Err(status) => status,
        };
        if status == STATUS_PENDING {
            let Some(irp_id) = pending_irp else {
                self.release_file_reference(file_id);
                return STATUS_INVALID_DEVICE_REQUEST;
            };
            self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
                route: PendingFileRoute::Hosted(file_id),
                irp_id: irp_id.raw(),
                major: major::IRP_MJ_DIRECTORY_CONTROL,
                control_code: 0,
                operation: nt_io_manager::PendingFileIoOperation::Transfer,
                delivery_state: 0,
                pi: self.pi as u32,
                tid: self.current_tid,
                busy: None,
                badge: self.current_badge,
                consumer_abandoned: false,
                output_va: output,
                output_len: length as u32,
                output_offset: 0,
                iosb_va: iosb,
                apc_routine,
                apc_context,
                completion_port_suppressed,
                signal_file: synchronous || event_obj_idx == u64::MAX,
                publish_iocp: apc_routine == 0,
                event_obj_idx,
                reply_cap: 0,
                reply_required: false,
                native_call_transport: self.current_native_call_transport,
                resume_ip: 0,
                resume_sp: 0,
                resume_flags: 0,
            });
            self.pending_file_io_wait = synchronous;
            return STATUS_PENDING;
        }
        if nt_io_completion::file_io_status_copies_output(status) {
            if information > routed_output.len() as u64 {
                status = STATUS_INVALID_BUFFER_SIZE;
                information = 0;
            } else if information != 0
                && !self.xas_try_write_buf(output, &routed_output[..information as usize])
            {
                status = STATUS_ACCESS_VIOLATION;
                information = 0;
            }
        }
        self.complete_terminal_file_io(
            file_id,
            event_obj_idx,
            self.current_tid,
            apc_routine,
            apc_context,
            iosb,
            status,
            information,
            true,
            completion_port_suppressed,
        );
        self.release_file_reference(file_id);
        status
    }
}
