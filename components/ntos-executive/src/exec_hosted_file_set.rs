//! Hosted SET admission and dispatch retain the caller's authenticated source File.

use super::*;

impl ExecNtHandler {
    pub(super) unsafe fn service_hosted_set_information(
        &mut self,
        handle: u64,
        iosb: u64,
        capture: &file_capture::HostedFileCapture,
        parameters: nt_io_manager::SetInformationParameters,
        input: &[u8],
    ) -> Result<(u32, u64), u32> {
        let route = capture.route;
        let file_id = route.file_id;
        let synchronous_file = match self.file_completion.is_synchronous(file_id) {
            Ok(synchronous) => synchronous,
            Err(status) => return Err(status),
        };
        if REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0
            || !wait_reply_pool_has_free()
            || !self.reserve_pending_file_io_owner()
        {
            return Err(nt_io_completion::STATUS_INSUFFICIENT_RESOURCES);
        }
        match self.prepare_hosted_file_io(route, handle, capture.granted_access) {
            Ok(true) => {}
            Ok(false) => return Ok((STATUS_PENDING, 0)),
            Err(status) => return Err(status),
        }
        if let Err(status) = self.file_completion.set_signaled(file_id, false) {
            self.release_file_reference(file_id);
            return Err(status);
        }
        let (mut status, mut information, pending_irp_id) =
            match self.dispatch_hosted_file_set_information_for(route, parameters, input) {
                Ok((driver_status, completed, irp_id)) => (driver_status as u32, completed, irp_id),
                Err(route_status) => (route_status, 0, 0),
            };
        if status == STATUS_PENDING {
            if pending_irp_id == 0 {
                status = nt_io_completion::STATUS_INSUFFICIENT_RESOURCES;
                information = 0;
                if synchronous_file {
                    let _ = self.signal_file_completion(file_id, status);
                }
                self.release_file_reference(file_id);
            } else {
                self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
                    route: PendingFileRoute::Hosted(file_id),
                    irp_id: pending_irp_id,
                    major: major::IRP_MJ_SET_INFORMATION,
                    control_code: 0,
                    operation: nt_io_manager::PendingFileIoOperation::Transfer,
                    delivery_state: 0,
                    pi: self.pi as u32,
                    tid: self.current_tid,
                    busy: None,
                    badge: self.current_badge,
                    consumer_abandoned: false,
                    output_va: 0,
                    output_len: 0,
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
            if synchronous_file {
                let _ = self.signal_file_completion(file_id, status);
            }
            self.release_file_reference(file_id);
        }
        Ok((status, information))
    }

    /// Execute the I/O Manager's internal target-parent open before a provider rename, link, or
    /// move-cluster request. The source File reference and synchronous Busy lock are retained across
    /// either pending IRP; the target File remains kernel-only and is released after the source SET
    /// reaches a terminal result.
    pub(super) unsafe fn service_hosted_set_file_name_with_open_parent(
        &mut self,
        handle: u64,
        iosb: u64,
        capture: &file_capture::HostedFileCapture,
        information_class: u32,
        control: nt_io_manager::SetInformationControl,
        target_name: &[u16],
        payload: Vec<u8>,
    ) -> Result<(u32, u64), u32> {
        let route = capture.route;
        let synchronous_file = match self.file_completion.is_synchronous(route.file_id) {
            Ok(synchronous) => synchronous,
            Err(status) => return Err(status),
        };
        let Some(target_name_bytes_len) = target_name.len().checked_mul(2) else {
            return Err(nt_fs::STATUS_INVALID_PARAMETER);
        };
        let mut target_name_bytes = match try_zeroed_transfer_buffer(target_name_bytes_len) {
            Ok(bytes) => bytes,
            Err(status) => return Err(status),
        };
        for (word, bytes) in target_name
            .iter()
            .zip(target_name_bytes.chunks_exact_mut(2))
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        if REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0
            || !wait_reply_pool_has_free()
            || !self.reserve_pending_file_io_owner()
        {
            return Err(nt_io_completion::STATUS_INSUFFICIENT_RESOURCES);
        }
        let Some(transaction_reservation) = self.reserve_pending_set_file_name_owner() else {
            return Err(nt_io_completion::STATUS_INSUFFICIENT_RESOURCES);
        };
        match self.prepare_hosted_file_io(route, handle, capture.granted_access) {
            Ok(true) => {}
            Ok(false) => {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                return Ok((STATUS_PENDING, 0));
            }
            Err(status) => {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                return Err(status);
            }
        }
        if let Err(status) = self.file_completion.set_signaled(route.file_id, false) {
            (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                .cancel_reservation(transaction_reservation);
            self.release_file_reference(route.file_id);
            return Err(status);
        }

        let Some(mut transaction) = nt_io_manager::PendingSetFileName::awaiting_source_query(
            route.file_id,
            information_class,
            control,
            target_name_bytes,
            payload,
        ) else {
            (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                .cancel_reservation(transaction_reservation);
            self.release_file_reference(route.file_id);
            return Err(nt_fs::STATUS_INVALID_PARAMETER);
        };

        let source_create_options = match driver_launch::hosted_file_create_options(route.file_id) {
            Some(options) => options,
            None => {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                self.release_file_reference(route.file_id);
                return Err(nt_fs::STATUS_INVALID_HANDLE);
            }
        };
        let mut pending_irp = None;
        let mut pending_major = major::IRP_MJ_QUERY_INFORMATION;
        let source_is_directory = if source_create_options
            .contains(nt_io_manager::CreateOptions::DIRECTORY_FILE)
        {
            Some(true)
        } else if source_create_options.contains(nt_io_manager::CreateOptions::NON_DIRECTORY_FILE) {
            Some(false)
        } else {
            let mut basic = [0u8; FILE_BASIC_INFORMATION_LEN];
            let query = driver_launch::dispatch_hosted_file_irp_result_exact(
                route.file_id,
                major::IRP_MJ_QUERY_INFORMATION as u64,
                nt_fs::FILE_BASIC_INFORMATION as u64,
                self.current_tid,
                &[],
                &mut basic,
                0,
            );
            let (status, information, irp_id) = match query {
                Ok((status, information, irp_id, _)) => (
                    status as u32,
                    information,
                    irp_id.map(nt_io_manager::IrpId::raw),
                ),
                Err(status) => (status, 0, None),
            };
            if status == STATUS_PENDING {
                let Some(irp_id) = irp_id else {
                    (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                        .cancel_reservation(transaction_reservation);
                    if synchronous_file {
                        let _ = self.signal_file_completion(
                            route.file_id,
                            nt_io_completion::STATUS_INSUFFICIENT_RESOURCES,
                        );
                    }
                    self.release_file_reference(route.file_id);
                    return Ok((nt_io_completion::STATUS_INSUFFICIENT_RESOURCES, 0));
                };
                pending_irp = Some(irp_id);
                None
            } else if (status as i32) < 0 {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                if synchronous_file {
                    let _ = self.signal_file_completion(route.file_id, status);
                }
                self.release_file_reference(route.file_id);
                return Ok((status, information));
            } else if information < FILE_BASIC_INFORMATION_LEN as u64 {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                if synchronous_file {
                    let _ = self
                        .signal_file_completion(route.file_id, nt_fs::STATUS_INFO_LENGTH_MISMATCH);
                }
                self.release_file_reference(route.file_id);
                return Ok((nt_fs::STATUS_INFO_LENGTH_MISMATCH, 0));
            } else {
                match nt_fs::parse_file_basic_information_attributes(&basic) {
                    Ok(attributes) => Some(attributes & nt_fs::FILE_ATTRIBUTE_DIRECTORY != 0),
                    Err(status) => {
                        (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                            .cancel_reservation(transaction_reservation);
                        if synchronous_file {
                            let _ = self.signal_file_completion(route.file_id, status);
                        }
                        self.release_file_reference(route.file_id);
                        return Ok((status, 0));
                    }
                }
            }
        };

        let mut target_file_id = 0;
        if let Some(source_is_directory) = source_is_directory {
            let (allocated_target, target_access) =
                match driver_launch::allocate_hosted_set_file_name_target(
                    route.file_id,
                    source_is_directory,
                    target_name,
                ) {
                    Ok(target) => target,
                    Err(status) => {
                        (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                            .cancel_reservation(transaction_reservation);
                        if synchronous_file {
                            let _ = self.signal_file_completion(route.file_id, status);
                        }
                        self.release_file_reference(route.file_id);
                        return Ok((status, 0));
                    }
                };
            target_file_id = allocated_target;
            assert!(transaction.advance_to_target_create(target_file_id));
            let create = driver_launch::dispatch_hosted_target_directory_create_irp_result_exact(
                target_file_id,
                self.current_tid,
                nt_io_manager::CreateParameters {
                    desired_access: nt_types::AccessMask::from_bits_retain(target_access),
                    share_access: nt_io_manager::ShareAccess::READ
                        | nt_io_manager::ShareAccess::WRITE,
                    create_options: nt_io_manager::CreateOptions::OPEN_FOR_BACKUP_INTENT,
                    create_disposition: nt_fs::FILE_OPEN,
                    file_attributes: 0,
                    ea_length: 0,
                    related_file: None,
                },
                transaction.target_name(),
            );
            let (create_status, create_information, create_irp) = match create {
                Ok((status, information, pending, _)) => (
                    status as u32,
                    information,
                    pending.map(nt_io_manager::IrpId::raw),
                ),
                Err(status) => (status, 0, None),
            };

            let mut terminal = None;
            pending_irp = create_irp;
            pending_major = major::IRP_MJ_CREATE;
            if create_status != STATUS_PENDING {
                if (create_status as i32) < 0 {
                    terminal = Some((create_status, create_information));
                } else if information_class == nt_fs::FILE_LINK_INFORMATION
                    && !control.replace_if_exists()
                    && create_information == nt_fs::FILE_EXISTS as u64
                {
                    terminal = Some((nt_fs::STATUS_OBJECT_NAME_COLLISION, 0));
                } else {
                    let Some(set_information_len) =
                        u32::try_from(transaction.set_information().len()).ok()
                    else {
                        (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                            .cancel_reservation(transaction_reservation);
                        let _ = driver_launch::abandon_unpublished_hosted_file(target_file_id);
                        if synchronous_file {
                            let _ = self.signal_file_completion(
                                route.file_id,
                                nt_fs::STATUS_INVALID_PARAMETER,
                            );
                        }
                        self.release_file_reference(route.file_id);
                        return Ok((nt_fs::STATUS_INVALID_PARAMETER, 0));
                    };
                    let parameters = nt_io_manager::SetInformationParameters {
                        info_class: information_class,
                        length: set_information_len,
                        target_file: Some(nt_io_manager::FileId(target_file_id)),
                        control,
                    };
                    match self.dispatch_hosted_file_set_information_for(
                        route,
                        parameters,
                        transaction.set_information(),
                    ) {
                        Ok((status, _information, irp_id)) if status as u32 == STATUS_PENDING => {
                            if irp_id == 0 {
                                terminal = Some((STATUS_INSUFFICIENT_RESOURCES, 0));
                            } else {
                                assert!(transaction.advance_to_source_set());
                                pending_irp = Some(irp_id);
                                pending_major = major::IRP_MJ_SET_INFORMATION;
                            }
                        }
                        Ok((status, information, _)) => {
                            terminal = Some((status as u32, information));
                        }
                        Err(status) => terminal = Some((status, 0)),
                    }
                }
            }

            if let Some((status, information)) = terminal {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                let _ = driver_launch::abandon_unpublished_hosted_file(target_file_id);
                if synchronous_file {
                    let _ = self.signal_file_completion(route.file_id, status);
                }
                self.release_file_reference(route.file_id);
                return Ok((status, information));
            }
        }

        let Some(pending_irp) = pending_irp else {
            (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                .cancel_reservation(transaction_reservation);
            if target_file_id != 0 {
                let _ = driver_launch::abandon_unpublished_hosted_file(target_file_id);
            }
            self.release_file_reference(route.file_id);
            return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
        };
        let transaction_id = (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
            .park_reserved(transaction_reservation, transaction)
            .expect("reserved set-file-name transaction rejected its captured buffers");
        // Both captured buffers transfer into the pending I/O owner before this dispatch returns.
        self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
            route: PendingFileRoute::Hosted(route.file_id),
            irp_id: pending_irp,
            major: pending_major,
            control_code: 0,
            operation: nt_io_manager::PendingFileIoOperation::SetFileName(
                nt_io_manager::PendingSetFileNameOperation {
                    transaction_id: transaction_id.raw(),
                    target_file_id,
                },
            ),
            delivery_state: 0,
            pi: self.pi as u32,
            tid: self.current_tid,
            busy: None,
            badge: self.current_badge,
            consumer_abandoned: false,
            output_va: 0,
            output_len: 0,
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
        Ok((STATUS_PENDING, 0))
    }
}
