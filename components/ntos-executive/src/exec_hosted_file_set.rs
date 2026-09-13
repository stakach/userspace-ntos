//! Hosted SET owns admission, payload capture and terminal delivery as one operation.

use super::*;

impl ExecNtHandler {
    pub(super) fn trace_set_information_payload(
        &self,
        handle: u64,
        information_class: u32,
        payload: &[u8],
    ) {
        let length = payload.len();
        if NT_SET_INFORMATION_FILE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 8 {
            print_str(b"[nt-set-information-file] pi=");
            print_u64(self.pi as u64);
            print_str(b" handle=0x");
            print_hex(handle as u32);
            print_str(b" class=");
            print_u64(information_class as u64);
            print_str(b" length=");
            print_u64(length as u64);
            if information_class == 23 && payload.len() >= 8 {
                print_str(b" read_mode=");
                print_u64(u32::from_le_bytes(payload[0..4].try_into().unwrap()) as u64);
                print_str(b" completion_mode=");
                print_u64(u32::from_le_bytes(payload[4..8].try_into().unwrap()) as u64);
            }
            print_str(b" payload=");
            for &byte in payload.iter().take(64) {
                print_hex(byte as u32);
                debug_put_char(b' ');
            }
            print_str(b"\n");
        }
    }

    pub(super) unsafe fn set_hosted_file_information(
        &mut self,
        handle: u64,
        iosb: u64,
        input: u64,
        length: usize,
        information_class: u32,
        capture: &file_capture::HostedFileCapture,
    ) -> u32 {
        let route = capture.route;
        let synchronous_file = match self.file_completion.is_synchronous(route.file_id) {
            Ok(synchronous) => synchronous,
            Err(status) => return status,
        };
        if !matches!(information_class, 30 | 41)
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
        // The synchronous position fast path still needs canonical offset/sector support.
        // Until then its existing driver path preserves capture-before-event-clear ordering.
        let position_capture =
            synchronous_file && information_class == nt_fs::FILE_POSITION_INFORMATION;
        let result = (|| -> Result<(u32, u64), u32> {
            if !position_capture {
                self.file_completion.set_signaled(route.file_id, false)?;
            }
            let payload = nt_io_manager::capture_set_information_payload(length, |buffer| {
                if self.xas_read(input, buffer) {
                    Ok(())
                } else {
                    Err(nt_status::NtStatus::ACCESS_VIOLATION)
                }
            })
            .map_err(|status| status.raw() as u32)?;
            if position_capture {
                self.file_completion.set_signaled(route.file_id, false)?;
            }
            nt_io_manager::validate_set_information_value(information_class, &payload)
                .map_err(|status| status.raw() as u32)?;
            if information_class == nt_fs::FILE_SHORT_NAME_INFORMATION
                && !self.current_token_has_privilege(nt_security::SE_RESTORE)
            {
                return Err(STATUS_PRIVILEGE_NOT_HELD);
            }
            self.trace_set_information_payload(handle, information_class, &payload);
            self.execute_acquired_file_set(
                iosb,
                capture,
                synchronous_file,
                information_class,
                payload,
            )
        })();
        let status = match result {
            Ok((STATUS_PENDING, _)) => {
                assert!(
                    self.pending_file_io_transfer.is_some() && self.pending_file_io_wait,
                    "hosted SET returned pending without transferring its admitted owner"
                );
                return STATUS_PENDING;
            }
            Ok((status, information)) => {
                nt_io_manager::publish_immediate_set_iosb(status, information, |offset, bytes| {
                    if self.xas_try_write_buf(iosb + offset as u64, bytes) {
                        Ok(())
                    } else {
                        Err(nt_status::NtStatus::ACCESS_VIOLATION)
                    }
                });
                let policy = nt_io_manager::SetInformationCompletionPolicy::immediate_driver();
                if policy.signals_file(status) {
                    if information_class == 30 {
                        match self
                            .file_completion
                            .signal_on_completion_association(route.file_id)
                        {
                            Ok(true) => {
                                let _ = wait_wake_dispatcher_set(self);
                            }
                            Ok(false) => {}
                            Err(error) => {
                                self.release_file_reference(route.file_id);
                                return error;
                            }
                        }
                    } else {
                        let _ = self.signal_file_completion(route.file_id, status);
                    }
                }
                status
            }
            Err(status) => status,
        };
        self.release_file_reference(route.file_id);
        status
    }

    unsafe fn execute_acquired_file_set(
        &mut self,
        iosb: u64,
        capture: &file_capture::HostedFileCapture,
        synchronous_file: bool,
        information_class: u32,
        mut payload: Vec<u8>,
    ) -> Result<(u32, u64), u32> {
        let length = payload.len();
        let mut information = 0u64;
        let status = match information_class {
            23 if length < 8 => nt_fs::STATUS_INFO_LENGTH_MISMATCH,
            30 => {
                const IO_COMPLETION_MODIFY_STATE: u32 = 0x2;
                if length < 16 {
                    0xC000_0004 // STATUS_INFO_LENGTH_MISMATCH
                } else {
                    let file_id = capture.route.file_id;
                    if file_id == 0 {
                        0xC000_0008 // STATUS_INVALID_HANDLE
                    } else if let Err(status) = self.file_completion.can_associate(file_id) {
                        status
                    } else {
                        let port_handle = u64::from_le_bytes(payload[0..8].try_into().unwrap());
                        let key_context = u64::from_le_bytes(payload[8..16].try_into().unwrap());
                        match self.io_completion_id_for(port_handle, IO_COMPLETION_MODIFY_STATE) {
                            Err(status) => status,
                            Ok(port_id) => match self.io_completion_ports.retain(port_id) {
                                Err(status) => status,
                                Ok(()) => {
                                    let binding = nt_io_completion::FileCompletionBinding {
                                        port_id,
                                        key_context,
                                    };
                                    match self.file_completion.associate(file_id, binding) {
                                        Ok(()) => nt_io_completion::STATUS_SUCCESS,
                                        Err(status) => {
                                            self.release_io_completion_reference(port_id);
                                            status
                                        }
                                    }
                                }
                            },
                        }
                    }
                }
            }
            41 => {
                if length < 4 {
                    0xC000_0004 // STATUS_INFO_LENGTH_MISMATCH
                } else {
                    let file_id = capture.route.file_id;
                    if file_id == 0 {
                        0xC000_0008 // STATUS_INVALID_HANDLE
                    } else {
                        let flags = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                        match self.file_completion.set_notification_modes(file_id, flags) {
                            Ok(_) => nt_io_completion::STATUS_SUCCESS,
                            Err(status) => status,
                        }
                    }
                }
            }
            _ => {
                let route = capture.route;
                let mut open_parent_name = [0u16; FILE_OBJECT_NAME_CAP];
                let target = match information_class {
                    nt_fs::FILE_RENAME_INFORMATION | nt_fs::FILE_LINK_INFORMATION => {
                        match nt_fs::parse_set_file_name_information(&payload) {
                            Err(status) => Err(status),
                            Ok(set_name) => self
                                .resolve_hosted_set_file_name_target(
                                    route,
                                    set_name.root_directory,
                                    set_name.file_name,
                                    &mut open_parent_name,
                                )
                                .map(|target| {
                                    (
                                        target,
                                        nt_io_manager::SetInformationControl::ReplaceIfExists(
                                            set_name.replace_if_exists,
                                        ),
                                    )
                                }),
                        }
                    }
                    nt_fs::FILE_MOVE_CLUSTER_INFORMATION => {
                        match nt_fs::parse_move_cluster_information(&payload) {
                            Err(status) => Err(status),
                            Ok(move_cluster) => self
                                .resolve_hosted_set_file_name_target(
                                    route,
                                    move_cluster.root_directory,
                                    move_cluster.file_name,
                                    &mut open_parent_name,
                                )
                                .map(|target| {
                                    (
                                        target,
                                        nt_io_manager::SetInformationControl::ClusterCount(
                                            move_cluster.cluster_count,
                                        ),
                                    )
                                }),
                        }
                    }
                    _ => Ok((
                        HostedSetFileNameTarget::SourceParent,
                        nt_io_manager::SetInformationControl::None,
                    )),
                };
                match target {
                    Err(status) => status,
                    Ok((target, control)) => {
                        if matches!(
                            information_class,
                            nt_fs::FILE_RENAME_INFORMATION
                                | nt_fs::FILE_LINK_INFORMATION
                                | nt_fs::FILE_MOVE_CLUSTER_INFORMATION
                        ) {
                            payload[8..16].fill(0);
                        }
                        if let HostedSetFileNameTarget::OpenParent(name_len) = target {
                            let (status, completed) = match self.dispatch_acquired_set_file_name(
                                iosb,
                                capture,
                                synchronous_file,
                                information_class,
                                control,
                                &open_parent_name[..name_len],
                                payload,
                            ) {
                                Ok(result) => result,
                                Err(status) => return Err(status),
                            };
                            information = completed;
                            if status == STATUS_PENDING {
                                return Ok((STATUS_PENDING, 0));
                            }
                            status
                        } else {
                            let target_file = match target {
                                HostedSetFileNameTarget::SourceParent => None,
                                HostedSetFileNameTarget::Canonical(file_id) => Some(file_id),
                                HostedSetFileNameTarget::OpenParent(_) => unreachable!(),
                            };
                            let parameters = nt_io_manager::SetInformationParameters {
                                info_class: information_class,
                                length: length as u32,
                                target_file: target_file.map(nt_io_abi::FileId),
                                control,
                            };
                            let (status, completed) = match self.dispatch_acquired_set_information(
                                iosb,
                                capture,
                                synchronous_file,
                                parameters,
                                &payload,
                            ) {
                                Ok(result) => result,
                                Err(status) => return Err(status),
                            };
                            information = completed;
                            if status == STATUS_PENDING {
                                return Ok((STATUS_PENDING, 0));
                            }
                            status
                        }
                    }
                }
            }
        };

        Ok((status, information))
    }

    unsafe fn dispatch_acquired_set_information(
        &mut self,
        iosb: u64,
        capture: &file_capture::HostedFileCapture,
        synchronous_file: bool,
        parameters: nt_io_manager::SetInformationParameters,
        input: &[u8],
    ) -> Result<(u32, u64), u32> {
        let route = capture.route;
        let file_id = route.file_id;
        let (mut status, mut information, pending_irp_id) =
            match self.dispatch_hosted_file_set_information_for(route, parameters, input) {
                Ok((driver_status, completed, irp_id)) => (driver_status as u32, completed, irp_id),
                Err(route_status) => (route_status, 0, 0),
            };
        if status == STATUS_PENDING {
            if pending_irp_id == 0 {
                status = nt_io_completion::STATUS_INSUFFICIENT_RESOURCES;
                information = 0;
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
        }
        Ok((status, information))
    }

    /// Execute the I/O Manager's internal target-parent open before a provider rename, link, or
    /// move-cluster request. The source File reference and synchronous Busy lock are retained across
    /// either pending IRP; the target File remains kernel-only and is released after the source SET
    /// reaches a terminal result.
    unsafe fn dispatch_acquired_set_file_name(
        &mut self,
        iosb: u64,
        capture: &file_capture::HostedFileCapture,
        synchronous_file: bool,
        information_class: u32,
        control: nt_io_manager::SetInformationControl,
        target_name: &[u16],
        payload: Vec<u8>,
    ) -> Result<(u32, u64), u32> {
        let route = capture.route;
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
        let Some(transaction_reservation) = self.reserve_pending_set_file_name_owner() else {
            return Err(nt_io_completion::STATUS_INSUFFICIENT_RESOURCES);
        };
        let Some(transaction) = nt_io_manager::PendingSetFileName::awaiting_source_query(
            route.file_id,
            information_class,
            control,
            target_name_bytes,
            payload,
        ) else {
            (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                .cancel_reservation(transaction_reservation);
            return Err(nt_fs::STATUS_INVALID_PARAMETER);
        };
        let source_owner = match driver_launch::hosted_file_capture::capture_owned(
            route.file_id,
            route.device_id,
            capture.granted_access,
        ) {
            Ok(owner) => owner,
            Err(status) => {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                return Err(status);
            }
        };
        let mut transaction = transaction.with_source_owner(source_owner);

        let source_create_options = match driver_launch::owned_hosted_file_metadata(route.file_id) {
            Ok(metadata) if metadata.device_id.raw() == route.device_id => metadata.create_options,
            result => {
                let status = match result {
                    Ok(_) => nt_fs::STATUS_INVALID_HANDLE,
                    Err(status) => status,
                };
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                return Err(status);
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
                    return Ok((nt_io_completion::STATUS_INSUFFICIENT_RESOURCES, 0));
                };
                pending_irp = Some(irp_id);
                None
            } else if (status as i32) < 0 {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                return Ok((status, information));
            } else if information < FILE_BASIC_INFORMATION_LEN as u64 {
                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .cancel_reservation(transaction_reservation);
                return Ok((nt_fs::STATUS_INFO_LENGTH_MISMATCH, 0));
            } else {
                match nt_fs::parse_file_basic_information_attributes(&basic) {
                    Ok(attributes) => Some(attributes & nt_fs::FILE_ATTRIBUTE_DIRECTORY != 0),
                    Err(status) => {
                        (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                            .cancel_reservation(transaction_reservation);
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
                return Ok((status, information));
            }
        }

        let Some(pending_irp) = pending_irp else {
            (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                .cancel_reservation(transaction_reservation);
            if target_file_id != 0 {
                let _ = driver_launch::abandon_unpublished_hosted_file(target_file_id);
            }
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
