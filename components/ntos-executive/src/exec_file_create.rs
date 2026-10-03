//! Native NtCreateFile input admission and finalized output publication.

use super::*;

impl ExecNtHandler {
    pub(super) unsafe fn nt_create_file_service(&mut self, args: &[u64]) -> u32 {
        let file_handle_out = args[0];
        let desired_access = nt_ulong_arg(args[1]);
        let file_attributes = nt_ulong_arg(args[5]);
        let share_access = nt_ulong_arg(args[6]);
        let create_disposition = nt_ulong_arg(args[7]);
        let create_options = nt_ulong_arg(args[8]);
        if let Err(status) = nt_fs::validate_file_create_parameters(
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
        ) {
            return status;
        }
        let iosb = args[3];
        if let Err(status) = self.probe_copy_output(self.pi, file_handle_out, 8) {
            return status;
        }
        if let Err(status) = self.probe_file_io_output(iosb, None) {
            return status;
        }
        if args[4] != 0 {
            let mut allocation_size = [0u8; 8];
            if let Err(status) = self.process_memory_read_status(self.pi, args[4], &mut allocation_size) {
                return status;
            }
            if i64::from_le_bytes(allocation_size) < 0 {
                return STATUS_INVALID_PARAMETER;
            }
        }
        let ea_length = nt_ulong_arg(args[10]) as usize;
        let ea = if args[9] != 0 && ea_length != 0 {
            let mut bytes = match try_zeroed_transfer_buffer(ea_length) {
                Ok(bytes) => bytes,
                Err(status) => return status,
            };
            if let Err(status) = self.process_memory_read_status(self.pi, args[9], &mut bytes) {
                return status;
            }
            if let Err(error) = nt_io_manager::validate_ea_buffer(&bytes) {
                const STATUS_EA_LIST_INCONSISTENT: u32 = 0x8000_0014;
                return match self.publish_file_create_result(
                    file_handle_out, iosb, 0, STATUS_EA_LIST_INCONSISTENT, error.offset as u64,
                ) {
                    Ok(()) => STATUS_EA_LIST_INCONSISTENT,
                    Err(status) => status,
                };
            }
            bytes
        } else {
            alloc::vec::Vec::new()
        };
        let captured = match self.capture_file_object_attributes(args[2]) {
            Ok(captured) => captured,
            Err(status) => return status,
        };
        let parse_root = match self.resolve_file_parse_root(&captured) {
            Ok(root) => root,
            Err(status) => return status,
        };
        let mut namespace_path = [0u8; NAMED_OBJECT_PATH_CAP];
        let mut absolute_name = [0u16; FILE_OBJECT_NAME_CAP];
        let (parse_root, name16) = match self.normalize_object_directory_file_name(
            parse_root,
            captured.name(),
            &mut namespace_path,
            &mut absolute_name,
        ) {
            Ok(resolved) => resolved,
            Err(status) => return status,
        };
        if !NT_CREATE_FILE_FRONTIER_TRACED.swap(true, Ordering::Relaxed) {
            print_str(b"[nt-create-file-frontier] pi=");
            print_u64(self.pi as u64);
            print_str(b" access=0x");
            print_hex(desired_access);
            print_str(b" attrs=0x");
            print_hex(file_attributes);
            print_str(b" share=0x");
            print_hex(share_access);
            print_str(b" disposition=0x");
            print_hex(create_disposition);
            print_str(b" options=0x");
            print_hex(create_options);
            print_str(b" name=\"");
            for &unit in name16.iter().take(160) {
                debug_put_char(if (0x20..0x7f).contains(&unit) {
                    unit as u8
                } else {
                    b'?'
                });
            }
            print_str(b"\"\n");
        }
        if !matches!(parse_root, FileParseRoot::Absolute) {
            if let FileParseRoot::HostedFile { file_id, device_id } = parse_root {
                if name16.first() == Some(&(b'\\' as u16)) {
                    return STATUS_OBJECT_NAME_INVALID;
                }
                if driver_launch::require_registered_kernel_filesystem_device(device_id)
                    .is_ok()
                {
                    return self.create_registered_kernel_file(
                        parse_root,
                        name16,
                        captured.attributes,
                        desired_access,
                        share_access,
                        create_disposition,
                        file_attributes,
                        create_options,
                        &ea,
                        file_handle_out,
                        iosb,
                    );
                }
                if driver_launch::device_id_by_name("\\Device\\NamedPipe")
                    != Some(device_id)
                {
                    return STATUS_INVALID_DEVICE_REQUEST;
                }
                if create_disposition != nt_fs::FILE_OPEN {
                    return STATUS_INVALID_PARAMETER;
                }
                if create_options & nt_fs::FILE_DIRECTORY_FILE != 0 {
                    return nt_fs::STATUS_OBJECT_NAME_COLLISION;
                }
                let provider_context = nt_io_manager::pipe_name_hash(name16);
                let dispatch = self.npfs_create_file(
                    major::IRP_MJ_CREATE,
                    name16,
                    Some(file_id),
                    captured.attributes,
                    provider_context,
                    desired_access,
                    share_access,
                    create_disposition,
                    file_attributes,
                    create_options,
                    &ea,
                    file_handle_out,
                    iosb,
                );
                let publication = match dispatch {
                    Ok(dispatch) => self.finish_registered_create_dispatch(
                        dispatch,
                        major::IRP_MJ_CREATE,
                        desired_access,
                        provider_context,
                    ),
                    Err(status) => Some(HostedCreatePublication {
                        status,
                        information: 0,
                        handle: 0,
                        wake_server_fid: 0,
                    }),
                };
                let Some(publication) = publication else {
                    return STATUS_PENDING;
                };
                self.pipe_endpoint_progress |= publication.wake_server_fid != 0;
                return match self.publish_file_create_result(
                    file_handle_out, iosb, publication.handle, publication.status, publication.information,
                ) {
                    Ok(()) => publication.status,
                    Err(status) => status,
                };
            }
            let (status, information, handle) = self.create_local_file_relative(
                parse_root,
                name16,
                desired_access,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
            );
            return match self.publish_file_create_result(file_handle_out, iosb, handle, status, information) {
                Ok(()) => status,
                Err(status) => status,
            };
        }
        if create_options & nt_fs::FILE_DIRECTORY_FILE != 0
            && !Self::is_named_pipe_root_path(name16)
            && !nt_fs::is_named_pipe_path(name16)
        {
            return self.create_registered_kernel_file(
                parse_root,
                name16,
                captured.attributes,
                desired_access,
                share_access,
                create_disposition,
                file_attributes,
                create_options,
                &ea,
                file_handle_out,
                iosb,
            );
        }
        let mut status;
        let mut info = 0u64;
        let mut opened_handle = 0;
        let mut pending_pipe_create = false;
        let mut volume_folded = [0u8; FILE_OBJECT_NAME_CAP];
        let mut volume_relative = [0u8; FILE_VOLUME_RELATIVE_CAP];
        let volume_relative_len = crate::writable_fs::volume_path_into(
            name16,
            &mut volume_folded,
            &mut volume_relative,
        );
        let mut writable_folded = [0u8; FILE_OBJECT_NAME_CAP];
        let mut writable_relative = [0u8; FILE_VOLUME_RELATIVE_CAP];
        let writable_relative_len = crate::writable_fs::writable_path_into(
            name16,
            &mut writable_folded,
            &mut writable_relative,
        );
        if let Some(length) = writable_relative_len {
            if let Err(status) = crate::writable_fs::query_metadata_relative(
                &writable_relative[..length],
            ) {
                return status;
            }
        }
        let volume_overlay_hit = match volume_relative_len {
            Some(length) => match crate::writable_fs::query_metadata_relative_if_mounted(
                &volume_relative[..length],
            ) {
                Ok(info) => info.is_some(),
                Err(status) => {
                    return status;
                }
            },
            None => false,
        };
        if Self::is_named_pipe_root_path(name16) {
            if create_disposition != nt_fs::FILE_OPEN {
                status = nt_fs::STATUS_INVALID_PARAMETER;
            } else {
                let root_name = [b'\\' as u16];
                let dispatch = self.npfs_create_file(
                    major::IRP_MJ_CREATE,
                    &root_name,
                    None,
                    captured.attributes,
                    0,
                    desired_access,
                    share_access,
                    create_disposition,
                    file_attributes,
                    create_options,
                    &ea,
                    file_handle_out,
                    iosb,
                );
                let publication = match dispatch {
                    Ok(dispatch) => self.finish_registered_create_dispatch(
                        dispatch,
                        major::IRP_MJ_CREATE,
                        desired_access,
                        0,
                    ),
                    Err(route_status) => Some(HostedCreatePublication {
                        status: route_status,
                        information: 0,
                        handle: 0,
                        wake_server_fid: 0,
                    }),
                };
                if let Some(publication) = publication {
                    status = publication.status;
                    info = publication.information;
                    opened_handle = publication.handle;
                    self.pipe_endpoint_progress |= publication.wake_server_fid != 0;
                } else {
                    status = STATUS_PENDING;
                    pending_pipe_create = true;
                }
            }
        } else if nt_fs::is_named_pipe_path(name16) {
            if create_disposition != nt_fs::FILE_OPEN {
                status = nt_fs::STATUS_INVALID_PARAMETER;
            } else if create_options & nt_fs::FILE_DIRECTORY_FILE != 0 {
                status = nt_fs::STATUS_OBJECT_NAME_COLLISION;
            } else {
                let mut leaf_buf = [0u16; FILE_OBJECT_NAME_CAP + 1];
                let Some(leaf_len) = Self::pipe_leaf16_into(name16, &mut leaf_buf) else {
                    return STATUS_OBJECT_NAME_INVALID;
                };
                let leaf = &leaf_buf[..leaf_len];
                let pipe_hash = nt_io_manager::pipe_name_hash(leaf);
                let dispatch = self.npfs_create_file(
                    major::IRP_MJ_CREATE,
                    leaf,
                    None,
                    captured.attributes,
                    pipe_hash,
                    desired_access,
                    share_access,
                    create_disposition,
                    file_attributes,
                    create_options,
                    &ea,
                    file_handle_out,
                    iosb,
                );
                let publication = match dispatch {
                    Ok(dispatch) => self.finish_registered_create_dispatch(
                        dispatch,
                        major::IRP_MJ_CREATE,
                        desired_access,
                        pipe_hash,
                    ),
                    Err(route_status) => Some(HostedCreatePublication {
                        status: route_status,
                        information: 0,
                        handle: 0,
                        wake_server_fid: 0,
                    }),
                };
                if let Some(publication) = publication {
                    status = publication.status;
                    info = publication.information;
                    opened_handle = publication.handle;
                    self.pipe_endpoint_progress |= publication.wake_server_fid != 0;
                } else {
                    status = STATUS_PENDING;
                    pending_pipe_create = true;
                }
            }
        } else if let Some((relative, source)) = volume_relative_len
            .filter(|_| !volume_overlay_hit)
            .and_then(|length| {
                Self::readonly_volume_metadata(name16)
                    .filter(|entry| !entry.metadata.is_directory)
                    .map(|entry| (&volume_relative[..length], entry))
            })
        {
            let (open_status, information, handle) = self.open_installed_file(
                source,
                relative,
                desired_access,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
            );
            status = open_status;
            info = information;
            opened_handle = handle;
        } else if let Some(relative_len) = writable_relative_len {
            let relative = &writable_relative[..relative_len];
            // ★ THE WRITABLE FILESYSTEM OVERLAY. The path resolved into a declared writable
            // mount prefix (see `writable_fs::WRITABLE_PREFIXES`) — this is the boundary the
            // previous batch's unserved namespace miss left open, and it is where
            // `CreateDirectoryW("C:\Profiles")` (userenv/profile.c:929) now lands. The
            // disposition, `FILE_DIRECTORY_FILE`, and `FileAttributes` are passed straight
            // through to a REAL file system: a create that cannot be satisfied still fails
            // with the correct NTSTATUS, and no handle is fabricated.
            let (st, file_id, information) = crate::writable_fs::create(
                relative,
                desired_access,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
            );
            status = st;
            info = information;
            if file_id.is_some() {
                self.writable_fs_dirty = true;
            }
            if create_options & nt_fs::FILE_DIRECTORY_FILE != 0 {
                if status == nt_fs::STATUS_SUCCESS && info == nt_fs::FILE_CREATED as u64 {
                    crate::writable_fs::note_directory_create(self.pi, relative, true);
                } else if status == nt_fs::STATUS_OBJECT_NAME_COLLISION {
                    crate::writable_fs::note_directory_create(self.pi, relative, false);
                }
            } else if status == nt_fs::STATUS_SUCCESS && info == nt_fs::FILE_CREATED as u64
            {
                crate::writable_fs::note_profile_file_create(self.pi, relative);
            }
            if let Some(file_id) = file_id {
                match self.mint_overlay_file_handle(file_id, desired_access) {
                    Some(handle) => opened_handle = handle,
                    None => {
                        status = 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                        info = 0;
                    }
                }
            }
        } else if let Some(relative) = volume_relative_len
            .filter(|_| create_disposition != nt_fs::FILE_OPEN || volume_overlay_hit)
            .map(|length| &volume_relative[..length])
        {
            let disposition = create_disposition;
            let options = create_options;
            if disposition == nt_fs::FILE_OPEN {
                let (st, file_id, information) =
                    crate::writable_fs::open_existing_relative_if_mounted(
                        relative,
                        desired_access,
                        file_attributes,
                        share_access,
                        options,
                    );
                status = st;
                info = information;
                if let Some(file_id) = file_id {
                    self.writable_fs_dirty = true;
                    match self.mint_overlay_file_handle(file_id, desired_access) {
                        Some(handle) => opened_handle = handle,
                        None => {
                            status = 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                            info = 0;
                        }
                    }
                }
            } else if disposition == nt_fs::FILE_CREATE
                && Self::readonly_volume_entry(name16).is_some()
            {
                status = nt_fs::STATUS_OBJECT_NAME_COLLISION;
            } else {
                if let Some(parent) = Self::volume_relative_parent(relative) {
                    if Self::readonly_volume_relative_is_dir(parent) {
                        match crate::writable_fs::ensure_installed_directory_relative(parent)
                        {
                            Ok(true) => self.writable_fs_dirty = true,
                            Ok(false) => {}
                            Err(status) => {
                                return status;
                            }
                        }
                    }
                }
                let (st, file_id, information) = crate::writable_fs::create(
                    relative,
                    desired_access,
                    file_attributes,
                    share_access,
                    disposition,
                    options,
                );
                status = st;
                info = information;
                if file_id.is_some() {
                    self.writable_fs_dirty = true;
                }
                if options & nt_fs::FILE_DIRECTORY_FILE != 0 {
                    if status == nt_fs::STATUS_SUCCESS && info == nt_fs::FILE_CREATED as u64
                    {
                        crate::writable_fs::note_directory_create(self.pi, relative, true);
                    } else if status == nt_fs::STATUS_OBJECT_NAME_COLLISION {
                        crate::writable_fs::note_directory_create(self.pi, relative, false);
                    }
                } else if status == nt_fs::STATUS_SUCCESS
                    && info == nt_fs::FILE_CREATED as u64
                {
                    crate::writable_fs::note_profile_file_create(self.pi, relative);
                }
                if let Some(file_id) = file_id {
                    match self.mint_overlay_file_handle(file_id, desired_access) {
                        Some(handle) => opened_handle = handle,
                        None => {
                            status = 0xC000_009A; // STATUS_INSUFFICIENT_RESOURCES
                            info = 0;
                        }
                    }
                }
            }
        } else if create_disposition == nt_fs::FILE_OPEN {
            if let Some(miss_status) = Self::readonly_disk_open_miss_status(name16) {
                status = miss_status;
            } else {
                status = self.unserved_nt_create_file_namespace(name16);
            }
        } else {
            status = self.unserved_nt_create_file_namespace(name16);
        }
        if pending_pipe_create {
            return STATUS_PENDING;
        }
        if let Err(status) = self.publish_file_create_result(file_handle_out, iosb, opened_handle, status, info) {
            return status;
        }
        if nt_fs::is_named_pipe_path(name16)
            && (self.pi == 2 || self.pi == 3 || self.pi == 7)
        {
            let trace = PIPE_CREATE_TRACE_N.fetch_add(1, Ordering::Relaxed);
            if trace < 64 || status != nt_fs::STATUS_SUCCESS {
                print_str(b"[pipe-create] #");
                print_u64(trace);
                print_str(b" pi=");
                print_u64(self.pi as u64);
                print_str(b" badge=");
                print_u64(self.current_badge);
                print_str(b" tid=");
                print_u64(self.current_tid);
                print_str(b" access=0x");
                print_hex(desired_access);
                print_str(b" share=0x");
                print_hex(share_access);
                print_str(b" disposition=0x");
                print_hex(create_disposition);
                print_str(b" options=0x");
                print_hex(create_options);
                print_str(b" status=0x");
                print_hex(status);
                print_str(b" info=");
                print_u64(info);
                print_str(b" name=\"");
                for &unit in name16.iter().take(96) {
                    debug_put_char(if (0x20..0x7f).contains(&unit) {
                        unit as u8
                    } else {
                        b'?'
                    });
                }
                print_str(b"\"\n");
            }
        }
        if self.current_process_is_winlogon()
            && NT_CREATE_FILE_WINLOGON_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 40
        {
            print_str(b"[nt-create-file-winlogon] status=0x");
            print_hex(status);
            print_str(b" info=");
            print_u64(info);
            print_str(b" name=\"");
            for &unit in name16.iter().take(96) {
                debug_put_char(if (0x20..0x7f).contains(&unit) {
                    unit as u8
                } else {
                    b'?'
                });
            }
            print_str(b"\"\n");
        }
        status
    }
}
