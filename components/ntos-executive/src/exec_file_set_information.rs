//! Local SET mutations complete once; their result and File reference outlive user delivery.

use super::*;

impl ExecNtHandler {
    /// The caller captures the payload and checks class/access/IOSB before routing local Files.
    pub(super) unsafe fn try_set_local_file_information(
        &mut self,
        handle: u64,
        iosb: u64,
        information_class: u32,
        payload: &[u8],
    ) -> Option<u32> {
        let pid = self.pm_pid_for_pi(self.pi)?;
        let process_handle = nt_process::Handle::try_from(handle).ok()?;
        match self.pm.lookup_handle(pid, process_handle)? {
            nt_process::HandleObject::OverlayFile(_) => {}
            nt_process::HandleObject::DiskFile { .. }
                if information_class == nt_fs::FILE_POSITION_INFORMATION => {}
            _ => return None,
        }
        let route = match self.local_file_io_route_for(handle) {
            Ok(Some(route)) => route,
            Ok(None) => unreachable!("local SET File lost its typed route"),
            Err(status) => return Some(status),
        };
        let policy =
            nt_io_manager::LocalSetInformationPolicy::capture(information_class, route.synchronous);
        let value = nt_io_manager::validate_local_set_information_value(information_class, payload);
        if !policy.resets_file_signal() {
            if let Err(status) = value {
                return Some(status.raw() as u32);
            }
        }
        let request_id = match self.reserve_local_file_io_delivery() {
            Ok(request_id) => request_id,
            Err(status) => return Some(status),
        };
        let retained = if policy.resets_file_signal() {
            self.begin_local_file_io(route.file_object)
        } else {
            self.retain_local_file_io_reference(route.file_object)
        };
        if let Err(status) = retained {
            return Some(status);
        }
        // Ordinary SET validation failure leaves the already-reset File event unsignaled.
        // No user-memory access or delivery retry may repeat the accepted mutation below.
        let status = match value {
            Err(status) => status.raw() as u32,
            Ok(()) => match route.file_object & !LOCAL_ID_PAYLOAD_MASK {
                LOCAL_OVERLAY_FILE_OBJECT_TAG => {
                    let status = self.set_overlay_file_information(
                        route.file_object & LOCAL_ID_PAYLOAD_MASK,
                        information_class,
                        payload,
                    );
                    if status == nt_fs::STATUS_SUCCESS {
                        self.writable_fs_dirty = true;
                    }
                    status
                }
                LOCAL_FAT_FILE_OBJECT_TAG => {
                    self.readonly_file_opens
                        .get_mut((route.file_object & LOCAL_ID_PAYLOAD_MASK) as u32)
                        .expect("retained FAT File disappeared during position SET")
                        .current_offset = u64::from_le_bytes(payload[..8].try_into().unwrap());
                    nt_fs::STATUS_SUCCESS
                }
                _ => unreachable!("local SET admitted an unsupported File kind"),
            },
        };
        assert_ne!(
            status, STATUS_PENDING,
            "local SET backend unexpectedly pended"
        );
        assert!(self.pending_file_io_transfer.is_none());
        self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
            file_id: route.file_object,
            irp_id: request_id,
            major: major::IRP_MJ_SET_INFORMATION,
            operation: nt_io_manager::PendingFileIoOperation::LocalInline(
                nt_io_manager::PendingLocalInline {
                    status,
                    information: 0,
                },
            ),
            pi: self.pi as u32,
            tid: self.current_tid,
            badge: self.current_badge,
            iosb_va: if policy.publishes_iosb(status) {
                iosb
            } else {
                0
            },
            signal_file: policy.signals_file(status),
            completion_port_suppressed: true,
            event_obj_idx: u64::MAX,
            ..nt_io_manager::PendingFileIo::default()
        });
        self.pending_file_io_wait = true;
        Some(STATUS_PENDING)
    }

    unsafe fn set_overlay_file_information(
        &mut self,
        file_id: u64,
        information_class: u32,
        payload: &[u8],
    ) -> u32 {
        if !matches!(
            information_class,
            nt_fs::FILE_RENAME_INFORMATION | nt_fs::FILE_LINK_INFORMATION
        ) {
            return crate::writable_fs::set_information(file_id, information_class, payload);
        }
        let set_name = match nt_fs::parse_set_file_name_information(payload) {
            Ok(set_name) => set_name,
            Err(status) => return status,
        };
        let mut target = [0u8; FILE_VOLUME_RELATIVE_CAP * 2];
        let (root, target_len) = match self.resolve_local_set_file_name_target(
            set_name.root_directory,
            set_name.file_name,
            &mut target,
        ) {
            Ok(target) => target,
            Err(status) => return status,
        };
        if information_class == nt_fs::FILE_RENAME_INFORMATION {
            crate::writable_fs::rename(
                file_id,
                root,
                &target[..target_len],
                set_name.replace_if_exists,
            )
        } else {
            crate::writable_fs::link(
                file_id,
                root,
                &target[..target_len],
                set_name.replace_if_exists,
            )
        }
    }
}
