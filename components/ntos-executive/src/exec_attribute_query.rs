//! Name-based installed-file metadata after the physical volume enters native routing.
//!
//! The temporary File is never made process-visible. Its CREATE and QUERY_INFORMATION retain
//! the same native caller, File identity and pending syscall owner through exact completion.

use super::*;

const ATTRIBUTE_READ_ACCESS: u32 = 0x0000_0080; // FILE_READ_ATTRIBUTES
const ATTRIBUTE_SHARE_ALL: u32 = 0x0000_0007;

struct ReleaseOwner { token: u64, file_id: Option<u64> }
static mut RELEASE_OWNERS: alloc::vec::Vec<ReleaseOwner> = alloc::vec::Vec::new();
static NEXT_RELEASE_TOKEN: AtomicU64 = AtomicU64::new(1);

fn reserve_release_owner() -> Option<u64> {
    let owners = unsafe { &mut *core::ptr::addr_of_mut!(RELEASE_OWNERS) };
    owners.try_reserve(1).ok()?;
    let token = NEXT_RELEASE_TOKEN.fetch_add(1, Ordering::Relaxed);
    if token == 0 { return None; }
    owners.push(ReleaseOwner { token, file_id: None });
    Some(token)
}

fn finish_release_owner(token: u64) {
    let owners = unsafe { &mut *core::ptr::addr_of_mut!(RELEASE_OWNERS) };
    let index = owners.iter().position(|owner| owner.token == token)
        .expect("attribute File release reservation disappeared");
    owners.swap_remove(index);
}

fn release_or_retain(token: u64, file_id: u64) {
    if driver_launch::abandon_unpublished_hosted_file(file_id).is_ok() {
        finish_release_owner(token);
    } else {
        let owners = unsafe { &mut *core::ptr::addr_of_mut!(RELEASE_OWNERS) };
        let owner = owners.iter_mut().find(|owner| owner.token == token)
            .expect("attribute File release owner disappeared");
        assert!(owner.file_id.is_none());
        owner.file_id = Some(file_id);
    }
}

/// Retry only a known zero-effect queue refusal; the generational File remains owned until
/// the I/O Manager accepts its CLEANUP/CLOSE intent. Never replay a provider operation.
pub(crate) fn retry_attribute_releases() -> usize {
    let mut released = 0;
    let mut index = 0;
    loop {
        let candidate = unsafe { (&*core::ptr::addr_of!(RELEASE_OWNERS))
            .get(index).map(|owner| (owner.token, owner.file_id)) };
        let Some((token, file_id)) = candidate else { break; };
        let Some(file_id) = file_id else { index += 1; continue; };
        // queue_external_file_release validates and reserves before it mutates File/IRP state;
        // its Err is a known no-effect refusal. Never retry a provider invocation here.
        if driver_launch::abandon_unpublished_hosted_file(file_id).is_ok() {
            let owners = unsafe { &mut *core::ptr::addr_of_mut!(RELEASE_OWNERS) };
            if let Some(position) = owners.iter().position(|owner|
                owner.token == token && owner.file_id == Some(file_id)) {
                owners.swap_remove(position);
                released += 1;
                if position < index { index -= 1; }
            }
        } else { index += 1; }
    }
    released
}

impl ExecNtHandler {
    /// Called only after the writable layer has missed. A `None` result keeps the Boot reader.
    pub(super) unsafe fn query_native_mounted_attributes(
        &mut self,
        name: &[u16],
        object_attributes: u32,
        information_class: u32,
        output_va: u64,
    ) -> Option<u32> {
        let route = unsafe { crate::fs_loader::exec_fs_mount_identity() }
            .and_then(crate::fs_loader::exec_block_route_kind);
        let journal_owned = crate::writable_fs::registry_journal::owns_volume();
        if route == Some(nt_fs::BlockSourceKind::Boot) && !journal_owned { return None; }
        let mut folded = [0u8; FILE_OBJECT_NAME_CAP];
        let mut relative_path = [0u8; FILE_VOLUME_RELATIVE_CAP];
        if crate::writable_fs::volume_path_into(name, &mut folded, &mut relative_path).is_none() {
            smss_attribute_probe_trace::trace_smss_attribute_resolution(
                self.pi, self.current_tid, name, None, nt_fs::STATUS_OBJECT_NAME_NOT_FOUND,
            );
            return Some(nt_fs::STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let device_id = match crate::mounted_volume::exec_volume_device() {
            Some(device) => device,
            None => {
                smss_attribute_probe_trace::trace_smss_attribute_resolution(
                    self.pi, self.current_tid, name, None, STATUS_DEVICE_NOT_READY,
                );
                return Some(STATUS_DEVICE_NOT_READY);
            }
        };
        let (resolved_device, relative) = match driver_launch::resolve_kernel_directory_file_name(
            name, object_attributes & 0x40 != 0,
        ) {
            Ok(target) => target,
            Err(status) => {
                smss_attribute_probe_trace::trace_smss_attribute_resolution(
                    self.pi, self.current_tid, name, None, status,
                );
                return Some(status);
            }
        };
        if resolved_device != device_id {
            smss_attribute_probe_trace::trace_smss_attribute_resolution(
                self.pi, self.current_tid, name,
                Some((resolved_device, &relative)), nt_fs::STATUS_NOT_SAME_DEVICE,
            );
            return Some(nt_fs::STATUS_NOT_SAME_DEVICE);
        }
        smss_attribute_probe_trace::trace_smss_attribute_resolution(
            self.pi, self.current_tid, name, Some((device_id, &relative)), nt_fs::STATUS_SUCCESS,
        );
        self.query_mounted_attributes_on_target(
            device_id, &relative, object_attributes, information_class, output_va,
        )
    }

    /// Query a validated target on the exact mounted File device. The caller owns the
    /// namespace or legacy-directory identity proof before entering this retained IRP path.
    pub(super) unsafe fn query_mounted_attributes_on_target(
        &mut self,
        device_id: u64,
        relative: &[u16],
        object_attributes: u32,
        information_class: u32,
        output_va: u64,
    ) -> Option<u32> {
        let trace_pi = self.pi;
        let trace_tid = self.current_tid;
        let report_failure = |stage: &[u8], status: u32, file_id: u64| {
            if (status as i32) < 0 {
                smss_attribute_probe_trace::trace_smss_attribute_target(
                    trace_pi, trace_tid, device_id, relative, file_id, None, stage, status,
                );
            }
        };
        let output_len = match information_class {
            nt_fs::FILE_BASIC_INFORMATION => 40,
            nt_fs::FILE_NETWORK_OPEN_INFORMATION => 56,
            _ => {
                report_failure(b"class", nt_fs::STATUS_INVALID_PARAMETER, 0);
                return Some(nt_fs::STATUS_INVALID_PARAMETER);
            }
        };
        if !self.probe_user_output(output_va, output_len) {
            report_failure(b"output", STATUS_ACCESS_VIOLATION, 0);
            return Some(STATUS_ACCESS_VIOLATION);
        }
        if !self.reserve_pending_file_io_owner()
            || REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0
            || !wait_reply_pool_has_free()
        {
            report_failure(b"owner-capacity", STATUS_INSUFFICIENT_RESOURCES, 0);
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
        let Some(release_token) = reserve_release_owner() else {
            report_failure(b"release-capacity", STATUS_INSUFFICIENT_RESOURCES, 0);
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        };
        let file_id = match driver_launch::allocate_hosted_file(
            device_id, ATTRIBUTE_READ_ACCESS, ATTRIBUTE_SHARE_ALL, 0, &relative,
        ) {
            Ok(file) => file,
            Err(status) => {
                smss_attribute_probe_trace::trace_smss_attribute_resolution(
                    self.pi, self.current_tid, relative, Some((device_id, relative)), status,
                );
                finish_release_owner(release_token);
                return Some(status);
            }
        };
        let caller = match self.hosted_file_native_caller() {
            Ok(caller) => caller,
            Err(status) => {
                report_failure(b"caller", status, file_id);
                release_or_retain(release_token, file_id);
                return Some(status);
            }
        };
        let mut name_bytes = alloc::vec::Vec::new();
        if name_bytes.try_reserve_exact(relative.len() * 2).is_err() {
            report_failure(b"name-capacity", STATUS_INSUFFICIENT_RESOURCES, file_id);
            release_or_retain(release_token, file_id);
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
        for &unit in relative { name_bytes.extend_from_slice(&unit.to_le_bytes()); }
        let created = driver_launch::dispatch_hosted_file_create_irp_result_exact(
            file_id,
            major::IRP_MJ_CREATE,
            caller,
            nt_io_manager::CreateParameters {
                opened_case_sensitive: object_attributes & 0x40 == 0,
                desired_access: nt_types::AccessMask::from_bits_retain(ATTRIBUTE_READ_ACCESS),
                share_access: nt_io_manager::ShareAccess::from_bits_retain(ATTRIBUTE_SHARE_ALL),
                create_options: nt_io_manager::CreateOptions::empty(),
                create_disposition: nt_fs::FILE_OPEN,
                file_attributes: 0,
                ea_length: 0,
                related_file: None,
            },
            &name_bytes,
        );
        let (status, _, pending_irp, _) = match created {
            Ok(result) => result,
            Err(status) => {
                smss_attribute_probe_trace::trace_smss_attribute_target(
                    self.pi, self.current_tid, device_id, relative, file_id, None,
                    b"create", status,
                );
                release_or_retain(release_token, file_id);
                return Some(status);
            }
        };
        smss_attribute_probe_trace::trace_smss_attribute_target(
            self.pi, self.current_tid, device_id, relative, file_id,
            pending_irp.as_ref().map(|irp| irp.raw()), b"create", status as u32,
        );
        if status == STATUS_PENDING as i32 && pending_irp.is_none() {
            report_failure(b"create-pending-owner", STATUS_INSUFFICIENT_RESOURCES, file_id);
            release_or_retain(release_token, file_id);
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
        if let Some(irp) = pending_irp {
            finish_release_owner(release_token);
            self.park_native_attribute_query(file_id, irp.raw(), major::IRP_MJ_CREATE,
                information_class, output_va, output_len as u32);
            return Some(STATUS_PENDING);
        }
        if status < 0 {
            release_or_retain(release_token, file_id);
            return Some(status as u32);
        }
        let mut output = [0u8; 56];
        let queried = driver_launch::dispatch_hosted_file_irp_result_exact(
            file_id, major::IRP_MJ_QUERY_INFORMATION as u64, information_class as u64,
            caller, &[], &mut output[..output_len], 0,
        );
        let (status, information, pending_irp, _) = match queried {
            Ok(result) => result,
            Err(status) => {
                smss_attribute_probe_trace::trace_smss_attribute_target(
                    self.pi, self.current_tid, device_id, relative, file_id, None,
                    b"query", status,
                );
                release_or_retain(release_token, file_id);
                return Some(status);
            }
        };
        smss_attribute_probe_trace::trace_smss_attribute_target(
            self.pi, self.current_tid, device_id, relative, file_id,
            pending_irp.as_ref().map(|irp| irp.raw()), b"query", status as u32,
        );
        if status == STATUS_PENDING as i32 && pending_irp.is_none() {
            report_failure(b"query-pending-owner", STATUS_INSUFFICIENT_RESOURCES, file_id);
            release_or_retain(release_token, file_id);
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
        if let Some(irp) = pending_irp {
            finish_release_owner(release_token);
            self.park_native_attribute_query(file_id, irp.raw(), major::IRP_MJ_QUERY_INFORMATION,
                information_class, output_va, output_len as u32);
            return Some(STATUS_PENDING);
        }
        let terminal = if status >= 0 && information != output_len as u64 {
            nt_fs::STATUS_DATA_ERROR
        } else if status >= 0 {
            if self.xas_try_write_buf(output_va, &output[..output_len]) {
                status as u32
            } else {
                STATUS_ACCESS_VIOLATION
            }
        } else { status as u32 };
        report_failure(b"inline-terminal", terminal, file_id);
        release_or_retain(release_token, file_id);
        Some(terminal)
    }

    fn park_native_attribute_query(&mut self, file_id: u64, irp_id: u64, major: u8,
        information_class: u32, output_va: u64, output_len: u32) {
        self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
            route: PendingFileRoute::Hosted(file_id),
            irp_id,
            major,
            operation: nt_io_manager::PendingFileIoOperation::AttributeQuery(
                nt_io_manager::PendingFileAttributeQuery { information_class, inline_terminal: None }),
            pi: self.pi as u32,
            tid: self.current_tid,
            badge: self.current_badge,
            output_va,
            output_len,
            event_obj_idx: u64::MAX,
            completion_port_suppressed: true,
            native_call_transport: self.current_native_call_transport,
            ..Default::default()
        });
        self.pending_file_io_wait = true;
    }
}
