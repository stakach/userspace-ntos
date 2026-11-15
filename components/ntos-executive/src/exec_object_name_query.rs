//! `NtQueryObject(ObjectNameInformation)` for objects named by their type's QueryName
//! procedure instead of the object header: a File (`IopQueryNameFile`) and a Key
//! (`CmpQueryKeyName`).

use super::*;
use nt_io_manager::file_object_name::{
    answer_file_object_name, FileObjectNameAnswer, FILE_OBJECT_NAME_SCRATCH_BYTES,
    OBJECT_NAME_INFORMATION_HEADER_BYTES,
};

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_KEY_DELETED: u32 = 0xC000_017C;
const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
const FILE_NAME_INFORMATION_CLASS: u64 = 9;

impl ExecNtHandler {
    /// The name of the Device a routed File was opened on, as UTF-16 units; empty for an
    /// unnamed Device. `None` when the File or its Device is gone.
    fn routed_file_device_name(file_id: u64, device_id: Option<u64>) -> Option<Vec<u16>> {
        let io = driver_launch::io_manager_mut();
        let file = io.file(nt_io_manager::FileId(file_id))?;
        if device_id.is_some_and(|device_id| file.device_id.raw() != device_id) {
            return None;
        }
        let name = io.device(file.device_id)?.name.as_ref().map(|path| path.to_unicode_string());
        let units = name.as_ref().map_or(&[][..], |name| name.as_units());
        let mut owned = Vec::new();
        owned.try_reserve_exact(units.len()).ok()?;
        owned.extend_from_slice(units);
        Some(owned)
    }

    /// Format a File's name from its Device and the terminal result of its FileNameInformation
    /// query, and publish the record and `ReturnLength` to the current process.
    pub(crate) unsafe fn publish_file_object_name(
        &mut self,
        file_id: u64,
        device_id: Option<u64>,
        query_status: u32,
        file_information: &[u8],
        query_information: u64,
        information: u64,
        length: u32,
        return_length: u64,
    ) -> u32 {
        let Some(device_name) = Self::routed_file_device_name(file_id, device_id) else {
            return STATUS_INVALID_HANDLE;
        };
        // A UNICODE_STRING name never needs more than this, whatever the caller offers.
        let capacity = (length as usize).min(OBJECT_NAME_INFORMATION_HEADER_BYTES + 0x1_0000);
        let mut record = match try_zeroed_transfer_buffer(capacity) {
            Ok(record) => record,
            Err(status) => return status,
        };
        let FileObjectNameAnswer { status, copy, return_length: reported } = answer_file_object_name(
            &device_name, query_status, file_information, query_information, information, length,
            &mut record,
        );
        if let Some(reported) = reported {
            if return_length != 0 && !self.xas_try_write_buf(return_length, &reported.to_le_bytes()) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if copy != 0 && !self.xas_try_write_buf(information, &record[..copy]) {
            return STATUS_ACCESS_VIOLATION;
        }
        status
    }

    /// `IopQueryNameFile` for a routed File: IRP_MJ_QUERY_INFORMATION(FileNameInformation) on
    /// the File's own route, prefixed with its Device's name. A request the driver pends is
    /// kept by the pending File I/O owner, which formats the answer when it completes.
    pub(super) unsafe fn query_file_object_name(
        &mut self,
        handle: u64,
        information: u64,
        length: u32,
        return_length: u64,
    ) -> u32 {
        if (length as usize) < OBJECT_NAME_INFORMATION_HEADER_BYTES {
            let needed = OBJECT_NAME_INFORMATION_HEADER_BYTES as u32;
            if return_length != 0 && !self.xas_try_write_buf(return_length, &needed.to_le_bytes()) {
                return STATUS_ACCESS_VIOLATION;
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if !self.probe_user_output(information, length as usize) {
            return STATUS_ACCESS_VIOLATION;
        }
        let capture = match self.capture_hosted_file_unless_local(handle) {
            Ok(Some(capture)) => capture,
            // An executive-local File has no Device object to name it by.
            Ok(None) => return STATUS_NOT_SUPPORTED,
            Err(status) => return status,
        };
        let route = capture.route;
        let file_id = route.file_id;
        let synchronous_file = match self.file_completion.is_synchronous(file_id) {
            Ok(synchronous) => synchronous,
            Err(status) => return status,
        };
        if REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0
            || !wait_reply_pool_has_free()
            || !self.reserve_pending_file_io_owner()
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
        let mut file_information = match try_zeroed_transfer_buffer(FILE_OBJECT_NAME_SCRATCH_BYTES) {
            Ok(buffer) => buffer,
            Err(status) => {
                self.release_file_reference(file_id);
                return status;
            }
        };
        let (query_status, query_information, pending_irp_id) = match self.dispatch_hosted_file_irp_for(
            route,
            major::IRP_MJ_QUERY_INFORMATION as u64,
            FILE_NAME_INFORMATION_CLASS,
            &[],
            &mut file_information,
            0,
        ) {
            Ok((status, information, irp_id)) => (status as u32, information, irp_id),
            Err(status) => (status, 0, 0),
        };
        if query_status == STATUS_PENDING && pending_irp_id != 0 {
            print_str(b"[query-object-name] file name query pended pi=");
            print_u64(self.pi as u64);
            print_str(b" fid=0x");
            print_hex(file_id as u32);
            print_str(b" irp=");
            print_u64(pending_irp_id);
            print_str(b"\n");
            self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
                route: PendingFileRoute::Hosted(file_id),
                irp_id: pending_irp_id,
                major: major::IRP_MJ_QUERY_INFORMATION,
                operation: nt_io_manager::PendingFileIoOperation::ObjectNameQuery(
                    nt_io_manager::PendingObjectNameQuery {
                        information_va: information,
                        length,
                        return_length_va: return_length,
                    },
                ),
                pi: self.pi as u32,
                tid: self.current_tid,
                badge: self.current_badge,
                completion_port_suppressed: true,
                signal_file: synchronous_file,
                event_obj_idx: u64::MAX,
                native_call_transport: self.current_native_call_transport,
                ..nt_io_manager::PendingFileIo::default()
            });
            self.pending_file_io_wait = true;
            return STATUS_PENDING;
        }
        let status = if query_status == STATUS_PENDING {
            STATUS_INSUFFICIENT_RESOURCES
        } else {
            self.publish_file_object_name(
                file_id, Some(route.device_id), query_status, &file_information, query_information,
                information, length, return_length,
            )
        };
        if synchronous_file {
            let _ = self.signal_file_completion(file_id, status);
        }
        self.release_file_reference(file_id);
        status
    }

    /// `CmpQueryKeyName`: the key's full `\REGISTRY\...` path.
    pub(super) unsafe fn query_key_object_name(
        &mut self,
        target: KeyRef,
        information: u64,
        length: u32,
        return_length: u64,
    ) -> u32 {
        let Some(path) = self.registry_target_path(target) else {
            return STATUS_KEY_DELETED;
        };
        let name = nt_object_manager::name_query::key_object_name(&path).unwrap_or(path);
        let Some(record) =
            nt_object_manager::name_query::encode_object_name_information(&name, information)
        else {
            return STATUS_NAME_TOO_LONG;
        };
        if return_length != 0
            && !self.xas_try_write_buf(return_length, &(record.len() as u32).to_le_bytes())
        {
            return STATUS_ACCESS_VIOLATION;
        }
        if (length as usize) < record.len() {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if self.xas_try_write_buf(information, &record) {
            0
        } else {
            STATUS_ACCESS_VIOLATION
        }
    }
}
