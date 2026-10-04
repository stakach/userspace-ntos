//! Process-local handle admission for readonly mounted-volume File bodies.

use super::*;
use core::fmt::Write;

impl ExecNtHandler {
    fn trace_disk_file_admission_failure(&self, stage: &str, path: &[u8], status: u32) {
        let pi = self.pi;
        let pid = self.pm_pid_for_pi(pi);
        let process = self.capture_process_identity(pi);
        let observed_tid = self.current_tid;
        let thread = u32::try_from(observed_tid)
            .ok()
            .and_then(|tid| self.pm.thread_lifetime(tid));
        let usage = self.readonly_file_opens.usage();
        let reason = if stage == "readonly-create" && status == STATUS_INSUFFICIENT_RESOURCES {
            let no_usable_vacancy = usage.allocated_slots
                == usage.occupied_bodies + usage.generation_exhausted_slots;
            if no_usable_vacancy && usage.allocated_slots >= usage.slot_limit {
                "identity-capacity"
            } else {
                "allocation-refusal"
            }
        } else {
            "not-classified"
        };

        let mut record = nt_printf::record::RecordBuffer::<2048>::new();
        let _ = write!(
            record,
            "[readonly-file-admission-failure] stage={stage} status=0x{status:08x} reason={reason} pi={pi} observed-tid={observed_tid}"
        );
        if let Some(pid) = pid {
            let _ = write!(record, " pid={pid}");
        } else {
            let _ = write!(record, " pid=none");
        }
        if let Some(process) = process {
            let (kind, generation) = match process.generation {
                nt_types::ProcessGeneration::Hosted(generation) => ("hosted", generation),
                nt_types::ProcessGeneration::Temporary(generation) => ("temporary", generation),
            };
            let _ = write!(record, " generation-kind={kind} generation={generation}");
        } else {
            let _ = write!(record, " generation=none");
        }
        if let Some(thread) = thread {
            let _ = write!(
                record,
                " thread-pid={} tid={} thread-generation={} thread-owner-matches={}",
                thread.process_id(),
                thread.thread_id(),
                thread.generation(),
                u8::from(pid == Some(thread.process_id())),
            );
        } else {
            let _ = write!(record, " thread-lifetime=none");
        }
        let _ = write!(
            record,
            " occupied={} io-only={} allocated-slots={} slot-limit={} generation-exhausted={} handle-refs={} path=\"",
            usage.occupied_bodies,
            usage.io_only_bodies,
            usage.allocated_slots,
            usage.slot_limit,
            usage.generation_exhausted_slots,
            usage.total_handle_refs,
        );
        for &byte in path {
            match byte {
                b'"' | b'\\' => {
                    let _ = write!(record, "\\{}", byte as char);
                }
                0x20..=0x7e => {
                    let _ = write!(record, "{}", byte as char);
                }
                _ => {
                    let _ = write!(record, "\\x{byte:02x}");
                }
            }
        }
        let _ = writeln!(record, "\"");
        sel4_rt::print_record(if record.overflowed() {
            b"[readonly-file-admission-failure] record-truncated\n"
        } else {
            record.bytes()
        });
    }

    /// Mint a process-local handle for a read-only file on the mounted FAT volume.
    pub(crate) fn mint_disk_file_handle(
        &mut self,
        file: crate::fs_loader::FatOpenMetadata,
        volume_relative_path: &[u8],
        access: u32,
        share_access: u32,
        create_options: u32,
    ) -> Result<u64, u32> {
        let pid = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => {
                self.trace_disk_file_admission_failure(
                    "identity",
                    volume_relative_path,
                    STATUS_INSUFFICIENT_RESOURCES,
                );
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        let first_cluster = file.first_cluster;
        let size = match u32::try_from(file.metadata.end_of_file) {
            Ok(size) => size,
            Err(_) => {
                self.trace_disk_file_admission_failure(
                    "size",
                    volume_relative_path,
                    STATUS_INSUFFICIENT_RESOURCES,
                );
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        let object_id = match self.readonly_file_opens.create(
            first_cluster,
            size,
            volume_relative_path,
            access,
            share_access,
            create_options,
            file.metadata,
            file.alternate_name,
        ) {
            Ok(object_id) => object_id,
            Err(status) => {
                self.trace_disk_file_admission_failure(
                    "readonly-create",
                    volume_relative_path,
                    status,
                );
                return Err(status);
            }
        };
        let handle = match self.insert_process_handle(
            pid,
            nt_process::HandleObject::DiskFile {
                first_cluster,
                size,
                object_id,
            },
            access,
        ) {
            Ok(handle) => handle,
            Err(status) => {
                self.trace_disk_file_admission_failure(
                    "handle-insert",
                    volume_relative_path,
                    status,
                );
                let _ = self.readonly_file_opens.release(object_id);
                return Err(status);
            }
        };
        Ok(handle as u64)
    }
}
