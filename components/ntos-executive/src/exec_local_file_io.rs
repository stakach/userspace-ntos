//! Retained completion and FILE_OBJECT lifetime for local filesystem operations.

use super::*;

impl ExecNtHandler {
    pub(super) unsafe fn reserved_local_file_io_id(&self) -> Result<u64, u32> {
        let pending = &*core::ptr::addr_of!(PENDING_FILE_IO);
        self.pending_file_io_reservation
            .and_then(|reservation| pending.local_operation_id(reservation))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)
    }

    pub(super) unsafe fn reserve_local_file_io_delivery(&mut self) -> Result<u64, u32> {
        // Inline asynchronous operations also need a parked reply if delivery must retry.
        if REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0
            || !wait_reply_pool_has_free()
            || !self.reserve_pending_file_io_owner()
        {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        self.reserved_local_file_io_id()
    }

    pub(super) unsafe fn begin_retained_local_file_io(
        &mut self,
        file_object: u64,
    ) -> Result<u64, u32> {
        let request_id = self.reserve_local_file_io_delivery()?;
        self.begin_local_file_io(file_object)?;
        Ok(request_id)
    }

    fn set_local_file_object_signaled(
        &mut self,
        file_object: u64,
        signaled: bool,
    ) -> Result<(), u32> {
        let object_id = (file_object & LOCAL_ID_PAYLOAD_MASK) as u32;
        match file_object & !LOCAL_ID_PAYLOAD_MASK {
            LOCAL_FAT_FILE_OBJECT_TAG => self.readonly_file_opens.set_signaled(object_id, signaled),
            LOCAL_FAT_DIRECTORY_OBJECT_TAG => {
                self.directory_opens.set_signaled(object_id, signaled)
            }
            LOCAL_OVERLAY_FILE_OBJECT_TAG => unsafe {
                crate::writable_fs::set_file_signaled(file_object & LOCAL_ID_PAYLOAD_MASK, signaled)
            },
            _ => Err(nt_fs::STATUS_INVALID_HANDLE),
        }
    }

    pub(super) fn begin_local_file_io(&mut self, file_object: u64) -> Result<(), u32> {
        let object_id = (file_object & LOCAL_ID_PAYLOAD_MASK) as u32;
        match file_object & !LOCAL_ID_PAYLOAD_MASK {
            LOCAL_FAT_FILE_OBJECT_TAG => self.readonly_file_opens.retain_io(object_id),
            LOCAL_FAT_DIRECTORY_OBJECT_TAG => self.directory_opens.retain_io(object_id),
            LOCAL_OVERLAY_FILE_OBJECT_TAG => unsafe {
                return crate::writable_fs::begin_file_io(file_object & LOCAL_ID_PAYLOAD_MASK);
            },
            _ => Err(nt_fs::STATUS_INVALID_HANDLE),
        }?;
        if let Err(status) = self.set_local_file_object_signaled(file_object, false) {
            self.release_local_file_io_reference(file_object);
            return Err(status);
        }
        Ok(())
    }

    pub(crate) fn release_local_file_io_reference(&mut self, file_object: u64) {
        self.try_release_local_file_io_reference(file_object)
            .expect("local pending I/O lost its FILE_OBJECT reference");
    }

    pub(crate) fn try_release_local_file_io_reference(
        &mut self,
        file_object: u64,
    ) -> Result<(), u32> {
        let object_id = (file_object & LOCAL_ID_PAYLOAD_MASK) as u32;
        match file_object & !LOCAL_ID_PAYLOAD_MASK {
            LOCAL_FAT_FILE_OBJECT_TAG => self.readonly_file_opens.release_io(object_id),
            LOCAL_FAT_DIRECTORY_OBJECT_TAG => self.directory_opens.release_io(object_id),
            LOCAL_OVERLAY_FILE_OBJECT_TAG => unsafe {
                crate::writable_fs::release_io_reference(file_object & LOCAL_ID_PAYLOAD_MASK)
            },
            _ => Err(nt_fs::STATUS_INVALID_HANDLE),
        }
    }

    pub(crate) fn signal_local_file_completion(&mut self, file_object: u64) -> u32 {
        match self.set_local_file_object_signaled(file_object, true) {
            Ok(()) => {
                unsafe {
                    let _ = wait_wake_dispatcher_set(self);
                }
                nt_fs::STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }

    pub(super) fn stage_terminal_local_file_io(
        &mut self,
        request_id: u64,
        major: u8,
        file_object: u64,
        synchronous: bool,
        event_obj_idx: u64,
        tid: u64,
        apc_routine: u64,
        apc_context: u64,
        iosb: u64,
        status: u32,
        information: u64,
        completion_port_suppressed: bool,
    ) {
        // Delivery may wait, but its original inline completion policy must not change.
        let publish = nt_io_completion::file_io_status_publishes_completion(status, true);
        assert!(self.pending_file_io_transfer.is_none());
        assert!(self.pending_file_io_reservation.is_some());
        self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
            file_id: file_object,
            irp_id: request_id,
            major,
            operation: nt_io_manager::PendingFileIoOperation::LocalInline(
                nt_io_manager::PendingLocalInline {
                    status,
                    information,
                },
            ),
            pi: self.pi as u32,
            tid,
            badge: self.current_badge,
            iosb_va: if publish { iosb } else { 0 },
            apc_routine: if publish { apc_routine } else { 0 },
            apc_context,
            completion_port_suppressed,
            signal_file: publish && (synchronous || event_obj_idx == u64::MAX),
            event_obj_idx: if publish { event_obj_idx } else { u64::MAX },
            ..nt_io_manager::PendingFileIo::default()
        });
        // Even an asynchronous FILE_OBJECT completed inline: return its real terminal status
        // through this request's parked reply, not a fabricated asynchronous operation result.
        self.pending_file_io_wait = true;
    }

    pub(super) unsafe fn complete_local_directory_query(
        &mut self,
        args: &[u64],
        request_id: u64,
        file_object: u64,
        synchronous: bool,
        event_obj_idx: u64,
        result: nt_fs::DirectoryQueryResult,
        encoded: &[u8],
    ) -> u32 {
        assert!(
            result.information <= encoded.len(),
            "directory output exceeds admitted buffer"
        );
        // The filesystem has accepted its cursor update. Neither copy nor delivery can undo it.
        let status = if result.information != 0
            && nt_io_completion::file_io_status_copies_output(result.status)
        {
            match self.process_memory_write_status(self.pi, args[5], &encoded[..result.information])
            {
                Ok(()) => result.status,
                Err(status) => status,
            }
        } else {
            result.status
        };
        self.stage_terminal_local_file_io(
            request_id,
            major::IRP_MJ_DIRECTORY_CONTROL,
            file_object,
            synchronous,
            event_obj_idx,
            self.current_tid,
            args[2],
            args[3],
            args[4],
            status,
            result.information as u64,
            nt_io_completion::io_event_suppresses_completion_port(args[1]),
        );
        STATUS_PENDING
    }
}
