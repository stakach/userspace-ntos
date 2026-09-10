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

    pub(super) unsafe fn reserve_local_file_io_output(
        &mut self,
        capacity: usize,
    ) -> Result<u64, u32> {
        let _durable = allocator::enter_durable();
        let request_id = self.reserve_local_file_io_delivery()?;
        (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO)).reserve_local_output(
            self.pending_file_io_reservation
                .expect("local output lost its reservation"),
            capacity,
        )?;
        Ok(request_id)
    }

    pub(super) unsafe fn begin_retained_local_buffered_io(
        &mut self,
        file_object: u64,
        capacity: usize,
    ) -> Result<u64, u32> {
        let request_id = self.reserve_local_file_io_output(capacity)?;
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

    pub(super) fn stage_terminal_local_buffered_io(
        &mut self,
        request_id: u64,
        major: u8,
        file_object: u64,
        synchronous: bool,
        event_obj_idx: u64,
        apc_routine: u64,
        apc_context: u64,
        iosb: u64,
        status: u32,
        information: u64,
        completion_port_suppressed: bool,
        output_va: u64,
        output_len: u32,
    ) {
        self.stage_terminal_local_file_io(
            request_id,
            major,
            file_object,
            synchronous,
            event_obj_idx,
            self.current_tid,
            apc_routine,
            apc_context,
            iosb,
            status,
            information,
            completion_port_suppressed,
        );
        let pending = self
            .pending_file_io_transfer
            .as_mut()
            .expect("local buffered result lost its delivery owner");
        pending.operation = nt_io_manager::PendingFileIoOperation::LocalBuffered(
            nt_io_manager::PendingLocalBuffered {
                status,
                information,
            },
        );
        pending.output_va = output_va;
        pending.output_len = output_len;
    }

    pub(super) fn complete_local_directory_query(
        &mut self,
        args: &[u64],
        request_id: u64,
        file_object: u64,
        synchronous: bool,
        event_obj_idx: u64,
        result: nt_fs::DirectoryQueryResult,
    ) -> u32 {
        let output_len = nt_ulong_arg(args[6]);
        assert!(
            result.information <= output_len as usize,
            "directory output exceeds admitted buffer"
        );
        self.stage_terminal_local_buffered_io(
            request_id,
            major::IRP_MJ_DIRECTORY_CONTROL,
            file_object,
            synchronous,
            event_obj_idx,
            args[2],
            args[3],
            args[4],
            result.status,
            result.information as u64,
            nt_io_completion::io_event_suppresses_completion_port(args[1]),
            args[5],
            output_len,
        );
        STATUS_PENDING
    }

    /// No filesystem call or table borrow crosses user-memory admission. An accepted prefix is
    /// committed page by page, so a refused destination page cannot replay an earlier copy.
    pub(crate) unsafe fn deliver_local_buffered_output(
        &mut self,
        slot: usize,
        mut pending: nt_io_manager::PendingFileIo,
    ) -> Result<nt_io_manager::PendingFileIo, ()> {
        let settled =
            nt_io_manager::IO_DELIVERY_BUFFER_PUBLISHED | nt_io_manager::IO_DELIVERY_OUTPUT_FAULTED;
        if pending.consumer_abandoned || pending.delivery_state & settled != 0 {
            return Ok(pending);
        }
        let (status, information) = pending
            .local_terminal_result()
            .expect("buffered local output has no terminal result");
        let length = if nt_io_completion::file_io_status_copies_output(status) {
            u32::try_from(information).expect("local buffered result exceeds ULONG")
        } else {
            0
        };
        let mut work = [0u8; 4096];
        while pending.output_offset < length {
            let address = pending
                .output_va
                .checked_add(u64::from(pending.output_offset))
                .expect("admitted local buffer address overflow");
            let chunk =
                ((length - pending.output_offset) as usize).min(4096 - (address as usize & 4095));
            let copied = (&*core::ptr::addr_of!(PENDING_FILE_IO))
                .copy_local_output_bytes_exact(
                    slot,
                    pending.irp_id,
                    pending.output_offset as usize,
                    &mut work[..chunk],
                )
                .expect("local buffered output lost its exact bytes");
            assert_eq!(copied, chunk);
            match self.process_memory_write_checked(pending.pi as usize, address, &work[..chunk]) {
                Ok(()) => {
                    (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                        .advance_output_exact(slot, pending.irp_id, chunk as u32, length)
                        .expect("local buffered output lost its progress owner");
                }
                Err(nt_address_space::copy::MemoryCopyFailure::Retry(_)) => return Err(()),
                Err(nt_address_space::copy::MemoryCopyFailure::UserFault(status)) => {
                    (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                        .settle_local_output_fault_exact(
                            slot,
                            pending.irp_id,
                            pending.output_va,
                            status,
                        )
                        .expect("local buffered output lost its fault owner");
                    break;
                }
            }
            pending = (&*core::ptr::addr_of!(PENDING_FILE_IO))
                .get(slot)
                .expect("local buffered output owner disappeared");
        }
        if length == 0 {
            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .advance_output_exact(slot, pending.irp_id, 0, 0)
                .expect("local empty output lost its settlement owner");
        }
        Ok((&*core::ptr::addr_of!(PENDING_FILE_IO))
            .get(slot)
            .expect("local buffered output owner disappeared"))
    }
}
