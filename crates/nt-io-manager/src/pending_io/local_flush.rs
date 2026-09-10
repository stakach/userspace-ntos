use super::*;

/// Distinguishes direct FILE_OBJECT completion from the private synchronous-API IOSB copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalFlushMode {
    SynchronousFile,
    SynchronousApi,
}

/// One accepted local flush, with immutable backing status and a separate IOSB-copy disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingLocalFlush {
    status: u32,
    mode: LocalFlushMode,
    iosb_fault_status: Option<u32>,
}

impl PendingLocalFlush {
    pub fn new(status: u32, mode: LocalFlushMode) -> Option<Self> {
        (status != nt_status::NtStatus::PENDING.raw() as u32).then_some(Self {
            status,
            mode,
            iosb_fault_status: None,
        })
    }

    pub const fn status(self) -> u32 {
        self.status
    }

    pub const fn mode(self) -> LocalFlushMode {
        self.mode
    }

    pub const fn publishes_iosb(self) -> bool {
        matches!(self.mode, LocalFlushMode::SynchronousApi) || self.status >> 30 != 3
    }

    pub const fn signals_file(self) -> bool {
        matches!(self.mode, LocalFlushMode::SynchronousFile) && self.status >> 30 != 3
    }

    pub const fn syscall_status(self) -> u32 {
        match (self.mode, self.iosb_fault_status) {
            (LocalFlushMode::SynchronousApi, Some(status)) => status,
            _ => self.status,
        }
    }
}

impl PendingFileIoTable {
    pub(super) fn local_flush_shape_is_valid(
        pending: PendingFileIo,
        operation: PendingLocalFlush,
    ) -> bool {
        pending.major == nt_io_abi::major::IRP_MJ_FLUSH_BUFFERS
            && operation.iosb_fault_status.is_none()
            && pending.output_va == 0
            && pending.output_len == 0
            && pending.apc_routine == 0
            && pending.apc_context == 0
            && pending.event_obj_idx == u64::MAX
            && !pending.publish_iocp
            && pending.completion_port_suppressed
            && pending.sync_lock_owner_tid == 0
            && !pending.consumer_abandoned
            && (pending.iosb_va != 0) == operation.publishes_iosb()
            && pending.signal_file == operation.signals_file()
    }

    pub(super) fn local_flush_iosb_settled(pending: PendingFileIo) -> bool {
        !matches!(pending.operation, PendingFileIoOperation::LocalFlush(_))
            || pending.iosb_va == 0
            || pending.delivery_state & (IO_DELIVERY_IOSB_PUBLISHED | IO_DELIVERY_IOSB_FAULTED) != 0
    }

    pub(super) fn local_flush_delivery_flag_is_valid(pending: PendingFileIo, flag: u16) -> bool {
        if !matches!(pending.operation, PendingFileIoOperation::LocalFlush(_)) {
            return true;
        }
        match flag {
            IO_DELIVERY_IOSB_PUBLISHED => pending.iosb_va != 0,
            IO_DELIVERY_FILE_PUBLISHED => {
                pending.signal_file && Self::local_flush_iosb_settled(pending)
            }
            _ => false,
        }
    }

    pub(super) fn local_flush_reply_ready(pending: PendingFileIo) -> bool {
        !matches!(pending.operation, PendingFileIoOperation::LocalFlush(_))
            || (Self::local_flush_iosb_settled(pending)
                && (!pending.signal_file
                    || pending.delivery_state & IO_DELIVERY_FILE_PUBLISHED != 0))
    }

    /// Settle a permanent IOSB fault once. Only the private synchronous-API copy changes the
    /// syscall return; direct FILE_OBJECT completion ignores it and preserves the backing result.
    pub fn mark_local_flush_iosb_faulted_exact(
        &mut self,
        slot: usize,
        irp_id: u64,
        expected_iosb_va: u64,
        status: u32,
    ) -> Option<u16> {
        if status & 0x8000_0000 == 0 {
            return None;
        }
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        let PendingFileIoOperation::LocalFlush(mut operation) = pending.operation else {
            return None;
        };
        if pending.irp_id != irp_id
            || expected_iosb_va == 0
            || pending.iosb_va != expected_iosb_va
            || pending.consumer_abandoned
            || pending.delivery_state != 0
            || operation.iosb_fault_status.is_some()
            || !operation.publishes_iosb()
        {
            return None;
        }
        operation.iosb_fault_status = Some(status);
        pending.operation = PendingFileIoOperation::LocalFlush(operation);
        pending.delivery_state = IO_DELIVERY_IOSB_FAULTED;
        Some(pending.delivery_state)
    }
}

#[cfg(test)]
#[path = "local_flush_tests.rs"]
mod tests;
