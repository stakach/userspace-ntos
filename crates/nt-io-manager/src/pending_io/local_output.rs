//! Storage retained by the exact pending-I/O reservation, never by a Copy delivery snapshot.

use super::*;

const INVALID_HANDLE: u32 = 0xc000_0008;
const INVALID_PARAMETER: u32 = 0xc000_000d;
const INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const DATA_ERROR: u32 = 0xc000_003e;

impl PendingFileIoTable {
    /// Allocate the complete destination before beginning the filesystem operation. A failed
    /// allocation leaves the exact reservation valid and empty; it never replaces an owned buffer.
    pub fn reserve_local_output(
        &mut self,
        reservation: PendingFileIoReservation,
        length: usize,
    ) -> Result<(), u32> {
        self.local_operation_id(reservation).ok_or(INVALID_HANDLE)?;
        if u32::try_from(length).is_err() || self.local_outputs[reservation.slot].is_some() {
            return Err(INVALID_PARAMETER);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| INSUFFICIENT_RESOURCES)?;
        output.resize(length, 0);
        self.local_outputs[reservation.slot] = Some(output);
        Ok(())
    }

    /// Borrow writable staging only while its reservation is uncommitted. The caller must not
    /// retain this borrow across re-entrant work or user-memory publication.
    pub fn reserved_local_output_mut(
        &mut self,
        reservation: PendingFileIoReservation,
    ) -> Result<&mut [u8], u32> {
        self.local_operation_id(reservation).ok_or(INVALID_HANDLE)?;
        self.local_outputs[reservation.slot]
            .as_deref_mut()
            .ok_or(INVALID_PARAMETER)
    }

    /// Copy an immutable terminal range into caller-owned scratch after validating the full range.
    /// Repeated reads do not advance publication. No table-owned reference escapes this operation.
    pub fn copy_local_output_bytes_exact(
        &self,
        slot: usize,
        irp_id: u64,
        offset: usize,
        output: &mut [u8],
    ) -> Result<usize, u32> {
        let pending = self
            .get(slot)
            .filter(|pending| {
                pending.irp_id == irp_id
                    && !pending.consumer_abandoned
                    && matches!(pending.operation, PendingFileIoOperation::LocalBuffered(_))
            })
            .ok_or(INVALID_HANDLE)?;
        if pending.delivery_state & IO_DELIVERY_OUTPUT_FAULTED != 0 {
            return Err(INVALID_PARAMETER);
        }
        let retained = self
            .local_outputs
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(DATA_ERROR)?;
        let PendingFileIoOperation::LocalBuffered(terminal) = pending.operation else {
            unreachable!()
        };
        let expected = if Self::local_status_copies_output(terminal.status) {
            usize::try_from(terminal.information).map_err(|_| DATA_ERROR)?
        } else {
            0
        };
        if retained.len() != expected || expected > pending.output_len as usize {
            return Err(DATA_ERROR);
        }
        let end = offset.checked_add(output.len()).ok_or(INVALID_PARAMETER)?;
        let bytes = retained.get(offset..end).ok_or(INVALID_PARAMETER)?;
        output.copy_from_slice(bytes);
        Ok(bytes.len())
    }

    /// Settle a definitive local output fault without undoing the accepted transfer or prefix.
    /// Transient copy failures must leave this owner unchanged for another copy attempt.
    pub fn settle_local_output_fault_exact(
        &mut self,
        slot: usize,
        irp_id: u64,
        expected_output_va: u64,
        status: u32,
    ) -> Option<u16> {
        if status & 0x8000_0000 == 0 {
            return None;
        }
        let pending = self.slots.get_mut(slot)?.as_mut()?;
        let PendingFileIoOperation::LocalBuffered(mut terminal) = pending.operation else {
            return None;
        };
        let retained = self.local_outputs.get(slot)?.as_ref()?;
        if pending.irp_id != irp_id
            || expected_output_va == 0
            || pending.output_va != expected_output_va
            || pending.consumer_abandoned
            || pending.delivery_state != 0
            || !Self::local_status_copies_output(terminal.status)
            || retained.is_empty()
            || retained.len() as u64 != terminal.information
            || retained.len() > pending.output_len as usize
            || pending.output_offset as usize >= retained.len()
        {
            return None;
        }
        terminal.status = status;
        pending.operation = PendingFileIoOperation::LocalBuffered(terminal);
        pending.delivery_state |= IO_DELIVERY_OUTPUT_FAULTED;
        if status & 0xc000_0000 == 0xc000_0000 {
            pending.iosb_va = 0;
            pending.apc_routine = 0;
            pending.event_obj_idx = u64::MAX;
            pending.signal_file = false;
        }
        Some(pending.delivery_state)
    }
}

#[cfg(test)]
#[path = "local_output_tests.rs"]
mod tests;
