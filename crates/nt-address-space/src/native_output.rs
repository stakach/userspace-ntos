//! Native VM parameter capture and ordered output stores. The caller owns operation status and
//! decides whether a late output exception is reported; publication never rolls back VM state.

use crate::copy::{probe_write_scalar, probe_write_user_range, WriteProbeMemory};

pub trait VmOutputMemory: WriteProbeMemory {
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), u32>;
}

#[derive(Clone, Copy, Debug)]
pub struct VmRangeOutput {
    pub base_pointer: u64,
    pub size_pointer: u64,
}

fn read_u64(memory: &mut impl VmOutputMemory, address: u64) -> Result<u64, u32> {
    memory.read_scalar::<8>(address).map(u64::from_le_bytes)
}

impl VmRangeOutput {
    fn probe(
        self,
        memory: &mut impl VmOutputMemory,
        old_protection: Option<u64>,
        user_limit: u64,
    ) -> Result<(), u32> {
        probe_write_scalar::<8>(memory, self.base_pointer, user_limit)?;
        probe_write_scalar::<8>(memory, self.size_pointer, user_limit)?;
        if let Some(address) = old_protection {
            probe_write_scalar::<4>(memory, address, user_limit)?;
        }
        Ok(())
    }

    /// Probe all outputs before capturing either input. Scalar pointers may be unaligned.
    pub fn capture(
        self,
        memory: &mut impl VmOutputMemory,
        old_protection: Option<u64>,
        user_limit: u64,
    ) -> Result<(u64, u64), u32> {
        self.probe(memory, old_protection, user_limit)?;
        self.read(memory)
    }

    fn read(self, memory: &mut impl VmOutputMemory) -> Result<(u64, u64), u32> {
        Ok((
            read_u64(memory, self.base_pointer)?,
            read_u64(memory, self.size_pointer)?,
        ))
    }

    /// NT publishes size before base and exits the store sequence at its first exception.
    pub fn publish(
        self,
        memory: &mut impl VmOutputMemory,
        base: u64,
        size: u64,
    ) -> Result<(), u32> {
        memory.write_bytes(self.size_pointer, &size.to_le_bytes())?;
        memory.write_bytes(self.base_pointer, &base.to_le_bytes())
    }

    /// Protection may have changed the output pages themselves. Reprobe every scalar before
    /// publishing size, base, then OldProtect, without restoring the completed protection change.
    pub fn publish_protection(
        self,
        memory: &mut impl VmOutputMemory,
        base: u64,
        size: u64,
        old_protection: (u64, u32),
        user_limit: u64,
    ) -> Result<(), u32> {
        self.probe(memory, Some(old_protection.0), user_limit)?;
        self.publish(memory, base, size)?;
        memory.write_bytes(old_protection.0, &old_protection.1.to_le_bytes())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VmFlushOutput {
    pub range: VmRangeOutput,
    pub iosb: u64,
}

impl VmFlushOutput {
    /// Probe the full IO_STATUS_BLOCK before capturing either range input.
    pub fn capture(
        self,
        memory: &mut impl VmOutputMemory,
        user_limit: u64,
    ) -> Result<(u64, u64), u32> {
        self.range.probe(memory, None, user_limit)?;
        probe_write_scalar::<16>(memory, self.iosb, user_limit)?;
        self.range.read(memory)
    }

    /// Completed writeback is retained even if an output faults. Stop the store sequence at that
    /// fault; never retry later fields or replace the operation's status.
    pub fn publish(
        self,
        memory: &mut impl VmOutputMemory,
        base: u64,
        size: u64,
        status: u32,
        information: u64,
    ) -> u32 {
        if self.range.publish(memory, base, size).is_ok() {
            let mut iosb = [0; 16];
            iosb[..4].copy_from_slice(&status.to_le_bytes());
            iosb[8..].copy_from_slice(&information.to_le_bytes());
            let _ = memory.write_bytes(self.iosb, &iosb);
        }
        status
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VmBasicQueryOutput {
    pub information: u64,
    pub length: u64,
    pub return_length: u64,
}

impl VmBasicQueryOutput {
    /// Basic information validates its minimum length before probing the entire caller buffer.
    pub fn probe(self, memory: &mut impl VmOutputMemory, user_limit: u64) -> Result<(), u32> {
        if self.length < crate::MEMORY_BASIC_INFORMATION_X64_SIZE as u64 {
            return Err(0xC000_0004); // STATUS_INFO_LENGTH_MISMATCH
        }
        if self.information & 7 != 0 {
            return Err(0x8000_0002); // STATUS_DATATYPE_MISALIGNMENT
        }
        probe_write_user_range(memory, self.information, self.length, user_limit)?;
        if self.return_length != 0 {
            probe_write_scalar::<8>(memory, self.return_length, user_limit)?;
        }
        Ok(())
    }

    /// A failed information store is reported; a failed optional length store after a complete
    /// information result does not change success (NT5 queryvm's Found boundary).
    pub fn publish(
        self,
        memory: &mut impl VmOutputMemory,
        information: &[u8; crate::MEMORY_BASIC_INFORMATION_X64_SIZE],
    ) -> Result<(), u32> {
        memory.write_bytes(self.information, information)?;
        if self.return_length != 0 {
            let length = crate::MEMORY_BASIC_INFORMATION_X64_SIZE as u64;
            let _ = memory.write_bytes(self.return_length, &length.to_le_bytes());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "native_output_tests.rs"]
mod tests;
