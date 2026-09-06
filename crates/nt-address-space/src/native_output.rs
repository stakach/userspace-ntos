//! Native VM parameter capture and ordered output stores. The caller owns operation status and
//! decides whether a late output exception is reported; publication never rolls back VM state.

use crate::copy::{probe_write_scalar, WriteProbeMemory};

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

#[cfg(test)]
#[path = "native_output_tests.rs"]
mod tests;
