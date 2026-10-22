//! CDB and legacy SRB images for an exact native block route.
//!
//! The caller owns the data allocation and the canonical IRP. This module only constructs
//! pointer-free commands and checks terminal SRB state; it never infers a LUN or retries I/O.

use crate::scsi_srb_transport::WDM_X64_LEGACY_SRB_SIZE;

const SECTOR_BYTES: u64 = 512;
const SRB_FLAGS_DATA_IN: u32 = 0x40;
const SRB_FLAGS_DATA_OUT: u32 = 0x80;
const SRB_STATUS_SUCCESS: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockCommandError {
    InvalidRange,
    InvalidTransfer,
    InvalidCompletion,
    GeometryMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockCommandKind {
    Capacity,
    Read,
    Write,
    Flush,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScsiBlockCommand {
    kind: BlockCommandKind,
    srb: [u8; WDM_X64_LEGACY_SRB_SIZE],
    data_len: u32,
}

impl ScsiBlockCommand {
    pub fn read_capacity() -> Self {
        let mut command = Self::new(BlockCommandKind::Capacity, 32, SRB_FLAGS_DATA_IN);
        command.srb[0x0a] = 16;
        command.srb[0x48] = 0x9e;
        command.srb[0x49] = 0x10;
        command.srb[0x52..0x56].copy_from_slice(&32u32.to_be_bytes());
        command
    }

    pub fn read(lba: u64, sectors: u32) -> Result<Self, BlockCommandError> {
        Self::transfer(BlockCommandKind::Read, lba, sectors)
    }

    pub fn write(lba: u64, sectors: u32) -> Result<Self, BlockCommandError> {
        Self::transfer(BlockCommandKind::Write, lba, sectors)
    }

    pub fn flush() -> Self {
        let mut command = Self::new(BlockCommandKind::Flush, 0, 0);
        command.srb[0x0a] = 10;
        command.srb[0x48] = 0x35;
        command
    }

    fn new(kind: BlockCommandKind, data_len: u32, direction: u32) -> Self {
        let mut srb = [0; WDM_X64_LEGACY_SRB_SIZE];
        srb[0..2].copy_from_slice(&(WDM_X64_LEGACY_SRB_SIZE as u16).to_le_bytes());
        srb[0x0c..0x10].copy_from_slice(&direction.to_le_bytes());
        srb[0x10..0x14].copy_from_slice(&data_len.to_le_bytes());
        srb[0x14..0x18].copy_from_slice(&30u32.to_le_bytes());
        Self { kind, srb, data_len }
    }

    fn transfer(kind: BlockCommandKind, lba: u64, sectors: u32) -> Result<Self, BlockCommandError> {
        if sectors == 0 || lba.checked_add(u64::from(sectors)).is_none() {
            return Err(BlockCommandError::InvalidRange);
        }
        let bytes = u64::from(sectors).checked_mul(SECTOR_BYTES)
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or(BlockCommandError::InvalidTransfer)?;
        let direction = if kind == BlockCommandKind::Read { SRB_FLAGS_DATA_IN }
            else { SRB_FLAGS_DATA_OUT };
        let mut command = Self::new(kind, bytes, direction);
        if lba <= u32::MAX as u64 && sectors <= u16::MAX as u32 {
            command.srb[0x0a] = 10;
            command.srb[0x48] = if kind == BlockCommandKind::Read { 0x28 } else { 0x2a };
            command.srb[0x4a..0x4e].copy_from_slice(&(lba as u32).to_be_bytes());
            command.srb[0x4f..0x51].copy_from_slice(&(sectors as u16).to_be_bytes());
        } else {
            command.srb[0x0a] = 16;
            command.srb[0x48] = if kind == BlockCommandKind::Read { 0x88 } else { 0x8a };
            command.srb[0x4a..0x52].copy_from_slice(&lba.to_be_bytes());
            command.srb[0x52..0x56].copy_from_slice(&sectors.to_be_bytes());
        }
        Ok(command)
    }

    pub const fn kind(&self) -> BlockCommandKind { self.kind }
    pub const fn data_len(&self) -> u32 { self.data_len }
    pub const fn sense_len(&self) -> u8 { 0 }
    pub const fn srb(&self) -> &[u8; WDM_X64_LEGACY_SRB_SIZE] { &self.srb }

    pub fn verify_completion(&self, completed: &[u8], transferred: usize) -> Result<(), BlockCommandError> {
        if completed.len() != WDM_X64_LEGACY_SRB_SIZE
            || completed[0..2] != self.srb[0..2]
            || completed[2] != 0
            || completed[3] & 0x3f != SRB_STATUS_SUCCESS
            || completed[4] != 0
            || completed[0x48..0x58] != self.srb[0x48..0x58]
            || usize::try_from(self.data_len).ok() != Some(transferred)
            || u32::from_le_bytes(completed[0x10..0x14].try_into().unwrap()) != self.data_len
        { return Err(BlockCommandError::InvalidCompletion); }
        Ok(())
    }

    pub fn parse_capacity(&self, data: &[u8]) -> Result<(u32, u64), BlockCommandError> {
        if self.kind != BlockCommandKind::Capacity || data.len() != 32 {
            return Err(BlockCommandError::InvalidCompletion);
        }
        let last_lba = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let sector_bytes = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let sectors = last_lba.checked_add(1).ok_or(BlockCommandError::GeometryMismatch)?;
        if sector_bytes != SECTOR_BYTES as u32 || sectors == 0 {
            return Err(BlockCommandError::GeometryMismatch);
        }
        Ok((sector_bytes, sectors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity16_encodes_and_rejects_bad_geometry() {
        let command = ScsiBlockCommand::read_capacity();
        assert_eq!(command.srb()[0x48..0x4a], [0x9e, 0x10]);
        assert_eq!(command.srb()[0x52..0x56], [0, 0, 0, 32]);
        let mut data = [0; 32];
        data[0..8].copy_from_slice(&4095u64.to_be_bytes());
        data[8..12].copy_from_slice(&512u32.to_be_bytes());
        assert_eq!(command.parse_capacity(&data), Ok((512, 4096)));
        data[8..12].copy_from_slice(&4096u32.to_be_bytes());
        assert_eq!(command.parse_capacity(&data), Err(BlockCommandError::GeometryMismatch));
    }

    #[test]
    fn sector_commands_select_10_or_16_byte_cdb_and_bound_transfer() {
        let read = ScsiBlockCommand::read(123, 1).unwrap();
        assert_eq!(read.srb()[0x48], 0x28);
        assert_eq!(read.srb()[0x4a..0x4e], 123u32.to_be_bytes());
        assert_eq!(read.data_len(), 512);
        let write = ScsiBlockCommand::write(u32::MAX as u64 + 1, 1).unwrap();
        assert_eq!(write.srb()[0x48], 0x8a);
        assert_eq!(write.srb()[0x4a..0x52], (u32::MAX as u64 + 1).to_be_bytes());
        assert_eq!(ScsiBlockCommand::read(0, 0), Err(BlockCommandError::InvalidRange));
        assert_eq!(ScsiBlockCommand::read(u64::MAX, 2), Err(BlockCommandError::InvalidRange));
        assert_eq!(ScsiBlockCommand::read(0, u32::MAX), Err(BlockCommandError::InvalidTransfer));
    }

    #[test]
    fn completion_requires_exact_successful_transfer() {
        let command = ScsiBlockCommand::read(1, 1).unwrap();
        let mut completed = *command.srb();
        completed[3] = SRB_STATUS_SUCCESS;
        assert_eq!(command.verify_completion(&completed, 512), Ok(()));
        assert_eq!(command.verify_completion(&completed, 511), Err(BlockCommandError::InvalidCompletion));
        completed[4] = 2;
        assert_eq!(command.verify_completion(&completed, 512), Err(BlockCommandError::InvalidCompletion));
    }
}
