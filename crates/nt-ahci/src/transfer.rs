//! Polled READ/WRITE DMA EXT over slot zero with typed HBA ownership outcomes.
//!
//! A command the HBA has not released keeps the slot and the whole DMA window: the caller may
//! neither inspect its payload nor stage another command there. The port registers are the
//! retained owner record. PxCI/PxSACT refuse reissue until the HBA clears them, and a latched
//! fatal PxIS refuses reissue on a running port until recovery restarts it. Neither is cleared
//! here on timeout or error.

use crate::{wait_clear, Error, PortIo, DATA_OFFSET, PORT_IS_FATAL, TASK_FILE_FAILURE};

const SECTOR_BYTES: usize = 512;
/// One PRDT entry's byte-count field is 22 bits.
const MAX_PRDT_BYTES: usize = 0x40_0000;
const PX_IS: u32 = 0x10;
const PX_CMD: u32 = 0x18;
const PX_TFD: u32 = 0x20;
const PX_SACT: u32 = 0x34;
const PX_CI: u32 = 0x38;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transfer<'a> {
    Read {
        lba: u64,
        sectors: u32,
    },
    /// Whole sectors staged into the DMA window only after the slot is known to be free.
    Write {
        lba: u64,
        data: &'a [u8],
    },
}

impl Transfer<'_> {
    fn lba(&self) -> u64 {
        match *self {
            Self::Read { lba, .. } | Self::Write { lba, .. } => lba,
        }
    }
    fn bytes(&self) -> Option<usize> {
        match *self {
            Self::Read { sectors, .. } => (sectors as usize).checked_mul(SECTOR_BYTES),
            Self::Write { data, .. } => (data.len() % SECTOR_BYTES == 0).then_some(data.len()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferOutcome {
    /// Nothing was issued. The slot and DMA window remain the caller's.
    Refused(Error),
    /// The HBA released the slot with the exact byte count and a task file without failure bits.
    Completed,
    /// The HBA released the slot but the command failed. Its payload must not be consumed.
    Failed { error: Error, task_file: u32 },
    /// Issued and not released: a timeout or fatal port error. The HBA owns the slot and the DMA
    /// window until it completes or the port is recovered; no replay or reuse is permitted.
    Outstanding(Error),
}

impl TransferOutcome {
    /// The one success contract: only a released, error-free, full-length transfer.
    pub fn is_completed(self) -> bool {
        self == Self::Completed
    }
    /// The HBA no longer owns the slot or window (it was never issued or it was released).
    pub fn hba_released(self) -> bool {
        !matches!(self, Self::Outstanding(_))
    }
    /// A compact code for diagnostics: the task file of a failed command, or 0xFF otherwise.
    pub fn diagnostic(self) -> u32 {
        match self {
            Self::Completed => 0,
            Self::Failed { task_file, .. } => task_file,
            Self::Refused(_) | Self::Outstanding(_) => 0xff,
        }
    }
}

/// Bring up port engine state for `dma_paddr` unless it is already running there.
pub(crate) fn ensure_running(
    io: &mut impl PortIo,
    dma_paddr: u64,
    start: u64,
    budget: u64,
) -> Result<bool, Error> {
    let clb = u64::from(io.read_port(0)) | (u64::from(io.read_port(4)) << 32);
    let fb = u64::from(io.read_port(8)) | (u64::from(io.read_port(12)) << 32);
    if clb == dma_paddr && fb == dma_paddr + 0x400 && io.read_port(PX_CMD) & 0x11 == 0x11 {
        return Ok(true);
    }
    io.enable_ahci();
    let cmd = io.read_port(PX_CMD);
    io.write_port(PX_CMD, cmd & !1);
    wait_clear(io, PX_CMD, 1 << 15, start, budget)?;
    let cmd = io.read_port(PX_CMD);
    io.write_port(PX_CMD, cmd & !(1 << 4));
    wait_clear(io, PX_CMD, 1 << 14, start, budget)?;
    io.write_dma(0x400, &[0; 256]);
    io.write_port(0, dma_paddr as u32);
    io.write_port(4, (dma_paddr >> 32) as u32);
    io.write_port(8, (dma_paddr + 0x400) as u32);
    io.write_port(12, ((dma_paddr + 0x400) >> 32) as u32);
    let cmd = io.read_port(PX_CMD);
    io.write_port(PX_CMD, cmd | (1 << 4));
    io.write_port(PX_CMD, cmd | (1 << 4) | 1);
    Ok(false)
}

/// Issue one data transfer through slot zero. `window_bytes` is the DMA window length at
/// [`DATA_OFFSET`]; the payload of a `Read` is valid there only after [`TransferOutcome::Completed`].
pub fn transfer(
    io: &mut impl PortIo,
    dma_paddr: u64,
    window_bytes: usize,
    request: Transfer<'_>,
    budget_ticks: u64,
) -> TransferOutcome {
    let Some(bytes) = request
        .bytes()
        .filter(|bytes| *bytes != 0 && *bytes <= window_bytes && *bytes <= MAX_PRDT_BYTES)
    else {
        return TransferOutcome::Refused(Error::InvalidDma);
    };
    if dma_paddr & 0x3ff != 0
        || dma_paddr
            .checked_add((DATA_OFFSET + window_bytes) as u64)
            .is_none()
        || request.lba() >> 48 != 0
        || budget_ticks == 0
    {
        return TransferOutcome::Refused(Error::InvalidDma);
    }
    if io.read_port(PX_CI) != 0 || io.read_port(PX_SACT) != 0 {
        return TransferOutcome::Refused(Error::Busy);
    }
    let start = io.ticks();
    match ensure_running(io, dma_paddr, start, budget_ticks) {
        // A fatal error on the running engine awaits recovery; clearing it here would discard
        // the only record that the HBA may still own this window.
        Ok(true) if io.read_port(PX_IS) & PORT_IS_FATAL != 0 => {
            return TransferOutcome::Refused(Error::Device)
        }
        Ok(_) => {}
        Err(error) => return TransferOutcome::Refused(error),
    }
    if wait_clear(io, PX_TFD, 0x88, start, budget_ticks).is_err() {
        return TransferOutcome::Refused(Error::Busy);
    }
    let (opcode, write) = match request {
        Transfer::Read { .. } => (0x25, false),
        Transfer::Write { data, .. } => {
            io.write_dma(DATA_OFFSET, data);
            (0x35, true)
        }
    };
    let lba = request.lba().to_le_bytes();
    let mut table = [0u8; 144];
    table[0] = 0x27; // Register H2D
    table[1] = 0x80; // C = 1
    table[2] = opcode;
    table[4..7].copy_from_slice(&lba[0..3]);
    table[7] = 0x40; // LBA mode
    table[8..11].copy_from_slice(&lba[3..6]);
    table[12..14].copy_from_slice(&((bytes / SECTOR_BYTES) as u16).to_le_bytes());
    table[128..136].copy_from_slice(&(dma_paddr + DATA_OFFSET as u64).to_le_bytes());
    table[140..144].copy_from_slice(&((bytes as u32 - 1) | (1 << 31)).to_le_bytes());
    let mut header = [0u8; 32];
    header[0] = 5 | if write { 1 << 6 } else { 0 };
    header[2] = 1; // PRDTL = 1; PRDBC (bytes 4..8) resets to zero on every issue.
    header[8..16].copy_from_slice(&(dma_paddr + 0x500).to_le_bytes());
    io.write_dma(0x500, &table);
    io.write_dma(0, &header);
    io.write_port(PX_IS, u32::MAX);
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    io.write_port(PX_CI, 1);
    loop {
        if io.read_port(PX_IS) & PORT_IS_FATAL != 0 {
            return TransferOutcome::Outstanding(Error::Device);
        }
        if io.read_port(PX_CI) & 1 == 0 {
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            if io.read_port(PX_IS) & PORT_IS_FATAL != 0 {
                return TransferOutcome::Outstanding(Error::Device);
            }
            let task_file = io.read_port(PX_TFD) & 0xff;
            if task_file & TASK_FILE_FAILURE != 0 {
                return TransferOutcome::Failed {
                    error: Error::Device,
                    task_file,
                };
            }
            if io.read_dma_u32(4) as usize != bytes {
                return TransferOutcome::Failed {
                    error: Error::ShortTransfer,
                    task_file,
                };
            }
            return TransferOutcome::Completed;
        }
        if io.ticks().wrapping_sub(start) >= budget_ticks {
            return TransferOutcome::Outstanding(Error::Timeout);
        }
        io.relax();
    }
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
