//! Polled AHCI maintenance commands over a caller-owned port and coherent DMA frame.
#![no_std]

#[cfg(test)]
mod tests;

pub const PORT_IS_FATAL: u32 = 0x7800_0000;
pub const TASK_FILE_FAILURE: u32 = 0xa9; // BSY | DF | DRQ | ERR
pub const DATA_OFFSET: usize = 0x800;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDma,
    Busy,
    Timeout,
    Device,
    ShortTransfer,
    UnsupportedFlush,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushCommand {
    Cache,
    CacheExt,
}

impl FlushCommand {
    /// ATA IDENTIFY word 83 includes its own validity bits. A device advertising neither
    /// command cannot satisfy this storage barrier contract.
    pub fn from_identify_word83(word: u16) -> Result<Self, Error> {
        if word & 0xc000 != 0x4000 {
            return Err(Error::UnsupportedFlush);
        }
        if word & (1 << 13) != 0 {
            Ok(Self::CacheExt)
        } else if word & (1 << 12) != 0 {
            Ok(Self::Cache)
        } else {
            Err(Error::UnsupportedFlush)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Identify,
    Flush(FlushCommand),
}

/// The caller exclusively owns the port, slot zero and one coherent 4 KiB DMA frame for the
/// whole command. Offsets are relative to that port/frame, not a controller-global port number.
/// `ticks` must be monotonic; the same clock defines the caller's timeout budget.
pub trait PortIo {
    fn read_port(&mut self, offset: u32) -> u32;
    fn write_port(&mut self, offset: u32, value: u32);
    fn enable_ahci(&mut self);
    fn write_dma(&mut self, offset: usize, bytes: &[u8]);
    fn read_dma_u32(&mut self, offset: usize) -> u32;
    fn ticks(&mut self) -> u64;
    fn relax(&mut self);
}

fn wait_clear(
    io: &mut impl PortIo,
    register: u32,
    mask: u32,
    start: u64,
    budget: u64,
) -> Result<(), Error> {
    loop {
        if io.read_port(register) & mask == 0 {
            return Ok(());
        }
        if io.ticks().wrapping_sub(start) >= budget {
            return Err(Error::Timeout);
        }
        io.relax();
    }
}

/// Synchronously issue IDENTIFY or a non-data cache flush. An active command is never overwritten,
/// including after a prior timeout. Recovery/reset of a failed port remains the caller's job.
pub fn execute(
    io: &mut impl PortIo,
    dma_paddr: u64,
    command: Command,
    timeout_ticks: u64,
) -> Result<(), Error> {
    if dma_paddr & 0x3ff != 0 || dma_paddr.checked_add(0xfff).is_none() || timeout_ticks == 0 {
        return Err(Error::InvalidDma);
    }
    if io.read_port(0x38) != 0 || io.read_port(0x34) != 0 {
        return Err(Error::Busy);
    }
    let start = io.ticks();
    let clb = u64::from(io.read_port(0)) | (u64::from(io.read_port(4)) << 32);
    let fb = u64::from(io.read_port(8)) | (u64::from(io.read_port(12)) << 32);
    if clb != dma_paddr || fb != dma_paddr + 0x400 || io.read_port(0x18) & 0x11 != 0x11 {
        io.enable_ahci();
        let cmd = io.read_port(0x18);
        io.write_port(0x18, cmd & !1);
        wait_clear(io, 0x18, 1 << 15, start, timeout_ticks)?;
        let cmd = io.read_port(0x18);
        io.write_port(0x18, cmd & !(1 << 4));
        wait_clear(io, 0x18, 1 << 14, start, timeout_ticks)?;
        io.write_dma(0x400, &[0; 256]);
        io.write_port(0, dma_paddr as u32);
        io.write_port(4, (dma_paddr >> 32) as u32);
        io.write_port(8, (dma_paddr + 0x400) as u32);
        io.write_port(12, ((dma_paddr + 0x400) >> 32) as u32);
        let cmd = io.read_port(0x18);
        io.write_port(0x18, cmd | (1 << 4));
        io.write_port(0x18, cmd | (1 << 4) | 1);
    }
    wait_clear(io, 0x20, 0x88, start, timeout_ticks)?;
    let mut table = [0u8; 144];
    table[0] = 0x27;
    table[1] = 0x80;
    table[2] = match command {
        Command::Identify => 0xec,
        Command::Flush(FlushCommand::Cache) => 0xe7,
        Command::Flush(FlushCommand::CacheExt) => 0xea,
    };
    let mut header = [0u8; 32];
    header[0] = 5; // CFL=5, W=0; PRDBC and reserved fields reset on every issue.
    header[8..16].copy_from_slice(&(dma_paddr + 0x500).to_le_bytes());
    if command == Command::Identify {
        header[2] = 1; // One PRDT entry only for IDENTIFY's 512-byte data transfer.
        table[128..136].copy_from_slice(&(dma_paddr + DATA_OFFSET as u64).to_le_bytes());
        table[140..144].copy_from_slice(&511u32.to_le_bytes());
    }
    io.write_dma(0x500, &table);
    io.write_dma(0, &header);
    io.write_port(0x10, u32::MAX);
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    io.write_port(0x38, 1);
    loop {
        if io.read_port(0x10) & PORT_IS_FATAL != 0 {
            return Err(Error::Device);
        }
        if io.read_port(0x38) & 1 == 0 {
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            if io.read_port(0x10) & PORT_IS_FATAL != 0
                || io.read_port(0x20) & TASK_FILE_FAILURE != 0
            {
                return Err(Error::Device);
            }
            if command == Command::Identify && io.read_dma_u32(4) != 512 {
                return Err(Error::ShortTransfer);
            }
            return Ok(());
        }
        if io.ticks().wrapping_sub(start) >= timeout_ticks {
            return Err(Error::Timeout);
        }
        io.relax();
    }
}
