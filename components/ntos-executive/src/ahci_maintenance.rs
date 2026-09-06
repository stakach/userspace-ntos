//! Boot-volume cache barriers. Device authority stays here; command policy is host-tested.

use super::{disk_census_ticks, platform_tsc_frequency_hz, Fat32};
use nt_ahci::{Command, Error, FlushCommand, PortIo};

struct Port {
    controller: u64,
    port: u64,
    dma: u64,
}

impl PortIo for Port {
    fn read_port(&mut self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.port + u64::from(offset)) as *const u32) }
    }

    fn write_port(&mut self, offset: u32, value: u32) {
        unsafe { core::ptr::write_volatile((self.port + u64::from(offset)) as *mut u32, value) }
    }

    fn enable_ahci(&mut self) {
        unsafe {
            let ghc = (self.controller + 4) as *mut u32;
            core::ptr::write_volatile(ghc, core::ptr::read_volatile(ghc) | (1 << 31));
        }
    }

    fn write_dma(&mut self, offset: usize, bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile((self.dma + (offset + index) as u64) as *mut u8, *byte)
            }
        }
    }

    fn read_dma_u32(&mut self, offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.dma + offset as u64) as *const u32) }
    }

    fn ticks(&mut self) -> u64 {
        disk_census_ticks()
    }
    fn relax(&mut self) {
        core::hint::spin_loop();
    }
}

/// The existing boot-volume transport exclusively owns port zero and this DMA frame during each
/// synchronous call. A timeout/error is returned, never converted to an unsupported no-op flush.
pub(super) unsafe fn flush(fat: &Fat32, selected: &mut Option<FlushCommand>) -> Result<(), Error> {
    let timeout = platform_tsc_frequency_hz()
        .checked_mul(30)
        .ok_or(Error::InvalidDma)?;
    let mut port = Port {
        controller: fat.ahci_vaddr,
        port: fat.ahci_vaddr + 0x100,
        dma: fat.dma_vaddr,
    };
    let command = match *selected {
        Some(command) => command,
        None => {
            nt_ahci::execute(&mut port, fat.dma_paddr, Command::Identify, timeout)?;
            let word83 = core::ptr::read_volatile(
                (fat.dma_vaddr + nt_ahci::DATA_OFFSET as u64 + 83 * 2) as *const u16,
            );
            let command = FlushCommand::from_identify_word83(word83)?;
            *selected = Some(command);
            command
        }
    };
    nt_ahci::execute(&mut port, fat.dma_paddr, Command::Flush(command), timeout)
}
