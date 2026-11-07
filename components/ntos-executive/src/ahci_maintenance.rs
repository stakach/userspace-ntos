//! Boot-volume cache barriers. Device authority stays here; command policy is host-tested.

use super::{disk_census_ticks, platform_tsc_frequency_hz, Fat32};
use nt_ahci::{Command, Error, FlushCommand, PortIo};
use nt_pnp_context::native_storage_handoff::ExpectedDisk;

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
    let admission = crate::boot_storage_dma_handoff::enter_boot_io()
        .map_err(|_| Error::Busy)?;
    let started = fat.census.then(disk_census_ticks);
    let result = flush_owned(fat, selected);
    crate::boot_storage_dma_handoff::finish_boot_io(admission, result.is_ok());
    crate::fs_loader::disk_census_record(
        nt_ahci::IoOperation::Barrier,
        started,
        0,
        result.is_err(),
    );
    result
}

/// Identify the actual AHCI device size while the boot-volume owner holds port zero.
/// Read-only GPT metadata is insufficient to authorize sectors appended after its backup header.
pub(super) unsafe fn physical_sector_count(fat: &Fat32) -> Result<u64, Error> {
    let admission = crate::boot_storage_dma_handoff::enter_boot_io()
        .map_err(|_| Error::Busy)?;
    let Some(timeout) = platform_tsc_frequency_hz().checked_mul(30) else {
        crate::boot_storage_dma_handoff::finish_boot_io(admission, true);
        return Err(Error::InvalidDma);
    };
    let mut port = Port {
        controller: fat.ahci_vaddr,
        port: fat.ahci_vaddr + 0x100,
        dma: fat.dma_vaddr,
    };
    let result = nt_ahci::execute(&mut port, fat.dma_paddr, Command::Identify, timeout);
    crate::boot_storage_dma_handoff::finish_boot_io(admission, result.is_ok());
    result?;
    let word = |index: u64| unsafe {
        core::ptr::read_volatile(
            (fat.dma_vaddr + nt_ahci::DATA_OFFSET as u64 + index * 2) as *const u16,
        )
    };
    nt_ahci::lba48_sector_count(word(83), [word(100), word(101), word(102), word(103)])
        .ok_or(Error::Device)
}

/// Capture actual boot-controller media sectors before the irreversible DMA drain. A native
/// LUN must later return these bytes and capacity through its own SRBs before it can serve the
/// mounted FAT and snapshot reserve; GPT or a registry disk name is not that proof.
pub(super) unsafe fn expected_disk(
    fat: &Fat32,
    physical_sectors: u64,
) -> Result<ExpectedDisk, Error> {
    if physical_sectors == 0
        || fat.volume_start_lba == 0
        || fat.volume_start_lba >= physical_sectors
    {
        return Err(Error::Device);
    }
    let mut sector_zero = [0u8; 512];
    let mut volume_sector = [0u8; 512];
    for (lba, output) in [
        (0, &mut sector_zero),
        (fat.volume_start_lba, &mut volume_sector),
    ] {
        if !nt_ahci::read_completion_ok(super::ahci_read_sector(
            fat.ahci_vaddr, fat.dma_vaddr, fat.dma_paddr, lba,
        )) {
            return Err(Error::Device);
        }
        core::ptr::copy_nonoverlapping(
            (fat.dma_vaddr + super::AHCI_DMA_DATA_OFFSET) as *const u8,
            output.as_mut_ptr(),
            output.len(),
        );
    }
    Ok(ExpectedDisk {
        sector_count: physical_sectors,
        volume_lba: fat.volume_start_lba,
        sector_zero,
        volume_sector,
    })
}

unsafe fn flush_owned(fat: &Fat32, selected: &mut Option<FlushCommand>) -> Result<(), Error> {
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
