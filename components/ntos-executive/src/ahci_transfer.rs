//! Boot AHCI data transfers through slot zero of the controller DMA run.
//!
//! The command list, FIS and command table live in the first 0x800 bytes; the data window runs
//! from `AHCI_DMA_DATA_OFFSET` to the end of the mapped run. Command policy and HBA ownership
//! outcomes are host-tested in `nt_ahci::transfer`. This path is shared with the isolated storage
//! host, whose image is mapped read-only, so it keeps no state in statics: the port registers are
//! the retained record of a command the HBA has not released.

use super::*;
use nt_ahci::{PortIo, Transfer, TransferOutcome};

const WINDOW_BYTES: usize = (AHCI_BOOT_DMA_PAGES * 0x1000 - AHCI_DMA_DATA_OFFSET) as usize;
/// Polls of the port, matching the previous fixed spin bound; a poll budget needs no clock that
/// the isolated host may lack.
const POLL_BUDGET: u64 = 5_000_000;

struct Port {
    controller: u64,
    dma: u64,
    polls: u64,
}

impl Port {
    fn port(&self) -> u64 {
        self.controller + 0x100
    }
}

impl PortIo for Port {
    fn read_port(&mut self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.port() + u64::from(offset)) as *const u32) }
    }
    fn write_port(&mut self, offset: u32, value: u32) {
        unsafe { core::ptr::write_volatile((self.port() + u64::from(offset)) as *mut u32, value) }
    }
    fn enable_ahci(&mut self) {
        unsafe {
            let ghc = (self.controller + 4) as *mut u32;
            core::ptr::write_volatile(ghc, core::ptr::read_volatile(ghc) | (1 << 31));
        }
    }
    fn write_dma(&mut self, offset: usize, bytes: &[u8]) {
        unsafe {
            let base = (self.dma + offset as u64) as *mut u8;
            if bytes.len() > 256 {
                // Bulk payload staging precedes the release fence that publishes it to the HBA.
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), base, bytes.len());
            } else {
                for (index, byte) in bytes.iter().enumerate() {
                    core::ptr::write_volatile(base.add(index), *byte);
                }
            }
        }
    }
    fn read_dma_u32(&mut self, offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.dma + offset as u64) as *const u32) }
    }
    fn ticks(&mut self) -> u64 {
        self.polls += 1;
        self.polls
    }
    fn relax(&mut self) {
        core::hint::spin_loop();
    }
}

unsafe fn transfer_untracked(
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    request: Transfer<'_>,
) -> TransferOutcome {
    let mut port = Port { controller: ahci_vaddr, dma: dma_vaddr, polls: 0 };
    nt_ahci::transfer(&mut port, dma_paddr, WINDOW_BYTES, request, POLL_BUDGET)
}

/// An issued command the HBA has not released keeps its boot I/O ticket, so the controller
/// cannot drain or hand off the DMA run beneath it.
unsafe fn transfer_admitted(
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    request: Transfer<'_>,
) -> TransferOutcome {
    let Ok(admission) = boot_storage_dma_handoff::enter_boot_io() else {
        return TransferOutcome::Refused(nt_ahci::Error::Busy);
    };
    let outcome = transfer_untracked(ahci_vaddr, dma_vaddr, dma_paddr, request);
    boot_storage_dma_handoff::finish_boot_io(admission, outcome.hba_released());
    outcome
}

/// READ one sector into the data window. Its bytes are valid only on `Completed`.
pub(super) unsafe fn ahci_read_sector(
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    sector: u64,
) -> TransferOutcome {
    ahci_read_sectors(ahci_vaddr, dma_vaddr, dma_paddr, sector, 1)
}

pub(super) unsafe fn ahci_read_sectors(
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    sector: u64,
    sectors: u32,
) -> TransferOutcome {
    transfer_admitted(ahci_vaddr, dma_vaddr, dma_paddr, Transfer::Read { lba: sector, sectors })
}

/// The one-shot storage host runs from a read-only alias of this image and cannot mutate the
/// executive's ticket ledger. Its owner is selected only by the isolated host mount entry.
pub(super) unsafe fn ahci_read_sector_isolated_storage_host(
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    sector: u64,
) -> TransferOutcome {
    ahci_read_sectors_isolated_storage_host(ahci_vaddr, dma_vaddr, dma_paddr, sector, 1)
}

pub(super) unsafe fn ahci_read_sectors_isolated_storage_host(
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    sector: u64,
    sectors: u32,
) -> TransferOutcome {
    transfer_untracked(ahci_vaddr, dma_vaddr, dma_paddr, Transfer::Read { lba: sector, sectors })
}

/// WRITE whole sectors, staged into the data window only once slot zero is free.
pub(super) unsafe fn ahci_write_sectors(
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    sector: u64,
    data: &[u8],
) -> TransferOutcome {
    transfer_admitted(ahci_vaddr, dma_vaddr, dma_paddr, Transfer::Write { lba: sector, data })
}
