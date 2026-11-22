use super::*;

const DMA: u64 = 0x4000;
const PAGES: usize = 3;
const WINDOW: usize = PAGES * 4096 - DATA_OFFSET;
const BUDGET: u64 = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Completion {
    Now,
    Never,
    /// Clear PxCI only after this many further port reads.
    After(u32),
}

struct Hba {
    regs: [u32; 16],
    dma: [u8; PAGES * 4096],
    ticks: u64,
    issues: u32,
    completion: Completion,
    pending_reads: Option<u32>,
    issue_is: u32,
    issue_tfd: u32,
    /// Bytes the device moves for a read and reports in PRDBC; `None` means the full request.
    moved: Option<usize>,
    dma_writes: usize,
}

impl Hba {
    fn new() -> Self {
        Self {
            regs: [0; 16],
            dma: [0xcc; PAGES * 4096],
            ticks: 0,
            issues: 0,
            completion: Completion::Now,
            pending_reads: None,
            issue_is: 0,
            issue_tfd: 0x50,
            moved: None,
            dma_writes: 0,
        }
    }

    fn requested_bytes(&self) -> usize {
        (u32::from_le_bytes(self.dma[0x58c..0x590].try_into().unwrap()) & 0x3f_ffff) as usize + 1
    }

    fn complete(&mut self) {
        let bytes = self.moved.unwrap_or(self.requested_bytes());
        if self.dma[0x502] == 0x25 {
            for (index, byte) in self.dma[DATA_OFFSET..DATA_OFFSET + bytes]
                .iter_mut()
                .enumerate()
            {
                *byte = index as u8;
            }
        }
        self.dma[4..8].copy_from_slice(&(bytes as u32).to_le_bytes());
        self.regs[14] = 0;
    }
}

impl PortIo for Hba {
    fn read_port(&mut self, offset: u32) -> u32 {
        if offset == PX_CI {
            if let Some(remaining) = self.pending_reads.as_mut() {
                if *remaining == 0 {
                    self.pending_reads = None;
                    self.complete();
                } else {
                    *remaining -= 1;
                }
            }
        }
        self.regs[offset as usize / 4]
    }
    fn write_port(&mut self, offset: u32, value: u32) {
        if offset == PX_IS {
            self.regs[4] &= !value;
            return;
        }
        self.regs[offset as usize / 4] = value;
        if offset == PX_CI {
            assert_eq!(&self.dma[4..8], &[0; 4], "PRDBC reset before issue");
            self.issues += 1;
            self.regs[4] = self.issue_is;
            self.regs[8] = self.issue_tfd;
            match self.completion {
                Completion::Now => self.complete(),
                Completion::Never => {}
                Completion::After(reads) => self.pending_reads = Some(reads),
            }
        }
    }
    fn enable_ahci(&mut self) {}
    fn write_dma(&mut self, offset: usize, bytes: &[u8]) {
        self.dma_writes += 1;
        self.dma[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    fn read_dma_u32(&mut self, offset: usize) -> u32 {
        u32::from_le_bytes(self.dma[offset..offset + 4].try_into().unwrap())
    }
    fn ticks(&mut self) -> u64 {
        self.ticks += 1;
        self.ticks
    }
    fn relax(&mut self) {}
}

fn read(hba: &mut Hba, sectors: u32) -> TransferOutcome {
    transfer(
        hba,
        DMA,
        WINDOW,
        Transfer::Read {
            lba: 0x12_3456_789a,
            sectors,
        },
        BUDGET,
    )
}

#[test]
fn completed_read_programs_one_exact_prdt_and_releases_the_slot() {
    let mut hba = Hba::new();
    assert_eq!(read(&mut hba, 4), TransferOutcome::Completed);
    assert_eq!(&hba.dma[..4], &[5, 0, 1, 0]);
    assert_eq!(
        &hba.dma[0x500..0x50e],
        &[0x27, 0x80, 0x25, 0, 0x9a, 0x78, 0x56, 0x40, 0x34, 0x12, 0, 0, 4, 0,]
    );
    assert_eq!(
        u64::from_le_bytes(hba.dma[0x580..0x588].try_into().unwrap()),
        DMA + 0x800
    );
    assert_eq!(hba.requested_bytes(), 2048);
    assert!(TransferOutcome::Completed.hba_released());
}

#[test]
fn legal_multi_sector_read_owns_the_former_fat_cache_bytes() {
    // The FAT sector cache used to live at [0xA00, 0xC08) of this DMA page. Any read of more
    // than one sector is legal and the HBA writes straight through that range.
    let mut hba = Hba::new();
    assert_eq!(read(&mut hba, 3), TransferOutcome::Completed);
    assert!(hba.dma[0xa00..0xc08].iter().any(|byte| *byte != 0xcc));
    const _: () = assert!(DATA_OFFSET + 3 * 512 > 0xa00 + 8);
}

#[test]
fn write_staging_covers_the_window_and_is_written_only_to_a_free_slot() {
    let data = [0x5a; 4 * 512];
    let mut hba = Hba::new();
    hba.regs[14] = 1; // A previous command still owns slot zero.
    let request = Transfer::Write {
        lba: 9,
        data: &data,
    };
    assert_eq!(
        transfer(&mut hba, DMA, WINDOW, request, BUDGET),
        TransferOutcome::Refused(Error::Busy)
    );
    assert_eq!(hba.dma_writes, 0);
    assert!(hba.dma[DATA_OFFSET..].iter().all(|byte| *byte == 0xcc));
    hba.regs[14] = 0;
    assert_eq!(
        transfer(&mut hba, DMA, WINDOW, request, BUDGET),
        TransferOutcome::Completed
    );
    assert!(hba.dma[DATA_OFFSET..DATA_OFFSET + data.len()]
        .iter()
        .all(|byte| *byte == 0x5a));
    assert_eq!(hba.dma[0x502], 0x35);
    assert_eq!(hba.dma[0] & (1 << 6), 1 << 6);
}

#[test]
fn completed_ata_error_is_a_released_failure_not_data() {
    for task_file in [0x51, 0x59, 0x71, 0xd0] {
        let mut hba = Hba::new();
        hba.issue_tfd = task_file;
        let outcome = read(&mut hba, 2);
        assert_eq!(
            outcome,
            TransferOutcome::Failed {
                error: Error::Device,
                task_file
            }
        );
        assert!(!outcome.is_completed());
        assert!(outcome.hba_released());
        assert_eq!(outcome.diagnostic(), task_file);
        // The HBA released the slot; once the device is ready a new command may be issued.
        hba.issue_tfd = 0x50;
        hba.regs[8] = 0x50;
        assert_eq!(read(&mut hba, 1), TransferOutcome::Completed);
    }
}

#[test]
fn cache_shaped_partial_dma_is_rejected_by_byte_count() {
    let mut hba = Hba::new();
    hba.moved = Some(520); // One sector plus a cache-header-sized tail.
    let outcome = read(&mut hba, 3);
    assert_eq!(
        outcome,
        TransferOutcome::Failed {
            error: Error::ShortTransfer,
            task_file: 0x50
        }
    );
    assert!(!outcome.is_completed());
}

#[test]
fn fatal_status_with_ci_still_set_retains_the_slot() {
    for fatal in [1 << 27, 1 << 28, 1 << 29, 1 << 30] {
        let mut hba = Hba::new();
        hba.completion = Completion::Never;
        hba.issue_is = fatal;
        let outcome = read(&mut hba, 4);
        assert_eq!(outcome, TransferOutcome::Outstanding(Error::Device));
        assert!(!outcome.hba_released());
        assert_eq!(hba.regs[14], 1, "the HBA still owns slot zero");
        let writes = hba.dma_writes;
        assert_eq!(read(&mut hba, 1), TransferOutcome::Refused(Error::Busy));
        assert_eq!(hba.dma_writes, writes);
        assert_eq!(hba.issues, 1);
    }
}

#[test]
fn latched_fatal_on_a_running_port_refuses_reissue_without_clearing_it() {
    let mut hba = Hba::new();
    hba.issue_is = 1 << 30;
    assert_eq!(
        read(&mut hba, 1),
        TransferOutcome::Outstanding(Error::Device)
    );
    hba.issue_is = 0;
    let writes = hba.dma_writes;
    assert_eq!(read(&mut hba, 1), TransferOutcome::Refused(Error::Device));
    assert_eq!(
        hba.regs[4],
        1 << 30,
        "the fatal record is retained for recovery"
    );
    assert_eq!((hba.dma_writes, hba.issues), (writes, 1));
}

#[test]
fn completion_delayed_past_timeout_is_outstanding_until_the_hba_releases_it() {
    let mut hba = Hba::new();
    hba.completion = Completion::After(BUDGET as u32 * 2);
    assert_eq!(
        read(&mut hba, 2),
        TransferOutcome::Outstanding(Error::Timeout)
    );
    let writes = hba.dma_writes;
    // Each refused attempt observes PxCI; the late completion eventually lands.
    let mut refused = 0;
    while read(&mut hba, 1) == TransferOutcome::Refused(Error::Busy) {
        refused += 1;
        assert_eq!(hba.dma_writes, writes);
        assert!(refused < BUDGET * 4);
    }
    assert!(refused > 0);
    assert_eq!(hba.issues, 2);
}

#[test]
fn invalid_requests_change_no_hardware_state() {
    let odd = [0u8; 513];
    for request in [
        Transfer::Read { lba: 0, sectors: 0 },
        Transfer::Read {
            lba: 0,
            sectors: (WINDOW / 512) as u32 + 1,
        },
        Transfer::Read {
            lba: 1 << 48,
            sectors: 1,
        },
        Transfer::Write { lba: 0, data: &odd },
        Transfer::Write { lba: 0, data: &[] },
    ] {
        let mut hba = Hba::new();
        assert_eq!(
            transfer(&mut hba, DMA, WINDOW, request, BUDGET),
            TransferOutcome::Refused(Error::InvalidDma)
        );
        assert_eq!((hba.dma_writes, hba.issues), (0, 0));
    }
    let mut hba = Hba::new();
    assert_eq!(
        transfer(
            &mut hba,
            DMA + 0x200,
            WINDOW,
            Transfer::Read { lba: 0, sectors: 1 },
            BUDGET
        ),
        TransferOutcome::Refused(Error::InvalidDma)
    );
}
