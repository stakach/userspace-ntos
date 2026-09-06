use super::*;

struct Port {
    regs: [u32; 16],
    dma: [u8; 4096],
    ticks: u64,
    issued: bool,
    complete: bool,
    error_is: u32,
    error_tfd: u32,
    dma_writes: usize,
    stuck_engine: bool,
    transfer_bytes: u32,
}

impl Port {
    fn new() -> Self {
        Self {
            regs: [0; 16],
            dma: [0xcc; 4096],
            ticks: 0,
            issued: false,
            complete: true,
            error_is: 0,
            error_tfd: 0,
            dma_writes: 0,
            stuck_engine: false,
            transfer_bytes: 512,
        }
    }
}

impl PortIo for Port {
    fn read_port(&mut self, offset: u32) -> u32 {
        self.regs[offset as usize / 4]
    }
    fn write_port(&mut self, offset: u32, value: u32) {
        if offset == 0x10 {
            self.regs[4] &= !value;
            return;
        }
        if offset == 0x18 && self.stuck_engine {
            return;
        }
        self.regs[offset as usize / 4] = value;
        if offset == 0x38 {
            assert_eq!(&self.dma[4..8], &[0; 4], "PRDBC reset before issue");
            self.issued = true;
            self.regs[4] = self.error_is;
            self.regs[8] = self.error_tfd;
            if self.complete {
                self.regs[14] = 0;
                if self.dma[0x502] == 0xec {
                    self.dma[4..8].copy_from_slice(&self.transfer_bytes.to_le_bytes());
                }
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
        let ticks = self.ticks;
        self.ticks += 1;
        ticks
    }
    fn relax(&mut self) {}
}

#[test]
fn flush_selection_uses_valid_advertised_capabilities() {
    for word in [0, 0xffff, 0x3000, 0xc000, 0x4000] {
        assert_eq!(
            FlushCommand::from_identify_word83(word),
            Err(Error::UnsupportedFlush)
        );
    }
    assert_eq!(
        FlushCommand::from_identify_word83(0x5000),
        Ok(FlushCommand::Cache)
    );
    assert_eq!(
        FlushCommand::from_identify_word83(0x6000),
        Ok(FlushCommand::CacheExt)
    );
    assert_eq!(
        FlushCommand::from_identify_word83(0x7000),
        Ok(FlushCommand::CacheExt)
    );
}

#[test]
fn flush_has_no_dma_payload_or_stale_task_file() {
    for (command, opcode) in [(FlushCommand::Cache, 0xe7), (FlushCommand::CacheExt, 0xea)] {
        let mut port = Port::new();
        execute(&mut port, 0x1234_0000_0000, Command::Flush(command), 30).unwrap();
        assert_eq!(&port.dma[..8], &[5, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&port.dma[0x500..0x503], &[0x27, 0x80, opcode]);
        assert!(port.dma[0x503..0x590].iter().all(|b| *b == 0));
        assert!(port.dma[DATA_OFFSET..].iter().all(|b| *b == 0xcc));
        assert_eq!(
            u64::from_le_bytes(port.dma[8..16].try_into().unwrap()),
            0x1234_0000_0500
        );
    }
}

#[test]
fn identify_transfers_exactly_one_sector_with_reset_prdbc() {
    let mut port = Port::new();
    execute(&mut port, 0x4000, Command::Identify, 30).unwrap();
    assert_eq!(&port.dma[..8], &[5, 0, 1, 0, 0, 2, 0, 0]);
    assert_eq!(port.dma[0x502], 0xec);
    assert_eq!(
        u64::from_le_bytes(port.dma[0x580..0x588].try_into().unwrap()),
        0x4800
    );
    assert_eq!(
        u32::from_le_bytes(port.dma[0x58c..0x590].try_into().unwrap()),
        511
    );
}

#[test]
fn active_commands_are_never_overwritten() {
    for register in [0x34, 0x38] {
        let mut port = Port::new();
        port.regs[register / 4] = 4;
        assert_eq!(
            execute(&mut port, 0x4000, Command::Identify, 30),
            Err(Error::Busy)
        );
        assert!(!port.issued);
        assert_eq!(port.dma_writes, 0);
    }
}

#[test]
fn identify_short_or_impossible_transfer_does_not_publish_capabilities() {
    for bytes in [0, 128, 511, 513] {
        let mut port = Port::new();
        port.transfer_bytes = bytes;
        assert_eq!(
            execute(&mut port, 0x4000, Command::Identify, 30),
            Err(Error::ShortTransfer)
        );
    }
}

#[test]
fn fatal_interface_bus_and_task_file_errors_are_reported() {
    for error_is in [1 << 27, 1 << 28, 1 << 29, 1 << 30] {
        let mut port = Port::new();
        port.error_is = error_is;
        port.complete = false;
        assert_eq!(
            execute(&mut port, 0x4000, Command::Identify, 30),
            Err(Error::Device)
        );
    }
    for error_tfd in [1, 8, 0x20, 0x80] {
        let mut port = Port::new();
        port.error_tfd = error_tfd;
        assert_eq!(
            execute(&mut port, 0x4000, Command::Identify, 30),
            Err(Error::Device)
        );
    }
}

#[test]
fn timed_out_slot_is_retained_and_reissue_is_refused() {
    let mut port = Port::new();
    port.complete = false;
    assert_eq!(
        execute(&mut port, 0x4000, Command::Identify, 30),
        Err(Error::Timeout)
    );
    let writes = port.dma_writes;
    assert_eq!(
        execute(&mut port, 0x4000, Command::Identify, 30),
        Err(Error::Busy)
    );
    assert_eq!(port.dma_writes, writes);
}

#[test]
fn engine_stop_failure_does_not_reprogram_bases_or_dma() {
    for stuck_bit in [1 << 14, 1 << 15] {
        let mut port = Port::new();
        port.regs[6] = stuck_bit | 0x11;
        port.stuck_engine = true;
        assert_eq!(
            execute(&mut port, 0x4000, Command::Identify, 30),
            Err(Error::Timeout)
        );
        assert_eq!(port.dma_writes, 0);
        assert_eq!(port.regs[0], 0);
        assert!(!port.issued);
    }
}

#[test]
fn busy_task_file_times_out_before_command_publication() {
    let mut port = Port::new();
    port.regs[8] = 0x80;
    assert_eq!(
        execute(&mut port, 0x4000, Command::Identify, 30),
        Err(Error::Timeout)
    );
    assert!(!port.issued);
}

#[test]
fn invalid_dma_or_timeout_is_rejected_without_hardware_changes() {
    for (dma, timeout) in [(1, 30), (u64::MAX & !0x3ff, 30), (0x4000, 0)] {
        let mut port = Port::new();
        assert_eq!(
            execute(&mut port, dma, Command::Identify, timeout),
            Err(Error::InvalidDma)
        );
        assert_eq!(port.dma_writes, 0);
        assert!(!port.issued);
    }
}
