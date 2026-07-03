//! # `nt-sim-device` — the simulated MMIO interrupt device
//!
//! The fake hardware the `MmioInterruptTest.sys` driver drives (spec: Milestone 11,
//! §5.8, §12): a bounded register bank plus a test-triggered interrupt line. Layout
//! (spec §12):
//!
//! | offset | register | access |
//! |--------|----------|--------|
//! | `0x00` | ID (`0x4d4d494f` = "MMIO") | read-only |
//! | `0x04` | control  | read/write |
//! | `0x08` | status (bit0 = interrupt pending) | read/write |
//! | `0x0c` | interrupt ack (write 1 clears pending) | read/write |
//! | `0x10` | interrupt count | read/write |
//!
//! `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use nt_register_access::{RegError, RegisterBank};

pub const REG_ID: u64 = 0x00;
pub const REG_CONTROL: u64 = 0x04;
pub const REG_STATUS: u64 = 0x08;
pub const REG_ACK: u64 = 0x0c;
pub const REG_IRQ_COUNT: u64 = 0x10;

/// The device ID register value (`"MMIO"` little-endian).
pub const ID_VALUE: u32 = 0x4d4d_494f;
/// `status` bit0 — an interrupt is pending.
pub const STATUS_INTERRUPT_PENDING: u32 = 0x0000_0001;

/// The simulated MMIO device (default region `0x1000` bytes).
pub struct SimDevice {
    bank: RegisterBank,
}

impl SimDevice {
    /// A fresh device: ID register set + marked read-only, all else zero.
    pub fn new() -> Self {
        Self::with_len(0x1000)
    }

    pub fn with_len(len: usize) -> Self {
        let mut bank = RegisterBank::new(len);
        bank.poke_u32(REG_ID, ID_VALUE).unwrap();
        bank.mark_readonly(REG_ID, 4);
        Self { bank }
    }

    pub fn bank(&mut self) -> &mut RegisterBank {
        &mut self.bank
    }

    /// The device's ID register.
    pub fn id(&self) -> u32 {
        self.bank.read_u32(REG_ID).unwrap()
    }

    /// Raise the interrupt line: set `status` bit0 (spec §9.4 injection). The ISR
    /// reads `status`, writes `ack`, then acknowledges via [`Self::acknowledge`].
    pub fn raise_interrupt(&mut self) {
        let s = self.bank.read_u32(REG_STATUS).unwrap_or(0);
        self.bank
            .poke_u32(REG_STATUS, s | STATUS_INTERRUPT_PENDING)
            .unwrap();
    }

    /// Whether the interrupt line is currently asserted.
    pub fn interrupt_pending(&self) -> bool {
        self.bank.read_u32(REG_STATUS).unwrap_or(0) & STATUS_INTERRUPT_PENDING != 0
    }

    /// Model the driver writing the ack register: clear `status` bit0 + bump the
    /// device's interrupt count (spec §12 "write 1 clears pending").
    pub fn acknowledge(&mut self) {
        let s = self.bank.read_u32(REG_STATUS).unwrap_or(0);
        self.bank
            .poke_u32(REG_STATUS, s & !STATUS_INTERRUPT_PENDING)
            .unwrap();
        let c = self.bank.read_u32(REG_IRQ_COUNT).unwrap_or(0);
        self.bank
            .poke_u32(REG_IRQ_COUNT, c.wrapping_add(1))
            .unwrap();
    }

    /// Checked register read (`READ_REGISTER_ULONG` path).
    pub fn read_reg32(&self, offset: u64) -> Result<u32, RegError> {
        self.bank.read_u32(offset)
    }

    /// Checked register write (`WRITE_REGISTER_ULONG` path).
    pub fn write_reg32(&mut self, offset: u64, value: u32) -> Result<(), RegError> {
        self.bank.write_u32(offset, value)
    }

    /// Raw pointer to the register bank — for the Driver Host to expose as the
    /// `MmMapIoSpace` result (inlined register macros dereference it directly).
    pub fn mmio_ptr(&mut self) -> *mut u8 {
        self.bank.as_mut_ptr()
    }
}

impl Default for SimDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_register_readonly_and_correct() {
        let mut d = SimDevice::new();
        assert_eq!(d.id(), 0x4d4d_494f);
        // ID is read-only.
        assert_eq!(d.write_reg32(REG_ID, 0), Err(RegError::ReadOnly));
        // Control is writable.
        d.write_reg32(REG_CONTROL, 0xABCD).unwrap();
        assert_eq!(d.read_reg32(REG_CONTROL).unwrap(), 0xABCD);
    }

    #[test]
    fn interrupt_line_raise_and_ack() {
        let mut d = SimDevice::new();
        assert!(!d.interrupt_pending());
        d.raise_interrupt();
        assert!(d.interrupt_pending());
        // The driver reads status, then acks.
        assert_eq!(
            d.read_reg32(REG_STATUS).unwrap() & STATUS_INTERRUPT_PENDING,
            1
        );
        d.acknowledge();
        assert!(!d.interrupt_pending());
        assert_eq!(d.read_reg32(REG_IRQ_COUNT).unwrap(), 1);
    }
}
