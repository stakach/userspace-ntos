//! Declared widths of x64 system-service arguments and results.
//!
//! A register or stack slot carries 64 bits, but only the bits of the declared C type are
//! defined: the caller may leave anything above them. A service decision must therefore read
//! the slot at the declared width before comparing it, using it as a length, or keying on it.

/// `BOOLEAN`, `UCHAR`, `BYTE`.
pub const fn boolean(slot: u64) -> bool {
    slot as u8 != 0
}

/// `BOOL`.
pub const fn bool32(slot: u64) -> bool {
    slot as u32 != 0
}

/// `USHORT`, `WORD`, `ATOM`, `RTL_ATOM`.
pub const fn ushort(slot: u64) -> u16 {
    slot as u16
}

/// `ULONG`, `DWORD`, `UINT`, `FLONG`.
pub const fn ulong(slot: u64) -> u32 {
    slot as u32
}

/// `LONG`, `INT`.
pub const fn long(slot: u64) -> i32 {
    slot as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// r9 as msgina left it for `BOOLEAN bNonImmersive` in KVM run 43595199385.
    const DIRTY_TRUE: u64 = 0x2_7e01;
    const DIRTY_FALSE: u64 = 0x2_7e00;

    #[test]
    fn a_boolean_is_its_low_byte() {
        assert!(boolean(DIRTY_TRUE));
        assert!(!boolean(DIRTY_FALSE));
    }

    #[test]
    fn thirty_two_bit_values_ignore_the_upper_half() {
        let slot = 0x100_0000_0000 | 0x14;
        assert_eq!(ulong(slot), 0x14);
        assert!(!bool32(0x100_0000_0000));
        assert!(bool32(0x100_0000_0001));
        assert_eq!(long(0xdead_beef_ffff_fffe), -2);
    }

    #[test]
    fn an_atom_is_its_low_word() {
        assert_eq!(ushort(0xffff_8000_0000_c03a), 0xc03a);
        assert_eq!(ushort(0xffff_8000_0001_0000), 0);
    }
}
