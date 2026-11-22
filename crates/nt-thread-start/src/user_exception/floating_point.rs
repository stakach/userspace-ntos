//! The exception an x87 (#MF) or SSE (#XM) floating-point fault raises, from the faulting
//! thread's `FXSAVE` image, as ReactOS `KiNpxHandler` (ke/i386/traphdlr.c) and
//! `KiXmmExceptionHandler` (ke/amd64/except.c) decide it.

use crate::amd64_context::{FX_MXCSR_OFFSET, LEGACY_FLOATING_POINT_BYTES};

pub const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xc000_008e;
pub const STATUS_FLOAT_INEXACT_RESULT: u32 = 0xc000_008f;
pub const STATUS_FLOAT_INVALID_OPERATION: u32 = 0xc000_0090;
pub const STATUS_FLOAT_OVERFLOW: u32 = 0xc000_0091;
pub const STATUS_FLOAT_STACK_CHECK: u32 = 0xc000_0092;
pub const STATUS_FLOAT_UNDERFLOW: u32 = 0xc000_0093;

const INVALID: u32 = 1 << 0;
const DENORMAL: u32 = 1 << 1;
const ZERO_DIVIDE: u32 = 1 << 2;
const OVERFLOW: u32 = 1 << 3;
const UNDERFLOW: u32 = 1 << 4;
const PRECISION: u32 = 1 << 5;
/// FSW.SF: an x87 invalid operation that is a register stack overflow or underflow.
const STACK_FAULT: u32 = 1 << 6;
/// MXCSR's exception masks sit seven bits above its exception flags.
const MXCSR_MASK_SHIFT: u32 = 7;

/// Most to least significant: the first pending, unmasked exception is the one reported.
/// A denormal operand reports an invalid operation, as Windows does.
const PRIORITY: [(u32, u32); 6] = [
    (INVALID, STATUS_FLOAT_INVALID_OPERATION),
    (ZERO_DIVIDE, STATUS_FLOAT_DIVIDE_BY_ZERO),
    (DENORMAL, STATUS_FLOAT_INVALID_OPERATION),
    (OVERFLOW, STATUS_FLOAT_OVERFLOW),
    (UNDERFLOW, STATUS_FLOAT_UNDERFLOW),
    (PRECISION, STATUS_FLOAT_INEXACT_RESULT),
];
/// KiXmmExceptionHandler tests the denormal flag before divide-by-zero.
const SIMD_PRIORITY: [(u32, u32); 6] = [
    (INVALID, STATUS_FLOAT_INVALID_OPERATION),
    (DENORMAL, STATUS_FLOAT_INVALID_OPERATION),
    (ZERO_DIVIDE, STATUS_FLOAT_DIVIDE_BY_ZERO),
    (OVERFLOW, STATUS_FLOAT_OVERFLOW),
    (UNDERFLOW, STATUS_FLOAT_UNDERFLOW),
    (PRECISION, STATUS_FLOAT_INEXACT_RESULT),
];

/// The pieces of an `FXSAVE64` image the floating-point exceptions report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloatingPointState {
    pub control_word: u16,
    pub status_word: u16,
    /// FIP: the last x87 instruction, the one that set the pending exception.
    pub instruction_pointer: u64,
    /// FDP: that instruction's memory operand.
    pub data_pointer: u64,
    pub mxcsr: u32,
}

impl FloatingPointState {
    /// Read from a 512-byte `FXSAVE64` image; `None` for any other length.
    pub fn from_fx_save(image: &[u8]) -> Option<Self> {
        if image.len() != LEGACY_FLOATING_POINT_BYTES {
            return None;
        }
        let u16_at = |offset: usize| u16::from_le_bytes([image[offset], image[offset + 1]]);
        let u64_at = |offset: usize| u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
        Some(Self {
            control_word: u16_at(0),
            status_word: u16_at(2),
            instruction_pointer: u64_at(8),
            data_pointer: u64_at(16),
            mxcsr: u32::from_le_bytes(image[FX_MXCSR_OFFSET..FX_MXCSR_OFFSET + 4].try_into().unwrap()),
        })
    }

    /// KiNpxHandler: the status of the x87 exception that is pending and unmasked, and whether
    /// it is a stack fault. `None` when nothing is (ReactOS bugchecks on such a trap).
    pub fn x87_status(&self) -> Option<(u32, bool)> {
        let status = u32::from(self.status_word);
        let pending = status & !u32::from(self.control_word);
        if pending & INVALID != 0 && status & STACK_FAULT != 0 {
            return Some((STATUS_FLOAT_STACK_CHECK, true));
        }
        first_unmasked(&PRIORITY, pending).map(|code| (code, false))
    }

    /// KiXmmExceptionHandler: the status of the SIMD exception that is pending and unmasked.
    /// `None` when nothing is.
    pub fn simd_status(&self) -> Option<u32> {
        let pending = self.mxcsr & !(self.mxcsr >> MXCSR_MASK_SHIFT);
        first_unmasked(&SIMD_PRIORITY, pending)
    }
}

fn first_unmasked(priority: &[(u32, u32)], pending: u32) -> Option<u32> {
    priority.iter().find(|(flag, _)| pending & flag != 0).map(|(_, code)| *code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(control_word: u16, status_word: u16, mxcsr: u32) -> FloatingPointState {
        FloatingPointState { control_word, status_word, instruction_pointer: 0, data_pointer: 0, mxcsr }
    }

    #[test]
    fn the_fx_save_image_fields_are_read_at_their_offsets() {
        let mut image = [0u8; 512];
        image[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        image[2..4].copy_from_slice(&0x0004u16.to_le_bytes());
        image[8..16].copy_from_slice(&0x1_4000_1000u64.to_le_bytes());
        image[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        image[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        assert_eq!(
            FloatingPointState::from_fx_save(&image),
            Some(FloatingPointState {
                control_word: 0x037f,
                status_word: 0x0004,
                instruction_pointer: 0x1_4000_1000,
                data_pointer: 0x2000,
                mxcsr: 0x1f80,
            })
        );
        assert_eq!(FloatingPointState::from_fx_save(&image[..511]), None);
    }

    #[test]
    fn simd_faults_report_the_first_unmasked_mxcsr_exception() {
        // Default MXCSR (all masked) with flags set raises nothing.
        assert_eq!(state(0, 0, 0x1f80 | 0x3f).simd_status(), None);
        // Divide-by-zero unmasked (ZM, bit 9, clear) and flagged.
        assert_eq!(state(0, 0, (0x1f80 & !(1 << 9)) | ZERO_DIVIDE).simd_status(), Some(STATUS_FLOAT_DIVIDE_BY_ZERO));
        // Everything unmasked: invalid first, then denormal (also invalid), then divide.
        assert_eq!(state(0, 0, 0x3f).simd_status(), Some(STATUS_FLOAT_INVALID_OPERATION));
        assert_eq!(state(0, 0, DENORMAL | ZERO_DIVIDE).simd_status(), Some(STATUS_FLOAT_INVALID_OPERATION));
        assert_eq!(state(0, 0, ZERO_DIVIDE | OVERFLOW).simd_status(), Some(STATUS_FLOAT_DIVIDE_BY_ZERO));
        assert_eq!(state(0, 0, OVERFLOW | UNDERFLOW).simd_status(), Some(STATUS_FLOAT_OVERFLOW));
        assert_eq!(state(0, 0, UNDERFLOW | PRECISION).simd_status(), Some(STATUS_FLOAT_UNDERFLOW));
        assert_eq!(state(0, 0, PRECISION).simd_status(), Some(STATUS_FLOAT_INEXACT_RESULT));
        // A flag whose mask is set does not count even when another is unmasked but clear.
        assert_eq!(state(0, 0, (0x1f80 & !(1 << 12)) | INVALID).simd_status(), None);
    }

    #[test]
    fn x87_faults_report_the_first_unmasked_status_word_exception() {
        // FINIT control word masks everything.
        assert_eq!(state(0x037f, 0x003f, 0).x87_status(), None);
        let unmasked = 0x0340; // precision control and the reserved bit only
        assert_eq!(state(unmasked, ZERO_DIVIDE as u16, 0).x87_status(), Some((STATUS_FLOAT_DIVIDE_BY_ZERO, false)));
        assert_eq!(state(unmasked, (INVALID | ZERO_DIVIDE) as u16, 0).x87_status(), Some((STATUS_FLOAT_INVALID_OPERATION, false)));
        assert_eq!(
            state(unmasked, (INVALID | STACK_FAULT) as u16, 0).x87_status(),
            Some((STATUS_FLOAT_STACK_CHECK, true))
        );
        // KiNpxHandler tests divide-by-zero before denormal.
        assert_eq!(state(unmasked, (DENORMAL | ZERO_DIVIDE) as u16, 0).x87_status(), Some((STATUS_FLOAT_DIVIDE_BY_ZERO, false)));
        assert_eq!(state(unmasked, DENORMAL as u16, 0).x87_status(), Some((STATUS_FLOAT_INVALID_OPERATION, false)));
        assert_eq!(state(unmasked, (OVERFLOW | PRECISION) as u16, 0).x87_status(), Some((STATUS_FLOAT_OVERFLOW, false)));
        assert_eq!(state(unmasked, UNDERFLOW as u16, 0).x87_status(), Some((STATUS_FLOAT_UNDERFLOW, false)));
        assert_eq!(state(unmasked, PRECISION as u16, 0).x87_status(), Some((STATUS_FLOAT_INEXACT_RESULT, false)));
        // A masked stack fault raises nothing.
        assert_eq!(state(0x037f, (INVALID | STACK_FAULT) as u16, 0).x87_status(), None);
    }
}
