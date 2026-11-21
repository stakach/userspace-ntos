//! Name an exception-unwind frame that the function tables cannot describe.
//!
//! On x64 only a leaf function has no `RUNTIME_FUNCTION`, and a leaf never calls, so only the
//! first frame of a walk (the faulting or capturing PC) may be one. A later frame is reached
//! through a return address; if its PC lies inside a loaded image and still has no entry, the walk
//! falls back to a leaf pop that skips that frame's saved non-volatile registers. Boot 44896134068:
//! LoadLibraryExW's `__except` ran with every non-volatile register still holding the faulting
//! frame's values (rbp=0x2) and faulted.

use core::fmt::Write;
use nt_printf::record::RecordBuffer;

/// Which SEH walk saw the frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Walk {
    /// `RtlDispatchException`'s search pass.
    Dispatch,
    /// `RtlUnwindEx`'s unwind pass.
    Unwind,
}

/// An image-owned frame with no function entry, beyond the first frame of a walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnwindGap {
    pub walk: Walk,
    pub frame: u32,
    pub pc: u64,
    pub image_base: u64,
}

/// Classify one frame of a walk whose function lookup found no entry. `frame` counts from 0 for the
/// walk's first PC; `image_base` is the loaded image containing `pc`, or 0 when no image does
/// (generated code, which only a dynamic function table describes).
pub fn classify_missing_entry(walk: Walk, frame: u32, pc: u64, image_base: u64) -> Option<UnwindGap> {
    (frame > 0 && image_base != 0 && pc > image_base)
        .then_some(UnwindGap { walk, frame, pc, image_base })
}

/// The one record a process emits for its first gap.
pub fn gap_record(gap: &UnwindGap, module: &[u8]) -> RecordBuffer<160> {
    let mut record = RecordBuffer::new();
    let walk = match gap.walk {
        Walk::Dispatch => "dispatch",
        Walk::Unwind => "unwind",
    };
    let _ = write!(record, "[seh-unwind-gap] walk={walk} frame={} module=", gap.frame);
    for &byte in module {
        let _ = record.write_char(if byte.is_ascii_graphic() { char::from(byte) } else { '?' });
    }
    let _ = writeln!(record, " rva=0x{:x} pc=0x{:x}", gap.pc - gap.image_base, gap.pc);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_called_frame_inside_an_image_is_a_gap() {
        // The first frame may be a genuine leaf.
        assert_eq!(classify_missing_entry(Walk::Dispatch, 0, 0x1_0003_0452_339, 0x1_0003_0440_000), None);
        // Generated code outside every image belongs to a dynamic function table.
        assert_eq!(classify_missing_entry(Walk::Unwind, 3, 0x5000_1234, 0), None);
        assert_eq!(
            classify_missing_entry(Walk::Unwind, 2, 0x100_3045_2339, 0x100_3044_0000),
            Some(UnwindGap { walk: Walk::Unwind, frame: 2, pc: 0x100_3045_2339, image_base: 0x100_3044_0000 })
        );
    }

    #[test]
    fn the_record_names_the_module_and_rva() {
        let gap = UnwindGap { walk: Walk::Dispatch, frame: 1, pc: 0x7ffa_2000_32f0, image_base: 0x7ffa_2000_0000 };
        assert_eq!(
            gap_record(&gap, b"version").bytes(),
            b"[seh-unwind-gap] walk=dispatch frame=1 module=version rva=0x32f0 pc=0x7ffa200032f0\n"
        );
    }
}
