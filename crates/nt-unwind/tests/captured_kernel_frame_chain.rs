//! A kernel frame walk starts at the provider's captured callsite, not at the broker's Rust PC.

use nt_unwind::exception_walk::{ExceptionFunction, ExceptionImageError, ExceptionImageReader};
use nt_unwind::{
    walk_captured_kernel_frame_chain, CapturedKernelCallSite, Context, ImageReader,
    RuntimeFunction, StackReader,
};

const IMAGE: u64 = 0x0000_0100_0680_0000;
const STACK_LOW: u64 = 0x1000;
const STACK_HIGH: u64 = 0x3000;
const ENTRY_RSP: u64 = 0x1ff8;
const PROVIDER_PC: u64 = IMAGE + 0x3008;

struct AdmittedImage;

impl ImageReader for AdmittedImage {
    fn lookup_function(&self, _pc: u64) -> Option<(u64, RuntimeFunction)> {
        None
    }

    fn read_u8(&self, _image_base: u64, _rva: u32) -> Option<u8> {
        None
    }
}

impl ExceptionImageReader for AdmittedImage {
    fn lookup_exception_function(
        &self,
        pc: u64,
    ) -> Result<ExceptionFunction, ExceptionImageError> {
        if (IMAGE + 0x3000..IMAGE + 0x4000).contains(&pc) {
            Ok(ExceptionFunction::Leaf)
        } else {
            Err(ExceptionImageError::UnknownImage)
        }
    }
}

struct LaneStack {
    live: bool,
}

impl StackReader for LaneStack {
    fn read_u64(&self, address: u64) -> Option<u64> {
        if !self.live {
            return None;
        }
        match address {
            ENTRY_RSP => Some(PROVIDER_PC),
            0x2000 => Some(IMAGE + 0x3010),
            0x2008 => Some(IMAGE + 0x3020),
            0x2010 => Some(0x4000_1000), // foreign executor: never publish it
            _ => None,
        }
    }
}

fn captured_context(pc: u64, rsp: u64) -> Context {
    let mut context = Context::default();
    context.rip = pc;
    context.set_rsp(rsp);
    context
}

#[test]
fn captured_provider_callsite_controls_count_and_high_flag_skip() {
    let stack = LaneStack { live: true };
    let captured = CapturedKernelCallSite::from_entry(
        captured_context(PROVIDER_PC, 0x2000),
        ENTRY_RSP,
        STACK_LOW,
        STACK_HIGH,
        &AdmittedImage,
        &stack,
    )
    .expect("real provider return slot and context agree");

    let mut callers = [0xdead_beefu64; 3];
    let count = walk_captured_kernel_frame_chain(captured, &mut callers, 0, &AdmittedImage, &stack)
        .expect("bounded admitted chain");
    assert_eq!(count, 2);
    assert_eq!(callers, [IMAGE + 0x3010, IMAGE + 0x3020, 0xdead_beef]);

    let mut skipped = [0xdead_beefu64; 2];
    let count = walk_captured_kernel_frame_chain(
        captured,
        &mut skipped,
        1 << 8,
        &AdmittedImage,
        &stack,
    )
    .expect("high flag bits skip one proven frame");
    assert_eq!(count, 2); // ReactOS includes the skipped frame in its return count.
    assert_eq!(skipped, [IMAGE + 0x3020, 0xdead_beef]);
}

#[test]
fn mismatched_or_retired_ingress_cannot_authorize_a_frame_walk() {
    let live = LaneStack { live: true };
    let retired = LaneStack { live: false };
    for (context, stack) in [
        (captured_context(IMAGE + 0x3090, 0x2000), &live), // forged PC
        (captured_context(PROVIDER_PC, 0x2008), &live), // wrong post-call RSP
        (captured_context(PROVIDER_PC, 0x2000), &retired), // retired lane reader
    ] {
        assert!(CapturedKernelCallSite::from_entry(
            context,
            ENTRY_RSP,
            STACK_LOW,
            STACK_HIGH,
            &AdmittedImage,
            stack,
        )
        .is_err());
    }
}
