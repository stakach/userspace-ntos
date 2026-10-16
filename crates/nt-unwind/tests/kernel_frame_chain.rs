//! A hosted win32k stack walk needs admitted executable images and bounded lane stacks.

use nt_unwind::exception_walk::{ExceptionFunction, ExceptionImageError, ExceptionImageReader};
use nt_unwind::{
    walk_kernel_frame_chain, Context, FrameWalkError, ImageReader, RuntimeFunction, StackReader,
};

const IMAGE: u64 = 0x0000_0100_0680_0000;

struct AdmittedImage;

impl ImageReader for AdmittedImage {
    fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
        (IMAGE + 0x1000..IMAGE + 0x1100).contains(&pc).then_some((
            IMAGE,
            RuntimeFunction { begin: 0x1000, end: 0x1100, unwind_info: 0x2000 },
        ))
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        if base != IMAGE { return None; }
        if (0x1000..0x1100).contains(&rva) { return Some(0x90); }
        if !(0x2000..0x2004).contains(&rva) { return None; }
        Some([1, 0, 0, 0][(rva - 0x2000) as usize])
    }
}

impl ExceptionImageReader for AdmittedImage {
    fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        if (IMAGE + 0x1000..IMAGE + 0x1100).contains(&pc) {
            return Ok(ExceptionFunction::Function {
                image_base: IMAGE,
                function: self.lookup_function(pc).unwrap().1,
            });
        }
        if (IMAGE + 0x3000..IMAGE + 0x4000).contains(&pc) {
            return Ok(ExceptionFunction::Leaf);
        }
        Err(ExceptionImageError::UnknownImage)
    }
}

struct BoundedStack(Vec<(u64, u64)>);

impl StackReader for BoundedStack {
    fn read_u64(&self, address: u64) -> Option<u64> {
        self.0.iter().find(|(slot, _)| *slot == address).map(|(_, word)| *word)
    }
}

fn context(rip: u64, rsp: u64) -> Context {
    let mut context = Context::default();
    context.rip = rip;
    context.set_rsp(rsp);
    context
}

#[test]
fn kernel_walk_unwinds_metadata_and_stops_before_foreign_executor() {
    let image = AdmittedImage;
    let stack = BoundedStack(vec![(0x2000, IMAGE + 0x3000), (0x2008, 0x4000_1000)]);
    let mut callers = [0xdead_beefu64; 2];
    let count = walk_kernel_frame_chain(
        context(IMAGE + 0x1050, 0x2000), &mut callers, 0,
        0x1000, 0x3000, &image, &stack,
    ).unwrap();
    assert_eq!(count, 1);
    assert_eq!(callers, [IMAGE + 0x3000, 0xdead_beef]);
}

#[test]
fn unknown_initial_frame_is_never_guessed_to_be_a_leaf() {
    let mut callers = [0xdead_beefu64];
    assert_eq!(
        walk_kernel_frame_chain(
            context(0x4000_1000, 0x2000), &mut callers, 0,
            0x1000, 0x3000, &AdmittedImage, &BoundedStack(vec![(0x2000, IMAGE + 0x3000)]),
        ),
        Err(FrameWalkError::UnknownImage),
    );
    assert_eq!(callers, [0xdead_beef]);
}

#[test]
fn kernel_walk_respects_skip_and_physical_stack_limit() {
    let image = AdmittedImage;
    let stack = BoundedStack(vec![(0x2ff0, IMAGE + 0x3100), (0x2ff8, IMAGE + 0x3200)]);
    let mut callers = [0xdead_beefu64];
    let count = walk_kernel_frame_chain(
        context(IMAGE + 0x3000, 0x2ff0), &mut callers, 1,
        0x1000, 0x3000, &image, &stack,
    ).unwrap();
    assert_eq!(count, 1);
    assert_eq!(callers, [0xdead_beef]);
}
