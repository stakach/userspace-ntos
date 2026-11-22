//! A win32k dispatch that parks before completing must still return the output it staged.
//!
//! KVM run 44981790454: conhost received TRUE from GetTextMetricsW with an unwritten TEXTMETRICW,
//! because only the immediate return copied staged output back. These tests drive the same
//! sequence with NtGdiGetTextExtent's SIZE output: stage, park, another dispatch reuses the
//! page, the provider finishes, and the completion copies back.

use nt_kernel_exec::win32k_staged_output::{
    OutputRange, ParkedStagedOutputs, StageBytes, StagedOutputPlan, TakeError,
};

const STAGE_VA: u64 = 0x100_071a_0000;
const SIZE_VA: u64 = STAGE_VA + 0x80;

/// NtGdiGetTextExtent's output: the caller's SIZE and its staged stand-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TextExtentPlan {
    client_size: u64,
    staged_size: u64,
}

impl StagedOutputPlan for TextExtentPlan {
    fn output_ranges(&self, out: &mut Vec<OutputRange>) {
        out.push(OutputRange { va: self.staged_size, len: 8 });
    }
}

struct Page(Vec<u8>);

impl Page {
    fn new() -> Self {
        Self(vec![0; 0x1000])
    }

    fn write(&mut self, va: u64, bytes: &[u8]) {
        let offset = (va - STAGE_VA) as usize;
        self.0[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn read(&self, va: u64, out: &mut [u8]) -> bool {
        let Some(offset) = va.checked_sub(STAGE_VA).map(|offset| offset as usize) else {
            return false;
        };
        match self.0.get(offset..offset + out.len()) {
            Some(bytes) => {
                out.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
}

fn size(cx: i32, cy: i32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&cx.to_le_bytes());
    bytes[4..].copy_from_slice(&cy.to_le_bytes());
    bytes
}

/// What the completion consumer writes to the caller for a TRUE result.
fn complete(
    parked: &mut ParkedStagedOutputs<TextExtentPlan>,
    dispatch_id: u64,
) -> Option<Result<(u64, [u8; 8]), TakeError>> {
    parked.take(dispatch_id).map(|taken| {
        taken.map(|(plan, captured)| {
            let bytes = captured.bytes(plan.staged_size, 8).unwrap();
            (plan.client_size, bytes.try_into().unwrap())
        })
    })
}

#[test]
fn a_parked_text_extent_returns_the_size_the_provider_wrote_after_the_page_was_reused() {
    let mut page = Page::new();
    let mut parked = ParkedStagedOutputs::new();
    let plan = TextExtentPlan { client_size: 0x7_0000_8f10, staged_size: SIZE_VA };
    // The executive zero-fills the stand-in and dispatches; the provider parks on a wait.
    page.write(SIZE_VA, &[0; 8]);
    parked.retain(41, plan).unwrap();
    // Another client's dispatch stages into the same page while the first is parked.
    page.write(STAGE_VA, &[0xcc; 0x200]);
    // The parked provider resumes and writes its SIZE through the staged pointer.
    page.write(SIZE_VA, &size(64, 16));
    assert!(parked.capture(41, |va, out| page.read(va, out)));
    // A later dispatch may reuse the page again before the completion is delivered.
    page.write(STAGE_VA, &[0xdd; 0x200]);
    assert_eq!(complete(&mut parked, 41), Some(Ok((0x7_0000_8f10, size(64, 16)))));
    // Exactly once.
    assert_eq!(complete(&mut parked, 41), None);
    assert!(parked.is_empty());
}

#[test]
fn a_completion_whose_output_was_never_captured_fails() {
    let mut parked = ParkedStagedOutputs::new();
    parked.retain(7, TextExtentPlan { client_size: 0x1000, staged_size: SIZE_VA }).unwrap();
    assert_eq!(complete(&mut parked, 7), Some(Err(TakeError::Uncaptured)));
}

#[test]
fn a_capture_outside_the_staged_memory_fails() {
    let page = Page::new();
    let mut parked = ParkedStagedOutputs::new();
    parked.retain(9, TextExtentPlan { client_size: 0x1000, staged_size: STAGE_VA + 0x2000 }).unwrap();
    assert!(!parked.capture(9, |va, out| page.read(va, out)));
    assert_eq!(complete(&mut parked, 9), Some(Err(TakeError::Uncaptured)));
}

#[test]
fn dispatches_without_staged_output_complete_untouched() {
    let page = Page::new();
    let mut parked: ParkedStagedOutputs<TextExtentPlan> = ParkedStagedOutputs::new();
    assert!(parked.capture(3, |va, out| page.read(va, out)));
    assert_eq!(complete(&mut parked, 3), None);
}

#[test]
fn a_dispatch_retains_one_plan_and_discard_forgets_it() {
    let mut parked = ParkedStagedOutputs::new();
    let plan = TextExtentPlan { client_size: 0x1000, staged_size: SIZE_VA };
    parked.retain(5, plan).unwrap();
    assert!(parked.retain(5, plan).is_err());
    parked.discard(5);
    assert!(parked.is_empty());
}
