//! Outputs a hosted win32k dispatch writes into the executive's staging memory.
//!
//! The executive gives win32k provider-owned stand-ins for a caller's output buffers and copies
//! them back to the caller when the service completes. A dispatch completes either immediately
//! or later, after parking on a provider wait, an LPC wait or a user callback, while other
//! dispatches reuse the same staging page. The rule is the same on every path:
//!
//! * a dispatch that parks retains its output plan ([`ParkedStagedOutputs::retain`]);
//! * when the provider finishes, the plan's declared output ranges are captured before the page
//!   can be reused ([`ParkedStagedOutputs::capture`]);
//! * the completion copies the captured bytes back, and a completion whose output was never
//!   captured fails instead of reporting success ([`ParkedStagedOutputs::take`]).
//!
//! The plan type is the caller's: it names the ranges it reads back and, when it staged in a
//! per-call bulk lease rather than the shared argument frames, that lease ([`StageWindows`]).

use alloc::vec;
use alloc::vec::Vec;

/// One staged output the provider may write: `len` bytes at the provider address `va`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputRange {
    pub va: u64,
    pub len: usize,
}

/// Read access to staged output, live or captured.
pub trait StageBytes {
    /// The `len` bytes at provider address `va`, or `None` outside the staged memory.
    fn bytes(&self, va: u64, len: usize) -> Option<&[u8]>;

    fn read_u16(&self, va: u64) -> Option<u16> {
        self.bytes(va, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32(&self, va: u64) -> Option<u32> {
        self.bytes(va, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    fn read_u64(&self, va: u64) -> Option<u64> {
        self.bytes(va, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
}

/// A plan that knows which staged ranges its copy-back reads.
pub trait StagedOutputPlan: Copy {
    fn output_ranges(&self, out: &mut Vec<OutputRange>);

    /// The call's own bulk lease, when it staged outputs there instead of in the shared frames.
    fn bulk_window(&self) -> Option<StageWindow> {
        None
    }
}

/// A span of provider memory the executive also maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageWindow {
    pub base: u64,
    pub bytes: u64,
}

impl StageWindow {
    /// Whether all `len` bytes at `va` lie inside this window.
    pub fn contains(&self, va: u64, len: usize) -> bool {
        let Some(end) = va.checked_add(len as u64) else { return false };
        va >= self.base && self.base.checked_add(self.bytes).is_some_and(|limit| end <= limit)
    }
}

/// Where one plan's staged outputs may be read: the shared argument frames and, if the call
/// staged there, its own bulk lease (which stays mapped until the dispatch completes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageWindows {
    shared: StageWindow,
    bulk: Option<StageWindow>,
}

impl StageWindows {
    pub fn of<P: StagedOutputPlan>(plan: &P, shared: StageWindow) -> Self {
        Self { shared, bulk: plan.bulk_window() }
    }

    pub fn contains(&self, va: u64, len: usize) -> bool {
        self.shared.contains(va, len) || self.bulk.is_some_and(|bulk| bulk.contains(va, len))
    }
}

/// The declared output ranges of a plan, copied when the provider completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedStage {
    ranges: Vec<(OutputRange, Vec<u8>)>,
}

impl CapturedStage {
    /// Copy each of `plan`'s ranges through `read` (`read(va, buffer)` fills `buffer` from the
    /// staged memory at `va`). A range outside the plan's [`StageWindows`] is never read.
    pub fn capture<P: StagedOutputPlan>(
        plan: &P,
        shared: StageWindow,
        mut read: impl FnMut(u64, &mut [u8]) -> bool,
    ) -> Option<Self> {
        let windows = StageWindows::of(plan, shared);
        let mut ranges = Vec::new();
        plan.output_ranges(&mut ranges);
        let mut captured = Vec::with_capacity(ranges.len());
        for range in ranges {
            let mut bytes = vec![0u8; range.len];
            if !windows.contains(range.va, range.len) || !read(range.va, &mut bytes) {
                return None;
            }
            captured.push((range, bytes));
        }
        Some(Self { ranges: captured })
    }
}

impl StageBytes for CapturedStage {
    fn bytes(&self, va: u64, len: usize) -> Option<&[u8]> {
        self.ranges.iter().find_map(|(range, bytes)| {
            let offset = va.checked_sub(range.va)? as usize;
            let end = offset.checked_add(len)?;
            (end <= range.len).then(|| &bytes[offset..end])
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainError {
    /// The dispatch already retains a plan.
    Duplicate,
}

/// Why a parked dispatch's output cannot be returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakeError {
    /// The provider's completion never captured the output; the page now belongs to others.
    Uncaptured,
}

struct Row<P> {
    dispatch_id: u64,
    plan: P,
    captured: Option<CapturedStage>,
}

/// The output plans of dispatches parked away from their immediate copy-back.
pub struct ParkedStagedOutputs<P> {
    rows: Vec<Row<P>>,
}

impl<P: StagedOutputPlan> ParkedStagedOutputs<P> {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Record that `dispatch_id` parked with `plan` still owed to its caller.
    pub fn retain(&mut self, dispatch_id: u64, plan: P) -> Result<(), RetainError> {
        if self.rows.iter().any(|row| row.dispatch_id == dispatch_id) {
            return Err(RetainError::Duplicate);
        }
        self.rows.push(Row { dispatch_id, plan, captured: None });
        Ok(())
    }

    /// The provider finished `dispatch_id`: copy its declared outputs out of the staged memory
    /// (`shared`, plus the plan's own bulk lease) now. `true` when the dispatch has no retained
    /// plan or its outputs were captured.
    pub fn capture(
        &mut self,
        dispatch_id: u64,
        shared: StageWindow,
        read: impl FnMut(u64, &mut [u8]) -> bool,
    ) -> bool {
        let Some(row) = self.rows.iter_mut().find(|row| row.dispatch_id == dispatch_id) else {
            return true;
        };
        row.captured = CapturedStage::capture(&row.plan, shared, read);
        row.captured.is_some()
    }

    /// Hand the completion its plan and captured output, exactly once. `None` when the dispatch
    /// staged no output.
    pub fn take(&mut self, dispatch_id: u64) -> Option<Result<(P, CapturedStage), TakeError>> {
        let index = self.rows.iter().position(|row| row.dispatch_id == dispatch_id)?;
        let row = self.rows.swap_remove(index);
        Some(row.captured.map(|captured| (row.plan, captured)).ok_or(TakeError::Uncaptured))
    }

    /// Forget a dispatch that will never complete to its caller.
    pub fn discard(&mut self, dispatch_id: u64) {
        self.rows.retain(|row| row.dispatch_id != dispatch_id);
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

impl<P: StagedOutputPlan> Default for ParkedStagedOutputs<P> {
    fn default() -> Self {
        Self::new()
    }
}
