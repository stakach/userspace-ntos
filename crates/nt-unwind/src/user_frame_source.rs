//! A user frame source admitted from an exact paused thread and process image catalog.
//!
//! This is a pure validation and unwind contract. It does not acquire a seL4 TCB, read a TEB,
//! or prove that a process memory alias remains attached; the native owner must retain and
//! revalidate those effects for the duration of a `Flags=1` walk.

use crate::{
    exception_walk::{ExceptionImageError, ExceptionImageReader},
    walk_kernel_frame_chain, Context, FrameWalkError, StackReader,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFrameIdentity {
    pub process_generation: u64,
    pub thread_activation: u64,
    pub tcb: u64,
    pub teb: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct UserFrameSnapshot {
    pub identity: UserFrameIdentity,
    /// Saved user TCB/trap context captured under the retained thread owner.
    pub context: Context,
    /// TEB NtTib.StackLimit, read through the exact process memory owner.
    pub teb_stack_low: u64,
    /// TEB NtTib.StackBase, checked against the runtime's stack top.
    pub teb_stack_high: u64,
}

/// Register layout returned by seL4 TCBReadRegisters (20 words) for a paused x64 user TCB.
/// A native adapter must first check the seL4 reply label and exact length, then revalidate its
/// retained thread identity before treating these words as a trap snapshot.
pub struct UserTrapRegisters;

impl UserTrapRegisters {
    /// TCBReadRegisters must return exactly twenty words with a zero reply label and no flags.
    pub const fn exact_sel4_reply(reply_info: u64) -> bool {
        reply_info == 20
    }

    pub fn from_sel4_words(words: &[u64]) -> Option<Context> {
        let words: &[u64; 20] = words.try_into().ok()?;
        if words[0] == 0 || words[1] == 0 {
            return None;
        }
        let mut context = Context::default();
        context.rip = words[0];
        context.set_rsp(words[1]);
        context.gpr[0] = words[3]; // RAX
        context.gpr[1] = words[5]; // RCX
        context.gpr[2] = words[6]; // RDX
        context.gpr[3] = words[4]; // RBX
        context.gpr[5] = words[9]; // RBP
        context.gpr[6] = words[7]; // RSI
        context.gpr[7] = words[8]; // RDI
        context.gpr[8..16].copy_from_slice(&words[10..18]); // R8..R15
        Some(context)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserFrameSourceError {
    WrongIdentity,
    InvalidStack,
    UnknownImage,
    ImageLookup(ExceptionImageError),
}

/// Checked copy of the trap context and TEB bounds. The native caller still owns the live lease.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedUserFrameSource {
    context: Context,
    stack_low: u64,
    stack_high: u64,
}

impl AuthenticatedUserFrameSource {
    pub fn admit<I: ExceptionImageReader>(
        expected: UserFrameIdentity,
        snapshot: UserFrameSnapshot,
        allocation_base: u64,
        runtime_stack_top: u64,
        image: &I,
    ) -> Result<Self, UserFrameSourceError> {
        if expected.process_generation == 0
            || expected.thread_activation == 0
            || expected.tcb <= 1
            || expected.teb == 0
            || snapshot.identity != expected
        {
            return Err(UserFrameSourceError::WrongIdentity);
        }
        let low = snapshot.teb_stack_low;
        let high = snapshot.teb_stack_high;
        if allocation_base == 0
            || allocation_base > low
            || low >= high
            || high != runtime_stack_top
            || snapshot.context.rsp() <= low
            || snapshot.context.rsp() >= high
        {
            return Err(UserFrameSourceError::InvalidStack);
        }
        match image.lookup_exception_function(snapshot.context.rip) {
            Ok(_) => Ok(Self { context: snapshot.context, stack_low: low, stack_high: high }),
            Err(ExceptionImageError::UnknownImage) => Err(UserFrameSourceError::UnknownImage),
            Err(error) => Err(UserFrameSourceError::ImageLookup(error)),
        }
    }

    /// Walk only through positively admitted user images and the checked TEB stack interval.
    /// Unknown image PCs terminate the proven chain before being published.
    pub fn walk<I: ExceptionImageReader>(
        self,
        callers: &mut [u64],
        frames_to_skip: usize,
        image: &I,
        stack: &dyn StackReader,
    ) -> Result<usize, FrameWalkError> {
        walk_kernel_frame_chain(
            self.context,
            callers,
            frames_to_skip,
            self.stack_low,
            self.stack_high,
            image,
            stack,
        )
    }

    /// Include the independently admitted saved trap PC at an authenticated dispatch boundary.
    /// It consumes one unit of the same skip/count budget as every subsequent user return PC.
    pub fn walk_continuation<I: ExceptionImageReader>(
        self,
        callers: &mut [u64],
        frames_to_skip: usize,
        image: &I,
        stack: &dyn StackReader,
    ) -> Result<usize, FrameWalkError> {
        let total = frames_to_skip.checked_add(callers.len())
            .ok_or(FrameWalkError::CountOverflow)?;
        if total == 0 {
            return Ok(0);
        }
        let walked = if frames_to_skip == 0 {
            let (first, remainder) = callers.split_first_mut()
                .ok_or(FrameWalkError::CountOverflow)?;
            *first = self.context.rip;
            self.walk(remainder, 0, image, stack)?
        } else {
            self.walk(callers, frames_to_skip - 1, image, stack)?
        };
        walked.checked_add(1).ok_or(FrameWalkError::CountOverflow)
    }
}
