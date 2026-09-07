//! Bounded x64 search and target-unwind passes over real unwind metadata.
//!
//! This is NOT yet a native `RtlDispatchException`/`RtlUnwindEx` implementation or a replacement
//! for ntdll's live dispatcher. Collided unwind is explicitly unsupported. Native use additionally
//! requires authenticated physical-stack/image readers, context capture/restore, and assembler
//! handler linkage with its own unwind metadata. An unknown Rust frame must not become a leaf
//! merely because the PE reader does not know it.
//!
//! The consuming continuation keeps the walker unavailable while a handler runs. Handler arguments
//! are owned snapshots, never references into the walker. Search preserves the original exception
//! context separately from the virtually unwound dispatcher context; unwind preserves Current
//! until its handler completes, then advances to Previous only for a non-target frame.
//!
//! Reference: NT5 `base/ntos/rtl/amd64/exdsptch.c`, `RtlDispatchException` and `RtlUnwindEx`;
//! ReactOS `sdk/lib/rtl/amd64/unwind.c`. Language-specific scope handling remains in `next_c_scope`.

use crate::{
    unw_flag, virtual_unwind, BoundedStack, Context, ExceptionRecord, ImageReader, RuntimeFunction,
    StackReader, EXCEPTION_EXIT_UNWIND, EXCEPTION_NONCONTINUABLE, EXCEPTION_TARGET_UNWIND,
    EXCEPTION_UNWINDING, REG_RAX,
};

/// `EXCEPTION_NESTED_CALL`, propagated while search crosses a nested handler's region.
pub const EXCEPTION_NESTED_CALL: u32 = 0x10;

/// Only operations whose handler-return semantics are implemented by this walker.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WalkMode {
    Search,
    Unwind {
        /// `None` requests exit unwind, which finishes by requesting second-chance dispatch.
        target_frame: Option<u64>,
        target_ip: u64,
        return_value: u64,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WalkError {
    InvalidStackBounds,
    InvalidBudget,
    BadStack,
    StackRead,
    UnwindData,
    BadFunctionTable,
    ImageLookup(ExceptionImageError),
    FrameLimit,
    InvalidDisposition(i32),
    NoncontinuableException,
    InvalidHandlerContexts,
    UnsupportedCollidedUnwind,
    /// Restore-time consolidate callbacks need an additional authenticated native continuation.
    UnsupportedUnwindConsolidate,
}

/// A lookup failure is not evidence of a leaf function.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExceptionImageError {
    UnknownImage,
    UnreadableImage,
    CorruptFunctionTable,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExceptionFunction {
    Function {
        image_base: u64,
        function: RuntimeFunction,
    },
    /// The reader positively identified executable code in an admitted image and established that
    /// its valid function table has no covering row. Unknown/non-PE code is not an affirmative leaf.
    Leaf,
}

/// Strict code admission for exception dispatch. There is deliberately no default implementation
/// mapping `ImageReader::lookup_function(None)` to a leaf. Reclassify every new control PC, including
/// PCs returned or modified by handlers, before touching that frame's stack.
pub trait ExceptionImageReader: ImageReader {
    fn lookup_exception_function(
        &self,
        control_pc: u64,
    ) -> Result<ExceptionFunction, ExceptionImageError>;
}

/// Search receives two distinct context pointers; unwind receives the same Current context through
/// both its third argument and dispatcher context. This enum preserves that aliasing contract.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandlerContexts {
    Search {
        exception: Context,
        unwound: Context,
    },
    Unwind {
        current: Context,
    },
}

/// Values for one language-handler invocation. A future ABI adapter must invoke the handler outside
/// the walker, copy back its actual context/flags/dispatcher establisher, then call `returned`.
/// The private continuation cannot be detached or paired with a different invocation's response.
///
/// ```compile_fail
/// use nt_unwind::exception_walk::HandlerInvocation;
/// fn detach(invocation: HandlerInvocation) {
///     let continuation = invocation.continuation;
/// }
/// ```
///
/// ```compile_fail
/// use nt_unwind::exception_walk::HandlerInvocation;
/// fn replay(invocation: HandlerInvocation) {
///     let _ = invocation.returned(1);
///     let _ = invocation.returned(1);
/// }
/// ```
#[derive(Debug)]
pub struct HandlerInvocation {
    pub exception: ExceptionRecord,
    pub control_pc: u64,
    pub image_base: u64,
    pub function: RuntimeFunction,
    pub establisher_frame: u64,
    pub handler: u64,
    pub handler_data: u64,
    pub target_ip: u64,
    /// A fresh frame starts at scope zero. Resuming a collided scope is not implemented.
    pub scope_index: u32,
    pub contexts: HandlerContexts,
    continuation: HandlerContinuation,
}

impl HandlerInvocation {
    /// Package actual handler outputs. Native adapters must first copy back mutations, including
    /// the dispatcher establisher used by `ExceptionNestedException`.
    pub fn returned(self, disposition: i32) -> Result<WalkStep, WalkError> {
        self.continuation.resume(HandlerResponse {
            disposition,
            exception: self.exception,
            contexts: self.contexts,
            dispatcher_establisher_frame: self.establisher_frame,
        })
    }
}

#[derive(Debug)]
struct HandlerResponse {
    disposition: i32,
    exception: ExceptionRecord,
    contexts: HandlerContexts,
    dispatcher_establisher_frame: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecondChanceReason {
    ExitUnwind,
    TargetNotFound,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WalkOutcome {
    Handled {
        exception: ExceptionRecord,
        context: Context,
    },
    Unhandled {
        exception: ExceptionRecord,
        context: Context,
    },
    TargetReached {
        exception: ExceptionRecord,
        context: Context,
    },
    /// This is not successful unwind completion and must not jump to `target_ip`.
    SecondChance {
        exception: ExceptionRecord,
        context: Context,
        reason: SecondChanceReason,
    },
}

#[derive(Debug)]
pub enum WalkStep {
    Continue(ExceptionWalk),
    Invoke(HandlerInvocation),
    Complete(WalkOutcome),
}

/// One owned pass, with an explicit bound on frames consumed. Neither it nor its continuation is
/// Clone: a handler cannot advance the same walk or return twice through this API.
#[derive(Debug)]
pub struct ExceptionWalk {
    mode: WalkMode,
    exception: ExceptionRecord,
    original: Context,
    current: Context,
    control_pc: u64,
    control_rsp: u64,
    low: u64,
    high: u64,
    frames_left: usize,
    flags: u32,
    nested_frame: Option<u64>,
}

#[derive(Debug)]
struct HandlerContinuation {
    walk: ExceptionWalk,
    previous: Context,
    establisher_frame: u64,
}

impl ExceptionWalk {
    /// Start from an already captured context, with physical execution-stack bounds. Zero frames is
    /// not a request for an unbounded walk. Consolidate-unwind is rejected before any handler runs.
    pub fn new(
        mode: WalkMode,
        exception: ExceptionRecord,
        context: Context,
        stack_low: u64,
        stack_high: u64,
        frame_limit: usize,
    ) -> Result<Self, WalkError> {
        if stack_low >= stack_high {
            return Err(WalkError::InvalidStackBounds);
        }
        if frame_limit == 0 {
            return Err(WalkError::InvalidBudget);
        }
        if context.rsp() < stack_low || context.rsp() > stack_high || context.rsp() & 7 != 0 {
            return Err(WalkError::BadStack);
        }
        let flags = match mode {
            WalkMode::Search => exception.flags & EXCEPTION_NONCONTINUABLE,
            WalkMode::Unwind { target_frame, .. } => {
                if exception.code == 0x8000_0029 {
                    return Err(WalkError::UnsupportedUnwindConsolidate);
                }
                if let Some(target) = target_frame {
                    if target < stack_low || target > stack_high || target & 15 != 0 {
                        return Err(WalkError::BadStack);
                    }
                }
                EXCEPTION_UNWINDING
                    | if target_frame.is_none() {
                        EXCEPTION_EXIT_UNWIND
                    } else {
                        0
                    }
            }
        };
        let control_pc = if mode == WalkMode::Search {
            exception.address
        } else {
            context.rip
        };
        Ok(Self {
            mode,
            exception,
            original: context,
            current: context,
            control_pc,
            control_rsp: context.rsp(),
            low: stack_low,
            high: stack_high,
            frames_left: frame_limit,
            flags,
            nested_frame: None,
        })
    }

    /// Unwind at most one frame, or suspend before calling its language handler.
    pub fn step(
        mut self,
        image: &dyn ExceptionImageReader,
        stack: &dyn StackReader,
    ) -> Result<WalkStep, WalkError> {
        self.validate_context(self.current)?;
        if self.current.rsp() == self.high {
            return Ok(self.end());
        }
        if self.frames_left == 0 {
            return Err(WalkError::FrameLimit);
        }
        self.frames_left -= 1;
        let bounded = BoundedStack::new(stack, self.low, self.high)
            .map_err(|_| WalkError::InvalidStackBounds)?;
        let mut previous = self.current;
        match image
            .lookup_exception_function(self.control_pc)
            .map_err(WalkError::ImageLookup)?
        {
            ExceptionFunction::Function {
                image_base,
                function,
            } => {
                let handler_type = if self.mode == WalkMode::Search {
                    unw_flag::EHANDLER
                } else {
                    unw_flag::UHANDLER
                };
                let result = virtual_unwind(
                    handler_type,
                    image_base,
                    self.control_pc,
                    function,
                    &mut previous,
                    image,
                    &bounded,
                )
                .ok_or(WalkError::UnwindData)?;
                self.validate_frame(result.establisher_frame)?;
                self.validate_context(previous)?;
                if let WalkMode::Unwind {
                    target_frame: Some(target),
                    ..
                } = self.mode
                {
                    if target < result.establisher_frame {
                        return Err(WalkError::BadStack);
                    }
                }
                if result.handler_rva != 0 {
                    let handler = result
                        .image_base
                        .checked_add(u64::from(result.handler_rva))
                        .ok_or(WalkError::UnwindData)?;
                    let handler_data = result
                        .image_base
                        .checked_add(u64::from(result.handler_data_rva))
                        .ok_or(WalkError::UnwindData)?;
                    let (contexts, target_ip) = match self.mode {
                        WalkMode::Search => (
                            HandlerContexts::Search {
                                exception: self.original,
                                unwound: previous,
                            },
                            0,
                        ),
                        WalkMode::Unwind {
                            target_frame,
                            target_ip,
                            return_value,
                        } => {
                            self.current.gpr[REG_RAX] = return_value;
                            if target_frame == Some(result.establisher_frame) {
                                self.flags |= EXCEPTION_TARGET_UNWIND;
                            }
                            (
                                HandlerContexts::Unwind {
                                    current: self.current,
                                },
                                target_ip,
                            )
                        }
                    };
                    self.exception.flags = self.flags;
                    let invocation = HandlerInvocation {
                        exception: self.exception.clone(),
                        control_pc: self.control_pc,
                        image_base,
                        function,
                        establisher_frame: result.establisher_frame,
                        handler,
                        handler_data,
                        target_ip,
                        scope_index: 0,
                        contexts,
                        continuation: HandlerContinuation {
                            walk: self,
                            previous,
                            establisher_frame: result.establisher_frame,
                        },
                    };
                    return Ok(WalkStep::Invoke(invocation));
                }
                self.advance(previous, Some(result.establisher_frame))
            }
            ExceptionFunction::Leaf => {
                previous.rip = bounded
                    .read_u64(previous.rsp())
                    .ok_or(WalkError::StackRead)?;
                previous.set_rsp(previous.rsp().checked_add(8).ok_or(WalkError::BadStack)?);
                self.advance(previous, None)
            }
        }
    }

    fn validate_frame(&self, frame: u64) -> Result<(), WalkError> {
        if frame < self.low || frame > self.high || frame & 15 != 0 {
            Err(WalkError::BadStack)
        } else {
            Ok(())
        }
    }

    fn validate_context(&self, context: Context) -> Result<(), WalkError> {
        if context.rsp() < self.low || context.rsp() > self.high || context.rsp() & 7 != 0 {
            Err(WalkError::BadStack)
        } else {
            Ok(())
        }
    }

    fn advance(
        mut self,
        previous: Context,
        establisher: Option<u64>,
    ) -> Result<WalkStep, WalkError> {
        if let WalkMode::Unwind {
            target_frame: Some(target),
            target_ip,
            return_value,
        } = self.mode
        {
            if establisher == Some(target) {
                if self.exception.code == 0x8000_0029 {
                    return Err(WalkError::UnsupportedUnwindConsolidate);
                }
                self.validate_context(self.current)?;
                self.current.rip = target_ip;
                self.current.gpr[REG_RAX] = return_value;
                return Ok(WalkStep::Complete(WalkOutcome::TargetReached {
                    exception: self.exception,
                    context: self.current,
                }));
            }
        }
        self.validate_context(previous)?;
        if previous.rip == self.control_pc && previous.rsp() == self.control_rsp {
            return Err(WalkError::BadFunctionTable);
        }
        self.current = previous;
        self.control_pc = previous.rip;
        self.control_rsp = previous.rsp();
        Ok(WalkStep::Continue(self))
    }

    fn end(mut self) -> WalkStep {
        self.exception.flags = self.flags;
        WalkStep::Complete(match self.mode {
            WalkMode::Search => WalkOutcome::Unhandled {
                exception: self.exception,
                context: self.original,
            },
            WalkMode::Unwind { target_frame, .. } => WalkOutcome::SecondChance {
                exception: self.exception,
                context: self.current,
                reason: if target_frame.is_none() {
                    SecondChanceReason::ExitUnwind
                } else {
                    SecondChanceReason::TargetNotFound
                },
            },
        })
    }
}

impl HandlerContinuation {
    /// Complete one real handler call. Unknown dispositions and incomplete collided-unwind support
    /// are errors, never `ContinueSearch`. A native caller must not translate these into success.
    fn resume(mut self, response: HandlerResponse) -> Result<WalkStep, WalkError> {
        if response.disposition == 3 {
            return Err(WalkError::UnsupportedCollidedUnwind);
        }
        self.walk.exception = response.exception;
        match (self.walk.mode, response.contexts) {
            (WalkMode::Search, HandlerContexts::Search { exception, unwound }) => {
                self.walk.original = exception;
                self.previous = unwound;
                self.walk.flags |= self.walk.exception.flags & EXCEPTION_NONCONTINUABLE;
                if self.walk.nested_frame == Some(self.establisher_frame) {
                    self.walk.nested_frame = None;
                    self.walk.flags &= !EXCEPTION_NESTED_CALL;
                }
                match response.disposition {
                    0 => {
                        if self.walk.flags & EXCEPTION_NONCONTINUABLE != 0 {
                            return Err(WalkError::NoncontinuableException);
                        }
                        self.walk.exception.flags = self.walk.flags;
                        return Ok(WalkStep::Complete(WalkOutcome::Handled {
                            exception: self.walk.exception,
                            context: self.walk.original,
                        }));
                    }
                    1 => {}
                    2 => {
                        let frame = response.dispatcher_establisher_frame;
                        self.walk.validate_frame(frame)?;
                        if frame < self.establisher_frame {
                            return Err(WalkError::BadStack);
                        }
                        self.walk.flags |= EXCEPTION_NESTED_CALL;
                        self.walk.nested_frame =
                            Some(self.walk.nested_frame.map_or(frame, |old| old.max(frame)));
                    }
                    raw => return Err(WalkError::InvalidDisposition(raw)),
                }
            }
            (WalkMode::Unwind { .. }, HandlerContexts::Unwind { current }) => {
                if response.disposition != 1 {
                    return Err(WalkError::InvalidDisposition(response.disposition));
                }
                self.walk.current = current;
                self.walk.flags &= !EXCEPTION_TARGET_UNWIND;
            }
            _ => return Err(WalkError::InvalidHandlerContexts),
        }
        self.walk
            .advance(self.previous, Some(self.establisher_frame))
    }
}

#[cfg(test)]
mod tests;
