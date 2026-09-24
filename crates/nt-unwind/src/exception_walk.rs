//! Bounded x64 search and target-unwind passes over real unwind metadata.
//!
//! This is NOT yet a native `RtlDispatchException`/`RtlUnwindEx` implementation or a replacement
//! for ntdll's live dispatcher. Native use additionally
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
    StackReader, EXCEPTION_COLLIDED_UNWIND, EXCEPTION_EXIT_UNWIND, EXCEPTION_NONCONTINUABLE,
    EXCEPTION_TARGET_UNWIND, EXCEPTION_UNWINDING, REG_RAX,
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
    InvalidCollisionDispatcher,
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

    /// A nonzero collided C scope index needs proof from the admitted handler-data table.
    /// Readers without such proof may only resume at index zero.
    fn validate_collision_scope(&self, _image_base: u64, _handler_data: u64, index: u32) -> bool {
        index == 0
    }
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

/// The saved outer dispatcher context copied by the x64 handler-linkage routine on a collision.
/// This must be populated from the handler's actual modified dispatcher context, not inferred
/// from the invocation that just returned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CollisionDispatcher {
    pub control_pc: u64,
    pub image_base: u64,
    pub function: RuntimeFunction,
    pub establisher_frame: u64,
    pub handler: u64,
    pub handler_data: u64,
    pub scope_index: u32,
    pub context: Context,
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
    /// Required only for `ExceptionCollidedUnwind` (3).
    pub collision: Option<CollisionDispatcher>,
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
            collision: self.collision,
        })
    }
}

#[derive(Debug)]
struct HandlerResponse {
    disposition: i32,
    exception: ExceptionRecord,
    contexts: HandlerContexts,
    dispatcher_establisher_frame: u64,
    collision: Option<CollisionDispatcher>,
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
    exception: ExceptionRecord,
    state: WalkState,
    pending_collision: Option<CollisionDispatcher>,
}

/// An admitted x64 software raise at a naked `ExRaiseStatus` entry. The captured context still
/// describes that entry; the return slot identifies the caller's control PC. Admission does not
/// inspect or invoke a language handler.
#[derive(Debug)]
pub struct SoftwareRaiseSite {
    caller_rip: u64,
    caller_rsp: u64,
    captured: Context,
    stack_low: u64,
    stack_high: u64,
}

impl SoftwareRaiseSite {
    /// Validate the Win64 entry stack and require affirmative executable-image admission for the
    /// return address. NT5 dispatches the return address itself, not that address minus one.
    pub fn admit(
        captured: Context,
        stack_low: u64,
        stack_high: u64,
        image: &dyn ExceptionImageReader,
        stack: &dyn StackReader,
    ) -> Result<Self, WalkError> {
        if stack_low >= stack_high {
            return Err(WalkError::InvalidStackBounds);
        }
        let entry_rsp = captured.rsp();
        let caller_rsp = entry_rsp.checked_add(8).ok_or(WalkError::BadStack)?;
        if entry_rsp < stack_low || caller_rsp > stack_high || entry_rsp & 15 != 8 {
            return Err(WalkError::BadStack);
        }
        let caller_rip = stack.read_u64(entry_rsp).ok_or(WalkError::StackRead)?;
        image
            .lookup_exception_function(caller_rip)
            .map_err(WalkError::ImageLookup)?;
        Ok(Self {
            caller_rip,
            caller_rsp,
            captured,
            stack_low,
            stack_high,
        })
    }

    /// Construct the first-pass search. The caller's return slot is consumed exactly as a `ret`
    /// would consume it; the original exception context is never a synthetic handler result.
    pub fn into_search(mut self, status: u32, frame_limit: usize) -> Result<ExceptionWalk, WalkError> {
        self.captured.rip = self.caller_rip;
        self.captured.set_rsp(self.caller_rsp);
        ExceptionWalk::new(
            WalkMode::Search,
            ExceptionRecord {
                code: status,
                flags: EXCEPTION_NONCONTINUABLE,
                address: self.caller_rip,
                information: Default::default(),
            },
            self.captured,
            self.stack_low,
            self.stack_high,
            frame_limit,
        )
    }
}

/// Control state has no exception-record owner. Suspending a handler moves the real record into
/// its invocation instead of cloning a parameter buffer or manufacturing an empty replacement.
#[derive(Debug)]
struct WalkState {
    mode: WalkMode,
    original: Context,
    current: Context,
    control_pc: u64,
    control_rsp: u64,
    low: u64,
    high: u64,
    frames_left: usize,
    handler_restarts_left: usize,
    flags: u32,
    nested_frame: Option<u64>,
}

#[derive(Debug)]
struct HandlerContinuation {
    state: WalkState,
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
            exception,
            state: WalkState {
                mode,
                original: context,
                current: context,
                control_pc,
                control_rsp: context.rsp(),
                low: stack_low,
                high: stack_high,
                frames_left: frame_limit,
                handler_restarts_left: frame_limit,
                flags,
                nested_frame: None,
            },
            pending_collision: None,
        })
    }

    /// Unwind at most one frame, or suspend before calling its language handler.
    pub fn step(
        mut self,
        image: &dyn ExceptionImageReader,
        stack: &dyn StackReader,
    ) -> Result<WalkStep, WalkError> {
        if let Some(dispatcher) = self.pending_collision.take() {
            return self.resume_collision(dispatcher, image, stack);
        }
        self.validate_context(self.state.current)?;
        if self.state.current.rsp() == self.state.high {
            return Ok(self.end());
        }
        if self.state.frames_left == 0 {
            return Err(WalkError::FrameLimit);
        }
        self.state.frames_left -= 1;
        let bounded = BoundedStack::new(stack, self.state.low, self.state.high)
            .map_err(|_| WalkError::InvalidStackBounds)?;
        let mut previous = self.state.current;
        match image
            .lookup_exception_function(self.state.control_pc)
            .map_err(WalkError::ImageLookup)?
        {
            ExceptionFunction::Function {
                image_base,
                function,
            } => {
                let handler_type = if self.state.mode == WalkMode::Search {
                    unw_flag::EHANDLER
                } else {
                    unw_flag::UHANDLER
                };
                let result = virtual_unwind(
                    handler_type,
                    image_base,
                    self.state.control_pc,
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
                } = self.state.mode
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
                    let (contexts, target_ip) = match self.state.mode {
                        WalkMode::Search => (
                            HandlerContexts::Search {
                                exception: self.state.original,
                                unwound: previous,
                            },
                            0,
                        ),
                        WalkMode::Unwind {
                            target_frame,
                            target_ip,
                            return_value,
                        } => {
                            self.state.current.gpr[REG_RAX] = return_value;
                            if target_frame == Some(result.establisher_frame) {
                                self.state.flags |= EXCEPTION_TARGET_UNWIND;
                            }
                            (
                                HandlerContexts::Unwind {
                                    current: self.state.current,
                                },
                                target_ip,
                            )
                        }
                    };
                    self.exception.flags = self.state.flags;
                    let invocation = HandlerInvocation {
                        exception: self.exception,
                        control_pc: self.state.control_pc,
                        image_base,
                        function,
                        establisher_frame: result.establisher_frame,
                        handler,
                        handler_data,
                        target_ip,
                        scope_index: 0,
                        contexts,
                        collision: None,
                        continuation: HandlerContinuation {
                            state: self.state,
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

    fn resume_collision(
        mut self,
        dispatcher: CollisionDispatcher,
        image: &dyn ExceptionImageReader,
        stack: &dyn StackReader,
    ) -> Result<WalkStep, WalkError> {
        self.validate_context(dispatcher.context)?;
        self.validate_frame(dispatcher.establisher_frame)?;
        if dispatcher.scope_index > 4096
            || !image.validate_collision_scope(
                dispatcher.image_base,
                dispatcher.handler_data,
                dispatcher.scope_index,
            )
        {
            return Err(WalkError::InvalidCollisionDispatcher);
        }
        let (image_base, function) = match image
            .lookup_exception_function(dispatcher.control_pc)
            .map_err(WalkError::ImageLookup)?
        {
            ExceptionFunction::Function {
                image_base,
                function,
            } => (image_base, function),
            ExceptionFunction::Leaf => return Err(WalkError::InvalidCollisionDispatcher),
        };
        if image_base != dispatcher.image_base || function != dispatcher.function {
            return Err(WalkError::InvalidCollisionDispatcher);
        }
        let bounded = BoundedStack::new(stack, self.state.low, self.state.high)
            .map_err(|_| WalkError::InvalidStackBounds)?;
        let mut previous = dispatcher.context;
        let result = virtual_unwind(
            unw_flag::UHANDLER,
            image_base,
            dispatcher.control_pc,
            function,
            &mut previous,
            image,
            &bounded,
        )
        .ok_or(WalkError::UnwindData)?;
        let handler = image_base
            .checked_add(u64::from(result.handler_rva))
            .ok_or(WalkError::UnwindData)?;
        let handler_data = image_base
            .checked_add(u64::from(result.handler_data_rva))
            .ok_or(WalkError::UnwindData)?;
        if result.handler_rva == 0
            || handler != dispatcher.handler
            || handler_data != dispatcher.handler_data
            || result.establisher_frame != dispatcher.establisher_frame
        {
            return Err(WalkError::InvalidCollisionDispatcher);
        }
        if matches!(self.state.mode, WalkMode::Unwind { .. }) {
            // NT5's collided unwind restores the saved Current context and virtually unwinds
            // a separate Previous context without invoking another language handler.
            previous = dispatcher.context;
            let no_handler = virtual_unwind(
                unw_flag::NHANDLER,
                image_base,
                dispatcher.control_pc,
                function,
                &mut previous,
                image,
                &bounded,
            )
            .ok_or(WalkError::UnwindData)?;
            if no_handler.establisher_frame != dispatcher.establisher_frame {
                return Err(WalkError::InvalidCollisionDispatcher);
            }
        }
        self.validate_context(previous)?;
        self.state.current = dispatcher.context;
        self.state.control_pc = dispatcher.control_pc;
        self.state.control_rsp = dispatcher.context.rsp();
        self.state.flags |= EXCEPTION_COLLIDED_UNWIND;
        let (contexts, target_ip, next_previous) = match self.state.mode {
            WalkMode::Search => (
                HandlerContexts::Search {
                    exception: self.state.original,
                    unwound: dispatcher.context,
                },
                0,
                dispatcher.context,
            ),
            WalkMode::Unwind {
                target_frame,
                target_ip,
                return_value,
            } => {
                self.state.current.gpr[REG_RAX] = return_value;
                if target_frame == Some(dispatcher.establisher_frame) {
                    self.state.flags |= EXCEPTION_TARGET_UNWIND;
                }
                (
                    HandlerContexts::Unwind {
                        current: self.state.current,
                    },
                    target_ip,
                    previous,
                )
            }
        };
        self.exception.flags = self.state.flags;
        Ok(WalkStep::Invoke(HandlerInvocation {
            exception: self.exception,
            control_pc: dispatcher.control_pc,
            image_base,
            function,
            establisher_frame: dispatcher.establisher_frame,
            handler,
            handler_data,
            target_ip,
            scope_index: dispatcher.scope_index,
            contexts,
            collision: None,
            continuation: HandlerContinuation {
                state: self.state,
                previous: next_previous,
                establisher_frame: dispatcher.establisher_frame,
            },
        }))
    }

    fn validate_frame(&self, frame: u64) -> Result<(), WalkError> {
        if frame < self.state.low || frame > self.state.high || frame & 15 != 0 {
            Err(WalkError::BadStack)
        } else {
            Ok(())
        }
    }

    fn validate_context(&self, context: Context) -> Result<(), WalkError> {
        if context.rsp() < self.state.low
            || context.rsp() > self.state.high
            || context.rsp() & 7 != 0
        {
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
        } = self.state.mode
        {
            if establisher == Some(target) {
                if self.exception.code == 0x8000_0029 {
                    return Err(WalkError::UnsupportedUnwindConsolidate);
                }
                self.validate_context(self.state.current)?;
                self.state.current.rip = target_ip;
                self.state.current.gpr[REG_RAX] = return_value;
                return Ok(WalkStep::Complete(WalkOutcome::TargetReached {
                    exception: self.exception,
                    context: self.state.current,
                }));
            }
        }
        self.validate_context(previous)?;
        if previous.rip == self.state.control_pc && previous.rsp() == self.state.control_rsp {
            return Err(WalkError::BadFunctionTable);
        }
        self.state.current = previous;
        self.state.control_pc = previous.rip;
        self.state.control_rsp = previous.rsp();
        Ok(WalkStep::Continue(self))
    }

    fn end(mut self) -> WalkStep {
        self.exception.flags = self.state.flags;
        WalkStep::Complete(match self.state.mode {
            WalkMode::Search => WalkOutcome::Unhandled {
                exception: self.exception,
                context: self.state.original,
            },
            WalkMode::Unwind { target_frame, .. } => WalkOutcome::SecondChance {
                exception: self.exception,
                context: self.state.current,
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
    /// Complete one real handler call. A collision is revalidated against the admitted image on
    /// the next step; an absent saved dispatcher context is never treated as ContinueSearch.
    fn resume(self, response: HandlerResponse) -> Result<WalkStep, WalkError> {
        if response.disposition == 3 {
            let collision = response
                .collision
                .ok_or(WalkError::InvalidCollisionDispatcher)?;
            let mut state = self.state;
            if state.handler_restarts_left == 0 {
                return Err(WalkError::FrameLimit);
            }
            state.handler_restarts_left -= 1;
            match (state.mode, response.contexts) {
                (WalkMode::Search, HandlerContexts::Search { exception, .. }) => {
                    state.original = exception;
                }
                (WalkMode::Unwind { .. }, HandlerContexts::Unwind { .. }) => {}
                _ => return Err(WalkError::InvalidHandlerContexts),
            }
            state.flags &= !(EXCEPTION_COLLIDED_UNWIND | EXCEPTION_TARGET_UNWIND);
            state.flags |= response.exception.flags & EXCEPTION_NONCONTINUABLE;
            return Ok(WalkStep::Continue(ExceptionWalk {
                exception: response.exception,
                state,
                pending_collision: Some(collision),
            }));
        }
        let HandlerContinuation {
            state,
            mut previous,
            establisher_frame,
        } = self;
        let mut walk = ExceptionWalk {
            state,
            exception: response.exception,
            pending_collision: None,
        };
        let collided_search = walk.state.flags & EXCEPTION_COLLIDED_UNWIND != 0;
        walk.state.flags &= !EXCEPTION_COLLIDED_UNWIND;
        match (walk.state.mode, response.contexts) {
            (WalkMode::Search, HandlerContexts::Search { exception, unwound }) => {
                walk.state.original = exception;
                previous = unwound;
                walk.state.flags |= walk.exception.flags & EXCEPTION_NONCONTINUABLE;
                if walk.state.nested_frame == Some(establisher_frame) {
                    walk.state.nested_frame = None;
                    walk.state.flags &= !EXCEPTION_NESTED_CALL;
                }
                match response.disposition {
                    0 => {
                        if walk.state.flags & EXCEPTION_NONCONTINUABLE != 0 {
                            return Err(WalkError::NoncontinuableException);
                        }
                        walk.exception.flags = walk.state.flags;
                        return Ok(WalkStep::Complete(WalkOutcome::Handled {
                            exception: walk.exception,
                            context: walk.state.original,
                        }));
                    }
                    1 => {}
                    2 => {
                        let frame = response.dispatcher_establisher_frame;
                        walk.validate_frame(frame)?;
                        if frame < establisher_frame {
                            return Err(WalkError::BadStack);
                        }
                        walk.state.flags |= EXCEPTION_NESTED_CALL;
                        walk.state.nested_frame =
                            Some(walk.state.nested_frame.map_or(frame, |old| old.max(frame)));
                    }
                    raw => return Err(WalkError::InvalidDisposition(raw)),
                }
                if collided_search && previous.rip == walk.state.control_pc {
                    walk.exception.flags = walk.state.flags;
                    return Ok(WalkStep::Complete(WalkOutcome::Unhandled {
                        exception: walk.exception,
                        context: walk.state.original,
                    }));
                }
            }
            (WalkMode::Unwind { .. }, HandlerContexts::Unwind { current }) => {
                if response.disposition != 1 {
                    return Err(WalkError::InvalidDisposition(response.disposition));
                }
                walk.state.current = current;
                walk.state.flags &= !EXCEPTION_TARGET_UNWIND;
            }
            _ => return Err(WalkError::InvalidHandlerContexts),
        }
        walk.advance(previous, Some(establisher_frame))
    }
}

#[cfg(test)]
mod tests;
