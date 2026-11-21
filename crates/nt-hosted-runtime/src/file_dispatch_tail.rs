//! The control dispatches a File invocation owes after its IRP returned (#420).
//!
//! A METHOD_NEITHER terminal still has to copy the retained mutable input back and then
//! acknowledge the completion. Each of those is its own native dispatch, whose pump can stop
//! unfinished like the IRP's own. The File owner's continuation keeps the stage that is running,
//! so a resumed return is received by that stage, into that stage's buffer, exactly once; no
//! earlier stage is ever issued again.

/// A control dispatch owed after the IRP returned the terminal `T`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileTailStage<T> {
    /// Copy the retained mutable input back into the invocation's input.
    CopyMutableInput(T),
    /// Acknowledge the completion after that copy.
    AckCompletion(T),
}

/// The invocation buffer a stage's native return is written into.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileTailBuffer {
    MutableInput,
    Empty,
}

/// What follows a native return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileTailNext<T, S> {
    /// Issue this control dispatch next.
    Issue(FileTailStage<T>),
    /// The invocation returns the IRP's terminal.
    Finish(T),
    /// A control did not do exactly its work; its effect is uncertain.
    Indeterminate(S),
}

impl<T> FileTailStage<T> {
    /// The IRP itself returned the non-pending terminal `terminal`.
    pub fn first<S>(terminal: T, mutable_input: bool) -> FileTailNext<T, S> {
        if mutable_input {
            FileTailNext::Issue(Self::CopyMutableInput(terminal))
        } else {
            FileTailNext::Finish(terminal)
        }
    }

    pub fn buffer(&self) -> FileTailBuffer {
        match self {
            Self::CopyMutableInput(_) => FileTailBuffer::MutableInput,
            Self::AckCompletion(_) => FileTailBuffer::Empty,
        }
    }

    /// This stage's control returned: `Ok` when it did exactly its work, else its status.
    pub fn returned<S>(self, result: Result<(), S>) -> FileTailNext<T, S> {
        match (self, result) {
            (Self::CopyMutableInput(terminal), Ok(())) =>
                FileTailNext::Issue(Self::AckCompletion(terminal)),
            (Self::AckCompletion(terminal), Ok(())) => FileTailNext::Finish(terminal),
            (_, Err(status)) => FileTailNext::Indeterminate(status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Next = FileTailNext<u32, i32>;

    #[test]
    fn a_method_neither_terminal_copies_its_input_back_first() {
        assert_eq!(FileTailStage::first::<i32>(7, true),
            Next::Issue(FileTailStage::CopyMutableInput(7)));
        assert_eq!(FileTailStage::first::<i32>(7, false), Next::Finish(7),
            "an ordinary terminal owes no control");
    }

    #[test]
    fn each_stage_resumes_into_its_own_buffer() {
        assert_eq!(FileTailStage::CopyMutableInput(7).buffer(), FileTailBuffer::MutableInput);
        assert_eq!(FileTailStage::AckCompletion(7).buffer(), FileTailBuffer::Empty);
    }

    #[test]
    fn a_returned_copy_is_acknowledged_and_then_the_terminal_returns() {
        let Next::Issue(ack) = FileTailStage::CopyMutableInput(7).returned::<i32>(Ok(())) else {
            panic!("an exact copy is acknowledged next");
        };
        assert_eq!(ack, FileTailStage::AckCompletion(7));
        assert_eq!(ack.returned::<i32>(Ok(())), Next::Finish(7),
            "the IRP's own terminal survives both controls");
    }

    #[test]
    fn an_inexact_control_is_uncertain_and_issues_nothing_more() {
        assert_eq!(FileTailStage::CopyMutableInput(7).returned(Err(-3)), Next::Indeterminate(-3),
            "a short copy is never acknowledged");
        assert_eq!(FileTailStage::AckCompletion(7).returned(Err(-4)), Next::Indeterminate(-4));
    }
}
