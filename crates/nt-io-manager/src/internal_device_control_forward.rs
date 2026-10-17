//! Admission and no-replay progress for a driver-originated internal control IRP.
//!
//! A native adapter must pin the source IRP and exact target before calling `enter`. The
//! provider's eight output bytes are retained here only as opaque data. In particular, a
//! successful control that returns a code pointer cannot publish that pointer to another
//! driver VSpace. A typed callable bridge must authenticate and translate it first.

use nt_io_abi::major;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalControlError {
    WrongMajor,
    WrongMinor,
    WrongMethod,
    WrongMode,
    WrongOutputLength,
    NotEntered,
    AlreadyEntered,
    AlreadyTerminal,
    ExcessInformation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalControlCapture {
    code: u32,
    output_length: u32,
}

impl InternalControlCapture {
    pub fn new(
        major: u8,
        minor: u8,
        code: u32,
        kernel_mode: bool,
        input_length: u32,
        output_length: u32,
    ) -> Result<Self, InternalControlError> {
        if major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL {
            return Err(InternalControlError::WrongMajor);
        }
        if minor != 0 {
            return Err(InternalControlError::WrongMinor);
        }
        if code & 3 != 3 || input_length != 0 {
            return Err(InternalControlError::WrongMethod);
        }
        if !kernel_mode {
            return Err(InternalControlError::WrongMode);
        }
        if output_length != 8 {
            return Err(InternalControlError::WrongOutputLength);
        }
        Ok(Self { code, output_length })
    }

    pub const fn code(self) -> u32 {
        self.code
    }

    pub const fn output_length(self) -> u32 {
        self.output_length
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalControlOutcome {
    Pending,
    Uncertain,
    Terminal {
        status: i32,
        information: u64,
        output: [u8; 8],
    },
}

/// Provider output remains opaque until a separate, typed owner transforms it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalControlTerminal {
    status: i32,
    information: u64,
    output: [u8; 8],
}

impl InternalControlTerminal {
    pub const fn status(self) -> i32 {
        self.status
    }

    pub const fn information(self) -> u64 {
        self.information
    }

    // No public output accessor: a raw provider pointer is not callable in the source VSpace.
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Captured,
    Entered,
    Pending,
    Uncertain,
    Terminal(InternalControlTerminal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalControlProgress {
    capture: InternalControlCapture,
    phase: Phase,
}

impl InternalControlProgress {
    pub const fn new(capture: InternalControlCapture) -> Self {
        Self { capture, phase: Phase::Captured }
    }

    pub fn enter(&mut self) -> Result<(), InternalControlError> {
        if self.phase != Phase::Captured {
            return Err(InternalControlError::AlreadyEntered);
        }
        self.phase = Phase::Entered;
        Ok(())
    }

    pub fn observe(
        &mut self,
        outcome: InternalControlOutcome,
    ) -> Result<Option<InternalControlTerminal>, InternalControlError> {
        match self.phase {
            Phase::Captured => return Err(InternalControlError::NotEntered),
            Phase::Terminal(_) => return Err(InternalControlError::AlreadyTerminal),
            _ => {}
        }
        match outcome {
            InternalControlOutcome::Pending => {
                if self.phase != Phase::Uncertain {
                    self.phase = Phase::Pending;
                }
                Ok(None)
            }
            InternalControlOutcome::Uncertain => {
                self.phase = Phase::Uncertain;
                Ok(None)
            }
            InternalControlOutcome::Terminal { status, information, output } => {
                if information > u64::from(self.capture.output_length) {
                    self.phase = Phase::Uncertain;
                    return Err(InternalControlError::ExcessInformation);
                }
                let terminal = InternalControlTerminal { status, information, output };
                self.phase = Phase::Terminal(terminal);
                Ok(Some(terminal))
            }
        }
    }

    /// Output publication remains closed until a typed protocol translates provider addresses.
    pub const fn can_publish(&self) -> bool {
        false
    }
}
