//! Typed result of one observed win32k dispatch.
//!
//! Callers must destructure this enum. Adding a retained physical result will then require
//! every caller to choose its Reply disposition explicitly, without tuple conversion.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32kDispatchOutcome {
    Known { value: u64, completed: bool },
}

impl From<(u64, bool)> for Win32kDispatchOutcome {
    fn from((value, completed): (u64, bool)) -> Self {
        Self::Known { value, completed }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32kDispatchWithReceipt {
    pub outcome: Win32kDispatchOutcome,
    pub dispatch_return: Option<nt_user_callback::DispatchReturn>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32kProcessCreateResult {
    NotEntered(u32),
    Returned(u32),
    /// The physical dispatch has a retained callback or wait.
    Suspended,
    Indeterminate(u32),
}

impl Win32kDispatchOutcome {
    pub fn process_create(self, entered: bool, suspended: bool) -> Win32kProcessCreateResult {
        match self {
            Self::Known { value, completed: true } =>
                Win32kProcessCreateResult::Returned(value as u32),
            Self::Known { .. } if suspended => Win32kProcessCreateResult::Suspended,
            Self::Known { value, .. } if entered =>
                Win32kProcessCreateResult::Indeterminate(value as u32),
            Self::Known { value, .. } => Win32kProcessCreateResult::NotEntered(value as u32),
        }
    }
}
