use crate::ProcessIdentity;

/// The authority that first owned a resident or transition page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLifetime {
    Process(ProcessIdentity),
    UnpublishedImage(u64),
}

impl MemoryLifetime {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Process(process) => process.is_valid(),
            Self::UnpublishedImage(token) => token != 0,
        }
    }
}
