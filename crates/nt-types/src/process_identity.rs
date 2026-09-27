/// Hosted and temporary process authorities have independent counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessGeneration {
    Hosted(u64),
    Temporary(u64),
}

impl ProcessGeneration {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Hosted(value) | Self::Temporary(value) => value != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub generation: ProcessGeneration,
}

impl ProcessIdentity {
    pub const fn empty() -> Self {
        Self {
            pid: 0,
            generation: ProcessGeneration::Hosted(0),
        }
    }

    pub const fn is_valid(self) -> bool {
        self.pid != 0 && self.generation.is_valid()
    }
}
