//! Ordered ownership of a hosted process's one-shot initial thread creation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialCreationStep {
    StartPhysical,
    PhysicalIndeterminate,
    CommitPs,
    PublishHandle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialCreationProgress {
    step: InitialCreationStep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrongInitialCreationPhase;

impl Default for InitialCreationProgress {
    fn default() -> Self { Self::new() }
}

impl InitialCreationProgress {
    pub const fn new() -> Self { Self { step: InitialCreationStep::StartPhysical } }
    pub const fn next_step(&self) -> InitialCreationStep { self.step }
    pub const fn may_cancel_no_effects(&self) -> bool {
        matches!(self.step, InitialCreationStep::StartPhysical)
    }
    pub fn physical_started(&mut self) -> Result<(), WrongInitialCreationPhase> {
        if self.step != InitialCreationStep::StartPhysical { return Err(WrongInitialCreationPhase); }
        self.step = InitialCreationStep::CommitPs;
        Ok(())
    }
    pub fn physical_indeterminate(&mut self) -> Result<(), WrongInitialCreationPhase> {
        if self.step != InitialCreationStep::StartPhysical { return Err(WrongInitialCreationPhase); }
        self.step = InitialCreationStep::PhysicalIndeterminate;
        Ok(())
    }
    pub fn physical_resolved(&mut self) -> Result<(), WrongInitialCreationPhase> {
        if self.step != InitialCreationStep::PhysicalIndeterminate { return Err(WrongInitialCreationPhase); }
        self.step = InitialCreationStep::CommitPs;
        Ok(())
    }
    pub fn physical_refused_no_effects(&mut self) -> Result<(), WrongInitialCreationPhase> {
        if self.step != InitialCreationStep::PhysicalIndeterminate { return Err(WrongInitialCreationPhase); }
        self.step = InitialCreationStep::StartPhysical;
        Ok(())
    }
    pub fn ps_committed(&mut self) -> Result<(), WrongInitialCreationPhase> {
        if self.step != InitialCreationStep::CommitPs { return Err(WrongInitialCreationPhase); }
        self.step = InitialCreationStep::PublishHandle;
        Ok(())
    }
}
