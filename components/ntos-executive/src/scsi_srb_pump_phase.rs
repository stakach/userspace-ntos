//! Pure phase boundaries for an admitted, synchronous SCSI SRB provider dispatch.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScsiSrbPumpPhase {
    admitted: u64,
    entered: Option<u64>,
    exited: Option<u64>,
}

impl ScsiSrbPumpPhase {
    pub(crate) const fn new(admitted: u64) -> Self {
        Self { admitted, entered: None, exited: None }
    }

    pub(crate) fn enter(&mut self, now: u64) -> Option<u64> {
        if self.entered.is_some() { return None; }
        self.entered = Some(now);
        Some(now.wrapping_sub(self.admitted))
    }

    pub(crate) fn exit(&mut self, now: u64) -> Option<u64> {
        let entered = self.entered?;
        if self.exited.is_some() { return None; }
        self.exited = Some(now);
        Some(now.wrapping_sub(entered))
    }

    pub(crate) fn finish(self, now: u64) -> Option<u64> {
        Some(now.wrapping_sub(self.exited?))
    }
}
