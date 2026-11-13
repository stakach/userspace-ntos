//! Observation-only timing for one exact retained startup wait.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupWaitKind {
    Object,
    Alpc,
    Delay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupWakeCause {
    ObjectSignaled,
    AlpcTerminal,
    Deadline,
    Alerted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupWaitSnapshot<Owner> {
    pub owner: Owner,
    pub kind: StartupWaitKind,
    pub target: u64,
    pub reply: u64,
    pub parked_at_100ns: u64,
    pub selected_at_100ns: Option<u64>,
    pub replied_at_100ns: Option<u64>,
    pub wake: Option<StartupWakeCause>,
}

/// A copied trace stamp. It neither owns a Reply nor grants wake authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupWaitObservation<Owner> {
    snapshot: StartupWaitSnapshot<Owner>,
}

impl<Owner: Copy + Eq> StartupWaitObservation<Owner> {
    pub const fn new(owner: Owner, kind: StartupWaitKind, target: u64, reply: u64,
        parked_at_100ns: u64) -> Self {
        Self { snapshot: StartupWaitSnapshot { owner, kind, target, reply,
            parked_at_100ns, selected_at_100ns: None, replied_at_100ns: None, wake: None } }
    }

    pub fn snapshot(&self, owner: Owner) -> Option<StartupWaitSnapshot<Owner>> {
        (self.snapshot.owner == owner).then_some(self.snapshot)
    }

    pub fn parked_age_100ns(&self, owner: Owner, now_100ns: u64) -> Option<u64> {
        now_100ns.checked_sub(self.snapshot(owner)?.parked_at_100ns)
    }

    pub fn mark_selected(&mut self, owner: Owner, at_100ns: u64,
        wake: StartupWakeCause) -> bool {
        if owner != self.snapshot.owner || self.snapshot.selected_at_100ns.is_some()
            || at_100ns < self.snapshot.parked_at_100ns { return false; }
        self.snapshot.selected_at_100ns = Some(at_100ns);
        self.snapshot.wake = Some(wake);
        true
    }

    pub fn mark_replied(&mut self, owner: Owner, at_100ns: u64) -> bool {
        if owner != self.snapshot.owner || self.snapshot.replied_at_100ns.is_some()
            || self.snapshot.selected_at_100ns.is_none_or(|selected| at_100ns < selected)
        { return false; }
        self.snapshot.replied_at_100ns = Some(at_100ns);
        true
    }

    pub fn phase_ages_100ns(&self, owner: Owner) -> Option<(u64, u64)> {
        let snapshot = self.snapshot(owner)?;
        let selected = snapshot.selected_at_100ns?;
        let replied = snapshot.replied_at_100ns?;
        Some((selected.checked_sub(snapshot.parked_at_100ns)?,
            replied.checked_sub(selected)?))
    }
}
