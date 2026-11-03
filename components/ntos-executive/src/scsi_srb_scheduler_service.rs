//! Observation-only intervals inside one retained component scheduler service pass.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SchedulerServicePhase {
    ParentPreserve,
    TimerWork,
    IrqDrain,
    DpcDrain,
    ReceivePrepare,
    ParentRestore,
}

impl SchedulerServicePhase {
    pub(crate) const ALL: [Self; 6] = [
        Self::ParentPreserve, Self::TimerWork, Self::IrqDrain, Self::DpcDrain,
        Self::ReceivePrepare, Self::ParentRestore,
    ];

    pub(crate) const fn label(self) -> &'static [u8] {
        match self {
            Self::ParentPreserve => b"parent-preserve",
            Self::TimerWork => b"timer-work",
            Self::IrqDrain => b"irq-drain",
            Self::DpcDrain => b"dpc-drain",
            Self::ReceivePrepare => b"receive-prepare",
            Self::ParentRestore => b"parent-restore",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SchedulerServiceSample {
    ticks: [u64; 6],
    timer_work: u64,
    irq_lines: u64,
    dpcs: u64,
}

impl SchedulerServiceSample {
    pub(crate) fn ticks(self, phase: SchedulerServicePhase) -> u64 {
        self.ticks[phase as usize]
    }

    pub(crate) fn work_counts(self) -> (u64, u64, u64) {
        (self.timer_work, self.irq_lines, self.dpcs)
    }

    pub(crate) fn is_empty(self) -> bool {
        self.timer_work == 0 && self.irq_lines == 0 && self.dpcs == 0
    }

    pub(crate) fn total_ticks(self) -> u64 {
        self.ticks.into_iter().fold(0, u64::wrapping_add)
    }
}

pub(crate) struct SchedulerServiceClock {
    phase: SchedulerServicePhase,
    started: u64,
    ticks: [u64; 6],
}

impl SchedulerServiceClock {
    pub(crate) const fn new(started: u64) -> Self {
        Self { phase: SchedulerServicePhase::ParentPreserve, started, ticks: [0; 6] }
    }

    pub(crate) fn transition(&mut self, next: SchedulerServicePhase, now: u64) {
        self.ticks[self.phase as usize] = self.ticks[self.phase as usize]
            .wrapping_add(now.wrapping_sub(self.started));
        self.phase = next;
        self.started = now;
    }

    pub(crate) fn finish(
        mut self, now: u64, timer_work: u64, irq_lines: u64, dpcs: u64,
    ) -> SchedulerServiceSample {
        self.ticks[self.phase as usize] = self.ticks[self.phase as usize]
            .wrapping_add(now.wrapping_sub(self.started));
        SchedulerServiceSample { ticks: self.ticks, timer_work, irq_lines, dpcs }
    }
}
