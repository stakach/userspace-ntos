//! Read-only classification for a bounded win32k admission-failure snapshot.

use nt_component_suspension::LanePhase;

#[derive(Default, Debug, PartialEq, Eq)]
pub(super) struct LaneCounts {
    pub idle: usize,
    pub running: usize,
    pub suspended: usize,
    pub terminal: usize,
    pub other: usize,
}

impl LaneCounts {
    pub fn observe(&mut self, phase: Option<LanePhase>) {
        match phase {
            Some(LanePhase::Idle) => self.idle += 1,
            Some(LanePhase::Running | LanePhase::NestedExecution(_)) => self.running += 1,
            Some(LanePhase::Suspended) => self.suspended += 1,
            Some(LanePhase::Terminal) => self.terminal += 1,
            _ => self.other += 1,
        }
    }
}

pub(super) fn phase_name(phase: Option<LanePhase>) -> &'static [u8] {
    match phase {
        Some(LanePhase::Staged) => b"staged",
        Some(LanePhase::Starting) => b"starting",
        Some(LanePhase::StartupStopping) => b"startup-stopping",
        Some(LanePhase::StartupStopAcknowledged) => b"startup-stop-ack",
        Some(LanePhase::StartupStopped) => b"startup-stopped",
        Some(LanePhase::StartupDetaching) => b"startup-detaching",
        Some(LanePhase::StartupDetached) => b"startup-detached",
        Some(LanePhase::StartupSchedulerDeleting) => b"startup-scheduler-deleting",
        Some(LanePhase::StartupSchedulerDeleted) => b"startup-scheduler-deleted",
        Some(LanePhase::Idle) => b"idle",
        Some(LanePhase::Running) => b"running",
        Some(LanePhase::NestedExecution(_)) => b"nested-execution",
        Some(LanePhase::Suspended) => b"suspended",
        Some(LanePhase::Terminal) => b"terminal",
        None => b"unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_nested_execution_as_owned_running_work_without_hiding_other_phases() {
        let mut counts = LaneCounts::default();
        for phase in [
            Some(LanePhase::Idle),
            Some(LanePhase::Running),
            Some(LanePhase::NestedExecution(42)),
            Some(LanePhase::Suspended),
            Some(LanePhase::Terminal),
            Some(LanePhase::StartupStopped),
            None,
        ] {
            counts.observe(phase);
        }
        assert_eq!(counts, LaneCounts { idle: 1, running: 2, suspended: 1, terminal: 1, other: 2 });
        assert_eq!(phase_name(Some(LanePhase::NestedExecution(42))), b"nested-execution");
        assert_eq!(phase_name(Some(LanePhase::StartupStopped)), b"startup-stopped");
    }
}
