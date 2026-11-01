//! Diagnostic timing for one retained hosted File dispatch.
//!
//! The canonical IRP identity labels measurements only. It grants no dispatch or retirement
//! authority. Pump and bank timings are nested within the invocation interval.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedFileRpcIdentity {
    pub irp_id: u64,
    pub major: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedFileRpcMarks {
    pub entered: u64,
    pub invoked: u64,
    pub returned: u64,
    pub terminal: u64,
    pub pump_ticks: u64,
    pub bank_ticks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedFileRpcDurations {
    pub prepare: u64,
    pub pump: u64,
    pub invoke_other: u64,
    pub terminal: u64,
    pub bank: u64,
    pub total: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostedFileRpcCounts {
    pub calls: u64,
    pub prepare_ticks: u64,
    pub pump_ticks: u64,
    pub invoke_other_ticks: u64,
    pub terminal_ticks: u64,
    pub bank_ticks: u64,
    pub total_ticks: u64,
    pub rejected: u64,
}

/// A cumulative observer; no retained File owner or pending wait is stored here.
pub struct HostedFileRpcDiagnostic {
    counts: HostedFileRpcCounts,
}

impl HostedFileRpcDiagnostic {
    pub const fn new() -> Self {
        Self { counts: HostedFileRpcCounts {
            calls: 0, prepare_ticks: 0, pump_ticks: 0, invoke_other_ticks: 0,
            terminal_ticks: 0, bank_ticks: 0, total_ticks: 0, rejected: 0,
        } }
    }

    pub fn record(
        &mut self,
        entered: HostedFileRpcIdentity,
        returned: HostedFileRpcIdentity,
        marks: HostedFileRpcMarks,
    ) -> Option<HostedFileRpcDurations> {
        let valid_identity = entered.irp_id != 0 && entered == returned && matches!(entered.major, 3 | 4);
        let valid_order = marks.entered <= marks.invoked
            && marks.invoked <= marks.returned && marks.returned <= marks.terminal;
        let invocation = marks.returned.saturating_sub(marks.invoked);
        if !valid_identity || !valid_order || marks.pump_ticks > invocation
            || marks.bank_ticks > marks.pump_ticks
        {
            self.counts.rejected = self.counts.rejected.saturating_add(1);
            return None;
        }
        let phases = HostedFileRpcDurations {
            prepare: marks.invoked - marks.entered,
            pump: marks.pump_ticks,
            invoke_other: invocation - marks.pump_ticks,
            terminal: marks.terminal - marks.returned,
            bank: marks.bank_ticks,
            total: marks.terminal - marks.entered,
        };
        self.counts.calls = self.counts.calls.saturating_add(1);
        self.counts.prepare_ticks = self.counts.prepare_ticks.saturating_add(phases.prepare);
        self.counts.pump_ticks = self.counts.pump_ticks.saturating_add(phases.pump);
        self.counts.invoke_other_ticks = self.counts.invoke_other_ticks.saturating_add(phases.invoke_other);
        self.counts.terminal_ticks = self.counts.terminal_ticks.saturating_add(phases.terminal);
        self.counts.bank_ticks = self.counts.bank_ticks.saturating_add(phases.bank);
        self.counts.total_ticks = self.counts.total_ticks.saturating_add(phases.total);
        Some(phases)
    }

    pub fn counts(&self) -> HostedFileRpcCounts { self.counts }
}

impl Default for HostedFileRpcDiagnostic {
    fn default() -> Self { Self::new() }
}
