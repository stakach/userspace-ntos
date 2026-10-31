//! Bounded coverage for terminal named-event open and single-object wait failures.

/// Keep the first failures and then sample at powers of two. This preserves evidence from a
/// late-starting client without allowing an unbounded error loop to fill the serial log.
#[derive(Default)]
pub struct EventTerminalReceiptSampler {
    seen: u64,
}

impl EventTerminalReceiptSampler {
    pub const fn new() -> Self {
        Self { seen: 0 }
    }

    pub fn should_emit(&mut self) -> bool {
        let sequence = self.seen;
        self.seen = self.seen.saturating_add(1);
        Self::sample_sequence(sequence)
    }

    pub const fn sample_sequence(sequence: u64) -> bool {
        sequence < 32 || sequence.is_power_of_two()
    }

    pub const fn is_failure(status: u32) -> bool {
        status & 0x8000_0000 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::EventTerminalReceiptSampler;

    #[test]
    fn failures_keep_late_coverage_without_unbounded_output() {
        let mut sampler = EventTerminalReceiptSampler::new();
        let mut emitted = 0;
        let mut late = false;
        for ticket in 0..100_000 {
            if sampler.should_emit() {
                emitted += 1;
                late |= ticket > 20_000;
            }
        }
        assert!(late, "failures after setup starts must remain visible");
        assert!(emitted <= 128, "receipts must remain finite");
    }

    #[test]
    fn normal_timeout_is_not_a_failure_receipt() {
        assert!(!EventTerminalReceiptSampler::is_failure(0));
        assert!(!EventTerminalReceiptSampler::is_failure(0x102));
        assert!(EventTerminalReceiptSampler::is_failure(0xC000_0008));
        assert!(EventTerminalReceiptSampler::is_failure(0xC000_0034));
    }
}
