//! Bounded diagnostic sampling for an exact setup-waited process and canonical File route.

/// Sampling is diagnostic only; it never grants boot progress or changes I/O ownership.
pub struct SetupReadStageSampler {
    observations: u32,
    emitted: u8,
}

impl SetupReadStageSampler {
    pub const MAX_EMITTED: u8 = 64;

    pub const fn new() -> Self {
        Self { observations: 0, emitted: 0 }
    }

    /// Return the exact matching call sequence when this sample should be emitted.
    pub fn observe<Process: Eq, Route: Eq>(
        &mut self,
        expected_process: Option<Process>,
        actual_process: Option<Process>,
        expected_route: Option<Route>,
        actual_route: Route,
        elapsed_ticks: u64,
    ) -> Option<u32> {
        if expected_process.is_none() || expected_process != actual_process
            || expected_route.as_ref() != Some(&actual_route)
            || self.emitted >= Self::MAX_EMITTED
        {
            return None;
        }
        let sequence = self.observations;
        self.observations = self.observations.saturating_add(1);
        if sequence < 8 || sequence % 128 == 0 || elapsed_ticks > 1_000_000_000 {
            self.emitted += 1;
            Some(sequence)
        } else {
            None
        }
    }

    pub const fn emitted(&self) -> u8 { self.emitted }
}

impl Default for SetupReadStageSampler {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: (u32, u64) = (408, 14);
    const ROUTE: (u64, u64) = (0x100, 0x800_0000_00ed);

    #[test]
    fn exact_process_generation_and_canonical_route_only() {
        let mut sampler = SetupReadStageSampler::new();
        assert_eq!(sampler.observe(None, Some(OWNER), Some(ROUTE), ROUTE, 2_000_000_000), None);
        assert_eq!(sampler.observe(Some(OWNER), Some((408, 15)), Some(ROUTE), ROUTE, 2_000_000_000), None);
        assert_eq!(sampler.observe(Some(OWNER), Some(OWNER), None, ROUTE, 2_000_000_000), None);
        assert_eq!(sampler.observe(Some(OWNER), Some(OWNER), Some(ROUTE), (ROUTE.0, ROUTE.1 + 1), 2_000_000_000), None);
        assert_eq!(sampler.observe(Some(OWNER), Some(OWNER), Some(ROUTE), ROUTE, 1), Some(0));
        assert_eq!(sampler.emitted(), 1);
    }

    #[test]
    fn first_eight_then_every_128th_or_slow_with_finite_output() {
        let mut sampler = SetupReadStageSampler::new();
        let mut samples = [u32::MAX; SetupReadStageSampler::MAX_EMITTED as usize];
        let mut sample_count = 0;
        for call in 0..10_000u32 {
            let slow = call == 63 || call == 1001;
            let elapsed = if slow { 1_000_000_001 } else { 1 };
            if let Some(sequence) = sampler.observe(Some(OWNER), Some(OWNER), Some(ROUTE), ROUTE, elapsed) {
                assert!(sample_count < samples.len());
                samples[sample_count] = sequence;
                sample_count += 1;
            }
        }
        assert_eq!(&samples[..8], &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert!(samples[..sample_count].contains(&63));
        assert!(samples[..sample_count].contains(&128));
        assert!(samples[..sample_count].contains(&1001));
        assert!(sample_count <= SetupReadStageSampler::MAX_EMITTED as usize);
        assert_eq!(sampler.emitted() as usize, sample_count);
    }

    #[test]
    fn rejected_identity_does_not_advance_matching_sequence() {
        let mut sampler = SetupReadStageSampler::new();
        for _ in 0..500 {
            assert_eq!(sampler.observe(Some(OWNER), Some((409, 14)), Some(ROUTE), ROUTE, 1), None);
        }
        assert_eq!(sampler.observe(Some(OWNER), Some(OWNER), Some(ROUTE), ROUTE, 1), Some(0));
    }
}
