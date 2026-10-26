//! Bounded diagnostic sampling of an exact acknowledged native block ticket.

/// Logical owner taken from the retained claim, never reconstructed from a block address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeBlockStageOwner {
    Sector,
    Mutation,
    Relation,
    Hive,
    Storage,
    Checkpoint,
    Fold,
}

impl NativeBlockStageOwner {
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Sector => b"sector",
            Self::Mutation => b"mutation",
            Self::Relation => b"relation",
            Self::Hive => b"hive",
            Self::Storage => b"storage",
            Self::Checkpoint => b"checkpoint",
            Self::Fold => b"fold",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBlockStageObservation {
    pub class: u8,
    pub owner: NativeBlockStageOwner,
    pub irp: u64,
    pub ticket: u64,
    pub claimed_at_100ns: u64,
    pub dispatch_started_at_100ns: u64,
    pub dispatch_returned_at_100ns: u64,
    pub terminal_seen_at_100ns: u64,
    pub acknowledged_at_100ns: u64,
    pub completed_at_100ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBlockStageSample {
    pub sequence: u32,
    pub observation: NativeBlockStageObservation,
}

/// Diagnostic output has a finite cap independent of the number of block requests.
pub struct NativeBlockStageSampler {
    observations: u32,
    periodic_emitted: u8,
    slow_emitted: u8,
}

impl NativeBlockStageSampler {
    pub const MAX_EMITTED: u8 = 64;
    const MAX_PERIODIC: u8 = 48;
    const MAX_SLOW: u8 = Self::MAX_EMITTED - Self::MAX_PERIODIC;

    pub const fn new() -> Self {
        Self { observations: 0, periodic_emitted: 0, slow_emitted: 0 }
    }

    /// Two samples per octave keep the setup and desktop frontier visible even
    /// after thousands of tickets, without spending the whole output budget early.
    fn periodic(sequence: u32) -> bool {
        if sequence < 8 { return true; }
        if sequence < 128 { return false; }
        let octave = 1u32 << (31 - sequence.leading_zeros());
        sequence == octave || (octave <= (1u32 << 30) && sequence == octave + octave / 4)
    }

    /// An unacknowledged or malformed observation cannot be reported as completed I/O.
    pub fn observe(&mut self, observation: NativeBlockStageObservation)
        -> Option<NativeBlockStageSample>
    {
        if !(1..=13).contains(&observation.class)
            || (observation.class == 13) == (observation.owner == NativeBlockStageOwner::Sector)
            || observation.irp == 0 || observation.ticket == 0
            || observation.claimed_at_100ns == 0
            || observation.dispatch_started_at_100ns < observation.claimed_at_100ns
            || observation.dispatch_returned_at_100ns < observation.dispatch_started_at_100ns
            || observation.terminal_seen_at_100ns < observation.dispatch_returned_at_100ns
            || observation.acknowledged_at_100ns < observation.terminal_seen_at_100ns
            || observation.completed_at_100ns < observation.acknowledged_at_100ns
            || self.emitted() >= Self::MAX_EMITTED
        {
            return None;
        }
        let sequence = self.observations;
        self.observations = self.observations.saturating_add(1);
        if Self::periodic(sequence) && self.periodic_emitted < Self::MAX_PERIODIC {
            self.periodic_emitted += 1;
            Some(NativeBlockStageSample { sequence, observation })
        } else if observation.completed_at_100ns - observation.claimed_at_100ns > 10_000_000
            && self.slow_emitted < Self::MAX_SLOW {
            self.slow_emitted += 1;
            Some(NativeBlockStageSample { sequence, observation })
        } else {
            None
        }
    }

    pub const fn emitted(&self) -> u8 { self.periodic_emitted + self.slow_emitted }
}

impl Default for NativeBlockStageSampler {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(class: u8, irp: u64, ticket: u64, elapsed_100ns: u64)
        -> NativeBlockStageObservation
    {
        NativeBlockStageObservation {
            class,
            owner: if class == 13 { NativeBlockStageOwner::Fold }
                else { NativeBlockStageOwner::Sector },
            irp, ticket,
            claimed_at_100ns: 100,
            dispatch_started_at_100ns: 110,
            dispatch_returned_at_100ns: 120,
            terminal_seen_at_100ns: 130,
            acknowledged_at_100ns: 140,
            completed_at_100ns: 100 + elapsed_100ns,
        }
    }

    #[test]
    fn exact_class_irp_ticket_survive_sampling() {
        let mut sampler = NativeBlockStageSampler::new();
        let observation = observation(7, 0x1234, 0x5678, 100);
        assert_eq!(sampler.observe(observation), Some(NativeBlockStageSample {
            sequence: 0, observation,
        }));
    }

    #[test]
    fn incomplete_invalid_or_reordered_boundaries_never_consume_sequence() {
        let mut sampler = NativeBlockStageSampler::new();
        for bad in [
            NativeBlockStageObservation { class: 0, ..observation(7, 1, 2, 100) },
            NativeBlockStageObservation { class: 14, ..observation(7, 1, 2, 100) },
            NativeBlockStageObservation { irp: 0, ..observation(7, 1, 2, 100) },
            NativeBlockStageObservation { ticket: 0, ..observation(7, 1, 2, 100) },
            NativeBlockStageObservation { acknowledged_at_100ns: 0, ..observation(7, 1, 2, 100) },
            NativeBlockStageObservation { terminal_seen_at_100ns: 121, dispatch_returned_at_100ns: 122,
                ..observation(7, 1, 2, 100) },
            NativeBlockStageObservation { completed_at_100ns: 139, ..observation(7, 1, 2, 100) },
        ] {
            assert_eq!(sampler.observe(bad), None);
        }
        assert_eq!(sampler.observe(observation(13, 3, 4, 100)).unwrap().sequence, 0);
    }

    #[test]
    fn first_eight_periodic_and_over_one_second_have_finite_output() {
        let mut sampler = NativeBlockStageSampler::new();
        let mut samples = [u32::MAX; NativeBlockStageSampler::MAX_EMITTED as usize];
        let mut count = 0;
        for n in 0..10_000u32 {
            let elapsed = if n == 63 || n == 1001 { 10_000_001 } else { 100 };
            if let Some(sample) = sampler.observe(observation(7, u64::from(n) + 1,
                u64::from(n) + 11, elapsed)) {
                assert!(count < samples.len());
                samples[count] = sample.sequence;
                count += 1;
            }
        }
        assert_eq!(&samples[..8], &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert!(samples[..count].contains(&63));
        assert!(samples[..count].contains(&128));
        assert!(samples[..count].contains(&1001));
        assert!(count <= NativeBlockStageSampler::MAX_EMITTED as usize);
        assert_eq!(sampler.emitted() as usize, count);
    }

    #[test]
    fn periodic_samples_reach_late_setup_tickets_with_a_finite_cap() {
        let mut sampler = NativeBlockStageSampler::new();
        let mut late_sample = None;
        let mut count = 0;
        for n in 0..25_000u32 {
            if let Some(sample) = sampler.observe(observation(7, u64::from(n) + 1,
                u64::from(n) + 11, 100)) {
                count += 1;
                if (20_000..23_000).contains(&n) { late_sample = Some(sample); }
            }
        }
        let late_sample = late_sample.expect("periodic sampling must reach late boot");
        assert!((20_000..23_000).contains(&late_sample.sequence));
        assert_eq!(late_sample.observation.ticket, u64::from(late_sample.sequence) + 11);
        assert!(count <= NativeBlockStageSampler::MAX_EMITTED as usize);
        assert_eq!(sampler.emitted() as usize, count);
    }

    #[test]
    fn early_slow_ticket_burst_preserves_late_periodic_sampling() {
        let mut sampler = NativeBlockStageSampler::new();
        let mut late_periodic = false;
        let mut slow_samples = 0;
        for n in 0..25_000u32 {
            let elapsed = if (8..1_000).contains(&n) { 10_000_001 } else { 100 };
            if sampler.observe(observation(7, u64::from(n) + 1,
                u64::from(n) + 11, elapsed)).is_some() {
                if (8..1_000).contains(&n) { slow_samples += 1; }
                if (20_000..23_000).contains(&n) { late_periodic = true; }
            }
        }
        assert!(slow_samples > 0, "long latency must still be sampled");
        assert!(late_periodic, "slow tickets must not exhaust the periodic horizon");
        assert!(sampler.emitted() >= 24);
        assert!(sampler.emitted() <= NativeBlockStageSampler::MAX_EMITTED);
    }

    #[test]
    fn snapshot_owner_survives_sampling_without_unbounded_output() {
        let mut sampler = NativeBlockStageSampler::new();
        let owners = [
            NativeBlockStageOwner::Mutation,
            NativeBlockStageOwner::Relation,
            NativeBlockStageOwner::Hive,
            NativeBlockStageOwner::Storage,
            NativeBlockStageOwner::Checkpoint,
            NativeBlockStageOwner::Fold,
        ];
        let labels: [&[u8]; 6] = [
            b"mutation", b"relation", b"hive", b"storage", b"checkpoint", b"fold",
        ];
        for (index, owner) in owners.into_iter().enumerate() {
            let observation = NativeBlockStageObservation {
                owner,
                ..observation(13, index as u64 + 1, index as u64 + 1, 100)
            };
            let sample = sampler.observe(observation).expect("first six samples are emitted");
            assert_eq!(sample.observation.owner, owner);
            assert_eq!(owner.label(), labels[index]);
        }
        // Diagnostic ownership must not be synthesized from the numeric block class.
        assert_eq!(sampler.observe(NativeBlockStageObservation {
            owner: NativeBlockStageOwner::Sector,
            ..observation(13, 7, 7, 100)
        }), None);
        for ticket in 8..10_000 {
            let _ = sampler.observe(NativeBlockStageObservation {
                owner: NativeBlockStageOwner::Fold,
                ..observation(13, ticket, ticket, 10_000_001)
            });
        }
        assert!(sampler.emitted() <= NativeBlockStageSampler::MAX_EMITTED);
    }
}
