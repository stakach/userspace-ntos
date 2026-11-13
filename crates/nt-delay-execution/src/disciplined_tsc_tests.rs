use super::{
    DisciplinedTsc, MonotonicTime, ReferenceSample, TscClockError, TscObservation, TscPhase,
    TscRead, CHECK_INTERVAL_100NS, CHECK_READS, CLEAN_WINDOWS_TO_ADMIT, FORGIVENESS_WINDOWS,
    MAX_BRACKET_100NS, MAX_EXCURSIONS, RATE_TOLERANCE_PPM, RATE_WINDOW_100NS,
};

const TRUE_HZ: u64 = 2_800_000_000;
const NS_PER_SECOND: u64 = 1_000_000_000;
/// The reference latches a quarter of the way through its read, so the bracket midpoint is
/// wrong by a quarter of the read: the discipline has to hold with an honest placement error.
const REFERENCE_READ_NS: u64 = 10_000;
/// Half a reference read in 100 ns units, plus rounding.
const PLACEMENT_BOUND_100NS: u64 = REFERENCE_READ_NS / 200 + 10;

/// A counter and a reference clock driven by one simulated real time.
struct Machine {
    real_ns: u64,
    tsc: u64,
    tsc_hz: u64,
    cycle_remainder: u128,
}

impl Machine {
    fn new() -> Self {
        Self { real_ns: 0, tsc: 20_405_468_090, tsc_hz: TRUE_HZ, cycle_remainder: 0 }
    }

    fn advance(&mut self, ns: u64) {
        self.real_ns += ns;
        self.cycle_remainder += u128::from(ns) * u128::from(self.tsc_hz);
        self.tsc += (self.cycle_remainder / u128::from(NS_PER_SECOND)) as u64;
        self.cycle_remainder %= u128::from(NS_PER_SECOND);
    }

    fn reference_100ns(&self) -> u64 { 2_040_546_809 + self.real_ns / 100 }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Source { Fast, Reference }

/// The adapter's whole flow: one read, at most one bracketed reference sample, one publication.
struct Clock {
    machine: Machine,
    tsc: DisciplinedTsc,
    published: MonotonicTime,
    ordinal: u64,
    reference_reads: u64,
    held: u64,
    latest: u64,
    reference_read_ns: u64,
    /// Where in its read the reference latches, in 1/1024ths; `None` moves it on every read.
    latch_position: Option<u64>,
    latch_sequence: u64,
    stall_next_reference_ns: u64,
    glitch_next_reference_100ns: u64,
    last_observation: Option<TscObservation>,
}

struct Reading { time: u64, source: Source }

impl Clock {
    fn seeded(seed_hz: u64) -> Self {
        Self {
            machine: Machine::new(),
            tsc: DisciplinedTsc::admit(true, seed_hz).unwrap(),
            published: MonotonicTime::new(),
            ordinal: 0,
            reference_reads: 0,
            held: 0,
            latest: 0,
            reference_read_ns: REFERENCE_READ_NS,
            latch_position: Some(256),
            latch_sequence: 0x9e37_79b9_7f4a_7c15,
            stall_next_reference_ns: 0,
            glitch_next_reference_100ns: 0,
            last_observation: None,
        }
    }

    fn now(&mut self) -> Reading {
        let ordinal = self.ordinal;
        self.ordinal += 1;
        let tsc_before = self.machine.tsc;
        let (reading, source) = match self.tsc.read(tsc_before, ordinal) {
            TscRead::Fast(time) => (time, Source::Fast),
            TscRead::NeedsReference => {
                self.machine.advance(core::mem::take(&mut self.stall_next_reference_ns));
                let position = self.latch_position.unwrap_or_else(|| {
                    // Anywhere in the read, both ends included.
                    self.latch_sequence = self.latch_sequence
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (self.latch_sequence >> 33) % 1025
                });
                let latch_ns = self.reference_read_ns * position / 1024;
                self.machine.advance(latch_ns);
                let reference_100ns = self.machine.reference_100ns()
                    + core::mem::take(&mut self.glitch_next_reference_100ns);
                self.machine.advance(self.reference_read_ns - latch_ns);
                let sample = ReferenceSample {
                    tsc_before, reference_100ns, tsc_after: self.machine.tsc,
                };
                self.last_observation = Some(self.tsc.observe(sample, ordinal));
                self.reference_reads += 1;
                (reference_100ns, Source::Reference)
            }
        };
        let published = self.published.publish(reading);
        self.held += u64::from(published.held);
        Reading { time: published.time_100ns, source }
    }

    /// One reading checked against the simulated truth: never earlier than a reading already
    /// returned, and never further from the reference than `bound_100ns`.
    fn checked_now(&mut self, bound_100ns: u64) -> Reading {
        let before = self.machine.reference_100ns();
        let reading = self.now();
        let after = self.machine.reference_100ns();
        assert!(reading.time >= self.latest, "time stepped back: {} -> {}", self.latest, reading.time);
        assert!(
            reading.time + bound_100ns >= before && reading.time <= after + bound_100ns,
            "{:?} reading {} is not within {bound_100ns} of the reference [{before}, {after}]",
            reading.source, reading.time,
        );
        self.latest = reading.time;
        reading
    }

    /// Read every `step_ns` for `duration_ns`, checking every reading.
    fn run(&mut self, duration_ns: u64, step_ns: u64, bound_100ns: u64) {
        let end = self.machine.real_ns + duration_ns;
        while self.machine.real_ns < end {
            self.machine.advance(step_ns);
            self.checked_now(bound_100ns);
        }
    }

    fn run_until_disciplined(&mut self, step_ns: u64) -> u64 {
        let start = self.machine.real_ns;
        while self.tsc.phase() != TscPhase::Disciplined {
            assert!(self.machine.real_ns - start < 10 * NS_PER_SECOND, "never admitted");
            self.run(step_ns, step_ns, PLACEMENT_BOUND_100NS);
        }
        self.machine.real_ns - start
    }

    /// Read every `step_ns` until the fast path is withdrawn; returns how long that took.
    fn run_while_disciplined(&mut self, step_ns: u64, bound_100ns: u64) -> u64 {
        let start = self.machine.real_ns;
        while self.tsc.phase() == TscPhase::Disciplined {
            assert!(self.machine.real_ns - start < 10 * NS_PER_SECOND, "never withdrawn");
            self.run(step_ns, step_ns, bound_100ns);
        }
        self.machine.real_ns - start
    }

    fn disciplined() -> Self {
        let mut clock = Self::seeded(TRUE_HZ);
        clock.run_until_disciplined(50_000);
        clock
    }
}

fn ppm_apart(a: u64, b: u64) -> u64 {
    (u128::from(a.abs_diff(b)) * 1_000_000 / u128::from(b)) as u64
}

fn window_ns() -> u64 { RATE_WINDOW_100NS * 100 }

#[test]
fn admission_requires_invariant_capability_and_a_seed_frequency() {
    assert_eq!(DisciplinedTsc::admit(false, TRUE_HZ), Err(TscClockError::NotInvariant));
    assert_eq!(DisciplinedTsc::admit(true, 0), Err(TscClockError::Uncalibrated));
    let tsc = DisciplinedTsc::admit(true, TRUE_HZ).unwrap();
    assert_eq!(tsc.phase(), TscPhase::Measuring);
    assert_eq!(tsc.read(1_000, 0), TscRead::NeedsReference,
        "an unmeasured counter never serves a reading");
}

#[test]
fn the_fast_path_is_served_only_after_consecutive_clean_rate_windows() {
    let mut clock = Clock::seeded(TRUE_HZ);
    let mut fast = 0;
    let admitted_after = {
        let start = clock.machine.real_ns;
        while clock.tsc.phase() != TscPhase::Disciplined {
            assert!(clock.machine.real_ns - start < 10 * NS_PER_SECOND, "never admitted");
            clock.machine.advance(50_000);
            fast += u64::from(clock.now().source == Source::Fast);
        }
        clock.machine.real_ns - start
    };
    assert_eq!(fast, 0, "every reading before admission is a reference reading");
    let windows = u64::from(CLEAN_WINDOWS_TO_ADMIT);
    assert!(admitted_after >= windows * window_ns());
    assert!(admitted_after < (windows + 1) * window_ns());
    assert_eq!(clock.tsc.excursions(), 0);
    clock.machine.advance(50_000);
    assert_eq!(clock.now().source, Source::Fast);
}

#[test]
fn a_hundred_ppm_seed_error_stays_on_the_fast_path_with_bounded_error() {
    let seed = TRUE_HZ + TRUE_HZ / 10_000;
    let mut clock = Clock::seeded(seed);
    assert!(clock.run_until_disciplined(50_000) <= 3 * window_ns() + NS_PER_SECOND / 10);

    // Two minutes at 20,000 reads per second. Measured from one fixed epoch, a 100 ppm error
    // would be 12 ms by the end; here no reading is further from the reference than the
    // placement of one reference sample.
    let reference_reads = clock.reference_reads;
    let reads = clock.ordinal;
    clock.run(120 * NS_PER_SECOND, 50_000, PLACEMENT_BOUND_100NS);
    assert_eq!(clock.tsc.phase(), TscPhase::Disciplined);
    assert_eq!(clock.tsc.excursions(), 0);
    assert_eq!(clock.tsc.seed_frequency_hz(), seed);
    assert!(ppm_apart(clock.tsc.frequency_hz(), TRUE_HZ) <= 20,
        "the rate is measured against the reference: {}", clock.tsc.frequency_hz());
    assert!(clock.tsc.max_rate_error_ppm() <= 20, "{}", clock.tsc.max_rate_error_ppm());
    let reference_reads = clock.reference_reads - reference_reads;
    let reads = clock.ordinal - reads;
    assert!(reference_reads * 100 < reads, "{reference_reads} reference reads in {reads}");
    assert_eq!(clock.tsc.anchors(), reference_reads);
}

#[test]
fn a_seed_far_outside_the_tolerance_is_replaced_by_the_measured_rate() {
    // 1.6%: the largest error the first KVM boot with an invariant TSC could have had.
    let mut clock = Clock::seeded(TRUE_HZ + TRUE_HZ / 1_000 * 16);
    let admitted_after = clock.run_until_disciplined(50_000);
    assert!(admitted_after >= 3 * window_ns(), "the seed's window is not a clean window");
    assert_eq!(clock.tsc.excursions(), 0, "a wrong seed is not a counter fault");
    assert!(ppm_apart(clock.tsc.frequency_hz(), TRUE_HZ) <= 20);
    clock.run(10 * NS_PER_SECOND, 50_000, PLACEMENT_BOUND_100NS);
    assert_eq!(clock.tsc.phase(), TscPhase::Disciplined);
}

#[test]
fn reference_reads_per_second_are_bounded_while_disciplined() {
    let mut clock = Clock::disciplined();
    let per_interval = 10_000_000 / CHECK_INTERVAL_100NS;
    for (step_ns, reads_per_second) in [(50_000, 20_000), (5_000, 200_000), (2_000_000, 500)] {
        for _ in 0..3 {
            let before = clock.reference_reads;
            clock.run(NS_PER_SECOND, step_ns, PLACEMENT_BOUND_100NS);
            let reference_reads = clock.reference_reads - before;
            let bound = per_interval + reads_per_second / CHECK_READS + 2;
            assert!(reference_reads <= bound,
                "{reference_reads} reference reads in a second of {reads_per_second} reads");
        }
    }
    assert_eq!(clock.tsc.phase(), TscPhase::Disciplined);
}

#[test]
fn time_never_steps_back_when_the_fast_clock_was_ahead_at_a_reanchor() {
    let mut clock = Clock::disciplined();
    // The counter speeds up inside the tolerance, so a projection late in an interval is ahead
    // of the reference. A reference reading is behind it only if it follows within that error,
    // so the reference read is cheap here and a fast read lands just before every check.
    clock.machine.tsc_hz = TRUE_HZ + TRUE_HZ / 1_000_000 * 400;
    clock.reference_read_ns = 1_000;
    let anchors = clock.tsc.anchors();
    let ahead_bound = PLACEMENT_BOUND_100NS + CHECK_INTERVAL_100NS * 400 / 1_000_000 + 1;
    let mut since_read_ns = 0;
    for _ in 0..500_000 {
        clock.machine.advance(1_000);
        since_read_ns += 1_000;
        let a_microsecond_later = clock.machine.tsc + clock.machine.tsc_hz / 1_000_000;
        let check_is_near = [(clock.machine.tsc, 0), (a_microsecond_later, 1)].iter().any(
            |&(tsc, reads)| clock.tsc.read(tsc, clock.ordinal + reads) == TscRead::NeedsReference);
        if since_read_ns >= 50_000 || check_is_near {
            clock.checked_now(ahead_bound);
            since_read_ns = 0;
        }
    }
    assert!(clock.tsc.anchors() > anchors + 10);
    assert!(clock.held > 0, "an anchor behind a returned reading holds that reading");
    clock.reference_read_ns = REFERENCE_READ_NS;
    assert_eq!(clock.tsc.phase(), TscPhase::Disciplined);
    assert_eq!(clock.tsc.excursions(), 0);

    // The rate is re-measured, after which the projection is as close as a fresh anchor.
    clock.run(3 * NS_PER_SECOND, 50_000, ahead_bound);
    assert!(ppm_apart(clock.tsc.frequency_hz(), clock.machine.tsc_hz) <= 20);
    clock.run(NS_PER_SECOND, 50_000, PLACEMENT_BOUND_100NS);
}

#[test]
fn a_fast_clock_behind_the_reference_only_steps_forward_by_the_interval_error() {
    let mut clock = Clock::disciplined();
    clock.machine.tsc_hz = TRUE_HZ - TRUE_HZ / 1_000_000 * 400;
    let behind_bound = PLACEMENT_BOUND_100NS + CHECK_INTERVAL_100NS * 400 / 1_000_000 + 1;
    clock.run(NS_PER_SECOND / 2, 50_000, behind_bound);
    assert_eq!(clock.tsc.phase(), TscPhase::Disciplined);
    assert_eq!(clock.tsc.excursions(), 0);
    assert!(clock.tsc.max_offset_100ns() <= behind_bound);
}

#[test]
fn a_delayed_reference_read_is_uncertain_and_not_a_rate_error() {
    let mut clock = Clock::disciplined();
    let anchors = clock.tsc.anchors();
    // The reader is descheduled for 5 ms between its counter reading and the reference latch.
    clock.machine.advance(CHECK_INTERVAL_100NS * 100 + 1_000);
    clock.stall_next_reference_ns = 5_000_000;
    let stalled = clock.now();
    assert_eq!(stalled.source, Source::Reference);
    assert_eq!(clock.last_observation, Some(TscObservation::Uncertain));
    let after_latch_100ns = (REFERENCE_READ_NS - REFERENCE_READ_NS / 4) / 100;
    assert_eq!(stalled.time, clock.machine.reference_100ns() - after_latch_100ns,
        "the delayed reading is still a real reference reading");
    assert_eq!(clock.tsc.phase(), TscPhase::Disciplined);
    assert_eq!((clock.tsc.excursions(), clock.tsc.uncertain_samples()), (0, 1));
    assert_eq!(clock.tsc.anchors(), anchors);

    // The unplaced sample is not an anchor, so the next read checks again.
    clock.machine.advance(50_000);
    assert_eq!(clock.now().source, Source::Reference);
    assert!(matches!(clock.last_observation, Some(TscObservation::Anchored { .. })));
    clock.run(NS_PER_SECOND, 50_000, PLACEMENT_BOUND_100NS);
    assert_eq!(clock.tsc.excursions(), 0);
}

#[test]
fn a_counter_jump_is_refused_before_publication_and_recovers_after_clean_windows() {
    let mut clock = Clock::disciplined();
    clock.machine.advance(50_000);
    clock.machine.tsc += TRUE_HZ / 20; // 50 ms of cycles appear at once
    let reading = clock.now();
    assert_eq!(reading.source, Source::Reference);
    assert!(matches!(clock.last_observation, Some(TscObservation::Excursion { .. })));
    assert!(reading.time <= clock.machine.reference_100ns(), "the jump was never published");
    assert_eq!(clock.tsc.phase(), TscPhase::Measuring);
    assert_eq!(clock.tsc.excursions(), 1);

    let reference_reads = clock.reference_reads;
    let reads = clock.ordinal;
    let recovered_after = clock.run_until_disciplined(50_000);
    assert_eq!(clock.reference_reads - reference_reads, clock.ordinal - reads,
        "the reference serves every reading until the counter is re-admitted");
    let windows = u64::from(CLEAN_WINDOWS_TO_ADMIT);
    assert!(recovered_after >= windows * window_ns());
    assert!(recovered_after < (windows + 1) * window_ns());
    clock.run(5 * NS_PER_SECOND, 50_000, PLACEMENT_BOUND_100NS);
    assert_eq!((clock.tsc.phase(), clock.tsc.excursions()), (TscPhase::Disciplined, 1));
}

#[test]
fn a_jump_inside_the_check_interval_is_caught_at_the_next_check_without_a_step_back() {
    let mut clock = Clock::disciplined();
    // Stop on the first fast reading after an anchor, so most of an interval is unchecked.
    let anchors = clock.tsc.anchors();
    while clock.tsc.anchors() == anchors {
        clock.run(50_000, 50_000, PLACEMENT_BOUND_100NS);
    }
    clock.machine.advance(50_000);
    assert_eq!(clock.now().source, Source::Fast);
    let jump_100ns = CHECK_INTERVAL_100NS / 5;
    clock.machine.tsc += TRUE_HZ / 10_000_000 * jump_100ns;
    // Readings run ahead by the jump for the rest of this interval, never by more.
    let withdrawn_after = clock.run_while_disciplined(50_000, jump_100ns + PLACEMENT_BOUND_100NS);
    assert!(withdrawn_after <= CHECK_INTERVAL_100NS * 100);
    assert_eq!(clock.tsc.excursions(), 1);
    assert!(clock.published.latest() > clock.machine.reference_100ns());
    // The reference then serves; the reading already returned is held until it catches up.
    let held = clock.held;
    clock.run(NS_PER_SECOND / 100, 50_000, jump_100ns + PLACEMENT_BOUND_100NS);
    assert!(clock.held > held);
    clock.run(NS_PER_SECOND / 100, 50_000, 0);
}

#[test]
fn a_rate_beyond_the_tolerance_falls_back_and_is_readmitted_at_the_measured_rate() {
    let mut clock = Clock::disciplined();
    let wrong_ppm = RATE_TOLERANCE_PPM * 4;
    clock.machine.tsc_hz = TRUE_HZ + TRUE_HZ / 1_000_000 * wrong_ppm;
    let wrong_bound = PLACEMENT_BOUND_100NS + CHECK_INTERVAL_100NS * wrong_ppm / 1_000_000 + 1;
    let withdrawn_after = clock.run_while_disciplined(50_000, wrong_bound);
    assert!(withdrawn_after <= 2 * CHECK_INTERVAL_100NS * 100,
        "a wrong rate is withdrawn at the first check that can see it");
    assert_eq!(clock.tsc.excursions(), 1);

    clock.run_until_disciplined(50_000);
    assert!(ppm_apart(clock.tsc.frequency_hz(), clock.machine.tsc_hz) <= 20);
    assert!(clock.tsc.max_rate_error_ppm() >= wrong_ppm - 20);
    clock.run(5 * NS_PER_SECOND, 50_000, PLACEMENT_BOUND_100NS);
    assert_eq!((clock.tsc.phase(), clock.tsc.excursions()), (TscPhase::Disciplined, 1));
}

#[test]
fn a_stalled_counter_is_checked_within_the_read_budget() {
    let mut clock = Clock::disciplined();
    clock.machine.tsc_hz = 0;
    let reads = clock.ordinal;
    while clock.tsc.phase() == TscPhase::Disciplined {
        assert!(clock.ordinal - reads <= CHECK_READS, "a stalled counter was never checked");
        clock.machine.advance(50_000);
        // Held readings fall behind by the whole stall, but never step back.
        clock.checked_now(CHECK_READS * 500);
    }
    assert!(clock.ordinal - reads <= CHECK_READS + 1);
    assert_eq!(clock.tsc.excursions(), 1);
    // A counter that does not count is never re-admitted.
    clock.run(5 * NS_PER_SECOND, 2_000_000, 0);
    assert_eq!(clock.tsc.phase(), TscPhase::Measuring);
}

#[test]
fn excursions_without_a_sustained_clean_run_fail_the_counter_for_the_boot() {
    let mut clock = Clock::disciplined();
    for excursion in 1..=MAX_EXCURSIONS + 1 {
        clock.machine.advance(2_000_000);
        clock.machine.tsc += TRUE_HZ / 20;
        clock.now();
        assert_eq!(clock.tsc.excursions(), u64::from(excursion));
        if excursion <= MAX_EXCURSIONS {
            clock.run_until_disciplined(2_000_000);
        }
    }
    assert_eq!(clock.tsc.phase(), TscPhase::Failed(TscClockError::Unstable));
    assert_eq!(clock.last_observation, Some(TscObservation::Failed(TscClockError::Unstable)));
    clock.run(5 * NS_PER_SECOND, 2_000_000, 0);
    assert_eq!(clock.tsc.phase(), TscPhase::Failed(TscClockError::Unstable));
    assert_eq!(clock.tsc.read(clock.machine.tsc, clock.ordinal), TscRead::NeedsReference);
}

#[test]
fn a_sustained_clean_run_forgives_earlier_excursions() {
    let mut clock = Clock::disciplined();
    for _ in 0..2 * MAX_EXCURSIONS {
        clock.machine.advance(2_000_000);
        clock.machine.tsc += TRUE_HZ / 20;
        clock.now();
        clock.run_until_disciplined(2_000_000);
        clock.run(u64::from(FORGIVENESS_WINDOWS + 1) * window_ns(), 2_000_000,
            PLACEMENT_BOUND_100NS);
    }
    assert_eq!(clock.tsc.phase(), TscPhase::Disciplined);
    assert_eq!(clock.tsc.excursions(), u64::from(2 * MAX_EXCURSIONS));
}

#[test]
fn a_counter_that_goes_backwards_fails_for_the_boot() {
    let clock = Clock::disciplined();
    let tsc = clock.machine.tsc;
    let reference = clock.machine.reference_100ns();
    let sample = |tsc_before, reference_100ns, tsc_after| {
        ReferenceSample { tsc_before, reference_100ns, tsc_after }
    };

    let mut inside_bracket = clock.tsc;
    assert_eq!(inside_bracket.observe(sample(tsc + 10, reference + 1, tsc + 9), clock.ordinal),
        TscObservation::Failed(TscClockError::CounterRegressed));
    assert_eq!(inside_bracket.phase(), TscPhase::Failed(TscClockError::CounterRegressed));

    let mut behind_anchor = clock.tsc;
    let before = tsc - TRUE_HZ;
    assert_eq!(behind_anchor.observe(sample(before, reference + 1, before + 10), clock.ordinal),
        TscObservation::Failed(TscClockError::CounterRegressed));

    assert_eq!(behind_anchor.observe(sample(tsc + 10, reference + 2, tsc + 20), clock.ordinal),
        TscObservation::Failed(TscClockError::CounterRegressed), "a failure is final");
    assert_eq!(behind_anchor.read(tsc + 30, clock.ordinal + 1), TscRead::NeedsReference);
}

#[test]
fn a_reference_glitch_is_an_excursion_and_not_the_end_of_the_counter() {
    // One reference reading 42.9 s ahead: a 64-bit HPET counter read split into two 32-bit
    // reads around a carry. The counter is not at fault, and the reference then appears to go
    // backwards from the anchor the glitch left behind.
    let mut clock = Clock::disciplined();
    clock.machine.advance(CHECK_INTERVAL_100NS * 100 + 1_000);
    clock.glitch_next_reference_100ns = 429_496_729;
    clock.now();
    assert!(matches!(clock.last_observation, Some(TscObservation::Excursion { .. })));
    clock.machine.advance(50_000);
    clock.now();
    assert!(matches!(clock.last_observation, Some(TscObservation::Excursion { .. })),
        "{:?}", clock.last_observation);
    assert_eq!((clock.tsc.phase(), clock.tsc.excursions()), (TscPhase::Measuring, 2));

    let windows = u64::from(CLEAN_WINDOWS_TO_ADMIT);
    let mut recovered_after = 0;
    while clock.tsc.phase() != TscPhase::Disciplined {
        assert!(recovered_after < 10 * NS_PER_SECOND, "never re-admitted");
        clock.machine.advance(50_000);
        clock.now();
        recovered_after += 50_000;
    }
    assert!(recovered_after < (windows + 1) * window_ns());
    assert_eq!(clock.tsc.excursions(), 2);
}

#[test]
fn a_counter_that_stalls_while_being_measured_is_readmitted_once_it_counts_again() {
    let mut clock = Clock::disciplined();
    clock.machine.tsc_hz = 0;
    clock.run_while_disciplined(50_000, CHECK_READS * 500);
    // The stall ends late in a rate window, which then measures a small fraction of the rate.
    clock.run(297 * NS_PER_SECOND / 100, 50_000, 0);
    clock.machine.tsc_hz = TRUE_HZ;
    let uncertain = clock.tsc.uncertain_samples();
    clock.run(NS_PER_SECOND / 10, 50_000, 0);
    assert!(clock.tsc.frequency_hz() < TRUE_HZ / 20,
        "the scenario must measure a window that spans the end of the stall");

    clock.run(4 * NS_PER_SECOND, 50_000, PLACEMENT_BOUND_100NS);
    assert_eq!(clock.tsc.uncertain_samples(), uncertain,
        "a wrong rate estimate must not make honest reference reads look delayed");
    assert_eq!(clock.tsc.phase(), TscPhase::Disciplined);
    assert!(ppm_apart(clock.tsc.frequency_hz(), TRUE_HZ) <= 20);
}

#[test]
fn a_reference_latch_anywhere_in_its_read_is_never_a_rate_error() {
    // Fast readers force checks every 1,024 reads, where almost nothing but the placement
    // uncertainty of the two samples is allowed; slow readers check every interval.
    let mut clock = Clock::seeded(TRUE_HZ + TRUE_HZ / 1_000_000 * 300);
    clock.latch_position = None;
    clock.run_until_disciplined(50_000);
    let bound = REFERENCE_READ_NS / 100 + 10;
    for step_ns in [50_000, 500, 3_000_000, 50_000] {
        clock.run(3 * NS_PER_SECOND, step_ns, bound);
    }
    assert!(clock.tsc.anchors() > 5_000, "{}", clock.tsc.anchors());
    assert_eq!((clock.tsc.phase(), clock.tsc.excursions()), (TscPhase::Disciplined, 0));
}

#[test]
fn the_first_read_after_a_long_idle_is_a_reference_reading_and_not_an_excursion() {
    let mut clock = Clock::disciplined();
    // The counter is 300 ppm from the estimate and nobody reads the clock for a minute: the
    // projection is 18 ms off by then, which is this counter's rate and not a discontinuity.
    clock.machine.tsc_hz = TRUE_HZ + TRUE_HZ / 1_000_000 * 300;
    clock.machine.advance(60 * NS_PER_SECOND);
    let reading = clock.checked_now(0);
    assert_eq!(reading.source, Source::Reference);
    assert!(matches!(clock.last_observation, Some(TscObservation::Anchored { .. })));
    assert_eq!(clock.tsc.excursions(), 0);
    clock.run(NS_PER_SECOND, 50_000, PLACEMENT_BOUND_100NS + 31);
}

#[test]
fn a_bracket_is_uncertain_exactly_past_the_bound() {
    let mut clock = Clock::disciplined();
    clock.machine.advance(CHECK_INTERVAL_100NS * 100 + 1_000);
    clock.stall_next_reference_ns = MAX_BRACKET_100NS * 100 - REFERENCE_READ_NS;
    clock.now();
    assert!(matches!(clock.last_observation, Some(TscObservation::Anchored { .. })));
    clock.machine.advance(CHECK_INTERVAL_100NS * 100 + 1_000);
    clock.stall_next_reference_ns = MAX_BRACKET_100NS * 100 - REFERENCE_READ_NS + 100;
    clock.now();
    assert_eq!(clock.last_observation, Some(TscObservation::Uncertain));
}

#[test]
fn publication_returns_the_latest_time_when_a_reading_is_behind_it() {
    let time = MonotonicTime::new();
    let first = time.publish(1_000);
    assert_eq!((first.time_100ns, first.held), (1_000, false));
    let behind = time.publish(990);
    assert_eq!((behind.time_100ns, behind.held), (1_000, true));
    let same = time.publish(1_000);
    assert_eq!((same.time_100ns, same.held), (1_000, false));
    let later = time.publish(1_001);
    assert_eq!((later.time_100ns, later.held), (1_001, false));
    assert_eq!(time.latest(), 1_001);
}
