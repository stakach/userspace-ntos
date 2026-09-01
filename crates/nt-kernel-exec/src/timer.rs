//! Timer objects + a deterministic clock (spec §6.4, §10). A `KTIMER` is opaque
//! driver storage; the runtime keeps its metadata keyed by the driver's pointer.
//! A due timer sets its signaled state and queues its associated DPC. All units
//! at the API boundary are Windows 100ns intervals.

use alloc::vec::Vec;
use nt_time::{AdjustableClock, Deadline, TimeSnapshot};

/// Input frequency of the PC-compatible 8254 timer.
pub const PIT_INPUT_HZ: u64 = 1_193_182;
const HUNDRED_NS_PER_SECOND: u64 = 10_000_000;
const PIT_MAX_TICKS: u64 = 65_536;

/// One bounded channel-0 one-shot. A zero reload is the 8254 encoding of 65,536 ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PitOneShot {
    pub reload: u16,
    pub ticks: u32,
    pub wake_deadline_100ns: u64,
    pub chunked: bool,
}

/// Convert an NT monotonic deadline into one PC timer channel-0 one-shot.
///
/// The PIT cannot represent more than 65,536 input clocks. Longer waits are deliberately split into
/// bounded chunks; the interrupt owner re-evaluates the authoritative wait queue after every chunk.
/// Both conversions round upward so neither timer granularity nor integer truncation can wake a
/// waiter before its requested deadline.
pub fn pit_oneshot_for_deadline(
    now_100ns: u64,
    deadline_100ns: u64,
    minimum_delay_100ns: u64,
) -> PitOneShot {
    let requested = deadline_100ns
        .saturating_sub(now_100ns)
        .max(minimum_delay_100ns)
        .max(1);
    let ticks = div_ceil_u128(
        requested as u128 * PIT_INPUT_HZ as u128,
        HUNDRED_NS_PER_SECOND as u128,
    )
    .clamp(1, PIT_MAX_TICKS as u128) as u64;
    let represented_100ns = div_ceil_u128(
        ticks as u128 * HUNDRED_NS_PER_SECOND as u128,
        PIT_INPUT_HZ as u128,
    ) as u64;
    let wake_deadline_100ns = now_100ns.saturating_add(represented_100ns);
    PitOneShot {
        reload: if ticks == PIT_MAX_TICKS {
            0
        } else {
            ticks as u16
        },
        ticks: ticks as u32,
        wake_deadline_100ns,
        chunked: wake_deadline_100ns < deadline_100ns,
    }
}

fn div_ceil_u128(numerator: u128, denominator: u128) -> u128 {
    numerator / denominator + u128::from(numerator % denominator != 0)
}

/// A monotonic + system time source (spec §10). Host tests use [`FakeClock`].
pub trait Clock {
    fn snapshot(&self) -> TimeSnapshot;
}

/// Expand Win32 generic access bits into the timer object's native access mask.
pub fn map_timer_access(mut access: u32) -> u32 {
    const TIMER_QUERY_STATE: u32 = 0x0001;
    const TIMER_MODIFY_STATE: u32 = 0x0002;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const TIMER_ALL_ACCESS: u32 = 0x001F_0003;

    if access & 0x8000_0000 != 0 {
        access |= 0x0002_0000 | TIMER_QUERY_STATE;
    }
    if access & 0x4000_0000 != 0 {
        access |= 0x0002_0000 | TIMER_MODIFY_STATE;
    }
    if access & 0x2000_0000 != 0 {
        access |= 0x0002_0000 | SYNCHRONIZE;
    }
    if access & (0x1000_0000 | 0x0200_0000) != 0 {
        access |= TIMER_ALL_ACCESS;
    }
    access & !(0xF000_0000 | 0x0200_0000)
}

/// A deterministic fake clock for tests (spec §10.3).
#[derive(Debug)]
pub struct FakeClock {
    mono: u64,
    system: AdjustableClock,
}

impl FakeClock {
    pub fn new() -> Self {
        Self {
            mono: 0,
            system: AdjustableClock::new(0, 0),
        }
    }
    /// Advance monotonic + system time by `d` 100ns units.
    pub fn advance_100ns(&mut self, d: u64) {
        self.mono = self.mono.saturating_add(d);
    }
    /// Advance by `ms` milliseconds.
    pub fn advance_ms(&mut self, ms: u64) {
        self.advance_100ns(ms * 10_000);
    }
    pub fn set_system_time(&mut self, t: u64) {
        self.system.set_system_time(self.mono, t).unwrap();
    }
}

impl Clock for FakeClock {
    fn snapshot(&self) -> TimeSnapshot {
        self.system.snapshot(self.mono)
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

struct Timer {
    ptr: u64,
    deadline: Deadline,
    period_100ns: u64,
    dpc_ptr: Option<u64>,
    active: bool,
    signaled: bool,
    generation: u64,
}

/// A timer that became signaled during a queue drain.
///
/// The runtime needs the timer identity even when no DPC is attached so it can
/// publish the dispatcher-header signal state and wake object waiters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerExpiry {
    pub timer_ptr: u64,
    pub dpc_ptr: Option<u64>,
}

/// The Driver Host's timer queue (spec §6.4).
#[derive(Default)]
pub struct TimerQueue {
    timers: Vec<Timer>,
    next_gen: u64,
}

impl TimerQueue {
    pub fn new() -> Self {
        Self {
            timers: Vec::new(),
            next_gen: 0,
        }
    }

    fn slot(&mut self, ptr: u64) -> &mut Timer {
        if let Some(i) = self.timers.iter().position(|t| t.ptr == ptr) {
            return &mut self.timers[i];
        }
        self.timers.push(Timer {
            ptr,
            deadline: Deadline::Infinite,
            period_100ns: 0,
            dpc_ptr: None,
            active: false,
            signaled: false,
            generation: 0,
        });
        self.timers.last_mut().unwrap()
    }

    /// `KeInitializeTimer` / `KeInitializeTimerEx`.
    pub fn initialize(&mut self, ptr: u64) {
        let t = self.slot(ptr);
        t.active = false;
        t.signaled = false;
        t.dpc_ptr = None;
        t.period_100ns = 0;
    }

    /// `KeSetTimer` / `KeSetTimerEx`. `due_time` is a 100ns `LARGE_INTEGER`:
    /// negative = relative to now, non-negative = absolute system time.
    /// `period_ms` = 0 for one-shot. Associates `dpc_ptr` if given. Returns whether
    /// the timer was already active (like `KeSetTimer`). Resetting bumps the
    /// generation, invalidating any prior due time (spec §6.4).
    pub fn set(
        &mut self,
        ptr: u64,
        due_time: i64,
        period_ms: u32,
        dpc_ptr: Option<u64>,
        clock: &dyn Clock,
    ) -> bool {
        let now = clock.snapshot();
        let deadline = Deadline::from_nt_timeout(Some(due_time), now);
        let gen = self.next_gen;
        self.next_gen += 1;
        let was_active = self.slot(ptr).active;
        let t = self.slot(ptr);
        t.deadline = deadline;
        t.period_100ns = period_ms as u64 * 10_000;
        t.dpc_ptr = dpc_ptr;
        t.active = true;
        t.signaled = false;
        t.generation = gen;
        was_active
    }

    /// `KeCancelTimer` — returns whether the timer was active.
    pub fn cancel(&mut self, ptr: u64) -> bool {
        match self.timers.iter_mut().find(|t| t.ptr == ptr) {
            Some(t) if t.active => {
                t.active = false;
                true
            }
            _ => false,
        }
    }

    /// `KeReadStateTimer` — the signaled state.
    pub fn read_state(&self, ptr: u64) -> bool {
        self.timers.iter().any(|t| t.ptr == ptr && t.signaled)
    }

    pub fn is_active(&self, ptr: u64) -> bool {
        self.timers.iter().any(|t| t.ptr == ptr && t.active)
    }

    pub fn active_count(&self) -> usize {
        self.timers.iter().filter(|t| t.active).count()
    }

    pub fn capacity(&self) -> usize {
        self.timers.capacity()
    }

    /// Earliest active comparator target at the clock's current snapshot.
    pub fn next_deadline(&self, clock: &dyn Clock) -> Option<u64> {
        self.next_deadline_at(clock.snapshot())
    }

    pub fn next_deadline_at(&self, now: TimeSnapshot) -> Option<u64> {
        self.timers
            .iter()
            .filter(|timer| timer.active)
            .filter_map(|timer| timer.deadline.monotonic_target(now))
            .min()
    }

    /// Discard all timer identities owned by this queue.
    pub fn clear(&mut self) {
        self.timers.clear();
        self.next_gen = 0;
    }

    /// The timer's current generation (bumped on every `set`; a stale expiry
    /// captured against an older generation must be ignored, spec §6.4).
    pub fn generation(&self, ptr: u64) -> Option<u64> {
        self.timers
            .iter()
            .find(|t| t.ptr == ptr)
            .map(|t| t.generation)
    }

    /// Expire all due timers: set their signaled state, reschedule periodic
    /// ones, and return both the timer and optional `KDPC` identities.
    pub fn run_due_expirations(&mut self, clock: &dyn Clock) -> Vec<TimerExpiry> {
        self.run_due_expirations_at(clock.snapshot())
    }

    /// Expire all timers due at the caller's authoritative monotonic time.
    ///
    /// Interrupt controllers may deliver an edge at a deadline that rounds one
    /// clock quantum ahead of a subsequent counter read. The interrupt owner
    /// must be able to preserve that deadline rather than miss the expiry and
    /// wait for an unrelated later interrupt.
    pub fn run_due_expirations_at(&mut self, now: TimeSnapshot) -> Vec<TimerExpiry> {
        let mut fired = Vec::new();
        for t in self.timers.iter_mut() {
            if t.active && t.deadline.is_due(now) {
                t.signaled = true;
                fired.push(TimerExpiry {
                    timer_ptr: t.ptr,
                    dpc_ptr: t.dpc_ptr,
                });
                if t.period_100ns > 0 {
                    t.deadline = Deadline::Relative {
                        monotonic_100ns: now.monotonic_100ns.saturating_add(t.period_100ns),
                    };
                } else {
                    t.active = false;
                }
            }
        }
        fired
    }

    /// Compatibility helper for runtimes that only consume queued DPCs.
    pub fn run_due(&mut self, clock: &dyn Clock) -> Vec<u64> {
        self.run_due_expirations(clock)
            .into_iter()
            .filter_map(|expiry| expiry.dpc_ptr)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec;

    #[test]
    fn pit_one_shot_rounds_up_and_honours_the_service_guard() {
        let one_tick = pit_oneshot_for_deadline(1_000, 1_001, 0);
        assert_eq!(one_tick.reload, 1);
        assert_eq!(one_tick.ticks, 1);
        assert!(one_tick.wake_deadline_100ns >= 1_001);
        assert!(!one_tick.chunked);

        let guarded = pit_oneshot_for_deadline(10_000, 10_001, 20_000);
        assert!(guarded.wake_deadline_100ns >= 30_000);
        assert!(!guarded.chunked);
    }

    #[test]
    fn pit_one_shot_chunks_unrepresentable_deadlines() {
        let shot = pit_oneshot_for_deadline(50, 10_000_000, 0);
        assert_eq!(shot.reload, 0);
        assert_eq!(shot.ticks, 65_536);
        assert!(shot.chunked);
        assert!(shot.wake_deadline_100ns > 50);
        assert!(shot.wake_deadline_100ns < 10_000_000);

        let next = pit_oneshot_for_deadline(shot.wake_deadline_100ns, 10_000_000, 0);
        assert_eq!(next.reload, 0);
        assert!(next.wake_deadline_100ns > shot.wake_deadline_100ns);
    }

    #[test]
    fn relative_timer_fires_and_queues_dpc() {
        let mut clk = FakeClock::new();
        let mut tq = TimerQueue::new();
        tq.initialize(0x700);
        // -1_000_000 * 100ns = 100 ms relative.
        assert!(!tq.set(0x700, -1_000_000, 0, Some(0xD1), &clk));
        assert!(tq.is_active(0x700));

        clk.advance_ms(50);
        assert_eq!(tq.run_due(&clk), vec![]); // not due yet
        clk.advance_ms(60);
        assert_eq!(tq.run_due(&clk), vec![0xD1]); // fired, queues DPC
        assert!(tq.read_state(0x700)); // signaled
        assert!(!tq.is_active(0x700)); // one-shot done
        assert_eq!(tq.run_due(&clk), vec![]); // no double fire
    }

    #[test]
    fn absolute_timer_via_system_time() {
        let mut clk = FakeClock::new();
        clk.set_system_time(1_000);
        let mut tq = TimerQueue::new();
        tq.set(0x700, 5_000, 0, None, &clk); // absolute: 4000 ticks ahead
        clk.advance_100ns(3_999);
        assert!(tq.run_due(&clk).is_empty());
        clk.advance_100ns(2);
        tq.run_due(&clk);
        assert!(tq.read_state(0x700));
    }

    #[test]
    fn reset_invalidates_old_due() {
        let mut clk = FakeClock::new();
        let mut tq = TimerQueue::new();
        tq.set(0x700, -1_000, 0, Some(0xD1), &clk); // due at 1000
        let g0 = tq.generation(0x700).unwrap();
        clk.advance_100ns(500);
        // Reset to a later time before the first fired.
        assert!(tq.set(0x700, -2_000, 0, Some(0xD1), &clk)); // was active; due at 2500
        assert!(tq.generation(0x700).unwrap() > g0);
        clk.advance_100ns(1_000); // now 1500 — old due 1000 passed, new due 2500 not
        assert!(tq.run_due(&clk).is_empty());
        clk.advance_100ns(1_100); // now 2600
        assert_eq!(tq.run_due(&clk), vec![0xD1]);
    }

    #[test]
    fn periodic_timer_requeues() {
        let mut clk = FakeClock::new();
        let mut tq = TimerQueue::new();
        tq.set(0x700, -100, 1, Some(0xD1), &clk); // due ~100, period 1ms = 10000
        clk.advance_100ns(100);
        assert_eq!(tq.run_due(&clk), vec![0xD1]);
        assert!(tq.is_active(0x700)); // still active (periodic)
        clk.advance_100ns(10_000);
        assert_eq!(tq.run_due(&clk), vec![0xD1]); // fires again
    }

    #[test]
    fn cancel_stops_a_timer() {
        let mut clk = FakeClock::new();
        let mut tq = TimerQueue::new();
        tq.set(0x700, -1_000, 0, Some(0xD1), &clk);
        assert!(tq.cancel(0x700)); // was active
        assert!(!tq.cancel(0x700)); // no longer active
        clk.advance_100ns(2_000);
        assert!(tq.run_due(&clk).is_empty()); // cancelled → no fire
    }

    #[test]
    fn expiration_reports_timer_without_dpc_and_tracks_next_deadline() {
        let mut clk = FakeClock::new();
        let mut tq = TimerQueue::new();
        tq.set(0x700, -1_000, 0, None, &clk);
        tq.set(0x800, -2_000, 0, Some(0xD2), &clk);
        assert_eq!(tq.next_deadline(&clk), Some(1_000));

        clk.advance_100ns(1_000);
        assert_eq!(
            tq.run_due_expirations(&clk),
            vec![TimerExpiry {
                timer_ptr: 0x700,
                dpc_ptr: None,
            }]
        );
        assert_eq!(tq.next_deadline(&clk), Some(2_000));

        tq.clear();
        assert_eq!(tq.next_deadline(&clk), None);
        assert_eq!(tq.active_count(), 0);
    }

    #[test]
    fn authoritative_interrupt_time_expires_at_the_armed_boundary() {
        let clk = FakeClock::new();
        let mut tq = TimerQueue::new();
        tq.set(0x700, -1_000, 0, Some(0xD1), &clk);

        // The sampled clock is still one quantum behind, but the interrupt
        // owner knows that the armed deadline produced this delivery.
        assert!(tq.run_due_expirations(&clk).is_empty());
        let now = TimeSnapshot {
            monotonic_100ns: 1_000,
            system_time_100ns: 1_000,
            clock_generation: 0,
        };
        assert_eq!(
            tq.run_due_expirations_at(now),
            vec![TimerExpiry {
                timer_ptr: 0x700,
                dpc_ptr: Some(0xD1),
            }]
        );
        assert!(tq.run_due_expirations_at(now).is_empty());
    }

    #[test]
    fn absolute_timer_follows_forward_and_backward_system_clock_changes() {
        let mut clk = FakeClock::new();
        clk.set_system_time(1_000);
        let mut tq = TimerQueue::new();
        tq.set(0x700, 5_000, 0, None, &clk);
        assert_eq!(tq.next_deadline(&clk), Some(4_000));

        clk.advance_100ns(1_000);
        clk.set_system_time(6_000);
        assert_eq!(tq.next_deadline(&clk), Some(1_000));
        assert_eq!(tq.run_due_expirations(&clk).len(), 1);

        tq.set(0x800, 8_000, 0, None, &clk);
        assert_eq!(tq.next_deadline(&clk), Some(3_000));
        clk.set_system_time(2_000);
        assert_eq!(tq.next_deadline(&clk), Some(7_000));
        clk.advance_100ns(5_999);
        assert!(tq.run_due_expirations(&clk).is_empty());
        clk.advance_100ns(1);
        assert_eq!(tq.run_due_expirations(&clk).len(), 1);
    }

    #[test]
    fn relative_and_periodic_deadlines_ignore_later_system_clock_changes() {
        let mut clk = FakeClock::new();
        clk.set_system_time(10_000);
        let mut tq = TimerQueue::new();
        tq.set(0x700, -1_000, 1, None, &clk);

        clk.set_system_time(100);
        assert_eq!(tq.next_deadline(&clk), Some(1_000));
        clk.advance_100ns(1_000);
        assert_eq!(tq.run_due_expirations(&clk).len(), 1);
        assert_eq!(tq.next_deadline(&clk), Some(11_000));

        clk.set_system_time(50_000);
        clk.advance_100ns(9_999);
        assert!(tq.run_due_expirations(&clk).is_empty());
        clk.advance_100ns(1);
        assert_eq!(tq.run_due_expirations(&clk).len(), 1);
    }

    #[test]
    fn timer_generic_access_maps_to_native_rights() {
        assert_eq!(map_timer_access(0x8000_0000), 0x0002_0001);
        assert_eq!(map_timer_access(0x4000_0000), 0x0002_0002);
        assert_eq!(map_timer_access(0x2000_0000), 0x0012_0000);
        assert_eq!(map_timer_access(0x1000_0000), 0x001F_0003);
    }
}
