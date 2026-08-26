//! Timer objects + a deterministic clock (spec §6.4, §10). A `KTIMER` is opaque
//! driver storage; the runtime keeps its metadata keyed by the driver's pointer.
//! A due timer sets its signaled state and queues its associated DPC. All units
//! at the API boundary are Windows 100ns intervals.

use alloc::vec::Vec;

/// A monotonic + system time source (spec §10). Host tests use [`FakeClock`].
pub trait Clock {
    /// Monotonic time in 100ns units (for relative timers).
    fn now_100ns(&self) -> u64;
    /// System time in 100ns units (for absolute timers).
    fn system_time_100ns(&self) -> i64;
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
#[derive(Debug, Default)]
pub struct FakeClock {
    mono: u64,
    system: i64,
}

impl FakeClock {
    pub fn new() -> Self {
        Self { mono: 0, system: 0 }
    }
    /// Advance monotonic + system time by `d` 100ns units.
    pub fn advance_100ns(&mut self, d: u64) {
        self.mono += d;
        self.system += d as i64;
    }
    /// Advance by `ms` milliseconds.
    pub fn advance_ms(&mut self, ms: u64) {
        self.advance_100ns(ms * 10_000);
    }
    pub fn set_system_time(&mut self, t: i64) {
        self.system = t;
    }
}

impl Clock for FakeClock {
    fn now_100ns(&self) -> u64 {
        self.mono
    }
    fn system_time_100ns(&self) -> i64 {
        self.system
    }
}

struct Timer {
    ptr: u64,
    due_mono: u64,
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
            due_mono: 0,
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
        let now = clock.now_100ns();
        let due_mono = if due_time < 0 {
            now + (due_time.unsigned_abs())
        } else {
            // Absolute system time → monotonic offset (facade; drift not modelled).
            let ahead = (due_time - clock.system_time_100ns()).max(0) as u64;
            now + ahead
        };
        let gen = self.next_gen;
        self.next_gen += 1;
        let was_active = self.slot(ptr).active;
        let t = self.slot(ptr);
        t.due_mono = due_mono;
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

    /// Earliest active monotonic deadline, in 100ns units.
    pub fn next_deadline(&self) -> Option<u64> {
        self.timers
            .iter()
            .filter(|timer| timer.active)
            .map(|timer| timer.due_mono)
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
        self.run_due_expirations_at(clock.now_100ns())
    }

    /// Expire all timers due at the caller's authoritative monotonic time.
    ///
    /// Interrupt controllers may deliver an edge at a deadline that rounds one
    /// clock quantum ahead of a subsequent counter read. The interrupt owner
    /// must be able to preserve that deadline rather than miss the expiry and
    /// wait for an unrelated later interrupt.
    pub fn run_due_expirations_at(&mut self, now_100ns: u64) -> Vec<TimerExpiry> {
        let mut fired = Vec::new();
        for t in self.timers.iter_mut() {
            if t.active && t.due_mono <= now_100ns {
                t.signaled = true;
                fired.push(TimerExpiry {
                    timer_ptr: t.ptr,
                    dpc_ptr: t.dpc_ptr,
                });
                if t.period_100ns > 0 {
                    t.due_mono = now_100ns + t.period_100ns; // periodic: reschedule
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
        assert_eq!(tq.next_deadline(), Some(1_000));

        clk.advance_100ns(1_000);
        assert_eq!(
            tq.run_due_expirations(&clk),
            vec![TimerExpiry {
                timer_ptr: 0x700,
                dpc_ptr: None,
            }]
        );
        assert_eq!(tq.next_deadline(), Some(2_000));

        tq.clear();
        assert_eq!(tq.next_deadline(), None);
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
        assert_eq!(
            tq.run_due_expirations_at(1_000),
            vec![TimerExpiry {
                timer_ptr: 0x700,
                dpc_ptr: Some(0xD1),
            }]
        );
        assert!(tq.run_due_expirations_at(1_000).is_empty());
    }

    #[test]
    fn timer_generic_access_maps_to_native_rights() {
        assert_eq!(map_timer_access(0x8000_0000), 0x0002_0001);
        assert_eq!(map_timer_access(0x4000_0000), 0x0002_0002);
        assert_eq!(map_timer_access(0x2000_0000), 0x0012_0000);
        assert_eq!(map_timer_access(0x1000_0000), 0x001F_0003);
    }
}
