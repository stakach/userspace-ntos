//! A service whose inner pump stopped unfinished (#420).
//!
//! Lane X calls a root service, and the service pumps another component. If that inner pump
//! stops before its dispatch finishes (a held lane, or a nested restore it is owed), the
//! service's result does not exist yet. Replying anyway would show X a failure for an
//! operation that later completes. Instead the service registers an owned post-pump step and
//! keeps the inner pump, and X stays parked:
//!
//! 1. X's pump reaches its reply. What it was about to send is only an envelope (the Reply
//!    object and transport shape). It is intercepted and never sent, and X's pump yields its
//!    parent's restore to X's owner.
//! 2. While the inner pump is unfinished, X's owner sees that restore as a no-effect refusal
//!    and retries it later. Nothing is replied.
//! 3. When the kept pump finishes, the step runs exactly once on its true result and produces
//!    the reply. Only then is X's parent handed back for release.
//! 4. X's owner restores X and takes the reply once; it is sent as the receive's first act.
//!
//! A fenced inner pump never runs its step and never replies: every resource stays held.

extern crate alloc;
use alloc::vec::Vec;

/// What one drive of a kept inner pump did.
#[derive(Debug, Eq, PartialEq)]
pub enum PumpProgress<P, O> {
    /// Still unfinished; the same pump is kept for the next drive.
    Unfinished(P),
    /// The dispatch finished with this true outcome.
    Finished(O),
    /// The pump entered an uncertain effect. It is kept and never driven again.
    Fenced(P),
}

/// Why a registration was refused. Every owned value is handed back, so nothing is lost.
#[derive(Debug, Eq, PartialEq)]
pub struct RegistrationRefused<T, S, P> {
    pub reason: RegistrationRefusal,
    pub parent: T,
    pub step: S,
    pub pump: P,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationRefusal {
    /// No row could be reserved.
    Capacity,
    /// That parent already has a registered service.
    Duplicate,
}

/// A parent handed back for release. It exists only once its reply is stored.
#[must_use = "the parent's release is owed: X's owner cannot restore it otherwise"]
#[derive(Debug, Eq, PartialEq)]
pub struct SettledParent<K, T> {
    pub key: K,
    pub parent: T,
}

enum Phase<T, S, P, E, R> {
    /// The step and pump are kept; X has not reached its reply yet.
    Registered { parent: T, step: S, pump: P },
    /// X's reply envelope was intercepted. The pump is driven at root boundaries.
    Awaiting { parent: T, step: S, pump: P, envelope: E },
    /// The step ran and its reply is kept. The parent has been handed back.
    Settled { envelope: E, reply: R },
    /// The pump entered an uncertain effect. Nothing is replied and nothing is released.
    Fenced { _parent: T, _step: S, _pump: P, _envelope: E },
    /// Only observable inside one transition of this module.
    Moving,
}

struct Row<K, T, S, P, E, R> {
    key: K,
    phase: Phase<T, S, P, E, R>,
}

/// The registered services, keyed by the parked parent of the lane that called them.
pub struct ServiceContinuations<K, T, S, P, E, R> {
    rows: Vec<Row<K, T, S, P, E, R>>,
}

impl<K: Copy + Eq, T, S, P, E, R> ServiceContinuations<K, T, S, P, E, R> {
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    /// Keep `step` and the unfinished `pump` for the parked `parent` of lane X. The row is
    /// reserved here, so no later transition allocates.
    pub fn register(
        &mut self, key: K, parent: T, step: S, pump: P,
    ) -> Result<(), RegistrationRefused<T, S, P>> {
        let reason = if self.rows.iter().any(|row| row.key == key) {
            Some(RegistrationRefusal::Duplicate)
        } else if self.rows.try_reserve(1).is_err() {
            Some(RegistrationRefusal::Capacity)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(RegistrationRefused { reason, parent, step, pump });
        }
        self.rows.push(Row { key, phase: Phase::Registered { parent, step, pump } });
        Ok(())
    }

    /// Called before a reply is sent on a lane. A reply to a lane with a registered service
    /// is not sent: its envelope is kept and the key of the parent whose restore X's owner
    /// now awaits is returned. Any other reply is handed back unchanged.
    pub fn intercept(&mut self, owns: impl Fn(K) -> bool, envelope: E) -> Result<K, E> {
        let Some(row) = self.rows.iter_mut()
            .find(|row| matches!(row.phase, Phase::Registered { .. }) && owns(row.key))
        else { return Err(envelope) };
        let Phase::Registered { parent, step, pump } =
            core::mem::replace(&mut row.phase, Phase::Moving)
        else { unreachable!("matched above") };
        row.phase = Phase::Awaiting { parent, step, pump, envelope };
        Ok(row.key)
    }

    /// Whether `key`'s service is still unsettled. Its parent's restore is then a no-effect
    /// refusal: the owner retries later and must not fence the lane.
    pub fn awaiting(&self, key: K) -> bool {
        self.rows.iter().any(|row| row.key == key
            && matches!(row.phase, Phase::Registered { .. } | Phase::Awaiting { .. }))
    }

    /// Whether any intercepted service still waits for its pump.
    pub fn has_awaiting(&self) -> bool {
        self.rows.iter().any(|row| matches!(row.phase, Phase::Awaiting { .. }))
    }

    /// Drive each intercepted pump once. A finished pump's step runs exactly once on its true
    /// outcome; the reply is stored, and only then is the parent passed to `release`. A row
    /// whose lane has not reached its reply yet is not driven. Returns how many settled.
    pub fn drive<O>(
        &mut self,
        mut progress: impl FnMut(P) -> PumpProgress<P, O>,
        mut complete: impl FnMut(S, O) -> R,
        mut release: impl FnMut(SettledParent<K, T>),
    ) -> usize {
        let mut settled = 0;
        for row in self.rows.iter_mut() {
            if !matches!(row.phase, Phase::Awaiting { .. }) { continue; }
            let Phase::Awaiting { parent, step, pump, envelope } =
                core::mem::replace(&mut row.phase, Phase::Moving)
            else { unreachable!("matched above") };
            match progress(pump) {
                PumpProgress::Unfinished(pump) =>
                    row.phase = Phase::Awaiting { parent, step, pump, envelope },
                PumpProgress::Fenced(pump) => row.phase = Phase::Fenced {
                    _parent: parent, _step: step, _pump: pump, _envelope: envelope,
                },
                PumpProgress::Finished(outcome) => {
                    row.phase = Phase::Settled { envelope, reply: complete(step, outcome) };
                    settled += 1;
                    release(SettledParent { key: row.key, parent });
                }
            }
        }
        settled
    }

    /// After X's parent is restored, release its reply exactly once.
    pub fn take_reply(&mut self, key: K) -> Option<(E, R)> {
        let index = self.rows.iter().position(|row|
            row.key == key && matches!(row.phase, Phase::Settled { .. }))?;
        match self.rows.swap_remove(index).phase {
            Phase::Settled { envelope, reply } => Some((envelope, reply)),
            _ => unreachable!("matched above"),
        }
    }

    pub fn is_empty(&self) -> bool { self.rows.is_empty() }
}

impl<K: Copy + Eq, T, S, P, E, R> Default for ServiceContinuations<K, T, S, P, E, R> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Parent handle, step, pump (steps left before it finishes), envelope and reply.
    type Services = ServiceContinuations<u32, &'static str, u8, u8, u64, (u64, i32)>;

    fn registered(key: u32, pump: u8) -> Services {
        let mut services = Services::new();
        services.register(key, "parent", 7, pump).unwrap();
        services
    }

    /// One drive step: a pump at 0 finishes with outcome 0x10 + step.
    fn advance(pump: u8) -> PumpProgress<u8, i32> {
        if pump == 0 { PumpProgress::Finished(0x10) } else { PumpProgress::Unfinished(pump - 1) }
    }

    #[test]
    fn no_reply_exists_before_the_inner_pump_finishes() {
        let mut services = registered(3, 2);
        assert_eq!(services.intercept(|key| key == 3, 0xE), Ok(3),
            "the lane's envelope is kept, never sent");
        assert!(services.take_reply(3).is_none());
        let mut released = vec![];
        assert_eq!(services.drive(advance, |_, _| panic!("step ran early"),
            |parent| released.push(parent)), 0);
        assert!(services.awaiting(3), "the owner sees a no-effect refusal and retries");
        assert!(released.is_empty() && services.take_reply(3).is_none());
    }

    #[test]
    fn the_step_runs_exactly_once_on_the_true_outcome() {
        let mut services = registered(3, 0);
        services.intercept(|key| key == 3, 0xE).unwrap();
        let mut runs = vec![];
        let mut released = vec![];
        for _ in 0..3 {
            services.drive(advance, |step, outcome| { runs.push((step, outcome)); (1, outcome) },
                |parent| released.push(parent));
        }
        assert_eq!(runs, vec![(7, 0x10)]);
        assert_eq!(released.len(), 1);
    }

    #[test]
    fn a_fenced_inner_pump_never_replies() {
        let mut services = registered(3, 9);
        services.intercept(|key| key == 3, 0xE).unwrap();
        let mut released = vec![];
        services.drive(PumpProgress::Fenced, |_, _: i32| panic!("a fenced pump ran its step"),
            |parent| released.push(parent));
        services.drive(|_| panic!("a fenced pump is never driven again"),
            |_, _: i32| panic!("step"), |parent| released.push(parent));
        assert!(released.is_empty(), "the parent stays held with every resource");
        assert!(!services.awaiting(3), "the owner must fence the lane, not retry it");
        assert!(services.take_reply(3).is_none());
    }

    #[test]
    fn the_parent_is_released_only_after_the_reply_exists() {
        let mut services = registered(5, 0);
        services.intercept(|key| key == 5, 0xE).unwrap();
        let order = core::cell::RefCell::new(vec![]);
        services.drive(advance, |_, outcome| { order.borrow_mut().push("reply"); (1, outcome) },
            |parent| order.borrow_mut().push(parent.parent));
        assert_eq!(order.into_inner(), vec!["reply", "parent"]);
        assert!(!services.awaiting(5));
    }

    #[test]
    fn the_reply_is_released_once() {
        let mut services = registered(5, 0);
        services.intercept(|key| key == 5, 0xE).unwrap();
        services.drive(advance, |_, outcome| (1, outcome), |_| {});
        assert_eq!(services.take_reply(5), Some((0xE, (1, 0x10))));
        assert_eq!(services.take_reply(5), None, "a released reply is never sent twice");
        assert!(services.is_empty());
    }

    #[test]
    fn a_lane_that_has_not_replied_yet_is_not_driven() {
        let mut services = registered(3, 0);
        assert_eq!(services.drive(|_| panic!("driven before interception"),
            |_, _: i32| (0, 0), |_| {}), 0);
        assert!(services.awaiting(3) && !services.has_awaiting());
    }

    #[test]
    fn another_lane_replies_normally() {
        let mut services = registered(3, 0);
        assert_eq!(services.intercept(|key| key == 4, 0xA), Err(0xA));
        assert_eq!(services.intercept(|key| key == 3, 0xB), Ok(3));
        assert_eq!(services.intercept(|key| key == 3, 0xC), Err(0xC),
            "only the one reply the service owes is intercepted");
    }

    #[test]
    fn a_refused_registration_hands_everything_back() {
        let mut services = registered(3, 0);
        let refused = services.register(3, "again", 8, 1).unwrap_err();
        assert_eq!(refused, RegistrationRefused {
            reason: RegistrationRefusal::Duplicate, parent: "again", step: 8, pump: 1,
        });
    }
}
