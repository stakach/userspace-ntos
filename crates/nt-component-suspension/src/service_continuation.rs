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
    /// The pump is out with its driver. Nothing else may drive it meanwhile.
    Driving { parent: T, step: S, envelope: E },
    /// The pump finished and the step is out with its runner, which owes the reply.
    Completing { parent: T, envelope: E },
    /// The step ran and its reply is kept. The parent has been handed back.
    Settled { envelope: E, reply: R },
    /// The pump entered an uncertain effect. Nothing is replied and nothing is released.
    Fenced { _parent: T, _step: Option<S>, _pump: Option<P>, _envelope: E },
    /// Only observable inside one transition of this module.
    Moving,
}

struct Row<K, T, S, P, E, R> {
    key: K,
    phase: Phase<T, S, P, E, R>,
}

/// The registered services, keyed by the parked parent of the lane that called them.
///
/// Driving a pump or running a step may reenter this owner (a nested service registers, a
/// nested lane replies). Every transition therefore moves its value out and back in separate
/// calls; no borrow of a row is held while the caller runs a pump or a step.
pub struct ServiceContinuations<K, T, S, P, E, R> {
    rows: Vec<Row<K, T, S, P, E, R>>,
}

impl<K: Copy + Eq, T, S, P, E, R> ServiceContinuations<K, T, S, P, E, R> {
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    fn row(&mut self, key: K) -> Option<&mut Row<K, T, S, P, E, R>> {
        self.rows.iter_mut().find(|row| row.key == key)
    }

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
        self.rows.iter().any(|row| row.key == key && matches!(row.phase,
            Phase::Registered { .. } | Phase::Awaiting { .. } | Phase::Driving { .. }
                | Phase::Completing { .. }))
    }

    /// The services whose lane has replied and whose pump may be driven, in registration
    /// order. A lane that has not reached its reply yet is never driven.
    pub fn drivable(&self) -> impl Iterator<Item = K> + '_ {
        self.rows.iter()
            .filter(|row| matches!(row.phase, Phase::Awaiting { .. }))
            .map(|row| row.key)
    }

    /// Whether any service's pump may be driven.
    pub fn has_drivable(&self) -> bool { self.drivable().next().is_some() }

    /// Take `key`'s pump to drive it once. It must come back through [`Self::unfinished`],
    /// [`Self::fenced`] or [`Self::finished`].
    pub fn take_pump(&mut self, key: K) -> Option<P> {
        let row = self.row(key).filter(|row| matches!(row.phase, Phase::Awaiting { .. }))?;
        let Phase::Awaiting { parent, step, pump, envelope } =
            core::mem::replace(&mut row.phase, Phase::Moving)
        else { unreachable!("matched above") };
        row.phase = Phase::Driving { parent, step, envelope };
        Some(pump)
    }

    /// The pump is still unfinished; keep it for the next drive.
    pub fn unfinished(&mut self, key: K, pump: P) -> Result<(), P> {
        let Some(row) = self.row(key).filter(|row| matches!(row.phase, Phase::Driving { .. }))
        else { return Err(pump) };
        let Phase::Driving { parent, step, envelope } =
            core::mem::replace(&mut row.phase, Phase::Moving)
        else { unreachable!("matched above") };
        row.phase = Phase::Awaiting { parent, step, pump, envelope };
        Ok(())
    }

    /// The pump entered an uncertain effect: keep everything and never drive or reply again.
    pub fn fenced(&mut self, key: K, pump: P) -> Result<(), P> {
        let Some(row) = self.row(key).filter(|row| matches!(row.phase, Phase::Driving { .. }))
        else { return Err(pump) };
        let Phase::Driving { parent, step, envelope } =
            core::mem::replace(&mut row.phase, Phase::Moving)
        else { unreachable!("matched above") };
        row.phase = Phase::Fenced {
            _parent: parent, _step: Some(step), _pump: Some(pump), _envelope: envelope,
        };
        Ok(())
    }

    /// The pump finished. Its step is handed out exactly once; its runner owes
    /// [`Self::settle`] with the reply the step produced.
    pub fn finished(&mut self, key: K) -> Option<S> {
        let row = self.row(key).filter(|row| matches!(row.phase, Phase::Driving { .. }))?;
        let Phase::Driving { parent, step, envelope } =
            core::mem::replace(&mut row.phase, Phase::Moving)
        else { unreachable!("matched above") };
        row.phase = Phase::Completing { parent, envelope };
        Some(step)
    }

    /// Store the step's reply, then hand back the parent for release.
    pub fn settle(&mut self, key: K, reply: R) -> Option<SettledParent<K, T>> {
        let row = self.row(key).filter(|row| matches!(row.phase, Phase::Completing { .. }))?;
        let Phase::Completing { parent, envelope } =
            core::mem::replace(&mut row.phase, Phase::Moving)
        else { unreachable!("matched above") };
        row.phase = Phase::Settled { envelope, reply };
        Some(SettledParent { key, parent })
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

/// Drive `key`'s pump once through `owner`, which is reborrowed for each transition only.
/// A finished pump's step runs once on its true outcome and the parent is returned only after
/// the reply is stored.
pub fn drive_one<K: Copy + Eq, T, S, P, E, R, O, Owner>(
    owner: &mut Owner,
    services: impl Fn(&mut Owner) -> &mut ServiceContinuations<K, T, S, P, E, R>,
    key: K,
    progress: impl FnOnce(P) -> PumpProgress<P, O>,
    complete: impl FnOnce(S, O) -> R,
) -> Option<SettledParent<K, T>> {
    let pump = services(owner).take_pump(key)?;
    match progress(pump) {
        PumpProgress::Unfinished(pump) => { let _ = services(owner).unfinished(key, pump); None }
        PumpProgress::Fenced(pump) => { let _ = services(owner).fenced(key, pump); None }
        PumpProgress::Finished(outcome) => {
            let step = services(owner).finished(key)?;
            let reply = complete(step, outcome);
            services(owner).settle(key, reply)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Parent handle, step, pump (drives left before it finishes), envelope and reply.
    type Services = ServiceContinuations<u32, &'static str, u8, u8, u64, (u64, i32)>;

    fn intercepted(key: u32, pump: u8) -> Services {
        let mut services = Services::new();
        services.register(key, "parent", 7, pump).unwrap();
        assert_eq!(services.intercept(|owner| owner == key, 0xE), Ok(key),
            "the lane's envelope is kept, never sent");
        services
    }

    /// One drive: a pump at 0 finishes with outcome 0x10.
    fn advance(pump: u8) -> PumpProgress<u8, i32> {
        if pump == 0 { PumpProgress::Finished(0x10) } else { PumpProgress::Unfinished(pump - 1) }
    }

    fn drive(services: &mut Services, key: u32,
        complete: impl FnOnce(u8, i32) -> (u64, i32)) -> Option<SettledParent<u32, &'static str>> {
        drive_one(services, |services| services, key, advance, complete)
    }

    #[test]
    fn no_reply_exists_before_the_inner_pump_finishes() {
        let mut services = intercepted(3, 2);
        assert!(services.take_reply(3).is_none());
        assert_eq!(drive(&mut services, 3, |_, _| panic!("step ran early")), None);
        assert!(services.awaiting(3), "the owner sees a no-effect refusal and retries");
        assert!(services.take_reply(3).is_none());
    }

    #[test]
    fn the_step_runs_exactly_once_on_the_true_outcome() {
        let mut services = intercepted(3, 1);
        let mut runs = vec![];
        let mut released = vec![];
        for _ in 0..4 {
            if let Some(parent) = drive(&mut services, 3,
                |step, outcome| { runs.push((step, outcome)); (1, outcome) })
            { released.push(parent); }
        }
        assert_eq!(runs, vec![(7, 0x10)]);
        assert_eq!(released, vec![SettledParent { key: 3, parent: "parent" }]);
        assert!(services.finished(3).is_none(), "the step is never handed out twice");
    }

    #[test]
    fn a_fenced_inner_pump_never_replies() {
        let mut services = intercepted(3, 9);
        assert_eq!(drive_one(&mut services, |services| services, 3, PumpProgress::Fenced,
            |_, _: i32| panic!("a fenced pump ran its step")), None);
        assert_eq!(drive_one(&mut services, |services| services, 3,
            |_| -> PumpProgress<u8, i32> { panic!("a fenced pump is never driven again") },
            |_, _| panic!("step")), None);
        assert!(!services.awaiting(3), "the owner must fence the lane, not retry it");
        assert!(!services.has_drivable() && services.take_reply(3).is_none());
    }

    #[test]
    fn the_parent_is_released_only_after_the_reply_exists() {
        let mut services = intercepted(5, 0);
        let pump = services.take_pump(5).unwrap();
        assert_eq!(advance(pump), PumpProgress::Finished(0x10));
        let step = services.finished(5).unwrap();
        assert!(services.take_reply(5).is_none(), "no reply while the step is out");
        assert!(services.awaiting(5));
        let parent = services.settle(5, (1, i32::from(step))).unwrap();
        assert_eq!(parent, SettledParent { key: 5, parent: "parent" });
        assert!(!services.awaiting(5));
        assert_eq!(services.take_reply(5), Some((0xE, (1, 7))));
    }

    #[test]
    fn the_reply_is_released_once() {
        let mut services = intercepted(5, 0);
        assert!(drive(&mut services, 5, |_, outcome| (1, outcome)).is_some());
        assert_eq!(services.take_reply(5), Some((0xE, (1, 0x10))));
        assert_eq!(services.take_reply(5), None, "a released reply is never sent twice");
        assert!(services.is_empty());
    }

    #[test]
    fn a_lane_that_has_not_replied_yet_is_not_driven() {
        let mut services = Services::new();
        services.register(3, "parent", 7, 0).unwrap();
        assert!(!services.has_drivable() && services.take_pump(3).is_none());
        assert!(services.awaiting(3));
    }

    #[test]
    fn a_pump_out_with_its_driver_admits_a_nested_service() {
        // Driving a pump can run another service that registers, and another lane's reply.
        let mut services = intercepted(3, 0);
        let pump = services.take_pump(3).unwrap();
        assert!(services.take_pump(3).is_none(), "a pump out with its driver is driven once");
        services.register(4, "nested", 8, 0).unwrap();
        assert_eq!(services.intercept(|key| key == 4, 0xF), Ok(4));
        assert_eq!(services.intercept(|key| key == 3, 0xA), Err(0xA),
            "the driven lane's reply was already intercepted");
        services.unfinished(3, pump).unwrap();
        assert_eq!(services.drivable().collect::<alloc::vec::Vec<_>>(), vec![3, 4]);
    }

    #[test]
    fn another_lane_replies_normally() {
        let mut services = Services::new();
        services.register(3, "parent", 7, 0).unwrap();
        assert_eq!(services.intercept(|key| key == 4, 0xA), Err(0xA));
        assert_eq!(services.intercept(|key| key == 3, 0xB), Ok(3));
        assert_eq!(services.intercept(|key| key == 3, 0xC), Err(0xC),
            "only the one reply the service owes is intercepted");
    }

    #[test]
    fn a_refused_registration_hands_everything_back() {
        let mut services = intercepted(3, 0);
        let refused = services.register(3, "again", 8, 1).unwrap_err();
        assert_eq!(refused, RegistrationRefused {
            reason: RegistrationRefusal::Duplicate, parent: "again", step: 8, pump: 1,
        });
    }
}
