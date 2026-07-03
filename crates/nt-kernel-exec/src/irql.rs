//! Simulated IRQL (spec §6.1). A single-threaded per-Driver-Host execution
//! context: dispatch routines run at `PASSIVE_LEVEL`, DPCs at `DISPATCH_LEVEL`,
//! work items at `PASSIVE_LEVEL`. `KeRaiseIrql` may only raise; `KeLowerIrql` may
//! only lower.

/// `PASSIVE_LEVEL` — normal thread / dispatch / work-item context.
pub const PASSIVE_LEVEL: u8 = 0;
/// `APC_LEVEL`.
pub const APC_LEVEL: u8 = 1;
/// `DISPATCH_LEVEL` — DPC + spin-lock context.
pub const DISPATCH_LEVEL: u8 = 2;

/// The current simulated IRQL of a Driver Host execution context.
#[derive(Debug, Default)]
pub struct IrqlState {
    level: u8,
    invalid_transitions: u32,
}

impl IrqlState {
    pub fn new() -> Self {
        Self {
            level: PASSIVE_LEVEL,
            invalid_transitions: 0,
        }
    }

    /// `KeGetCurrentIrql`.
    pub fn current(&self) -> u8 {
        self.level
    }

    /// `KeRaiseIrql(new)` — raise to `new` (must be `>=` current), returning the
    /// old level. A "raise" that lowers is recorded as an invalid transition
    /// (and rejected — the level is left unchanged).
    pub fn raise(&mut self, new: u8) -> u8 {
        let old = self.level;
        if new < old {
            self.invalid_transitions += 1;
        } else {
            self.level = new;
        }
        old
    }

    /// `KeLowerIrql(new)` — lower to `new` (must be `<=` current). A "lower" that
    /// raises is rejected + recorded.
    pub fn lower(&mut self, new: u8) {
        if new > self.level {
            self.invalid_transitions += 1;
        } else {
            self.level = new;
        }
    }

    /// Run `f` at IRQL `new` (raising if needed), restoring the prior level after.
    /// The standard callback-invocation shape for DPCs (spec §17).
    pub fn with_irql<R>(&mut self, new: u8, f: impl FnOnce(&mut Self) -> R) -> R {
        let old = self.level;
        self.level = self.level.max(new);
        let r = f(self);
        self.level = old;
        r
    }

    /// True if a blocking wait is permitted at the current IRQL (spec §6.1:
    /// waiting above `APC_LEVEL` must fail).
    pub fn can_wait(&self) -> bool {
        self.level <= APC_LEVEL
    }

    /// Count of rejected (invalid) IRQL transitions — a debug/test signal.
    pub fn invalid_transitions(&self) -> u32 {
        self.invalid_transitions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_passive_and_raises_lowers() {
        let mut irql = IrqlState::new();
        assert_eq!(irql.current(), PASSIVE_LEVEL);
        assert_eq!(irql.raise(DISPATCH_LEVEL), PASSIVE_LEVEL);
        assert_eq!(irql.current(), DISPATCH_LEVEL);
        irql.lower(PASSIVE_LEVEL);
        assert_eq!(irql.current(), PASSIVE_LEVEL);
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        let mut irql = IrqlState::new();
        irql.raise(DISPATCH_LEVEL);
        // Raising to a *lower* level is invalid.
        irql.raise(PASSIVE_LEVEL);
        assert_eq!(irql.current(), DISPATCH_LEVEL);
        // Lowering to a *higher* level is invalid.
        irql.lower(PASSIVE_LEVEL);
        let mut irql2 = IrqlState::new();
        irql2.lower(DISPATCH_LEVEL);
        assert_eq!(irql2.current(), PASSIVE_LEVEL);
        assert_eq!(irql.invalid_transitions(), 1);
        assert_eq!(irql2.invalid_transitions(), 1);
    }

    #[test]
    fn waits_above_apc_are_rejected() {
        let mut irql = IrqlState::new();
        assert!(irql.can_wait()); // PASSIVE
        irql.raise(APC_LEVEL);
        assert!(irql.can_wait()); // APC ok
        irql.raise(DISPATCH_LEVEL);
        assert!(!irql.can_wait()); // DISPATCH: no waiting
    }

    #[test]
    fn with_irql_restores() {
        let mut irql = IrqlState::new();
        irql.with_irql(DISPATCH_LEVEL, |i| assert_eq!(i.current(), DISPATCH_LEVEL));
        assert_eq!(irql.current(), PASSIVE_LEVEL);
    }
}
