//! Bounded, read-only process runtime pair after an installer batch becomes quiet.
//! A printed row is evidence only; it never grants process or wait authority.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupOwnerSample {
    pub process_index: usize,
    pub pid: u32,
    pub process_generation: u64,
    pub thread_signature: u64,
    pub live_threads: u64,
    pub parked_threads: u64,
    pub sc_errors: u64,
    pub bound_us: u64,
    pub donated_us: u64,
    pub table_calls: u64,
}

/// Exact live identity used only to attribute a diagnostic row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupOwnerIdentity {
    pub process_index: usize,
    pub pid: u32,
    pub generation: u64,
}

/// A retained process wait, resolved against the current hosted identity and image catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupWaitedApplication {
    pub caller: SetupOwnerIdentity,
    pub child: SetupOwnerIdentity,
    pub live_application: bool,
    /// Process Manager creation parent equals the exact live logon process's nonreused PID.
    pub direct_parent: bool,
}

/// Select the one live direct child whose process object the interactive logon owner waits on.
/// Repeated waits for the same child are harmless; distinct direct children are ambiguous.
pub fn select_unique_waited_application(
    logon: SetupOwnerIdentity,
    waits: impl IntoIterator<Item = SetupWaitedApplication>,
) -> Option<SetupOwnerIdentity> {
    let mut selected = None;
    for wait in waits {
        if wait.caller != logon || !wait.live_application || !wait.direct_parent {
            continue;
        }
        if selected.is_some_and(|child| child != wait.child) {
            return None;
        }
        selected = Some(wait.child);
    }
    selected
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupOwnerPairValidity {
    Baseline,
    Valid,
    MissingOwner,
    ChangedOwner,
    InterruptedByChild,
    ChangedThreadSet,
    FailedRuntimeRead,
    CounterRegression,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupOwnerReceipt {
    pub ordinal: u8,
    pub terminal_count: u64,
    pub sample: Option<SetupOwnerSample>,
    pub validity: SetupOwnerPairValidity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerTableCost {
    pub generation: u64,
    pub calls: u64,
    pub ticks: u64,
}

impl OwnerTableCost {
    pub const EMPTY: Self = Self {
        generation: 0,
        calls: 0,
        ticks: 0,
    };
}

/// Largest exact-generation native table-dispatch cost in the same interval.
/// Fast paths outside the table-dispatch bracket are intentionally uncounted.
pub fn top_owner_table_delta<const N: usize>(
    before: &[OwnerTableCost; N],
    after: &[OwnerTableCost; N],
) -> Option<(usize, u64, u64, u64)> {
    let mut top = None;
    for (pi, (old, new)) in before.iter().zip(after).enumerate() {
        if old.generation == 0 || old.generation != new.generation {
            continue;
        }
        let (Some(calls), Some(ticks)) = (
            new.calls.checked_sub(old.calls),
            new.ticks.checked_sub(old.ticks),
        ) else {
            continue;
        };
        if ticks == 0 {
            continue;
        }
        if top.is_none_or(|(_, _, _, best_ticks)| ticks > best_ticks) {
            top = Some((pi, new.generation, calls, ticks));
        }
    }
    top
}

/// Two observations, one census period apart, after two quiet census intervals.
/// A new terminal or active child restarts the quiet interval, but not the output budget.
pub struct SetupOwnerCensusGate {
    terminal_count: u64,
    quiet_intervals: u8,
    emitted: u8,
    baseline: Option<SetupOwnerSample>,
    interrupted: bool,
}

impl SetupOwnerCensusGate {
    pub const fn new() -> Self {
        Self {
            terminal_count: 0,
            quiet_intervals: 0,
            emitted: 0,
            baseline: None,
            interrupted: false,
        }
    }

    pub fn observe(
        &mut self,
        terminal_count: u64,
        active_children: usize,
        sample: Option<SetupOwnerSample>,
    ) -> Option<SetupOwnerReceipt> {
        if self.emitted == 2 {
            return None;
        }
        if terminal_count == 0 || terminal_count != self.terminal_count || active_children != 0 {
            if self.emitted == 1 {
                self.interrupted = true;
            }
            self.terminal_count = terminal_count;
            self.quiet_intervals = 0;
            return None;
        }
        self.quiet_intervals = self.quiet_intervals.saturating_add(1);
        if self.quiet_intervals < 2 {
            return None;
        }
        self.emitted += 1;
        let validity = if self.emitted == 1 {
            self.baseline = sample;
            if sample.is_some() {
                SetupOwnerPairValidity::Baseline
            } else {
                SetupOwnerPairValidity::MissingOwner
            }
        } else if self.interrupted {
            SetupOwnerPairValidity::InterruptedByChild
        } else {
            match (self.baseline, sample) {
                (_, None) | (None, _) => SetupOwnerPairValidity::MissingOwner,
                (Some(before), Some(after))
                    if (before.process_index, before.pid, before.process_generation)
                        != (after.process_index, after.pid, after.process_generation) =>
                {
                    SetupOwnerPairValidity::ChangedOwner
                }
                (Some(before), Some(after))
                    if before.live_threads == 0
                        || before.live_threads != after.live_threads
                        || before.thread_signature != after.thread_signature =>
                {
                    SetupOwnerPairValidity::ChangedThreadSet
                }
                (Some(before), Some(after)) if before.sc_errors != 0 || after.sc_errors != 0 => {
                    SetupOwnerPairValidity::FailedRuntimeRead
                }
                (Some(before), Some(after))
                    if after.bound_us < before.bound_us
                        || after.donated_us < before.donated_us
                        || after.table_calls < before.table_calls =>
                {
                    SetupOwnerPairValidity::CounterRegression
                }
                (Some(_), Some(_)) => SetupOwnerPairValidity::Valid,
            }
        };
        Some(SetupOwnerReceipt {
            ordinal: self.emitted,
            terminal_count,
            sample,
            validity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waited_application_is_selected_without_a_creator_role_entry() {
        let logon = SetupOwnerIdentity {
            process_index: 8,
            pid: 104,
            generation: 3,
        };
        let setup = SetupOwnerIdentity {
            process_index: 14,
            pid: 236,
            generation: 9,
        };
        let other = SetupOwnerIdentity {
            process_index: 20,
            pid: 464,
            generation: 16,
        };
        let waits = [
            SetupWaitedApplication {
                caller: logon,
                child: setup,
                live_application: true,
                direct_parent: true,
            },
            SetupWaitedApplication {
                caller: other,
                child: other,
                live_application: true,
                direct_parent: true,
            },
        ];
        assert_eq!(select_unique_waited_application(logon, waits), Some(setup));
        assert_eq!(
            select_unique_waited_application(
                logon,
                [
                    SetupWaitedApplication {
                        caller: logon,
                        child: setup,
                        live_application: true,
                        direct_parent: true,
                    },
                    SetupWaitedApplication {
                        caller: logon,
                        child: setup,
                        live_application: true,
                        direct_parent: true,
                    },
                ]
            ),
            Some(setup)
        );
        assert_eq!(
            select_unique_waited_application(
                logon,
                [
                    SetupWaitedApplication {
                        caller: other,
                        child: setup,
                        live_application: true,
                        direct_parent: true,
                    },
                    SetupWaitedApplication {
                        caller: logon,
                        child: setup,
                        live_application: false,
                        direct_parent: true,
                    },
                ]
            ),
            None
        );
        let reused = SetupOwnerIdentity {
            generation: 10,
            ..setup
        };
        assert_eq!(
            select_unique_waited_application(
                logon,
                [
                    SetupWaitedApplication {
                        caller: logon,
                        child: setup,
                        live_application: true,
                        direct_parent: true,
                    },
                    SetupWaitedApplication {
                        caller: logon,
                        child: reused,
                        live_application: true,
                        direct_parent: true,
                    },
                ]
            ),
            None
        );
    }

    #[test]
    fn direct_logon_child_wins_over_an_unrelated_waited_application() {
        let logon = SetupOwnerIdentity {
            process_index: 8,
            pid: 104,
            generation: 3,
        };
        let service_child = SetupOwnerIdentity {
            process_index: 13,
            pid: 224,
            generation: 8,
        };
        let setup = SetupOwnerIdentity {
            process_index: 14,
            pid: 236,
            generation: 9,
        };
        // In the live trace, Winlogon waits on both process objects. The first is
        // another process's child; only setup is Winlogon's direct child.
        let waits = [
            SetupWaitedApplication {
                caller: logon,
                child: service_child,
                live_application: true,
                direct_parent: false,
            },
            SetupWaitedApplication {
                caller: logon,
                child: setup,
                live_application: true,
                direct_parent: true,
            },
        ];
        assert_eq!(select_unique_waited_application(logon, waits), Some(setup));
        assert_eq!(
            select_unique_waited_application(
                logon,
                [
                    SetupWaitedApplication {
                        direct_parent: true,
                        ..waits[0]
                    },
                    waits[1]
                ],
            ),
            None,
        );
    }

    const OWNER: SetupOwnerSample = SetupOwnerSample {
        process_index: 14,
        pid: 236,
        process_generation: 9,
        thread_signature: 123,
        live_threads: 1,
        parked_threads: 0,
        sc_errors: 0,
        bound_us: 100,
        donated_us: 10,
        table_calls: 1_000,
    };

    fn armed() -> SetupOwnerCensusGate {
        let mut gate = SetupOwnerCensusGate::new();
        assert_eq!(gate.observe(1, 0, Some(OWNER)), None);
        assert_eq!(gate.observe(1, 0, Some(OWNER)), None);
        gate
    }

    #[test]
    fn only_two_rows_after_quiet_child_terminal() {
        let mut gate = armed();
        let first = gate.observe(1, 0, Some(OWNER)).unwrap();
        assert_eq!(
            (first.ordinal, first.validity),
            (1, SetupOwnerPairValidity::Baseline)
        );
        let second = gate
            .observe(
                1,
                0,
                Some(SetupOwnerSample {
                    bound_us: 200,
                    table_calls: 1_100,
                    ..OWNER
                }),
            )
            .unwrap();
        assert_eq!(
            (second.ordinal, second.validity),
            (2, SetupOwnerPairValidity::Valid)
        );
        assert_eq!(gate.observe(1, 0, Some(OWNER)), None);
        assert_eq!(gate.observe(2, 0, Some(OWNER)), None);
    }

    #[test]
    fn active_child_or_new_terminal_restarts_quiet_interval() {
        let mut gate = armed();
        assert_eq!(gate.observe(1, 1, Some(OWNER)), None);
        assert_eq!(gate.observe(1, 0, Some(OWNER)), None);
        assert_eq!(gate.observe(2, 0, Some(OWNER)), None);
        assert_eq!(gate.observe(2, 0, Some(OWNER)), None);
        assert_eq!(gate.observe(2, 0, Some(OWNER)).unwrap().ordinal, 1);
    }

    #[test]
    fn pair_interrupted_after_baseline_consumes_final_output_budget() {
        let mut gate = armed();
        let _ = gate.observe(1, 0, Some(OWNER));
        assert_eq!(gate.observe(1, 1, Some(OWNER)), None);
        assert_eq!(gate.observe(2, 0, Some(OWNER)), None);
        assert_eq!(gate.observe(2, 0, Some(OWNER)), None);
        let final_receipt = gate.observe(2, 0, Some(OWNER)).unwrap();
        assert_eq!(
            final_receipt.validity,
            SetupOwnerPairValidity::InterruptedByChild
        );
        assert_eq!(gate.observe(2, 0, Some(OWNER)), None);
    }

    #[test]
    fn reused_generation_and_changed_sc_are_not_cpu_evidence() {
        for (changed, expected) in [
            (
                SetupOwnerSample {
                    process_generation: 10,
                    ..OWNER
                },
                SetupOwnerPairValidity::ChangedOwner,
            ),
            (
                SetupOwnerSample {
                    thread_signature: 124,
                    ..OWNER
                },
                SetupOwnerPairValidity::ChangedThreadSet,
            ),
            (
                SetupOwnerSample {
                    sc_errors: 1,
                    ..OWNER
                },
                SetupOwnerPairValidity::FailedRuntimeRead,
            ),
            (
                SetupOwnerSample {
                    bound_us: 99,
                    ..OWNER
                },
                SetupOwnerPairValidity::CounterRegression,
            ),
        ] {
            let mut gate = armed();
            let _ = gate.observe(1, 0, Some(OWNER));
            assert_eq!(
                gate.observe(1, 0, Some(changed)).unwrap().validity,
                expected
            );
        }
    }

    #[test]
    fn hot_owner_rank_never_splices_reused_process_counters() {
        let before = [
            OwnerTableCost {
                generation: 1,
                calls: 3,
                ticks: 10,
            },
            OwnerTableCost {
                generation: 2,
                calls: 5,
                ticks: 20,
            },
        ];
        let after = [
            OwnerTableCost {
                generation: 3,
                calls: 100,
                ticks: 10_000,
            },
            OwnerTableCost {
                generation: 2,
                calls: 8,
                ticks: 220,
            },
        ];
        assert_eq!(top_owner_table_delta(&before, &after), Some((1, 2, 3, 200)));
    }
}
