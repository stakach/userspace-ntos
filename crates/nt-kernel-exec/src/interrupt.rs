//! NT interrupt connection metadata and shared-line arbitration.
//!
//! Driver callbacks are returned to the host as values so no runtime borrow is held while driver
//! code runs. The host reports each ISR's Boolean result back to [`InterruptScan`], which applies
//! the NT5 shared-line rules: level-sensitive lines stop at the first claimant; latched lines scan
//! every handler and repeat the full chain while any handler claims a pass.

use alloc::vec::Vec;

/// Compatibility DIRQL used by callers that do not yet supply a platform IRQL.
pub const SYNTHETIC_DIRQL: u8 = 5;

/// Interrupt trigger mode (`KINTERRUPT_MODE`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InterruptMode {
    LevelSensitive,
    Latched,
}

/// Exact `IoConnectInterrupt` policy retained for one interrupt object.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InterruptConnection {
    pub interrupt: u64,
    pub service_routine: u64,
    pub service_context: u64,
    pub spin_lock: u64,
    pub vector: u32,
    pub irql: u8,
    pub synchronize_irql: u8,
    pub mode: InterruptMode,
    pub share_vector: bool,
    pub affinity: u64,
}

impl InterruptConnection {
    fn valid(self) -> bool {
        self.interrupt != 0
            && self.service_routine != 0
            && self.synchronize_irql >= self.irql
            && self.affinity != 0
    }

    fn ready(self) -> ReadyIsr {
        ReadyIsr {
            service_routine: self.service_routine,
            interrupt: self.interrupt,
            service_context: self.service_context,
            spin_lock: self.spin_lock,
            dirql: self.irql,
            synchronize_irql: self.synchronize_irql,
            mode: self.mode,
            affinity: self.affinity,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InterruptConnectError {
    InvalidParameter,
    SharingViolation,
}

/// The Driver Host's connected interrupts, retained in deterministic connection order.
#[derive(Default)]
pub struct InterruptTable {
    interrupts: Vec<InterruptConnection>,
}

impl InterruptTable {
    pub fn new() -> Self {
        Self {
            interrupts: Vec::new(),
        }
    }

    /// Compatibility form for older hosts. New kernel wiring should call [`Self::connect_exact`].
    pub fn connect(
        &mut self,
        ptr: u64,
        service_routine: u64,
        service_context: u64,
        vector: u32,
        dirql: u8,
    ) {
        let _ = self.connect_exact(InterruptConnection {
            interrupt: ptr,
            service_routine,
            service_context,
            spin_lock: 0,
            vector,
            irql: dirql,
            synchronize_irql: dirql,
            mode: InterruptMode::LevelSensitive,
            share_vector: false,
            affinity: 1,
        });
    }

    /// Register the complete `IoConnectInterrupt` contract.
    pub fn connect_exact(
        &mut self,
        connection: InterruptConnection,
    ) -> Result<(), InterruptConnectError> {
        if !connection.valid() {
            return Err(InterruptConnectError::InvalidParameter);
        }
        if self.interrupts.iter().any(|entry| {
            entry.interrupt != connection.interrupt
                && entry.vector == connection.vector
                && (entry.mode != connection.mode
                    || !entry.share_vector
                    || !connection.share_vector)
        }) {
            return Err(InterruptConnectError::SharingViolation);
        }
        if let Some(entry) = self
            .interrupts
            .iter_mut()
            .find(|entry| entry.interrupt == connection.interrupt)
        {
            *entry = connection;
        } else {
            self.interrupts.push(connection);
        }
        Ok(())
    }

    /// `IoDisconnectInterrupt[Ex]`.
    pub fn disconnect(&mut self, ptr: u64) {
        self.interrupts.retain(|entry| entry.interrupt != ptr);
    }

    pub fn is_connected(&self, ptr: u64) -> bool {
        self.interrupts.iter().any(|entry| entry.interrupt == ptr)
    }

    pub fn connection(&self, ptr: u64) -> Option<InterruptConnection> {
        self.interrupts
            .iter()
            .copied()
            .find(|entry| entry.interrupt == ptr)
    }

    /// Compatibility lookup for a single-handler host.
    pub fn find_vector(&self, vector: u32) -> Option<(u64, u64, u64, u8)> {
        self.interrupts
            .iter()
            .find(|entry| entry.vector == vector)
            .map(|entry| {
                (
                    entry.service_routine,
                    entry.interrupt,
                    entry.service_context,
                    entry.irql,
                )
            })
    }

    /// Snapshot a vector's ordered ISR chain for invocation without a table borrow.
    pub fn begin_scan(&self, vector: u32) -> Option<InterruptScan> {
        let entries: Vec<_> = self
            .interrupts
            .iter()
            .copied()
            .filter(|entry| entry.vector == vector)
            .collect();
        InterruptScan::new(entries)
    }
}

/// An ISR ready to run with the complete synchronization contract.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReadyIsr {
    pub service_routine: u64,
    pub interrupt: u64,
    pub service_context: u64,
    pub spin_lock: u64,
    pub dirql: u8,
    pub synchronize_irql: u8,
    pub mode: InterruptMode,
    pub affinity: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InterruptScanProgress {
    Continue,
    Complete { claimed: bool, passes: u64 },
}

/// Borrow-free NT shared-line scan state.
pub struct InterruptScan {
    entries: Vec<InterruptConnection>,
    mode: InterruptMode,
    cursor: usize,
    pass_claimed: bool,
    ever_claimed: bool,
    passes: u64,
    awaiting_result: bool,
    complete: bool,
}

impl InterruptScan {
    fn new(entries: Vec<InterruptConnection>) -> Option<Self> {
        let mode = entries.first()?.mode;
        debug_assert!(entries.iter().all(|entry| entry.mode == mode));
        Some(Self {
            entries,
            mode,
            cursor: 0,
            pass_claimed: false,
            ever_claimed: false,
            passes: 1,
            awaiting_result: false,
            complete: false,
        })
    }

    /// Return the next ISR. The previous ISR result must be reported first.
    pub fn next_isr(&mut self) -> Option<ReadyIsr> {
        if self.complete || self.awaiting_result {
            return None;
        }
        let entry = self.entries.get(self.cursor).copied()?;
        self.awaiting_result = true;
        Some(entry.ready())
    }

    /// Apply one `KSERVICE_ROUTINE` result and advance the NT scan state.
    pub fn complete_isr(&mut self, claimed: bool) -> InterruptScanProgress {
        if self.complete || !self.awaiting_result {
            return InterruptScanProgress::Complete {
                claimed: self.ever_claimed,
                passes: self.passes,
            };
        }
        self.awaiting_result = false;
        self.pass_claimed |= claimed;
        self.ever_claimed |= claimed;

        if self.mode == InterruptMode::LevelSensitive && claimed {
            self.complete = true;
        } else {
            self.cursor += 1;
            if self.cursor == self.entries.len() {
                if self.mode == InterruptMode::Latched && self.pass_claimed {
                    self.cursor = 0;
                    self.pass_claimed = false;
                    self.passes = self.passes.saturating_add(1);
                } else {
                    self.complete = true;
                }
            }
        }

        if self.complete {
            InterruptScanProgress::Complete {
                claimed: self.ever_claimed,
                passes: self.passes,
            }
        } else {
            InterruptScanProgress::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn connection(ptr: u64, mode: InterruptMode, shared: bool) -> InterruptConnection {
        InterruptConnection {
            interrupt: ptr,
            service_routine: ptr + 1,
            service_context: ptr + 2,
            spin_lock: ptr + 3,
            vector: 0x30,
            irql: 5,
            synchronize_irql: 6,
            mode,
            share_vector: shared,
            affinity: 1,
        }
    }

    #[test]
    fn connect_find_disconnect_retains_exact_policy() {
        let mut table = InterruptTable::new();
        let exact = connection(0x1000, InterruptMode::LevelSensitive, false);
        table.connect_exact(exact).unwrap();
        assert_eq!(table.connection(0x1000), Some(exact));
        assert_eq!(table.find_vector(0x30), Some((0x1001, 0x1000, 0x1002, 5)));
        table.disconnect(0x1000);
        assert!(!table.is_connected(0x1000));
        assert!(table.find_vector(0x30).is_none());
    }

    #[test]
    fn rejects_incompatible_shared_line_contracts() {
        let mut table = InterruptTable::new();
        table
            .connect_exact(connection(1, InterruptMode::LevelSensitive, true))
            .unwrap();
        assert_eq!(
            table.connect_exact(connection(2, InterruptMode::Latched, true)),
            Err(InterruptConnectError::SharingViolation)
        );
        assert_eq!(
            table.connect_exact(connection(2, InterruptMode::LevelSensitive, false)),
            Err(InterruptConnectError::SharingViolation)
        );
    }

    #[test]
    fn level_scan_stops_at_first_claimant() {
        let mut table = InterruptTable::new();
        for ptr in [1, 2, 3] {
            table
                .connect_exact(connection(ptr, InterruptMode::LevelSensitive, true))
                .unwrap();
        }
        let mut scan = table.begin_scan(0x30).unwrap();
        assert_eq!(scan.next_isr().unwrap().interrupt, 1);
        assert_eq!(scan.complete_isr(false), InterruptScanProgress::Continue);
        assert_eq!(scan.next_isr().unwrap().interrupt, 2);
        assert_eq!(
            scan.complete_isr(true),
            InterruptScanProgress::Complete {
                claimed: true,
                passes: 1
            }
        );
        assert!(scan.next_isr().is_none());
    }

    #[test]
    fn latched_scan_repeats_until_a_full_pass_is_unclaimed() {
        let mut table = InterruptTable::new();
        for ptr in [1, 2] {
            table
                .connect_exact(connection(ptr, InterruptMode::Latched, true))
                .unwrap();
        }
        let mut scan = table.begin_scan(0x30).unwrap();
        let results = [(1, true), (2, false), (1, false), (2, false)];
        for (index, (interrupt, claimed)) in results.into_iter().enumerate() {
            assert_eq!(scan.next_isr().unwrap().interrupt, interrupt);
            let progress = scan.complete_isr(claimed);
            if index + 1 == results.len() {
                assert_eq!(
                    progress,
                    InterruptScanProgress::Complete {
                        claimed: true,
                        passes: 2
                    }
                );
            } else {
                assert_eq!(progress, InterruptScanProgress::Continue);
            }
        }
    }
}
