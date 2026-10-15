//! Allocation-free ownership of native PnP completion acknowledgements.
//!
//! Place each table in the hosted component's private arena. A table stored in the
//! shared executive image would mix rows from components whose heaps and IRP
//! addresses are independent. The caller serializes access to `&mut self` and
//! validates the physical IRP owner before reporting a terminal completion.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldPnpIdentity {
    pub irp: u64,
    pub token: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldPnpAcknowledgement {
    pub identity: HeldPnpIdentity,
    pub operation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldPnpError {
    InvalidIdentity,
    AlreadyRetained,
    Full,
    NotFound,
    WrongPhase,
}

#[derive(Clone, Copy)]
struct Row {
    acknowledgement: HeldPnpAcknowledgement,
    bound: bool,
    armed: bool,
    terminal_seen: bool,
    acknowledging: bool,
}

/// A component-private table. Reserve before the lower service call, then bind
/// its returned token before allowing a native completion to select an ACK.
pub struct HeldPnpCompletionTable<const CAPACITY: usize> {
    rows: [Option<Row>; CAPACITY],
}

impl<const CAPACITY: usize> Default for HeldPnpCompletionTable<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> HeldPnpCompletionTable<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            rows: [None; CAPACITY],
        }
    }

    /// Reserve ownership before entering the lower service. A raw IRP has at
    /// most one live row, including while its token has not been returned.
    pub fn reserve(&mut self, irp: u64, operation: u64) -> Result<(), HeldPnpError> {
        if irp == 0 || operation == 0 {
            return Err(HeldPnpError::InvalidIdentity);
        }
        if self
            .rows
            .iter()
            .flatten()
            .any(|row| row.acknowledgement.identity.irp == irp)
        {
            return Err(HeldPnpError::AlreadyRetained);
        }
        let slot = self
            .rows
            .iter_mut()
            .find(|row| row.is_none())
            .ok_or(HeldPnpError::Full)?;
        *slot = Some(Row {
            acknowledgement: HeldPnpAcknowledgement {
                identity: HeldPnpIdentity { irp, token: 0 },
                operation,
            },
            bound: false,
            armed: false,
            terminal_seen: false,
            acknowledging: false,
        });
        Ok(())
    }

    /// Attach the exact token returned by an accepted lower service call.
    pub fn bind(&mut self, irp: u64, token: u64) -> Result<HeldPnpIdentity, HeldPnpError> {
        let row = self.raw_row_mut(irp)?;
        // An accepted PDO FILTER has no service token; its ACK uses zero.
        if token == 0 && row.acknowledgement.operation != 5 {
            return Err(HeldPnpError::InvalidIdentity);
        }
        if row.bound || row.armed || row.terminal_seen {
            return Err(HeldPnpError::WrongPhase);
        }
        row.acknowledgement.identity.token = token;
        row.bound = true;
        Ok(row.acknowledgement.identity)
    }

    /// The lower service rejected the request before returning a token.
    pub fn cancel_unbound(&mut self, irp: u64) -> Result<(), HeldPnpError> {
        let slot = self.raw_slot_mut(irp)?;
        if slot.as_ref().is_some_and(|row| {
            row.bound
                || row.armed
                || row.terminal_seen
                || row.acknowledging
        }) {
            return Err(HeldPnpError::WrongPhase);
        }
        *slot = None;
        Ok(())
    }

    /// The lower forward stopped its completion walk. If the terminal callback
    /// raced ahead of this arm, return the acknowledgement to send now.
    pub fn arm(
        &mut self,
        irp: u64,
        token: u64,
    ) -> Result<Option<HeldPnpAcknowledgement>, HeldPnpError> {
        let identity = HeldPnpIdentity { irp, token };
        let row = self
            .exact_slot_mut(identity)?
            .as_mut()
            .ok_or(HeldPnpError::NotFound)?;
        if !row.bound || row.armed || row.acknowledging {
            return Err(HeldPnpError::WrongPhase);
        }
        row.armed = true;
        if row.terminal_seen {
            row.acknowledging = true;
            Ok(Some(row.acknowledgement))
        } else {
            Ok(None)
        }
    }

    /// Called after the canonical source IRP reaches its native terminal walk.
    /// Only its live row can select a token for acknowledgement.
    pub fn terminal(&mut self, irp: u64) -> Result<Option<HeldPnpAcknowledgement>, HeldPnpError> {
        let row = self.raw_row_mut(irp)?;
        if !row.bound {
            return Err(HeldPnpError::WrongPhase);
        }
        if row.terminal_seen || row.acknowledging {
            return Err(HeldPnpError::WrongPhase);
        }
        row.terminal_seen = true;
        if row.armed {
            row.acknowledging = true;
            Ok(Some(row.acknowledgement))
        } else {
            Ok(None)
        }
    }

    /// Record the direct completion walk only after it returned Terminal. A callback that
    /// returned MoreProcessingRequired must use `arm` and a later `terminal` instead.
    pub fn direct_terminal(&mut self, identity: HeldPnpIdentity) -> Result<(), HeldPnpError> {
        let row = self.exact_slot_mut(identity)?
            .as_mut().ok_or(HeldPnpError::NotFound)?;
        if row.acknowledgement.operation != 8 || !row.bound || row.armed || row.acknowledging {
            return Err(HeldPnpError::WrongPhase);
        }
        // A terminal IoCompleteRequest may have raced the direct dispatch return.
        row.terminal_seen = true;
        row.acknowledging = true;
        Ok(())
    }

    /// Source-side START ACK admission proof. An exact row in Bound or Armed phase alone
    /// cannot authorize provider/source retirement, even if the pending node is READY.
    pub fn start_terminal_evidence(&self, identity: HeldPnpIdentity, operation: u64) -> bool {
        self.rows.iter().flatten().any(|row| {
            row.acknowledgement.identity == identity
                && row.acknowledgement.operation == 8
                && row.bound && row.terminal_seen && row.acknowledging
                && match operation {
                    7 => !row.armed,
                    8 => row.armed,
                    _ => false,
                }
        })
    }

    /// Retire only after the exact direct or held ACK actually succeeded. The
    /// caller retains the row when the ACK result is uncertain.
    pub fn retire_exact(&mut self, identity: HeldPnpIdentity) -> Result<(), HeldPnpError> {
        let slot = self.exact_slot_mut(identity)?;
        if !slot.as_ref().is_some_and(|row| {
            row.bound && ((!row.armed && !row.terminal_seen && !row.acknowledging)
                || (row.terminal_seen && row.acknowledging)
            )
        }) {
            return Err(HeldPnpError::WrongPhase);
        }
        *slot = None;
        Ok(())
    }

    fn raw_row_mut(&mut self, irp: u64) -> Result<&mut Row, HeldPnpError> {
        self.raw_slot_mut(irp)?
            .as_mut()
            .ok_or(HeldPnpError::NotFound)
    }

    fn raw_slot_mut(&mut self, irp: u64) -> Result<&mut Option<Row>, HeldPnpError> {
        self.rows
            .iter_mut()
            .find(|slot| {
                slot.as_ref()
                    .is_some_and(|row| row.acknowledgement.identity.irp == irp)
            })
            .ok_or(HeldPnpError::NotFound)
    }

    fn exact_slot_mut(
        &mut self,
        identity: HeldPnpIdentity,
    ) -> Result<&mut Option<Row>, HeldPnpError> {
        self.rows
            .iter_mut()
            .find(|slot| {
                slot.as_ref()
                    .is_some_and(|row| row.acknowledgement.identity == identity)
            })
            .ok_or(HeldPnpError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixty_four_rows_fit_in_one_component_data_page() {
        assert!(core::mem::size_of::<HeldPnpCompletionTable<64>>() <= 4096 - 8);
    }

    fn ack(irp: u64, token: u64) -> HeldPnpAcknowledgement {
        HeldPnpAcknowledgement {
            identity: HeldPnpIdentity { irp, token },
            operation: 8,
        }
    }

    #[test]
    fn start_ack_requires_exact_direct_or_held_terminal_evidence() {
        let mut table = HeldPnpCompletionTable::<2>::new();
        let direct = HeldPnpIdentity { irp: 0x1000, token: 0x51 };
        table.reserve(direct.irp, 8).unwrap();
        table.bind(direct.irp, direct.token).unwrap();
        assert!(!table.start_terminal_evidence(direct, 7));
        assert!(!table.start_terminal_evidence(direct, 8));
        table.direct_terminal(direct).unwrap();
        assert!(table.start_terminal_evidence(direct, 7));
        assert!(!table.start_terminal_evidence(direct, 8));
        assert!(!table.start_terminal_evidence(HeldPnpIdentity { token: 0x52, ..direct }, 7));
        table.retire_exact(direct).unwrap();
        assert!(!table.start_terminal_evidence(direct, 7));

        let held = HeldPnpIdentity { irp: 0x2000, token: 0x61 };
        table.reserve(held.irp, 8).unwrap();
        table.bind(held.irp, held.token).unwrap();
        assert_eq!(table.arm(held.irp, held.token), Ok(None));
        assert!(!table.start_terminal_evidence(held, 8));
        assert_eq!(table.terminal(held.irp), Ok(Some(ack(held.irp, held.token))));
        assert!(table.start_terminal_evidence(held, 8));
        assert!(!table.start_terminal_evidence(held, 7));
    }

    #[test]
    fn independent_component_tables_keep_exact_ack_after_unrelated_mutation() {
        let mut component_a = HeldPnpCompletionTable::<2>::new();
        let mut component_b = HeldPnpCompletionTable::<2>::new();
        let expected = ack(0x1000, 0x51);
        component_a
            .reserve(expected.identity.irp, expected.operation)
            .unwrap();
        assert_eq!(
            component_a.bind(expected.identity.irp, expected.identity.token),
            Ok(expected.identity)
        );
        assert_eq!(
            component_a.arm(expected.identity.irp, expected.identity.token),
            Ok(None)
        );

        // Both components may reuse the same raw VA, but their tables and tokens
        // must never meet. B can also reuse its vacated slot before A completes.
        let unrelated = ack(0x1000, 0x72);
        component_b
            .reserve(unrelated.identity.irp, unrelated.operation)
            .unwrap();
        component_b
            .bind(unrelated.identity.irp, unrelated.identity.token)
            .unwrap();
        component_b.retire_exact(unrelated.identity).unwrap();
        let later = ack(0x2000, 0x73);
        component_b
            .reserve(later.identity.irp, later.operation)
            .unwrap();
        component_b
            .bind(later.identity.irp, later.identity.token)
            .unwrap();
        assert_eq!(
            component_b.arm(later.identity.irp, later.identity.token),
            Ok(None)
        );

        assert_eq!(
            component_a.terminal(expected.identity.irp),
            Ok(Some(expected))
        );
        assert_eq!(
            component_a.retire_exact(unrelated.identity),
            Err(HeldPnpError::NotFound)
        );
        component_a.retire_exact(expected.identity).unwrap();
        assert_eq!(
            component_a.terminal(expected.identity.irp),
            Err(HeldPnpError::NotFound)
        );
        assert_eq!(component_b.terminal(later.identity.irp), Ok(Some(later)));
    }

    #[test]
    fn terminal_before_arm_sends_ack_once() {
        let mut table = HeldPnpCompletionTable::<1>::new();
        let expected = ack(10, 20);
        table.reserve(10, expected.operation).unwrap();
        table.bind(10, 20).unwrap();
        assert_eq!(table.terminal(10), Ok(None));
        assert_eq!(
            table.arm(expected.identity.irp, expected.identity.token),
            Ok(Some(expected))
        );
        assert_eq!(table.terminal(10), Err(HeldPnpError::WrongPhase));
        table.retire_exact(expected.identity).unwrap();
    }

    #[test]
    fn capacity_and_duplicate_fail_before_changing_ownership() {
        let mut table = HeldPnpCompletionTable::<1>::new();
        let first = ack(10, 20);
        table.reserve(first.identity.irp, first.operation).unwrap();
        assert_eq!(table.reserve(10, 8), Err(HeldPnpError::AlreadyRetained));
        assert_eq!(table.reserve(11, 8), Err(HeldPnpError::Full));
        assert_eq!(table.bind(10, 20), Ok(first.identity));
        assert_eq!(table.arm(10, 21), Err(HeldPnpError::NotFound));
        assert_eq!(
            table.retire_exact(HeldPnpIdentity { irp: 10, token: 21 }),
            Err(HeldPnpError::NotFound)
        );
        table.retire_exact(first.identity).unwrap();
        table.reserve(11, 8).unwrap();
    }

    #[test]
    fn rejected_reservation_can_be_cancelled_but_bound_owner_cannot() {
        let mut table = HeldPnpCompletionTable::<1>::new();
        table.reserve(10, 8).unwrap();
        assert_eq!(table.terminal(10), Err(HeldPnpError::WrongPhase));
        table.cancel_unbound(10).unwrap();
        table.reserve(10, 8).unwrap();
        let identity = table.bind(10, 20).unwrap();
        assert_eq!(table.cancel_unbound(10), Err(HeldPnpError::WrongPhase));
        table.retire_exact(identity).unwrap();
    }

    #[test]
    fn accepted_pdo_filter_binds_zero_token_and_acknowledges_exactly_once() {
        let mut table = HeldPnpCompletionTable::<1>::new();
        table.reserve(0x1000, 5).unwrap();
        let identity = table.bind(0x1000, 0).unwrap();
        assert_eq!(identity, HeldPnpIdentity { irp: 0x1000, token: 0 });
        assert_eq!(table.cancel_unbound(0x1000), Err(HeldPnpError::WrongPhase));
        assert_eq!(table.arm(0x1000, 0), Ok(None));
        assert_eq!(table.terminal(0x1000), Ok(Some(HeldPnpAcknowledgement { identity, operation: 5 })));
        table.retire_exact(identity).unwrap();
        assert_eq!(table.terminal(0x1000), Err(HeldPnpError::NotFound));
    }
}
