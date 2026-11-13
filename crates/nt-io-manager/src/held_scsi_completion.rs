//! Component-private retention of a hosted SCSI completion acknowledgement.
//!
//! The root service proves the physical IRP identity and publishes the old
//! use before accepting `IoReuseIrp`. This table only correlates that success
//! with the exact service token retained by the calling component. A token is
//! kept until its acknowledgement succeeds, including when the native
//! completion callback and reuse race the origin's hold receipt.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldScsiIdentity {
    pub irp: u64,
    pub token: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldScsiError {
    InvalidIdentity,
    AlreadyRetained,
    Full,
    NotFound,
    WrongPhase,
}

#[derive(Clone, Copy)]
struct Row {
    identity: HeldScsiIdentity,
    reused: bool,
    armed: bool,
    terminal_seen: bool,
    acknowledging: bool,
}

/// Caller-serialized, allocation-free state for a single hosted component.
/// A root-confirmed reuse may have a new row while an older callback still
/// holds an exact token. Only the newest non-reused row receives raw-IRP
/// terminal observations.
pub struct HeldScsiCompletionTable<const CAPACITY: usize> {
    rows: [Option<Row>; CAPACITY],
}

impl<const CAPACITY: usize> Default for HeldScsiCompletionTable<CAPACITY> {
    fn default() -> Self { Self::new() }
}

impl<const CAPACITY: usize> HeldScsiCompletionTable<CAPACITY> {
    pub const fn new() -> Self { Self { rows: [None; CAPACITY] } }

    /// Record ownership before the lower service can have an effect.
    pub fn reserve(&mut self, irp: u64) -> Result<(), HeldScsiError> {
        if irp == 0 { return Err(HeldScsiError::InvalidIdentity); }
        if self.rows.iter().flatten().any(|row| row.identity.irp == irp && !row.reused) {
            return Err(HeldScsiError::AlreadyRetained);
        }
        let slot = self.rows.iter_mut().find(|row| row.is_none())
            .ok_or(HeldScsiError::Full)?;
        *slot = Some(Row {
            identity: HeldScsiIdentity { irp, token: 0 },
            reused: false, armed: false, terminal_seen: false, acknowledging: false,
        });
        Ok(())
    }

    /// Bind the root-issued token returned for an accepted forward.
    pub fn bind(&mut self, irp: u64, token: u64) -> Result<HeldScsiIdentity, HeldScsiError> {
        if token == 0 { return Err(HeldScsiError::InvalidIdentity); }
        if self.rows.iter().flatten().any(|row| row.identity.irp == irp && row.identity.token == token) {
            return Err(HeldScsiError::AlreadyRetained);
        }
        let row = self.row_mut(irp)?;
        if row.identity.token != 0 || row.armed || row.terminal_seen || row.acknowledging {
            return Err(HeldScsiError::WrongPhase);
        }
        row.identity.token = token;
        Ok(row.identity)
    }

    pub fn cancel_unbound(&mut self, irp: u64) -> Result<(), HeldScsiError> {
        let slot = self.active_slot_mut(irp)?;
        let row = slot.as_ref().ok_or(HeldScsiError::NotFound)?;
        if row.identity.token != 0 || row.armed || row.terminal_seen || row.acknowledging {
            return Err(HeldScsiError::WrongPhase);
        }
        *slot = None;
        Ok(())
    }

    /// The native completion walk reached Terminal without a held callback.
    pub fn cancel_bound(&mut self, identity: HeldScsiIdentity) -> Result<(), HeldScsiError> {
        let slot = self.exact_slot_mut(identity)?;
        let row = slot.as_ref().ok_or(HeldScsiError::NotFound)?;
        if identity.token == 0 || row.armed || row.terminal_seen || row.acknowledging {
            return Err(HeldScsiError::WrongPhase);
        }
        *slot = None;
        Ok(())
    }

    /// An MPR completion has received the root operation-4 hold receipt.
    /// A prior terminal or successful reuse makes its exact ACK ready now.
    pub fn arm(&mut self, identity: HeldScsiIdentity)
        -> Result<Option<HeldScsiIdentity>, HeldScsiError>
    {
        let row = self.exact_row_mut(identity)?;
        if identity.token == 0 || row.armed || row.acknowledging {
            return Err(HeldScsiError::WrongPhase);
        }
        row.armed = true;
        Ok(Self::ready_ack(row))
    }

    /// A later native `IoCompleteRequest` reached Terminal for the current IRP.
    pub fn terminal(&mut self, irp: u64)
        -> Result<Option<HeldScsiIdentity>, HeldScsiError>
    {
        let row = self.row_mut(irp)?;
        if row.identity.token == 0 || row.terminal_seen || row.acknowledging {
            return Err(HeldScsiError::WrongPhase);
        }
        row.terminal_seen = true;
        Ok(Self::ready_ack(row))
    }

    /// Invoke only after the root service commits `IoReuseIrp` successfully.
    /// Root's exact-use publication proof makes the old MPR use terminal even
    /// if its caller will never invoke `IoCompleteRequest` again.
    pub fn reuse_committed(&mut self, irp: u64)
        -> Result<Option<HeldScsiIdentity>, HeldScsiError>
    {
        let row = self.row_mut(irp)?;
        if row.identity.token == 0 {
            return Err(HeldScsiError::WrongPhase);
        }
        row.reused = true;
        row.terminal_seen = true;
        if row.acknowledging {
            // The exact old token is already in flight. Keep it until its
            // caller observes the ACK result; reuse cannot replay that effect.
            Ok(None)
        } else {
            Ok(Self::ready_ack(row))
        }
    }

    /// An ACK is an uncertain external effect. Retire only after op5 succeeds.
    pub fn retire_exact(&mut self, identity: HeldScsiIdentity)
        -> Result<(), HeldScsiError>
    {
        let slot = self.exact_slot_mut(identity)?;
        if !slot.as_ref().is_some_and(|row| row.acknowledging) {
            return Err(HeldScsiError::WrongPhase);
        }
        *slot = None;
        Ok(())
    }

    fn ready_ack(row: &mut Row) -> Option<HeldScsiIdentity> {
        if row.armed && row.terminal_seen {
            row.acknowledging = true;
            Some(row.identity)
        } else { None }
    }

    fn active_slot_mut(&mut self, irp: u64) -> Result<&mut Option<Row>, HeldScsiError> {
        self.rows.iter_mut().find(|slot| slot.as_ref().is_some_and(|row| {
            row.identity.irp == irp && !row.reused
        }))
            .ok_or(HeldScsiError::NotFound)
    }

    fn row_mut(&mut self, irp: u64) -> Result<&mut Row, HeldScsiError> {
        self.active_slot_mut(irp)?.as_mut().ok_or(HeldScsiError::NotFound)
    }

    fn exact_slot_mut(&mut self, identity: HeldScsiIdentity)
        -> Result<&mut Option<Row>, HeldScsiError>
    {
        self.rows.iter_mut().find(|slot| {
            slot.as_ref().is_some_and(|row| row.identity == identity)
        }).ok_or(HeldScsiError::NotFound)
    }

    fn exact_row_mut(&mut self, identity: HeldScsiIdentity)
        -> Result<&mut Row, HeldScsiError>
    {
        self.exact_slot_mut(identity)?.as_mut().ok_or(HeldScsiError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_reuse_allows_retry_while_old_ack_is_in_flight() {
        let mut table = HeldScsiCompletionTable::<2>::new();
        table.reserve(0x1000).unwrap();
        let old = table.bind(0x1000, 41).unwrap();
        assert_eq!(table.arm(old), Ok(None));
        assert_eq!(table.reserve(0x1000), Err(HeldScsiError::AlreadyRetained));
        assert_eq!(table.reuse_committed(0x1000), Ok(Some(old)));
        table.reserve(0x1000).unwrap();
        let new = table.bind(0x1000, 42).unwrap();
        assert_eq!(table.reserve(0x1000), Err(HeldScsiError::AlreadyRetained));
        table.retire_exact(old).unwrap();
        assert_eq!(table.retire_exact(old), Err(HeldScsiError::NotFound));
        assert_eq!(table.arm(new), Ok(None));
        assert_eq!(table.terminal(0x1000), Ok(Some(new)));
        table.retire_exact(new).unwrap();
    }

    #[test]
    fn failed_reuse_does_not_authorize_an_ack() {
        let mut table = HeldScsiCompletionTable::<1>::new();
        table.reserve(0x1000).unwrap();
        let old = table.bind(0x1000, 41).unwrap();
        assert_eq!(table.arm(old), Ok(None));
        assert_eq!(table.reserve(0x1000), Err(HeldScsiError::AlreadyRetained));
        assert_eq!(table.retire_exact(old), Err(HeldScsiError::WrongPhase));
    }

    #[test]
    fn reuse_during_callback_is_remembered_until_arm() {
        let mut table = HeldScsiCompletionTable::<2>::new();
        table.reserve(0x1000).unwrap();
        let old = table.bind(0x1000, 41).unwrap();
        assert_eq!(table.reuse_committed(0x1000), Ok(None));
        table.reserve(0x1000).unwrap();
        let new = table.bind(0x1000, 42).unwrap();
        assert_eq!(table.arm(old), Ok(Some(old)));
        table.retire_exact(old).unwrap();
        assert_eq!(table.arm(new), Ok(None));
        assert_eq!(table.terminal(0x1000), Ok(Some(new)));
        table.retire_exact(new).unwrap();
    }

    #[test]
    fn terminal_before_arm_preserves_exact_token() {
        let mut table = HeldScsiCompletionTable::<1>::new();
        table.reserve(0x1000).unwrap();
        let id = table.bind(0x1000, 41).unwrap();
        assert_eq!(table.terminal(0x1000), Ok(None));
        assert_eq!(table.arm(id), Ok(Some(id)));
        assert_eq!(table.arm(id), Err(HeldScsiError::WrongPhase));
    }

    #[test]
    fn stale_or_cross_use_token_cannot_retire_current_row() {
        let mut table = HeldScsiCompletionTable::<2>::new();
        table.reserve(0x1000).unwrap();
        let old = table.bind(0x1000, 41).unwrap();
        table.arm(old).unwrap();
        assert_eq!(table.reuse_committed(0x1000), Ok(Some(old)));
        assert_eq!(table.retire_exact(HeldScsiIdentity { irp: 0x1000, token: 42 }),
            Err(HeldScsiError::NotFound));
        table.retire_exact(old).unwrap();
        table.reserve(0x1000).unwrap();
        let new = table.bind(0x1000, 42).unwrap();
        assert_eq!(table.cancel_bound(old), Err(HeldScsiError::NotFound));
        assert_eq!(table.retire_exact(old), Err(HeldScsiError::NotFound));
        table.cancel_bound(new).unwrap();
    }

    #[test]
    fn reuse_during_old_ack_admits_new_use_without_replaying_ack() {
        let mut table = HeldScsiCompletionTable::<2>::new();
        table.reserve(0x1000).unwrap();
        let old = table.bind(0x1000, 41).unwrap();
        table.arm(old).unwrap();
        assert_eq!(table.terminal(0x1000), Ok(Some(old)));
        assert_eq!(table.reuse_committed(0x1000), Ok(None));
        table.reserve(0x1000).unwrap();
        let new = table.bind(0x1000, 42).unwrap();
        table.retire_exact(old).unwrap();
        assert_eq!(table.arm(new), Ok(None));
        assert_eq!(table.terminal(0x1000), Ok(Some(new)));
        table.retire_exact(new).unwrap();
    }

    #[test]
    fn capacity_and_unbound_cancel_are_explicit() {
        let mut table = HeldScsiCompletionTable::<1>::new();
        table.reserve(0x1000).unwrap();
        assert_eq!(table.reserve(0x2000), Err(HeldScsiError::Full));
        assert_eq!(table.reuse_committed(0x1000), Err(HeldScsiError::WrongPhase));
        table.cancel_unbound(0x1000).unwrap();
        table.reserve(0x2000).unwrap();
    }
}
