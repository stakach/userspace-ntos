//! Exact local-to-canonical directory publication ownership.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackingError {
    NoMemory,
    DuplicateOwner,
    PathOccupied,
    InvalidPath,
    WrongOwner,
    InvalidPhase,
    LocalIdentityCollision,
    NoEffect(u32),
    Terminal(u32),
    EffectUncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication { Ready, Pending }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryAction { Create, Open }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalHandle<H> { pub handle: H, pub created: bool }

pub enum PortCreate<H, P> {
    NoEffect(u32),
    Completed(Result<CanonicalHandle<H>, u32>),
    Indeterminate(P),
    Incoherent,
}

pub enum PortEffect<P> {
    NoEffect(u32),
    Completed(Result<(), u32>),
    Indeterminate(P),
    Incoherent,
}

pub enum PortTerminal<T> { Success(T), Failure(u32), Incoherent }

pub trait DirectoryPort {
    type Handle: Copy + Eq;
    type Pending;
    fn create(&mut self, path: &[u16], desired_access: u32, attributes: u32)
        -> PortCreate<Self::Handle, Self::Pending>;
    fn open(&mut self, path: &[u16], desired_access: u32, attributes: u32)
        -> PortCreate<Self::Handle, Self::Pending>;
    fn poll_create(&mut self, pending: &mut Self::Pending)
        -> Option<PortTerminal<CanonicalHandle<Self::Handle>>>;
    fn make_temporary(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending>;
    fn make_permanent(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending>;
    fn close(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending>;
    fn poll_effect(&mut self, pending: &mut Self::Pending) -> Option<PortTerminal<()>>;
}

enum Phase<H, P> {
    Reserved,
    Creating(P),
    Ready(CanonicalHandle<H>),
    Bound(CanonicalHandle<H>),
    MakingTemporary(CanonicalHandle<H>, P),
    MakingPermanent(CanonicalHandle<H>, P),
    Closing(CanonicalHandle<H>, P),
    RollbackTemporary(CanonicalHandle<H>, P),
    RollbackClose(CanonicalHandle<H>, P),
    Aborted,
    Closed,
    Quarantined(Option<CanonicalHandle<H>>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Permanence { Unknown, Temporary, Permanent }

struct Row<O, L, H, P> {
    owner: O,
    local: Option<L>,
    leases: u32,
    action: DirectoryAction,
    path: Vec<u16>,
    desired_access: u32,
    attributes: u32,
    permanence: Permanence,
    phase: Phase<H, P>,
}

pub struct CanonicalDirectoryBackings<O, L, H, P> {
    rows: Vec<Row<O, L, H, P>>,
}

const INTERNAL_DELETE_ACCESS: u32 = 0x0001_0000;

impl<O: Copy + Eq, L: Copy + Eq, H: Copy + Eq, P> CanonicalDirectoryBackings<O, L, H, P> {
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    pub fn reserve(&mut self, owner: O, action: DirectoryAction, path: &[u16],
        desired_access: u32, attributes: u32) -> Result<(), BackingError> {
        if path.is_empty() || path.iter().any(|&unit| unit == 0 || unit > 0x7f) {
            return Err(BackingError::InvalidPath);
        }
        if self.rows.iter().any(|row| row.owner == owner) {
            return Err(BackingError::DuplicateOwner);
        }
        if self.rows.iter().any(|row| {
            !matches!(row.phase, Phase::Closed | Phase::Aborted)
                && row.path.len() == path.len()
                && row.path.iter().zip(path).all(|(&left, &right)| {
                    (left as u8).to_ascii_lowercase() == (right as u8).to_ascii_lowercase()
                })
        }) {
            return Err(BackingError::PathOccupied);
        }
        let mut retained_path = Vec::new();
        retained_path.try_reserve_exact(path.len()).map_err(|_| BackingError::NoMemory)?;
        retained_path.extend_from_slice(path);
        self.rows.try_reserve(1).map_err(|_| BackingError::NoMemory)?;
        // The canonical handle is service-owned. DELETE is required to undo a
        // permanent create after a definite native mirror failure, irrespective
        // of the caller's separately admitted native handle rights.
        self.rows.push(Row { owner, local: None, leases: 0, action, path: retained_path,
            desired_access: desired_access | INTERNAL_DELETE_ACCESS,
            attributes,
            permanence: match action {
                DirectoryAction::Create if attributes & 0x10 != 0 => Permanence::Permanent,
                DirectoryAction::Create => Permanence::Temporary,
                DirectoryAction::Open => Permanence::Unknown,
            },
            phase: Phase::Reserved });
        Ok(())
    }

    /// Cancel a reservation only while no Object Manager request has been
    /// submitted. Once publication starts, its exact terminal must be settled.
    pub fn abort_before_effect(&mut self, owner: O) -> Result<(), BackingError> {
        let index = self.rows.iter().position(|row| row.owner == owner)
            .ok_or(BackingError::WrongOwner)?;
        if !matches!(self.rows[index].phase, Phase::Reserved) {
            return Err(BackingError::InvalidPhase);
        }
        self.rows.swap_remove(index);
        Ok(())
    }

    pub fn publish(&mut self, owner: O, port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Publication, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.owner == owner)
            .ok_or(BackingError::WrongOwner)?;
        if !matches!(row.phase, Phase::Reserved) { return Err(BackingError::InvalidPhase); }
        let result = match row.action {
            DirectoryAction::Create => port.create(&row.path, row.desired_access, row.attributes),
            DirectoryAction::Open => port.open(&row.path, row.desired_access, row.attributes),
        };
        match result {
            PortCreate::NoEffect(status) => Err(BackingError::NoEffect(status)),
            PortCreate::Completed(Ok(handle)) => {
                if !handle.created { row.permanence = Permanence::Unknown; }
                row.phase = Phase::Ready(handle);
                Ok(Publication::Ready)
            }
            PortCreate::Completed(Err(status)) => {
                row.phase = Phase::Aborted;
                Err(BackingError::Terminal(status))
            }
            PortCreate::Indeterminate(pending) => {
                row.phase = Phase::Creating(pending);
                Ok(Publication::Pending)
            }
            PortCreate::Incoherent => {
                row.phase = Phase::Quarantined(None);
                Err(BackingError::EffectUncertain)
            }
        }
    }

    pub fn poll_publish(&mut self, owner: O, port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Option<Publication>, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.owner == owner)
            .ok_or(BackingError::WrongOwner)?;
        let Phase::Creating(pending) = &mut row.phase else { return Err(BackingError::InvalidPhase); };
        match port.poll_create(pending) {
            None => Ok(None),
            Some(PortTerminal::Success(handle)) => {
                if !handle.created { row.permanence = Permanence::Unknown; }
                row.phase = Phase::Ready(handle); Ok(Some(Publication::Ready))
            }
            Some(PortTerminal::Failure(status)) => {
                row.phase = Phase::Aborted; Err(BackingError::Terminal(status))
            }
            Some(PortTerminal::Incoherent) => {
                row.phase = Phase::Quarantined(None); Err(BackingError::EffectUncertain)
            }
        }
    }

    pub fn bind_local(&mut self, owner: O, local: L) -> Result<H, BackingError> {
        if self.rows.iter().any(|row| row.local == Some(local)) {
            return Err(BackingError::LocalIdentityCollision);
        }
        let row = self.rows.iter_mut().find(|row| row.owner == owner)
            .ok_or(BackingError::WrongOwner)?;
        let Phase::Ready(handle) = row.phase else { return Err(BackingError::InvalidPhase); };
        row.local = Some(local);
        row.leases = 1;
        row.phase = Phase::Bound(handle);
        Ok(handle.handle)
    }

    /// Another native handle to the same exact directory generation shares the
    /// retained canonical handle. It does not publish another canonical object.
    pub fn acquire_existing(&mut self, local: L) -> Result<H, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.local == Some(local))
            .ok_or(BackingError::WrongOwner)?;
        let Phase::Bound(handle) = row.phase else { return Err(BackingError::InvalidPhase); };
        row.leases = row.leases.checked_add(1).ok_or(BackingError::NoMemory)?;
        Ok(handle.handle)
    }

    pub fn lease_count(&self, local: L) -> Option<u32> {
        self.rows.iter().find(|row| row.local == Some(local)).map(|row| row.leases)
    }

    pub fn owner_for_local(&self, local: L) -> Option<O> {
        self.rows.iter().find(|row| row.local == Some(local)).map(|row| row.owner)
    }

    /// Undo a canonical publication when the native mirror could not commit.
    /// A pending cleanup keeps the owner row and canonical handle reserved.
    pub fn rollback_ready(&mut self, owner: O,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Publication, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.owner == owner)
            .ok_or(BackingError::WrongOwner)?;
        if row.local.is_some() { return Err(BackingError::InvalidPhase); }
        let Phase::Ready(handle) = row.phase else { return Err(BackingError::InvalidPhase); };
        if handle.created && row.permanence == Permanence::Permanent {
            match port.make_temporary(handle.handle) {
                PortEffect::NoEffect(status) => return Err(BackingError::NoEffect(status)),
                PortEffect::Completed(Ok(())) => row.permanence = Permanence::Temporary,
                PortEffect::Completed(Err(status)) => return Err(BackingError::Terminal(status)),
                PortEffect::Indeterminate(pending) => {
                    row.phase = Phase::RollbackTemporary(handle, pending);
                    return Ok(Publication::Pending);
                }
                PortEffect::Incoherent => {
                    row.phase = Phase::Quarantined(Some(handle));
                    return Err(BackingError::EffectUncertain);
                }
            }
        }
        Self::rollback_close(row, handle, port)
    }

    fn rollback_close(row: &mut Row<O, L, H, P>, handle: CanonicalHandle<H>,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Publication, BackingError> {
        match port.close(handle.handle) {
            PortEffect::NoEffect(status) => Err(BackingError::NoEffect(status)),
            PortEffect::Completed(Ok(())) => {
                row.phase = Phase::Aborted;
                Ok(Publication::Ready)
            }
            PortEffect::Completed(Err(status)) => Err(BackingError::Terminal(status)),
            PortEffect::Indeterminate(pending) => {
                row.phase = Phase::RollbackClose(handle, pending);
                Ok(Publication::Pending)
            }
            PortEffect::Incoherent => {
                row.phase = Phase::Quarantined(Some(handle));
                Err(BackingError::EffectUncertain)
            }
        }
    }

    pub fn poll_rollback(&mut self, owner: O,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Option<Publication>, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.owner == owner)
            .ok_or(BackingError::WrongOwner)?;
        if row.local.is_some() { return Err(BackingError::InvalidPhase); }
        if let Phase::RollbackTemporary(handle, pending) = &mut row.phase {
            let handle = *handle;
            match port.poll_effect(pending) {
                None => return Ok(None),
                Some(PortTerminal::Success(())) => {
                    row.permanence = Permanence::Temporary;
                    row.phase = Phase::Ready(handle);
                    return Self::rollback_close(row, handle, port).map(Some);
                }
                Some(PortTerminal::Failure(status)) => {
                    row.phase = Phase::Ready(handle);
                    return Err(BackingError::Terminal(status));
                }
                Some(PortTerminal::Incoherent) => {
                    row.phase = Phase::Quarantined(Some(handle));
                    return Err(BackingError::EffectUncertain);
                }
            }
        }
        let Phase::RollbackClose(handle, pending) = &mut row.phase else {
            return Err(BackingError::InvalidPhase);
        };
        let handle = *handle;
        match port.poll_effect(pending) {
            None => Ok(None),
            Some(PortTerminal::Success(())) => {
                row.phase = Phase::Aborted;
                Ok(Some(Publication::Ready))
            }
            Some(PortTerminal::Failure(status)) => {
                row.phase = Phase::Ready(handle);
                Err(BackingError::Terminal(status))
            }
            Some(PortTerminal::Incoherent) => {
                row.phase = Phase::Quarantined(Some(handle));
                Err(BackingError::EffectUncertain)
            }
        }
    }

    pub fn make_temporary(&mut self, local: L,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Publication, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.local == Some(local))
            .ok_or(BackingError::WrongOwner)?;
        let Phase::Bound(handle) = row.phase else { return Err(BackingError::InvalidPhase); };
        if row.permanence == Permanence::Temporary { return Ok(Publication::Ready); }
        match port.make_temporary(handle.handle) {
            PortEffect::NoEffect(status) => Err(BackingError::NoEffect(status)),
            PortEffect::Completed(Ok(())) => {
                row.permanence = Permanence::Temporary;
                Ok(Publication::Ready)
            }
            PortEffect::Completed(Err(status)) => Err(BackingError::Terminal(status)),
            PortEffect::Indeterminate(pending) => {
                row.phase = Phase::MakingTemporary(handle, pending);
                Ok(Publication::Pending)
            }
            PortEffect::Incoherent => {
                row.phase = Phase::Quarantined(Some(handle));
                Err(BackingError::EffectUncertain)
            }
        }
    }

    pub fn poll_make_temporary(&mut self, local: L,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Option<Publication>, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.local == Some(local))
            .ok_or(BackingError::WrongOwner)?;
        let Phase::MakingTemporary(handle, pending) = &mut row.phase else {
            return Err(BackingError::InvalidPhase);
        };
        let handle = *handle;
        match port.poll_effect(pending) {
            None => Ok(None),
            Some(PortTerminal::Success(())) => {
                row.permanence = Permanence::Temporary;
                row.phase = Phase::Bound(handle);
                Ok(Some(Publication::Ready))
            }
            Some(PortTerminal::Failure(status)) => {
                row.phase = Phase::Bound(handle);
                Err(BackingError::Terminal(status))
            }
            Some(PortTerminal::Incoherent) => {
                row.phase = Phase::Quarantined(Some(handle));
                Err(BackingError::EffectUncertain)
            }
        }
    }

    /// Promote only the exact bound directory generation. Native privilege
    /// admission belongs to the executive before it calls this operation.
    pub fn make_permanent(&mut self, local: L,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Publication, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.local == Some(local))
            .ok_or(BackingError::WrongOwner)?;
        let Phase::Bound(handle) = row.phase else { return Err(BackingError::InvalidPhase); };
        if row.permanence == Permanence::Permanent { return Ok(Publication::Ready); }
        match port.make_permanent(handle.handle) {
            PortEffect::NoEffect(status) => Err(BackingError::NoEffect(status)),
            PortEffect::Completed(Ok(())) => {
                row.permanence = Permanence::Permanent;
                Ok(Publication::Ready)
            }
            PortEffect::Completed(Err(status)) => Err(BackingError::Terminal(status)),
            PortEffect::Indeterminate(pending) => {
                row.phase = Phase::MakingPermanent(handle, pending);
                Ok(Publication::Pending)
            }
            PortEffect::Incoherent => {
                row.phase = Phase::Quarantined(Some(handle));
                Err(BackingError::EffectUncertain)
            }
        }
    }

    pub fn poll_make_permanent(&mut self, local: L,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Option<Publication>, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.local == Some(local))
            .ok_or(BackingError::WrongOwner)?;
        let Phase::MakingPermanent(handle, pending) = &mut row.phase else {
            return Err(BackingError::InvalidPhase);
        };
        let handle = *handle;
        match port.poll_effect(pending) {
            None => Ok(None),
            Some(PortTerminal::Success(())) => {
                row.permanence = Permanence::Permanent;
                row.phase = Phase::Bound(handle);
                Ok(Some(Publication::Ready))
            }
            Some(PortTerminal::Failure(status)) => {
                row.phase = Phase::Bound(handle);
                Err(BackingError::Terminal(status))
            }
            Some(PortTerminal::Incoherent) => {
                row.phase = Phase::Quarantined(Some(handle));
                Err(BackingError::EffectUncertain)
            }
        }
    }

    /// Release one native handle lease. Only the last lease enters a canonical
    /// close; an unanswered close retains the exact row and cannot be replayed.
    pub fn release_local(&mut self, local: L,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Publication, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.local == Some(local))
            .ok_or(BackingError::WrongOwner)?;
        let Phase::Bound(handle) = row.phase else { return Err(BackingError::InvalidPhase); };
        if row.leases == 0 { return Err(BackingError::InvalidPhase); }
        if row.leases > 1 {
            row.leases -= 1;
            return Ok(Publication::Ready);
        }
        match port.close(handle.handle) {
            PortEffect::NoEffect(status) => Err(BackingError::NoEffect(status)),
            PortEffect::Completed(Ok(())) => {
                row.leases = 0;
                row.phase = Phase::Closed;
                Ok(Publication::Ready)
            }
            PortEffect::Completed(Err(status)) => Err(BackingError::Terminal(status)),
            PortEffect::Indeterminate(pending) => {
                row.phase = Phase::Closing(handle, pending);
                Ok(Publication::Pending)
            }
            PortEffect::Incoherent => {
                row.phase = Phase::Quarantined(Some(handle));
                Err(BackingError::EffectUncertain)
            }
        }
    }

    pub fn poll_close(&mut self, local: L,
        port: &mut impl DirectoryPort<Handle=H, Pending=P>)
        -> Result<Option<Publication>, BackingError> {
        let row = self.rows.iter_mut().find(|row| row.local == Some(local))
            .ok_or(BackingError::WrongOwner)?;
        let Phase::Closing(handle, pending) = &mut row.phase else {
            return Err(BackingError::InvalidPhase);
        };
        let handle = *handle;
        match port.poll_effect(pending) {
            None => Ok(None),
            Some(PortTerminal::Success(())) => {
                row.leases = 0;
                row.phase = Phase::Closed;
                Ok(Some(Publication::Ready))
            }
            Some(PortTerminal::Failure(status)) => {
                row.phase = Phase::Bound(handle);
                Err(BackingError::Terminal(status))
            }
            Some(PortTerminal::Incoherent) => {
                row.phase = Phase::Quarantined(Some(handle));
                Err(BackingError::EffectUncertain)
            }
        }
    }

    pub fn handle_for(&self, local: L) -> Option<H> {
        self.rows.iter().find(|row| row.local == Some(local)).and_then(|row| {
            if let Phase::Bound(handle) = row.phase { Some(handle.handle) } else { None }
        })
    }

    /// Diagnostics/reconciliation may inspect a retained handle, but a
    /// quarantined row never authorizes normal close, retry, or name reuse.
    pub fn quarantined_handle(&self, owner: O) -> Option<H> {
        self.rows.iter().find(|row| row.owner == owner).and_then(|row| {
            if let Phase::Quarantined(Some(handle)) = row.phase {
                Some(handle.handle)
            } else {
                None
            }
        })
    }

    pub fn retire_terminal(&mut self, owner: O) -> Result<(), BackingError> {
        let index = self.rows.iter().position(|row| row.owner == owner)
            .ok_or(BackingError::WrongOwner)?;
        if !matches!(self.rows[index].phase, Phase::Closed | Phase::Aborted) {
            return Err(BackingError::InvalidPhase);
        }
        self.rows.swap_remove(index);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
