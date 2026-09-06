//! Admission for the executive's serialized thread-to-mechanism binding table.
//! This checks routing identity, not ownership transfer or Ps thread activation.

/// Captured holds, not lookups through a possibly reused current TID or badge mapping.
/// The native adapter validates slot bounds and ownership before admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRuntimeReservations {
    pub badge: u64,
    pub pool_slot: usize,
    pub window_slot: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadBinding<R> {
    pub pi: usize,
    pub tid: u64,
    pub badge: u64,
    pub role: R,
    /// One denotes a reserved identity with no TCB; larger values identify real TCB caps.
    pub tcb: u64,
    /// None for runtimes that do not own worker pool/window reservations.
    pub reservations: Option<ThreadRuntimeReservations>,
}

impl<R> ThreadBinding<R> {
    /// Ownership queries include unbuilt, constructing, live and cleanup-pending rows.
    pub fn holds_pool_slot(&self, pi: usize, slot: usize) -> bool {
        self.pi == pi
            && self
                .reservations
                .is_some_and(|holds| holds.pool_slot == slot)
    }

    pub fn holds_window_slot(&self, pi: usize, slot: usize) -> bool {
        self.pi == pi
            && self
                .reservations
                .is_some_and(|holds| holds.window_slot == Some(slot))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadBindingAdmission {
    Insert,
    Replay { index: usize },
    Promote { index: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadBindingError {
    InvalidIdentity,
    IdentityConflict,
    BadgeConflict,
    RoleConflict,
    TcbConflict,
    DuplicateOwner,
    ReservationConflict,
}

/// Plan without mutation or allocation. The caller must commit against the unchanged, exclusively
/// held table. Empty rows are omitted from `live`; their slot policy belongs to the table owner.
/// Badge zero is valid. The reservation sentinel is shareable, real TCB identities are not.
pub fn admit_thread_binding<R: Copy + Eq>(
    requested: ThreadBinding<R>,
    live: impl IntoIterator<Item = (usize, ThreadBinding<R>)>,
) -> Result<ThreadBindingAdmission, ThreadBindingError> {
    if requested.tid == 0
        || requested.tcb == 0
        || requested
            .reservations
            .is_some_and(|holds| holds.badge != requested.badge)
    {
        return Err(ThreadBindingError::InvalidIdentity);
    }
    let mut existing = None;
    for (index, owner) in live {
        if owner.tid == requested.tid {
            if existing.is_some() {
                return Err(ThreadBindingError::DuplicateOwner);
            }
            if owner.pi != requested.pi
                || owner.badge != requested.badge
                || owner.role != requested.role
                || owner.reservations != requested.reservations
            {
                return Err(ThreadBindingError::IdentityConflict);
            }
            existing = Some(if owner.tcb == requested.tcb {
                ThreadBindingAdmission::Replay { index }
            } else if owner.tcb == 1 && requested.tcb > 1 {
                ThreadBindingAdmission::Promote { index }
            } else {
                return Err(ThreadBindingError::TcbConflict);
            });
        } else {
            if owner.badge == requested.badge {
                return Err(ThreadBindingError::BadgeConflict);
            }
            if owner.pi == requested.pi && owner.role == requested.role {
                return Err(ThreadBindingError::RoleConflict);
            }
            if requested.tcb > 1 && owner.tcb == requested.tcb {
                return Err(ThreadBindingError::TcbConflict);
            }
            if let Some(holds) = requested.reservations {
                if owner.holds_pool_slot(requested.pi, holds.pool_slot)
                    || holds
                        .window_slot
                        .is_some_and(|slot| owner.holds_window_slot(requested.pi, slot))
                {
                    return Err(ThreadBindingError::ReservationConflict);
                }
            }
        }
    }
    Ok(existing.unwrap_or(ThreadBindingAdmission::Insert))
}

/// Main runtime registration can add a previously absent mechanism triple or replay the exact
/// existing one, but may not replace already-owned caps. Checked deletion must precede replacement.
pub fn admits_mechanism_publication(existing: [u64; 3], requested: [u64; 3]) -> bool {
    requested != [0; 3] && (existing == [0; 3] || existing == requested)
}

#[cfg(test)]
#[path = "thread_binding_tests.rs"]
mod tests;
