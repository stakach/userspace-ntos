//! Controller-window coherent DMA reservations and SG alias authority.

use super::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum CoherentReservationState {
    Active,
    Quarantined,
    Released,
}

pub(super) struct CoherentWindow {
    pub(super) owner: DmaOwner,
    pub(super) identity: CoherentWindowIdentity,
    pub(super) logical_base: u64,
    pub(super) length: u64,
    pub(super) backing_va: u64,
    pub(super) state: CoherentReservationState,
}

pub(super) struct CoherentReservation {
    pub(super) id: u64,
    pub(super) owner: DmaOwner,
    pub(super) window: CoherentWindowIdentity,
    pub(super) logical_base: u64,
    pub(super) length: u64,
    pub(super) backing_va: u64,
    pub(super) state: CoherentReservationState,
}

pub(super) struct CoherentAliasRecord {
    pub(super) alias: CoherentReservationAlias,
    pub(super) owner: DmaOwner,
    pub(super) active: bool,
}

/// Exact generation of a PnP-granted coherent DMA window.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CoherentWindowIdentity {
    pub lease_id: u64,
    pub generation: u64,
}

impl CoherentWindowIdentity {
    pub const fn new(lease_id: u64, generation: u64) -> Self {
        Self {
            lease_id,
            generation,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CoherentReservationGrant {
    pub reservation_id: u64,
    pub logical_base: u64,
}

/// A scatter/gather view bound to one adapter while its backing reservation remains
/// owned by the controller's PnP window rather than any one adapter.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CoherentReservationAlias {
    pub(super) alias_id: u64,
    pub(super) reservation_id: u64,
    pub(super) adapter_id: u64,
    pub(super) window: CoherentWindowIdentity,
    pub logical_base: u64,
    pub backing_va: u64,
    pub length: u64,
}

impl DmaManager {
    /// Register an exact PnP-granted coherent window before reserving slices in it.
    /// Repeating the same live grant is idempotent; changing its range or owner is refused.
    pub fn register_coherent_window(
        &mut self,
        owner: DmaOwner,
        identity: CoherentWindowIdentity,
        logical_base: u64,
        length: u64,
        backing_va: u64,
    ) -> Result<(), DmaError> {
        if owner.driver_host_id == 0
            || owner.driver_host_cookie == 0
            || owner.devnode_id == 0
            || identity.lease_id == 0
            || identity.generation == 0
            || logical_base == 0
            || backing_va == 0
            || length == 0
            || logical_base.checked_add(length).is_none()
            || backing_va.checked_add(length).is_none()
        {
            return Err(DmaError::OutOfRange);
        }
        if let Some(existing) = self
            .coherent_windows
            .iter()
            .find(|window| window.identity == identity)
        {
            if existing.state == CoherentReservationState::Released {
                return Err(DmaError::StaleId);
            }
            if existing.owner != owner {
                return Err(DmaError::WrongOwner);
            }
            if existing.logical_base != logical_base
                || existing.length != length
                || existing.backing_va != backing_va
            {
                return Err(DmaError::LogicalViolation);
            }
            return if existing.state == CoherentReservationState::Quarantined {
                Err(DmaError::Quarantined)
            } else {
                Ok(())
            };
        }
        let logical_end = logical_base + length;
        let backing_end = backing_va + length;
        if self.coherent_windows.iter().any(|window| {
            if window.owner != owner || window.state == CoherentReservationState::Released {
                return false;
            }
            let window_logical_end = window.logical_base + window.length;
            let window_backing_end = window.backing_va + window.length;
            logical_base < window_logical_end && window.logical_base < logical_end
                || backing_va < window_backing_end && window.backing_va < backing_end
        }) {
            return Err(DmaError::LogicalViolation);
        }
        let window = CoherentWindow {
            owner,
            identity,
            logical_base,
            length,
            backing_va,
            state: CoherentReservationState::Active,
        };
        self.coherent_windows.push(window);
        Ok(())
    }

    /// Retire a window only after every reservation in its generation is fully released.
    pub fn release_coherent_window(
        &mut self,
        owner: DmaOwner,
        identity: CoherentWindowIdentity,
    ) -> Result<(), DmaError> {
        let window = self
            .coherent_windows
            .iter()
            .find(|window| {
                window.identity == identity && window.state != CoherentReservationState::Released
            })
            .ok_or(DmaError::StaleId)?;
        if window.owner != owner {
            return Err(DmaError::WrongOwner);
        }
        if window.state == CoherentReservationState::Quarantined {
            return Err(DmaError::Quarantined);
        }
        if self.coherent_reservations.iter().any(|reservation| {
            reservation.owner == owner
                && reservation.window == identity
                && reservation.state != CoherentReservationState::Released
        }) {
            return Err(DmaError::AdapterBusy);
        }
        let window = self
            .coherent_windows
            .iter_mut()
            .find(|window| window.identity == identity)
            .unwrap();
        window.state = CoherentReservationState::Released;
        Ok(())
    }

    /// Reserve a slice of a PnP-granted coherent window independently of the DMA adapter
    /// Storport may later use for scatter/gather. A fresh reservation ID is its generation.
    pub fn register_coherent_reservation_at(
        &mut self,
        owner: DmaOwner,
        window: CoherentWindowIdentity,
        logical_base: u64,
        length: u64,
        backing_va: u64,
    ) -> Result<CoherentReservationGrant, DmaError> {
        if owner.driver_host_id == 0
            || owner.driver_host_cookie == 0
            || owner.devnode_id == 0
            || window.lease_id == 0
            || window.generation == 0
            || logical_base == 0
            || backing_va == 0
            || length == 0
            || logical_base.checked_add(length).is_none()
            || backing_va.checked_add(length).is_none()
        {
            return Err(DmaError::OutOfRange);
        }
        let registered = self
            .coherent_windows
            .iter()
            .find(|registered| {
                registered.identity == window
                    && registered.state != CoherentReservationState::Released
            })
            .ok_or(DmaError::StaleId)?;
        if registered.owner != owner {
            return Err(DmaError::WrongOwner);
        }
        if registered.state == CoherentReservationState::Quarantined {
            return Err(DmaError::Quarantined);
        }
        let offset = backing_va
            .checked_sub(registered.backing_va)
            .ok_or(DmaError::OutOfRange)?;
        if offset >= registered.length
            || length > registered.length - offset
            || registered.logical_base.checked_add(offset) != Some(logical_base)
        {
            return Err(DmaError::OutOfRange);
        }
        if self.logical_range_in_use(owner, logical_base, length) {
            return Err(DmaError::LogicalViolation);
        }
        let id = self.next_coherent_reservation_id;
        self.next_coherent_reservation_id = id.checked_add(1).ok_or(DmaError::OutOfRange)?;
        let reservation = CoherentReservation {
            id,
            owner,
            window,
            logical_base,
            length,
            backing_va,
            state: CoherentReservationState::Active,
        };
        if let Some(slot) = self
            .coherent_reservations
            .iter_mut()
            .find(|slot| slot.state == CoherentReservationState::Released)
        {
            *slot = reservation;
        } else {
            self.coherent_reservations.push(reservation);
        }
        Ok(CoherentReservationGrant {
            reservation_id: id,
            logical_base,
        })
    }

    /// Bind a live SG adapter of the same owner to a fully covered coherent slice.
    pub fn begin_coherent_reservation_alias(
        &mut self,
        owner: DmaOwner,
        adapter_id: u64,
        reservation_id: u64,
        window: CoherentWindowIdentity,
        backing_va: u64,
        length: u64,
    ) -> Result<CoherentReservationAlias, DmaError> {
        self.adapter(adapter_id, owner)?;
        let reservation = self
            .coherent_reservations
            .iter()
            .find(|reservation| {
                reservation.id == reservation_id
                    && reservation.state != CoherentReservationState::Released
            })
            .ok_or(DmaError::StaleId)?;
        if reservation.owner != owner {
            return Err(DmaError::WrongOwner);
        }
        if reservation.window != window {
            return Err(DmaError::StaleId);
        }
        if reservation.state == CoherentReservationState::Quarantined {
            return Err(DmaError::Quarantined);
        }
        let offset = backing_va
            .checked_sub(reservation.backing_va)
            .ok_or(DmaError::OutOfRange)?;
        if length == 0 || offset >= reservation.length || length > reservation.length - offset {
            return Err(DmaError::OutOfRange);
        }
        let logical_base = reservation
            .logical_base
            .checked_add(offset)
            .ok_or(DmaError::OutOfRange)?;
        let alias_id = self.next_coherent_alias_id;
        self.next_coherent_alias_id = alias_id.checked_add(1).ok_or(DmaError::OutOfRange)?;
        let alias = CoherentReservationAlias {
            alias_id,
            reservation_id,
            adapter_id,
            window,
            logical_base,
            backing_va,
            length,
        };
        let record = CoherentAliasRecord {
            alias,
            owner,
            active: true,
        };
        if let Some(slot) = self.coherent_aliases.iter_mut().find(|slot| !slot.active) {
            *slot = record;
        } else {
            self.coherent_aliases.push(record);
        }
        Ok(alias)
    }

    pub fn end_coherent_reservation_alias(
        &mut self,
        owner: DmaOwner,
        alias: CoherentReservationAlias,
    ) -> Result<(), DmaError> {
        let record = self
            .coherent_aliases
            .iter_mut()
            .find(|record| record.active && record.alias.alias_id == alias.alias_id)
            .ok_or(DmaError::StaleId)?;
        if record.owner != owner {
            return Err(DmaError::WrongOwner);
        }
        if record.alias != alias {
            return Err(DmaError::OutOfRange);
        }
        record.active = false;
        Ok(())
    }

    /// A known terminal completion may release an exact reservation only after all SG aliases end.
    pub fn release_coherent_reservation(
        &mut self,
        owner: DmaOwner,
        window: CoherentWindowIdentity,
        reservation_id: u64,
    ) -> Result<(), DmaError> {
        let reservation = self
            .coherent_reservations
            .iter()
            .find(|reservation| {
                reservation.id == reservation_id
                    && reservation.state != CoherentReservationState::Released
            })
            .ok_or(DmaError::StaleId)?;
        if reservation.owner != owner {
            return Err(DmaError::WrongOwner);
        }
        if reservation.window != window {
            return Err(DmaError::StaleId);
        }
        if reservation.state == CoherentReservationState::Quarantined {
            return Err(DmaError::Quarantined);
        }
        if self
            .coherent_aliases
            .iter()
            .any(|alias| alias.active && alias.alias.reservation_id == reservation_id)
        {
            return Err(DmaError::AdapterBusy);
        }
        let reservation = self
            .coherent_reservations
            .iter_mut()
            .find(|reservation| reservation.id == reservation_id)
            .unwrap();
        reservation.state = CoherentReservationState::Released;
        Ok(())
    }

    /// An uncertain completion keeps the backing and IOVA occupied. The recorded reservation
    /// cannot issue a new alias or be released by a later, possibly unrelated completion.
    pub fn quarantine_coherent_reservation(
        &mut self,
        owner: DmaOwner,
        window: CoherentWindowIdentity,
        reservation_id: u64,
    ) -> Result<(), DmaError> {
        let reservation = self
            .coherent_reservations
            .iter_mut()
            .find(|reservation| {
                reservation.id == reservation_id
                    && reservation.state != CoherentReservationState::Released
            })
            .ok_or(DmaError::StaleId)?;
        if reservation.owner != owner {
            return Err(DmaError::WrongOwner);
        }
        if reservation.window != window {
            return Err(DmaError::StaleId);
        }
        reservation.state = CoherentReservationState::Quarantined;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> DmaOwner {
        DmaOwner::new(1, 100, 10)
    }

    #[test]
    fn coherent_window_reservation_aliases_exact_live_adapter_of_same_owner() {
        let mut dma = DmaManager::new();
        let controller = dma.register_adapter(owner(), true, 4096, true);
        let storport = dma.register_adapter(owner(), true, 4096, false);
        let foreign_owner = DmaOwner::new(2, 200, 20);
        let foreign = dma.register_adapter(foreign_owner, true, 4096, true);
        let window = CoherentWindowIdentity::new(7, 3);
        dma.register_coherent_window(owner(), window, 0x10_000, 0x1000, 0x60_000)
            .unwrap();
        let reservation = dma
            .register_coherent_reservation_at(owner(), window, 0x10_000, 512, 0x60_000)
            .unwrap();

        assert_eq!(
            dma.begin_coherent_reservation_alias(
                owner(),
                foreign,
                reservation.reservation_id,
                window,
                0x60_020,
                32
            ),
            Err(DmaError::WrongOwner)
        );
        assert_eq!(
            dma.begin_coherent_reservation_alias(
                foreign_owner,
                foreign,
                reservation.reservation_id,
                window,
                0x60_020,
                32
            ),
            Err(DmaError::WrongOwner)
        );
        assert_eq!(
            dma.begin_coherent_reservation_alias(
                owner(),
                storport,
                reservation.reservation_id,
                CoherentWindowIdentity::new(7, 4),
                0x60_020,
                32
            ),
            Err(DmaError::StaleId)
        );
        assert_eq!(
            dma.begin_coherent_reservation_alias(
                owner(),
                storport,
                reservation.reservation_id,
                window,
                0x60_1ff,
                2
            ),
            Err(DmaError::OutOfRange)
        );
        assert_eq!(
            dma.begin_coherent_reservation_alias(
                owner(),
                storport,
                reservation.reservation_id,
                window,
                0x60_000,
                0
            ),
            Err(DmaError::OutOfRange)
        );

        let alias = dma
            .begin_coherent_reservation_alias(
                owner(),
                storport,
                reservation.reservation_id,
                window,
                0x60_020,
                32,
            )
            .unwrap();
        assert_eq!(alias.logical_base, 0x10_020);
        assert_eq!(
            dma.decode_owner_logical(owner(), alias.logical_base, 32),
            Ok(0x60_020)
        );
        assert_eq!(
            dma.decode_owner_logical_with_kind(owner(), alias.logical_base, 32),
            Ok((0x60_020, DmaLogicalRangeKind::CoherentReservation))
        );
        assert_eq!(
            dma.release_coherent_reservation(owner(), window, reservation.reservation_id),
            Err(DmaError::AdapterBusy)
        );
        assert_eq!(
            dma.put_adapter_for_owner(owner(), storport),
            Err(DmaError::AdapterBusy)
        );
        assert_eq!(dma.end_coherent_reservation_alias(owner(), alias), Ok(()));
        assert_eq!(
            dma.end_coherent_reservation_alias(owner(), alias),
            Err(DmaError::StaleId)
        );
        assert_eq!(
            dma.release_coherent_reservation(owner(), window, reservation.reservation_id),
            Ok(())
        );
        assert_eq!(dma.release_coherent_window(owner(), window), Ok(()));
        assert_eq!(
            dma.register_coherent_window(owner(), window, 0x10_000, 0x1000, 0x60_000),
            Err(DmaError::StaleId)
        );
        assert_eq!(dma.put_adapter_for_owner(owner(), storport), Ok(()));
        assert_eq!(dma.put_adapter_for_owner(owner(), controller), Ok(()));
    }

    #[test]
    fn coherent_reservation_generation_does_not_follow_reused_window_bytes() {
        let mut dma = DmaManager::new();
        let adapter = dma.register_adapter(owner(), true, 4096, true);
        let window = CoherentWindowIdentity::new(11, 8);
        dma.register_coherent_window(owner(), window, 0x20_000, 0x1000, 0x70_000)
            .unwrap();
        let old = dma
            .register_coherent_reservation_at(owner(), window, 0x20_000, 256, 0x70_000)
            .unwrap();
        dma.release_coherent_reservation(owner(), window, old.reservation_id)
            .unwrap();
        let new = dma
            .register_coherent_reservation_at(owner(), window, 0x20_000, 256, 0x70_000)
            .unwrap();
        assert_ne!(old.reservation_id, new.reservation_id);
        assert_eq!(
            dma.begin_coherent_reservation_alias(
                owner(),
                adapter,
                old.reservation_id,
                window,
                0x70_000,
                16
            ),
            Err(DmaError::StaleId)
        );
        let alias = dma
            .begin_coherent_reservation_alias(
                owner(),
                adapter,
                new.reservation_id,
                window,
                0x70_000,
                16,
            )
            .unwrap();
        assert_eq!(dma.end_coherent_reservation_alias(owner(), alias), Ok(()));
    }

    #[test]
    fn uncertain_coherent_reservation_stays_pinned_without_new_alias_or_reuse() {
        let mut dma = DmaManager::new();
        let adapter = dma.register_adapter(owner(), true, 4096, true);
        let window = CoherentWindowIdentity::new(13, 9);
        dma.register_coherent_window(owner(), window, 0x30_000, 0x1000, 0x80_000)
            .unwrap();
        let grant = dma
            .register_coherent_reservation_at(owner(), window, 0x30_000, 128, 0x80_000)
            .unwrap();
        let alias = dma
            .begin_coherent_reservation_alias(
                owner(),
                adapter,
                grant.reservation_id,
                window,
                0x80_000,
                32,
            )
            .unwrap();
        assert_eq!(
            dma.quarantine_coherent_reservation(owner(), window, grant.reservation_id),
            Ok(())
        );
        assert_eq!(dma.end_coherent_reservation_alias(owner(), alias), Ok(()));
        assert_eq!(
            dma.begin_coherent_reservation_alias(
                owner(),
                adapter,
                grant.reservation_id,
                window,
                0x80_000,
                32
            ),
            Err(DmaError::Quarantined)
        );
        assert_eq!(
            dma.release_coherent_reservation(owner(), window, grant.reservation_id),
            Err(DmaError::Quarantined)
        );
        assert_eq!(
            dma.register_coherent_reservation_at(owner(), window, 0x30_000, 128, 0x80_000),
            Err(DmaError::LogicalViolation)
        );
        assert_eq!(
            dma.decode_owner_logical(owner(), 0x30_000, 32),
            Ok(0x80_000)
        );
        assert_eq!(
            dma.put_adapter_for_owner(owner(), adapter),
            Err(DmaError::AdapterBusy)
        );
    }

    #[test]
    fn coherent_reservation_requires_registered_window_bounds_and_matching_offsets() {
        let mut dma = DmaManager::new();
        let window = CoherentWindowIdentity::new(17, 2);
        assert_eq!(
            dma.register_coherent_reservation_at(owner(), window, 0x40_000, 64, 0x90_000),
            Err(DmaError::StaleId)
        );
        dma.register_coherent_window(owner(), window, 0x40_000, 0x1000, 0x90_000)
            .unwrap();
        assert_eq!(
            dma.register_coherent_reservation_at(owner(), window, 0x40_080, 64, 0x90_040),
            Err(DmaError::OutOfRange)
        );
        assert_eq!(
            dma.register_coherent_reservation_at(owner(), window, 0x40_fff, 2, 0x90_fff),
            Err(DmaError::OutOfRange)
        );
        let first = dma
            .register_coherent_reservation_at(owner(), window, 0x40_080, 128, 0x90_080)
            .unwrap();
        assert_eq!(
            dma.register_coherent_reservation_at(owner(), window, 0x40_0c0, 128, 0x90_0c0),
            Err(DmaError::LogicalViolation)
        );
        assert_eq!(
            dma.release_coherent_reservation(owner(), window, first.reservation_id),
            Ok(())
        );
    }

    #[test]
    fn owner_revocation_quarantines_inflight_coherent_alias_and_window() {
        let mut dma = DmaManager::new();
        let adapter = dma.register_adapter(owner(), true, 4096, true);
        let window = CoherentWindowIdentity::new(19, 4);
        dma.register_coherent_window(owner(), window, 0x50_000, 0x1000, 0xa0_000)
            .unwrap();
        let grant = dma
            .register_coherent_reservation_at(owner(), window, 0x50_000, 128, 0xa0_000)
            .unwrap();
        let alias = dma
            .begin_coherent_reservation_alias(
                owner(),
                adapter,
                grant.reservation_id,
                window,
                0xa0_000,
                32,
            )
            .unwrap();
        assert_eq!(dma.revoke_owner(owner()), (0, 0));
        assert_eq!(
            dma.decode_owner_logical(owner(), alias.logical_base, 32),
            Ok(0xa0_000)
        );
        assert_eq!(
            dma.release_coherent_reservation(owner(), window, grant.reservation_id),
            Err(DmaError::Quarantined)
        );
        assert_eq!(
            dma.release_coherent_window(owner(), window),
            Err(DmaError::Quarantined)
        );
        assert_eq!(dma.end_coherent_reservation_alias(owner(), alias), Ok(()));
        assert_eq!(
            dma.register_coherent_window(owner(), window, 0x50_000, 0x1000, 0xa0_000),
            Err(DmaError::Quarantined)
        );
    }
}
