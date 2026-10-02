//! Retained ownership of one native resource leaf shared by exact device leases.
//!
//! These values do not authenticate devices or capabilities. The native caller validates
//! their live authority, records admission here before effects, and acknowledges only known
//! successful map/delete results. Uncertain effects retain the entire row without replay.

use crate::ContextLeaseIdentity;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_AUTHORITY: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingDomain {
    pub id: u64,
    pub cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingKey {
    pub domain: MappingDomain,
    pub pml4: u64,
    pub virtual_page: u64,
    pub physical_page: u64,
    /// Original admission evidence, not a later dereference target. The owned map cap is
    /// the backing for repairs even if this source alias's context subsequently retires.
    pub source_cap: u64,
    pub rights: u64,
    pub attributes: u64,
}

impl MappingKey {
    // Native admission must prove physical_page from each retained source cap. Numeric aliases
    // to that same frame may join, but never replace the first owner's retained backing cap.
    fn equivalent(self, other: Self) -> bool {
        self.domain == other.domain
            && self.pml4 == other.pml4
            && self.virtual_page == other.virtual_page
            && self.physical_page == other.physical_page
            && self.rights == other.rights
            && self.attributes == other.attributes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingOwner {
    pub instance: usize,
    pub device_id: u64,
    pub context_lease: ContextLeaseIdentity,
}

/// Copying a receipt neither adds an owner nor authorizes another native effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerReceipt {
    authority: u64,
    serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapEffectReceipt {
    authority: u64,
    serial: u64,
    owner: OwnerReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPhase {
    Prepared,
    Mapping,
    Mapped,
    Uncertain,
    Retiring,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingError {
    InvalidKey,
    InvalidOwner,
    UnknownOwner,
    Conflict,
    Unavailable,
    InvalidPhase,
    InsufficientResources,
    IdExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    New(OwnerReceipt),
    Joined(OwnerReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseAction {
    OwnerReleased,
    UnmappedReleased,
    DeleteCap(u64),
}

pub struct ResourceMapping {
    key: MappingKey,
    cap: Option<u64>,
    phase: MappingPhase,
    effect_owner: OwnerReceipt,
    map_effect: Option<MapEffectReceipt>,
    owners: Vec<(OwnerReceipt, MappingOwner)>,
}

impl ResourceMapping {
    pub fn key(&self) -> MappingKey {
        self.key
    }
    pub fn cap(&self) -> Option<u64> {
        self.cap
    }
    pub fn phase(&self) -> MappingPhase {
        self.phase
    }
    pub fn owners(&self) -> impl Iterator<Item = (OwnerReceipt, MappingOwner)> + '_ {
        self.owners.iter().copied()
    }
}

/// Sole mapping and owner ledger; capacity growth is fallible before ownership changes.
pub struct ResourceMappingTable {
    authority: u64,
    next_serial: u64,
    next_effect: u64,
    rows: Vec<ResourceMapping>,
}

impl ResourceMappingTable {
    pub const fn new() -> Self {
        Self {
            authority: 0,
            next_serial: 1,
            next_effect: 1,
            rows: Vec::new(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &ResourceMapping> {
        self.rows.iter()
    }

    pub fn try_reserve(&mut self, additional: usize) -> Result<(), MappingError> {
        self.rows
            .try_reserve(additional)
            .map_err(|_| MappingError::InsufficientResources)
    }

    pub fn prepare(
        &mut self,
        key: MappingKey,
        owner: MappingOwner,
    ) -> Result<Admission, MappingError> {
        if key.domain.id == 0
            || key.domain.cookie == 0
            || key.pml4 == 0
            || key.virtual_page == 0
            || key.virtual_page & 0xfff != 0
            || key.virtual_page.checked_add(0x1000).is_none()
            || key.physical_page & 0xfff != 0
            || key.physical_page.checked_add(0x1000).is_none()
            || key.source_cap == 0
            || key.rights == 0
        {
            return Err(MappingError::InvalidKey);
        }
        if owner.device_id == 0 {
            return Err(MappingError::InvalidOwner);
        }

        // A reused numeric VSpace cannot carry leaves from another domain generation.
        let existing = self
            .rows
            .iter()
            .position(|row| row.key.pml4 == key.pml4 && row.key.virtual_page == key.virtual_page);
        if let Some(index) = existing {
            let row = &self.rows[index];
            if !row.key.equivalent(key) {
                return Err(MappingError::Conflict);
            }
            if row.phase != MappingPhase::Mapped {
                return Err(MappingError::Unavailable);
            }
            if let Some((receipt, _)) = row.owners.iter().find(|(_, held)| *held == owner) {
                return Ok(Admission::Joined(*receipt));
            }
            self.rows[index]
                .owners
                .try_reserve(1)
                .map_err(|_| MappingError::InsufficientResources)?;
            let receipt = self.issue_receipt()?;
            self.rows[index].owners.push((receipt, owner));
            return Ok(Admission::Joined(receipt));
        }

        self.try_reserve(1)?;
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(1)
            .map_err(|_| MappingError::InsufficientResources)?;
        let receipt = self.issue_receipt()?;
        owners.push((receipt, owner));
        self.rows.push(ResourceMapping {
            key,
            cap: None,
            phase: MappingPhase::Prepared,
            effect_owner: receipt,
            map_effect: None,
            owners,
        });
        Ok(Admission::New(receipt))
    }

    fn issue_receipt(&mut self) -> Result<OwnerReceipt, MappingError> {
        let next = self
            .next_serial
            .checked_add(1)
            .ok_or(MappingError::IdExhausted)?;
        if self.authority == 0 {
            self.authority = NEXT_AUTHORITY
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| MappingError::IdExhausted)?;
        }
        let receipt = OwnerReceipt {
            authority: self.authority,
            serial: self.next_serial,
        };
        self.next_serial = next;
        Ok(receipt)
    }

    fn index(&self, receipt: OwnerReceipt) -> Result<usize, MappingError> {
        if receipt.authority != self.authority {
            return Err(MappingError::UnknownOwner);
        }
        self.rows
            .iter()
            .position(|row| row.owners.iter().any(|(held, _)| *held == receipt))
            .ok_or(MappingError::UnknownOwner)
    }

    pub fn attach_cap(&mut self, receipt: OwnerReceipt, cap: u64) -> Result<(), MappingError> {
        let index = self.index(receipt)?;
        let row = &mut self.rows[index];
        if row.phase != MappingPhase::Prepared || row.effect_owner != receipt || row.cap.is_some() {
            return Err(MappingError::InvalidPhase);
        }
        if cap == 0 {
            return Err(MappingError::InvalidKey);
        }
        row.cap = Some(cap);
        Ok(())
    }

    /// Reserve the native PageMap effect before entering it, retaining cap and all owners.
    pub fn begin_map(
        &mut self,
        receipt: OwnerReceipt,
    ) -> Result<(u64, MapEffectReceipt), MappingError> {
        let index = self.index(receipt)?;
        let row = &self.rows[index];
        if row.phase != MappingPhase::Prepared || row.effect_owner != receipt {
            return Err(MappingError::InvalidPhase);
        }
        let cap = row.cap.ok_or(MappingError::InvalidPhase)?;
        let effect = self.issue_effect(receipt)?;
        let row = &mut self.rows[index];
        row.phase = MappingPhase::Mapping;
        row.map_effect = Some(effect);
        Ok((cap, effect))
    }

    pub fn acknowledge_map(&mut self, effect: MapEffectReceipt) -> Result<(), MappingError> {
        let index = self.index(effect.owner)?;
        let row = &mut self.rows[index];
        if row.phase != MappingPhase::Mapping || row.map_effect != Some(effect) {
            return Err(MappingError::InvalidPhase);
        }
        row.phase = MappingPhase::Mapped;
        row.map_effect = None;
        Ok(())
    }

    pub fn begin_remap(
        &mut self,
        receipt: OwnerReceipt,
    ) -> Result<(u64, MapEffectReceipt), MappingError> {
        let index = self.index(receipt)?;
        let row = &self.rows[index];
        if row.phase != MappingPhase::Mapped {
            return Err(MappingError::InvalidPhase);
        }
        let cap = row.cap.ok_or(MappingError::InvalidPhase)?;
        let effect = self.issue_effect(receipt)?;
        let row = &mut self.rows[index];
        row.phase = MappingPhase::Mapping;
        row.effect_owner = receipt;
        row.map_effect = Some(effect);
        Ok((cap, effect))
    }

    fn issue_effect(&mut self, owner: OwnerReceipt) -> Result<MapEffectReceipt, MappingError> {
        let next = self
            .next_effect
            .checked_add(1)
            .ok_or(MappingError::IdExhausted)?;
        let effect = MapEffectReceipt {
            authority: self.authority,
            serial: self.next_effect,
            owner,
        };
        self.next_effect = next;
        Ok(effect)
    }

    pub fn mark_map_uncertain(&mut self, effect: MapEffectReceipt) -> Result<(), MappingError> {
        let index = self.index(effect.owner)?;
        let row = &mut self.rows[index];
        if row.phase != MappingPhase::Mapping || row.map_effect != Some(effect) {
            return Err(MappingError::InvalidPhase);
        }
        row.phase = MappingPhase::Uncertain;
        Ok(())
    }

    pub fn mark_delete_uncertain(&mut self, receipt: OwnerReceipt) -> Result<(), MappingError> {
        let index = self.index(receipt)?;
        let row = &mut self.rows[index];
        if row.phase != MappingPhase::Retiring || row.effect_owner != receipt {
            return Err(MappingError::InvalidPhase);
        }
        row.phase = MappingPhase::Uncertain;
        Ok(())
    }

    pub fn begin_release(&mut self, receipt: OwnerReceipt) -> Result<ReleaseAction, MappingError> {
        let index = self.index(receipt)?;
        let row = &mut self.rows[index];
        if matches!(
            row.phase,
            MappingPhase::Mapping | MappingPhase::Uncertain | MappingPhase::Retiring
        ) {
            return Err(MappingError::Unavailable);
        }
        if row.owners.len() > 1 {
            row.owners.retain(|(held, _)| *held != receipt);
            return Ok(ReleaseAction::OwnerReleased);
        }
        if let Some(cap) = row.cap {
            row.phase = MappingPhase::Retiring;
            row.effect_owner = receipt;
            Ok(ReleaseAction::DeleteCap(cap))
        } else {
            self.rows.remove(index);
            Ok(ReleaseAction::UnmappedReleased)
        }
    }

    pub fn acknowledge_delete(&mut self, receipt: OwnerReceipt) -> Result<(), MappingError> {
        let index = self.index(receipt)?;
        let row = &self.rows[index];
        if row.phase != MappingPhase::Retiring || row.effect_owner != receipt {
            return Err(MappingError::InvalidPhase);
        }
        self.rows.remove(index);
        Ok(())
    }
}
