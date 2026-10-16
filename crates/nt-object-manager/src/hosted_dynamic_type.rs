//! Loaded-image ownership for native `ObCreateObjectType` definitions.
//!
//! An object type retains its name, access policy, and driver delete procedure for the lifetime
//! of the type. In particular, dropping the last object does not unregister the type or allow its
//! provider image to retire. This ledger records exact image and domain generations; the native
//! broker supplies those identities after authenticating the physical provider.

use alloc::vec::Vec;
use nt_status::NtStatus;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicTypeOwner {
    pub image_base: u64,
    pub image_len: u64,
    pub image_generation: u64,
    pub domain_id: u64,
    pub domain_cookie: u64,
}

impl DynamicTypeOwner {
    fn contains_callback(self, callback: u64) -> bool {
        self.image_base != 0
            && self.image_generation != 0
            && self.domain_id != 0
            && self.domain_cookie != 0
            && self.image_base.checked_add(self.image_len)
                .is_some_and(|end| self.image_len != 0 && callback >= self.image_base && callback < end)
    }
}

/// The initializer fields that affect `DxgkSharedResource` creation and access. The native
/// adapter validates/copies these from the provider's `OBJECT_TYPE_INITIALIZER` before admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicTypeDefinition {
    pub name: Vec<u16>,
    pub delete_procedure: u64,
    pub invalid_attributes: u32,
    pub generic_mapping: [u32; 4],
    pub valid_access_mask: u32,
    pub pool_type: u32,
    pub default_nonpaged_pool_charge: u32,
    pub use_default_object: bool,
    pub security_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicTypeId(u64);

impl DynamicTypeId {
    /// Registry sequence, used by the native broker to assign a distinct OBJECT_TYPE index.
    pub const fn sequence(self) -> u64 { self.0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicObjectLease {
    type_id: DynamicTypeId,
    generation: u64,
    body: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicDeleteTicket {
    pub owner: DynamicTypeOwner,
    pub callback: u64,
    pub object: u64,
    lease: DynamicObjectLease,
}

struct RegisteredType {
    id: DynamicTypeId,
    owner: DynamicTypeOwner,
    definition: DynamicTypeDefinition,
}

struct ObjectRow {
    lease: DynamicObjectLease,
    in_flight: bool,
}

/// A memory-only type and delete-callback ledger. Actual `OBJECT_TYPE` memory, object bodies,
/// handles, and provider IPC are owned by their corresponding native layers.
#[derive(Default)]
pub struct HostedDynamicTypeRegistry {
    types: Vec<RegisteredType>,
    objects: Vec<ObjectRow>,
    next_type: u64,
    next_object: u64,
}

impl HostedDynamicTypeRegistry {
    pub fn new() -> Self { Self::default() }

    pub fn type_count(&self) -> usize { self.types.len() }

    pub fn register(
        &mut self,
        owner: DynamicTypeOwner,
        definition: DynamicTypeDefinition,
    ) -> Result<DynamicTypeId, NtStatus> {
        if !owner.contains_callback(definition.delete_procedure)
            || definition.name.is_empty()
            || definition.name.len() > (u16::MAX as usize / 2)
            || definition.name.contains(&0)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self.types.iter().any(|row| row.definition.name == definition.name) {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        let next = self.next_type.checked_add(1).ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.types.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let id = DynamicTypeId(next);
        self.types.push(RegisteredType { id, owner, definition });
        self.next_type = next;
        Ok(id)
    }

    pub fn owner(&self, id: DynamicTypeId) -> Option<DynamicTypeOwner> {
        self.types.iter().find(|row| row.id == id).map(|row| row.owner)
    }

    pub fn definition(&self, id: DynamicTypeId) -> Option<&DynamicTypeDefinition> {
        self.types.iter().find(|row| row.id == id).map(|row| &row.definition)
    }

    /// `ObCreateObjectType` has no corresponding unregister. A registered delete procedure keeps
    /// its image and physical domain alive, even when no object body is currently allocated.
    pub fn blocks_owner_retirement(&self, owner: DynamicTypeOwner) -> bool {
        self.types.iter().any(|row| row.owner == owner)
    }

    /// Called only after the native object broker owns a concrete body of this exact type.
    pub fn publish_object(
        &mut self,
        type_id: DynamicTypeId,
        body: u64,
    ) -> Result<DynamicObjectLease, NtStatus> {
        if body == 0 || !self.types.iter().any(|row| row.id == type_id)
            || self.objects.iter().any(|row| row.lease.body == body)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let next = self.next_object.checked_add(1).ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.objects.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let lease = DynamicObjectLease { type_id, generation: next, body };
        self.objects.push(ObjectRow { lease, in_flight: false });
        self.next_object = next;
        Ok(lease)
    }

    /// Claim the delete callback once. An uncertain call remains in flight and cannot be retried.
    pub fn take_delete(&mut self, lease: DynamicObjectLease) -> Option<DynamicDeleteTicket> {
        let row = self.objects.iter_mut().find(|row| row.lease == lease && !row.in_flight)?;
        let ty = self.types.iter().find(|ty| ty.id == lease.type_id)?;
        row.in_flight = true;
        Some(DynamicDeleteTicket {
            owner: ty.owner,
            callback: ty.definition.delete_procedure,
            object: lease.body,
            lease,
        })
    }

    /// Called only after the native provider callback has definitely returned. The type itself
    /// remains registered and continues to retain the provider image.
    pub fn complete_delete(&mut self, ticket: DynamicDeleteTicket) -> Result<(), NtStatus> {
        let position = self.objects.iter().position(|row| row.lease == ticket.lease && row.in_flight)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let ty = self.types.iter().find(|ty| ty.id == ticket.lease.type_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if ticket.owner != ty.owner
            || ticket.callback != ty.definition.delete_procedure
            || ticket.object != ticket.lease.body
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.objects.remove(position);
        Ok(())
    }
}
