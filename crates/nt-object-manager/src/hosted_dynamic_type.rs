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

impl DynamicObjectLease {
    pub const fn generation(self) -> u64 { self.generation }
    pub const fn body(self) -> u64 { self.body }
    pub const fn type_id(self) -> DynamicTypeId { self.type_id }
}

/// An authenticated process-table identity, never assembled from driver-supplied arguments.
/// A PID alone can be reused; the creation sequence distinguishes successive process objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicHandleOwner {
    pub process_id: u32,
    pub creation_sequence: u64,
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
    creator_reference: bool,
    handle: Option<(DynamicHandleOwner, u64)>,
    borrowed_references: u64,
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
        self.objects.push(ObjectRow {
            lease,
            creator_reference: true,
            handle: None,
            borrowed_references: 0,
            in_flight: false,
        });
        self.next_object = next;
        Ok(lease)
    }

    /// Resolve an exact live object incarnation. A recycled body address cannot stand in for a
    /// previous lease because generations are never reused.
    pub fn object_for_body(&self, body: u64, generation: u64) -> Option<DynamicObjectLease> {
        self.objects.iter().find(|row| {
            row.lease.body == body && row.lease.generation == generation && !row.in_flight
        }).map(|row| row.lease)
    }

    pub fn object_for_handle(
        &self, owner: DynamicHandleOwner, handle: u64,
    ) -> Option<DynamicObjectLease> {
        self.objects.iter().find(|row| row.handle == Some((owner, handle)) && !row.in_flight)
            .map(|row| row.lease)
    }

    pub fn pending_object_for_body(&self, body: u64) -> Option<DynamicObjectLease> {
        self.objects.iter().find(|row| {
            row.lease.body == body && row.creator_reference && !row.in_flight
        }).map(|row| row.lease)
    }

    /// Transfer the sole creator reference to an inserted handle. The caller must supply a
    /// concrete handle already reserved for this object; duplicate numeric handles cannot name
    /// two live dynamic objects in this ledger.
    pub fn insert_object(
        &mut self,
        lease: DynamicObjectLease,
        owner: DynamicHandleOwner,
        handle: u64,
    ) -> Result<(), NtStatus> {
        if handle == 0 || owner.process_id == 0 || owner.creation_sequence == 0
            || self.objects.iter().any(|row| row.handle == Some((owner, handle))) {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let row = self.objects.iter_mut().find(|row| row.lease == lease)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if !row.creator_reference || row.in_flight {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        row.handle = Some((owner, handle));
        row.creator_reference = false;
        Ok(())
    }

    /// `ObInsertObject` consumes the creator reference even if handle publication fails. The
    /// native broker must invoke the type's delete procedure before freeing the body.
    pub fn fail_insert(&mut self, lease: DynamicObjectLease) -> Result<(), NtStatus> {
        let row = self.objects.iter_mut().find(|row| row.lease == lease)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if !row.creator_reference || row.in_flight {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        row.creator_reference = false;
        Ok(())
    }

    /// Return a typed body reference and retain it independently of the handle. A later close
    /// cannot delete the body until every borrowed reference is released.
    pub fn reference_handle(
        &mut self,
        owner: DynamicHandleOwner,
        handle: u64,
        expected_type: DynamicTypeId,
    ) -> Result<DynamicObjectLease, NtStatus> {
        let row = self.objects.iter_mut().find(|row| row.handle == Some((owner, handle)))
            .ok_or(NtStatus::INVALID_HANDLE)?;
        if row.lease.type_id != expected_type {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        row.borrowed_references = row.borrowed_references.checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        Ok(row.lease)
    }

    pub fn close_handle(&mut self, owner: DynamicHandleOwner, handle: u64) -> Result<(), NtStatus> {
        let row = self.objects.iter_mut().find(|row| row.handle == Some((owner, handle)))
            .ok_or(NtStatus::INVALID_HANDLE)?;
        row.handle = None;
        Ok(())
    }

    /// Process rundown has already removed this exact generation from its canonical table.
    /// Its table walk does not expose the numeric handle, so the lease is the close receipt.
    pub fn close_removed_object(&mut self, lease: DynamicObjectLease) -> Result<(), NtStatus> {
        let row = self.objects.iter_mut().find(|row| row.lease == lease)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if row.handle.is_none() || row.in_flight {
            return Err(NtStatus::INVALID_HANDLE);
        }
        row.handle = None;
        Ok(())
    }

    pub fn dereference_object(&mut self, lease: DynamicObjectLease) -> Result<(), NtStatus> {
        let row = self.objects.iter_mut().find(|row| row.lease == lease)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if row.borrowed_references == 0 || row.in_flight {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        row.borrowed_references -= 1;
        Ok(())
    }

    pub fn borrowed_references(&self, lease: DynamicObjectLease) -> Option<u64> {
        self.objects.iter().find(|row| row.lease == lease && !row.in_flight)
            .map(|row| row.borrowed_references)
    }

    /// Claim the delete callback once the creator, handle, and borrowed references are all gone.
    /// An uncertain call remains in flight and cannot be retried.
    pub fn take_delete(&mut self, lease: DynamicObjectLease) -> Option<DynamicDeleteTicket> {
        let row = self.objects.iter_mut().find(|row| {
            row.lease == lease && !row.creator_reference && row.handle.is_none()
                && row.borrowed_references == 0 && !row.in_flight
        })?;
        let ty = self.types.iter().find(|ty| ty.id == lease.type_id)?;
        row.in_flight = true;
        Some(DynamicDeleteTicket {
            owner: ty.owner,
            callback: ty.definition.delete_procedure,
            object: lease.body,
            lease,
        })
    }

    /// The object rows are the durable pending queue. Claim only after a delivery lane is ready.
    pub fn next_ready_delete(&self) -> Option<DynamicObjectLease> {
        self.objects.iter().find(|row| {
            !row.creator_reference && row.handle.is_none()
                && row.borrowed_references == 0 && !row.in_flight
        }).map(|row| row.lease)
    }

    pub fn lease_for_live_body(&self, body: u64) -> Option<DynamicObjectLease> {
        self.objects.iter().find(|row| row.lease.body == body && !row.in_flight)
            .map(|row| row.lease)
    }

    /// Includes a callback already in flight. Its body cannot enter the pool free list until
    /// DeleteProcedure has definitely returned and the ledger has completed that exact ticket.
    pub fn owns_live_body(&self, type_id: DynamicTypeId, body: u64) -> bool {
        self.objects.iter().any(|row| {
            row.lease.type_id == type_id && row.lease.body == body
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
