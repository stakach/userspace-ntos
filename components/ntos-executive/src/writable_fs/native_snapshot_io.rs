//! Move-only commands handed from retained snapshot owners to the outer native block executor.

use super::*;
use alloc::vec::Vec;
use nt_memory_manager::SectionMountId;

enum SnapshotOwnerToken {
    Mutation { work_id: u64, request: nt_fs::AsyncWalIoRequest },
    RelationWal {
        claim: nt_pnp_context::native_route_publication::RelationWalClaim<
            nt_pnp_manager::DeviceRelationInvalidation, nt_fs::AsyncWalIoRequest,
        >,
    },
    Hive(super::hive_wal::HiveTicket),
    Storage(snapshot_storage::SnapshotStorageTicket),
    Checkpoint(super::native_checkpoint::CheckpointTicket),
    Fold(super::system_wal_fold::native::FoldTicket),
}

#[must_use = "retain the native snapshot claim through exact provider terminal and ACK"]
pub(crate) struct SnapshotClaim {
    pub mount: SectionMountId,
    pub operation: nt_fs::BlockOperation,
    pub input: Vec<u8>,
    owner: SnapshotOwnerToken,
}

impl SnapshotClaim {
    pub(crate) fn from_hive(
        mount: SectionMountId, operation: nt_fs::BlockOperation, input: Vec<u8>,
        ticket: super::hive_wal::HiveTicket,
    ) -> Self {
        Self { mount, operation, input, owner: SnapshotOwnerToken::Hive(ticket) }
    }
    pub(crate) fn from_checkpoint(
        mount: SectionMountId, operation: nt_fs::BlockOperation, input: Vec<u8>,
        ticket: super::native_checkpoint::CheckpointTicket,
    ) -> Self {
        Self { mount, operation, input, owner: SnapshotOwnerToken::Checkpoint(ticket) }
    }
    pub(crate) fn from_fold(
        mount: SectionMountId, operation: nt_fs::BlockOperation, input: Vec<u8>,
        ticket: super::system_wal_fold::native::FoldTicket,
    ) -> Self {
        Self { mount, operation, input, owner: SnapshotOwnerToken::Fold(ticket) }
    }
    pub(crate) fn from_storage(
        mount: SectionMountId, operation: nt_fs::BlockOperation, input: Vec<u8>,
        ticket: snapshot_storage::SnapshotStorageTicket,
    ) -> Self {
        Self { mount, operation, input, owner: SnapshotOwnerToken::Storage(ticket) }
    }

    pub(crate) fn from_mutation(
        mount: SectionMountId, operation: nt_fs::BlockOperation, input: Vec<u8>,
        work_id: u64, request: nt_fs::AsyncWalIoRequest,
    ) -> Self {
        Self { mount, operation, input,
            owner: SnapshotOwnerToken::Mutation { work_id, request } }
    }

    pub(crate) fn from_relation_wal(
        mount: SectionMountId, operation: nt_fs::BlockOperation, input: Vec<u8>,
        owner: nt_pnp_manager::DeviceRelationInvalidation, request: nt_fs::AsyncWalIoRequest,
    ) -> Self {
        Self { mount, operation, input,
            owner: SnapshotOwnerToken::RelationWal {
                claim: nt_pnp_context::native_route_publication::RelationWalClaim { owner, request },
            },
        }
    }
}

pub(crate) fn admission_busy(status: u32) -> bool {
    status == snapshot_storage::BUSY
}

static mut RELATION_WAL_FIRST: bool = false;

/// Claim at most one request from an owner already retained in the executive. No caller may
/// create a physical command from a copied LBA or an unheld snapshot lease.
pub(crate) unsafe fn claim_next_native_snapshot_io() -> Option<SnapshotClaim> {
    let generic = || snapshot_storage::claim_next_storage_io()
        .or_else(|| super::native_checkpoint::claim_next())
        .or_else(|| super::system_wal_fold::native::claim_next())
        .or_else(|| super::hive_wal::claim_next_native_hive_io().map(
            |(ticket, mount, operation, input)| SnapshotClaim::from_hive(
                mount, operation, input, ticket)))
        .or_else(|| crate::registry_mutation_work::claim_next_native_wal_io());
    let relation = || claim_retained_relation_wal_io();
    let claim = if *core::ptr::addr_of!(RELATION_WAL_FIRST) {
        relation().or_else(generic)
    } else {
        generic().or_else(relation)
    };
    if claim.is_some() {
        *core::ptr::addr_of_mut!(RELATION_WAL_FIRST) =
            !*core::ptr::addr_of!(RELATION_WAL_FIRST);
    }
    claim
}

pub(crate) unsafe fn claim_relation_header_recheck(id: u64) -> Option<SnapshotClaim> {
    snapshot_storage::claim_storage_io_for(id)
}

/// A retained registry mutation may claim only its own authenticated header recheck.
/// The caller separately requires the normally published native storage route.
pub(crate) unsafe fn claim_registry_header_recheck(id: u64) -> Option<SnapshotClaim> {
    snapshot_storage::claim_storage_io_for(id)
}

pub(crate) unsafe fn claim_retained_relation_wal_io() -> Option<SnapshotClaim> {
    crate::driver_launch::claim_native_relation_wal_io()
}

pub(crate) unsafe fn mark_entered_native_snapshot_io(claim: &SnapshotClaim) -> Result<(), u32> {
    match &claim.owner {
        SnapshotOwnerToken::Hive(ticket) => {
            super::hive_wal::mark_native_hive_io_entered(ticket)?;
            if ticket.enters_wal_effect() {
                crate::mutable_hive_mutation_work::mark_prepared_entered(ticket.owner_id())?;
            }
            Ok(())
        }
        SnapshotOwnerToken::Mutation { work_id, request } =>
            crate::registry_mutation_work::mark_native_wal_io_entered(*work_id, *request),
        SnapshotOwnerToken::RelationWal { claim } =>
            crate::driver_launch::mark_native_relation_wal_entered(claim.owner, claim.request),
        SnapshotOwnerToken::Storage(ticket) => snapshot_storage::mark_storage_io_entered(ticket),
        SnapshotOwnerToken::Checkpoint(ticket) => super::native_checkpoint::mark_entered(ticket),
        SnapshotOwnerToken::Fold(ticket) => super::system_wal_fold::native::mark_entered(ticket),
    }
}

pub(crate) unsafe fn release_unentered_native_snapshot_io(claim: SnapshotClaim) -> Result<(), u32> {
    match claim.owner {
        SnapshotOwnerToken::Hive(ticket) => super::hive_wal::release_unentered_native_hive_io(ticket),
        SnapshotOwnerToken::Mutation { work_id, request } =>
            crate::registry_mutation_work::release_unentered_native_wal_io(work_id, request),
        SnapshotOwnerToken::RelationWal { claim } =>
            crate::driver_launch::release_unentered_native_relation_wal(claim.owner, claim.request),
        SnapshotOwnerToken::Storage(ticket) => snapshot_storage::release_unentered_storage_io(ticket),
        SnapshotOwnerToken::Checkpoint(ticket) => super::native_checkpoint::release_unentered(ticket),
        SnapshotOwnerToken::Fold(ticket) => super::system_wal_fold::native::release_unentered(ticket),
    }
}

/// A permanent local refusal cannot be retried as though the exact command was busy.
pub(crate) unsafe fn refuse_unentered_native_snapshot_io(
    claim: SnapshotClaim, status: nt_status::NtStatus,
) -> Result<(), u32> {
    match claim.owner {
        SnapshotOwnerToken::Hive(ticket) => super::hive_wal::refuse_unentered_native_hive_io(ticket, status),
        SnapshotOwnerToken::Mutation { work_id, request } =>
            crate::registry_mutation_work::refuse_unentered_native_wal_io(work_id, request, status),
        SnapshotOwnerToken::RelationWal { claim } =>
            crate::driver_launch::refuse_unentered_native_relation_wal(claim.owner, claim.request, status),
        SnapshotOwnerToken::Storage(ticket) => snapshot_storage::refuse_unentered_storage_io(ticket, status),
        SnapshotOwnerToken::Checkpoint(ticket) => super::native_checkpoint::refuse_unentered(ticket, status),
        SnapshotOwnerToken::Fold(ticket) => super::system_wal_fold::native::refuse_unentered(ticket, status),
    }
}

pub(crate) unsafe fn complete_native_snapshot_io(
    claim: SnapshotClaim, result: Result<&[u8], nt_status::NtStatus>,
) -> Result<(), u32> {
    match claim.owner {
        SnapshotOwnerToken::Hive(ticket) => super::hive_wal::complete_native_hive_io(ticket, result),
        SnapshotOwnerToken::Mutation { work_id, request } =>
            crate::registry_mutation_work::complete_native_wal_io(work_id, request, result),
        SnapshotOwnerToken::RelationWal { claim } =>
            crate::driver_launch::complete_native_relation_wal_io(claim.owner, claim.request, result),
        SnapshotOwnerToken::Storage(ticket) => snapshot_storage::complete_storage_io(ticket, result),
        SnapshotOwnerToken::Checkpoint(ticket) => super::native_checkpoint::complete(ticket, result),
        SnapshotOwnerToken::Fold(ticket) => super::system_wal_fold::native::complete(ticket, result),
    }
}
