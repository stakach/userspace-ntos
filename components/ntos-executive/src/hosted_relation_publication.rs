// Retained CM and PnP publication for one hosted bus relation query.
// The enclosing query owns this value across pump turns. A transport failure never releases
// its CM token, snapshot lease, prepared PnP batches, or invalidation claim.

use nt_config_client::{
    CmMutationBeginAttempt, CmMutationBeginAttempts, CmMutationBeginOperation,
    CmMutationPreparationOperation, CmMutationPreparationPhase, PreparedSystemHiveMutation,
    SystemHiveMutationAbortAcknowledgement, SystemHiveMutationAbortReceipt,
    SystemHiveMutationAcknowledgement, SystemHiveMutationCommitReceipt,
    SystemHiveMutationPreparation,
};

#[derive(Clone, Copy)]
enum HostedRelationPublicationPhase {
    AcquireBusLease,
    ProveNativeDisk,
    Begin,
    Prepare,
    Admit,
    Durable,
    Commit,
    DurableCommit,
    Reprepare,
    PostCommitRepair,
    FinishLocalPublication,
    Acknowledge,
    Release,
    ReleaseBus,
    Rollback,
    Abort,
    AbortStorage,
    AcknowledgeAbort,
    ReleaseRollback,
    AbortProvider,
    ReleaseRefusedBus,
    Published,
    Refused,
}

enum HostedRelationPublicationProgress {
    Pending,
    Published,
    Refused(nt_status::NtStatus),
}

#[must_use = "retain the exact CM and PnP owners until publication or acknowledged abort"]
struct HostedRelationPublication {
    claim: nt_pnp_manager::DeviceRelationInvalidation,
    relation_owner: nt_pnp::AcpiPciProviderEndpoint,
    parent_relation: nt_pnp_manager::ParentRelationIdentity,
    mount_identity: u64,
    children: usize,
    bus_lease: Option<nt_pnp_manager::BusRelationPublicationLease>,
    original_changes: Option<Vec<nt_pnp_manager::BusRelationChange>>,
    after_bus_lease: HostedRelationPublicationPhase,
    after_native_disk: HostedRelationPublicationPhase,
    native_disk_required: bool,
    native_disk_candidate: usize,
    native_disk_proof: Option<crate::driver_launch::native_disk_relation::NativeDiskProof>,
    native_disk_refresh: Option<(
        crate::driver_launch::native_disk_relation::NativeStorageRoute,
        crate::driver_launch::native_disk_relation::NativeStorageRoute,
    )>,
    native_disk_published: bool,
    reported_children: Vec<nt_pnp_manager::BusReportedChild>,
    child_properties: Vec<HostedBusChildProperties>,
    providers: Vec<(u64, nt_io_manager::HostedDevicePointerRegistration)>,
    catalog_sources: Vec<nt_pnp::AcpiPciScopeSource>,
    catalog_link_candidates: Vec<nt_pnp::AcpiPciLinkCandidateFact>,
    prepared_relations: Option<nt_pnp_manager::PreparedBusRelations>,
    prepared_devnodes: Option<nt_pnp_manager::PreparedEnumeratedPdoBatch>,
    provider_batch: Option<nt_pnp_manager::PreparedAcceptedPdoProviderBatch>,
    critical_starts: Vec<(u64, String)>,
    critical_start_index: usize,
    catalog_update: Option<nt_pnp::PreparedAcpiPciScopeCatalogUpdate>,
    pci_catalog_published: bool,
    invalidation_completion: Option<nt_pnp_manager::DeviceRelationInvalidationCompletion>,
    route_reconciliation_ready: Option<bool>,
    _mutations: Vec<HostedRelationRegistryMutation>,
    attempt: Option<CmMutationBeginAttempt<()>>,
    preparation: Option<SystemHiveMutationPreparation<()>>,
    prepared: Option<PreparedSystemHiveMutation>,
    persistence: crate::registry_mutation_work::MutationPersistence,
    receipt: Option<SystemHiveMutationCommitReceipt>,
    acknowledgement: Option<SystemHiveMutationAcknowledgement>,
    abort_receipt: Option<SystemHiveMutationAbortReceipt>,
    abort_acknowledgement: Option<SystemHiveMutationAbortAcknowledgement>,
    phase: HostedRelationPublicationPhase,
    commit_entered: bool,
    preparation_refused: bool,
    refusal: nt_status::NtStatus,
}

// The server's requester grant survives an acknowledged publication. Reuse that exact bank
// across successive bus relation queries so completed owners do not consume fresh grants.
static mut RELATION_BEGIN_ATTEMPTS: CmMutationBeginAttempts = CmMutationBeginAttempts::new();

pub(super) unsafe fn reserve_relation_mutation_begin(
    mount: nt_config_client::SystemHiveMount,
    expected_generation: u64,
    mutations: &[nt_config_client::SystemHiveMutation<'_>],
) -> Result<CmMutationBeginAttempt<()>, (i32, ())> {
    (&mut *core::ptr::addr_of_mut!(RELATION_BEGIN_ATTEMPTS))
        .reserve(mount, expected_generation, mutations, ())
}

unsafe fn relation_begin_attempts() -> &'static mut CmMutationBeginAttempts {
    &mut *core::ptr::addr_of_mut!(RELATION_BEGIN_ATTEMPTS)
}

impl HostedRelationPublication {
    fn pending(&self) -> HostedRelationPublicationProgress {
        HostedRelationPublicationProgress::Pending
    }
}

unsafe fn finish_hosted_relation_local_publication(
    owner: &mut HostedRelationPublication,
) -> bool {
    use HostedRelationPublicationPhase as Phase;
    if owner.native_disk_required && !owner.native_disk_published {
        if let Some((previous, next)) = owner.native_disk_refresh {
            if crate::driver_launch::native_disk_relation::validate_refreshed_native_storage_route(
                previous, next,
            ).is_err() { return false; }
        } else if owner.native_disk_proof.is_none() { return false; }
    }
    if let Some(prepared) = owner.catalog_update.take() {
        match crate::hosted_pci_topology::try_commit_hosted_acpi_pci_relation_sources(prepared) {
            Ok(_) => owner.pci_catalog_published = true,
            Err((_status, prepared)) => {
                owner.catalog_update = Some(prepared);
                return false;
            }
        }
    }
    while owner.critical_start_index < owner.critical_starts.len() {
        let (pdo, instance_id) = &mut owner.critical_starts[owner.critical_start_index];
        let owned = core::mem::take(instance_id);
        if let Err((_error, retained)) = hosted_critical_child_starts_mut()
            .try_reserve_committed_owned(
            hosted_pnp_manager_mut(), hosted_bus_relations(), owner.mount_identity,
            *pdo, owned,
        ) {
            *instance_id = retained;
            return false;
        }
        owner.critical_start_index += 1;
    }
    if owner.invalidation_completion.is_none() {
        let completion = match hosted_device_relation_invalidations_mut()
            .complete_terminal(owner.claim, nt_status::NtStatus::SUCCESS)
        {
            Ok(completion) => completion,
            Err(_) => return false,
        };
        owner.invalidation_completion = Some(completion);
        remove_hosted_device_relation_owner(owner.claim);
    }
    if owner.route_reconciliation_ready.is_none() {
        let ready = match crate::hosted_pci_topology::note_hosted_pci_relation_completion(
            owner.relation_owner, owner.claim,
            owner.invalidation_completion.expect("retained invalidation completion"),
            owner.pci_catalog_published,
        ) {
            Ok(ready) => ready,
            Err(_) => return false,
        };
        owner.route_reconciliation_ready = Some(ready);
    }
    if owner.native_disk_required && !owner.native_disk_published {
        if let Some(proof) = owner.native_disk_proof.as_mut() {
            if proof.mark_published().is_err() { return false; }
        }
        if let Some((previous, next)) = owner.native_disk_refresh {
            if crate::driver_launch::native_disk_relation::commit_refreshed_native_storage_route(
                previous, next,
            ).is_err() { return false; }
            owner.native_disk_refresh = None;
        }
        owner.native_disk_published = true;
    }
    owner.phase = if owner.receipt.is_some() {
        Phase::Acknowledge
    } else {
        Phase::ReleaseBus
    };
    true
}

unsafe fn advance_hosted_relation_publication(
    owner: &mut HostedRelationPublication,
) -> HostedRelationPublicationProgress {
    use HostedRelationPublicationPhase as Phase;
    // Bound each pump turn; a transport or storage refusal always leaves this owner installed.
    for _ in 0..16 {
        match owner.phase {
            Phase::AcquireBusLease => {
                if owner.bus_lease.is_none() {
                    let lease = match hosted_bus_relations_mut()
                        .reserve_publication_lease(owner.claim.pdo_device_id)
                    {
                        Ok(lease) => lease,
                        Err(_) => return owner.pending(),
                    };
                    owner.bus_lease = Some(lease);
                }
                if owner.original_changes.is_none() {
                    let changes = owner.prepared_relations.as_ref()
                        .expect("retained relation before bus lease")
                        .changes();
                    let mut original = Vec::new();
                    if original.try_reserve_exact(changes.len()).is_err() {
                        return owner.pending();
                    }
                    original.extend_from_slice(changes);
                    owner.original_changes = Some(original);
                }
                owner.phase = owner.after_bus_lease;
            }
            Phase::ProveNativeDisk => {
                if owner.native_disk_proof.is_none() && owner.native_disk_refresh.is_none() {
                    if let Some(published) = crate::driver_launch::native_disk_relation::native_storage_route() {
                        if crate::fs_loader::exec_native_block_pending(published.mount).is_some() {
                            return owner.pending();
                        }
                        let next = owner.providers.iter().find_map(|(pdo, registration)| {
                            (*pdo == published.scsi.pdo.raw()
                                && registration.domain() == published.scsi.provider
                                && registration.address() == published.scsi.provider_pdo)
                                .then_some(*registration)
                        });
                        let Some(registration) = next else {
                            owner.refusal = nt_status::NtStatus::INVALID_DEVICE_REQUEST;
                            owner.phase = Phase::AbortProvider;
                            continue;
                        };
                        let next_generation = owner.parent_relation.relation().generation();
                        let mut key = published.key;
                        key.relation.generation = next_generation;
                        if crate::boot_storage_dma_handoff::validate_native_disk_refresh(
                            published.key, key,
                        ).is_err()
                            || registration.device_id() != published.scsi.pdo
                            || io_manager_mut().device(published.scsi.pdo)
                                .is_none_or(|device| device.delete_pending
                                    || device.driver_id != published.driver_id)
                        {
                            owner.refusal = nt_status::NtStatus::INVALID_DEVICE_REQUEST;
                            owner.phase = Phase::AbortProvider;
                            continue;
                        }
                        let mut route = published;
                        route.scsi.relation_generation = next_generation;
                        route.key = key;
                        if crate::driver_launch::native_disk_relation::begin_native_storage_refresh(
                            published,
                        ).is_err() { return owner.pending(); }
                        owner.native_disk_refresh = Some((published, route));
                        owner.phase = owner.after_native_disk;
                        continue;
                    }
                }
                if owner.native_disk_proof.is_none() {
                    if owner.native_disk_candidate >= owner.reported_children.len() {
                        owner.refusal = nt_status::NtStatus::DEVICE_NOT_READY;
                        owner.phase = Phase::AbortProvider;
                        continue;
                    }
                    let pdo = owner.reported_children[owner.native_disk_candidate].pdo_object_id;
                    let Some((_, registration)) = owner.providers.iter()
                        .find(|(device, _)| *device == pdo).copied()
                    else {
                        owner.refusal = nt_status::NtStatus::INVALID_DEVICE_REQUEST;
                        owner.phase = Phase::AbortProvider;
                        continue;
                    };
                    let Some(device) = io_manager_mut().device(nt_io_manager::DeviceId(pdo)) else {
                        owner.refusal = nt_status::NtStatus::INVALID_DEVICE_REQUEST;
                        owner.phase = Phase::AbortProvider;
                        continue;
                    };
                    let driver_id = device.driver_id;
                    if device.delete_pending || driver_id.is_null() {
                        owner.refusal = nt_status::NtStatus::INVALID_DEVICE_REQUEST;
                        owner.phase = Phase::AbortProvider;
                        continue;
                    }
                    let relation = nt_pnp_context::native_storage_handoff::StorageRelation {
                        bus_device: owner.claim.pdo_device_id,
                        generation: owner.parent_relation.relation().generation(),
                        provider_domain: registration.domain().domain_id.raw(),
                        provider_cookie: registration.domain().cookie,
                    };
                    let storage_pdo = nt_pnp_context::native_storage_handoff::StoragePdo {
                        device: pdo,
                        raw_pointer: registration.address(),
                        provider_driver: driver_id.raw(),
                    };
                    let handoff = match crate::boot_storage_dma_handoff::begin_native_disk_proof(
                        relation, storage_pdo,
                    ) {
                        Ok(handoff) => handoff,
                        Err(status) if status == nt_status::NtStatus::DEVICE_NOT_READY =>
                            return owner.pending(),
                        Err(_) => {
                            owner.native_disk_candidate += 1;
                            continue;
                        }
                    };
                    let Some((mount, _)) = crate::fs_loader::exec_expected_disk() else {
                        return owner.pending();
                    };
                    if mount.value() != handoff.key().mount { return owner.pending(); }
                    let scsi = nt_io_manager::scsi_srb_transport::ScsiSrbRoute {
                        pdo: nt_io_manager::DeviceId(pdo),
                        provider: registration.domain(),
                        relation_generation: relation.generation,
                        provider_pdo: registration.address(),
                    };
                    let key = handoff.key();
                    owner.native_disk_proof = Some(
                        crate::driver_launch::native_disk_relation::NativeDiskProof::new(
                            handoff,
                            crate::driver_launch::native_disk_relation::NativeStorageRoute {
                                mount, scsi, driver_id, key,
                            },
                        )
                    );
                }
                match owner.native_disk_proof.as_mut().unwrap().progress() {
                    crate::driver_launch::native_disk_relation::ProofProgress::Pending =>
                        return owner.pending(),
                    crate::driver_launch::native_disk_relation::ProofProgress::Refused => {
                        owner.native_disk_proof = None;
                        owner.native_disk_candidate += 1;
                    }
                    crate::driver_launch::native_disk_relation::ProofProgress::Mounted => {
                        owner.phase = owner.after_native_disk;
                    }
                }
            }
            Phase::Begin => {
                let attempt = owner.attempt.as_mut().expect("retained relation BEGIN");
                if attempt.is_acknowledged() {
                    if attempt.outcome_status() == Some(0) {
                        let upload = match relation_begin_attempts().take_upload(attempt) {
                            Ok(upload) => upload,
                            Err(_) => return owner.pending(),
                        };
                        owner.preparation = Some(upload.into_preparation());
                        owner.attempt = None;
                        owner.phase = Phase::Prepare;
                        continue;
                    }
                    let (status, ()) = match relation_begin_attempts().take_failure(attempt) {
                        Ok(failure) => failure,
                        Err(_) => return owner.pending(),
                    };
                    owner.refusal = nt_status::NtStatus(status);
                    owner.attempt = None;
                    owner.phase = Phase::AbortProvider;
                    continue;
                }
                let operation = if attempt.server_nonce().is_none() {
                    CmMutationBeginOperation::Query
                } else if attempt.outcome_status().is_none() {
                    CmMutationBeginOperation::Begin
                } else {
                    CmMutationBeginOperation::Acknowledge
                };
                let mut exchange = match relation_begin_attempts().begin_exchange(attempt, operation) {
                    Ok(exchange) => exchange,
                    Err(_) => return owner.pending(),
                };
                let response = crate::cm_mutation_transport::begin(&exchange);
                if relation_begin_attempts().complete_exchange(attempt, &mut exchange, response).is_err() {
                    return owner.pending();
                }
            }
            Phase::Prepare => {
                use CmMutationPreparationPhase as P;
                let preparation = owner.preparation.as_mut().expect("retained relation PREPARE");
                if preparation.phase() == P::Cancelled {
                    if preparation.take_cancelled().is_err() {
                        return owner.pending();
                    }
                    owner.preparation = None;
                    owner.phase = Phase::AbortProvider;
                    continue;
                }
                if preparation.phase() == P::Prepared && !owner.preparation_refused {
                    let (prepared, ()) = match preparation.take_prepared() {
                        Ok(value) => value,
                        Err(_) => return owner.pending(),
                    };
                    owner.prepared = Some(prepared);
                    owner.preparation = None;
                    owner.phase = Phase::Admit;
                    continue;
                }
                if preparation.phase() == P::Allocating && !owner.preparation_refused {
                    if let Err(status) = preparation.allocate_journal() {
                        owner.refusal = nt_status::NtStatus(status);
                        owner.preparation_refused = true;
                    }
                    continue;
                }
                let operation = match preparation.phase() {
                    P::AcknowledgingCancellation => CmMutationPreparationOperation::AcknowledgeCancellation,
                    _ if owner.preparation_refused => CmMutationPreparationOperation::Cancel,
                    P::Appending => CmMutationPreparationOperation::Append,
                    P::Preparing => CmMutationPreparationOperation::Prepare,
                    P::Pulling => CmMutationPreparationOperation::Pull,
                    _ => return owner.pending(),
                };
                let mut exchange = match preparation.begin_exchange(operation) {
                    Ok(exchange) => exchange,
                    Err(_) => return owner.pending(),
                };
                let response = crate::cm_mutation_transport::prepare(&exchange);
                if let Err(status) = preparation.complete_exchange(&mut exchange, response) {
                    if !owner.preparation_refused {
                        owner.refusal = nt_status::NtStatus(status);
                        owner.preparation_refused = true;
                    }
                    return owner.pending();
                }
            }
            Phase::Admit => {
                let prepared = owner.prepared.as_ref().expect("retained relation preparation");
                if let Err(status) = crate::cm_mutation_transport::validate_storage(prepared) {
                    owner.refusal = nt_status::NtStatus(status);
                    owner.phase = Phase::Abort;
                    continue;
                }
                let mut bytes = Vec::new();
                if bytes.try_reserve_exact(prepared.durable_journal().len()).is_err() {
                    owner.refusal = nt_status::NtStatus::INSUFFICIENT_RESOURCES;
                    owner.phase = Phase::Abort;
                    continue;
                }
                bytes.extend_from_slice(prepared.durable_journal());
                if let Err(status) = owner.persistence.admit(prepared, bytes) {
                    owner.refusal = nt_status::NtStatus(status as i32);
                    owner.phase = Phase::Abort;
                    continue;
                }
                owner.phase = Phase::Durable;
            }
            Phase::Durable => {
                if owner.persistence.make_durable().is_err() {
                    return owner.pending();
                }
                owner.phase = Phase::Commit;
            }
            Phase::Commit => {
                if !owner.commit_entered {
                    if owner.persistence.begin_publication().is_err() {
                        return owner.pending();
                    }
                    owner.commit_entered = true;
                }
                let receipt = match crate::cm_mutation_transport::commit(
                    owner.prepared.as_ref().expect("retained relation COMMIT"),
                ) {
                    Ok(receipt) => receipt,
                    Err(_) => return owner.pending(),
                };
                owner.receipt = Some(receipt);
                owner.phase = Phase::DurableCommit;
            }
            Phase::DurableCommit => {
                if owner.persistence.commit_durable(
                    owner.receipt.expect("retained relation COMMIT receipt"),
                ).is_err() {
                    return owner.pending();
                }
                let outcome = owner.receipt.expect("retained relation COMMIT receipt").outcome();
                crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.fetch_max(
                    outcome.generation, Ordering::AcqRel,
                );
                if outcome.has_pending_device_action
                    && !crate::CONFIG_DEVICE_ACTION_PENDING.swap(true, Ordering::AcqRel)
                {
                    crate::config_manager_request_device_action_wake();
                }
                owner.phase = Phase::PostCommitRepair;
            }
            Phase::Reprepare => {
                // A generation drift invalidates the whole speculative publication. Release
                // the exact old provider lease before capturing its replacement.
                if let Some(batch) = owner.provider_batch.take() {
                    if let Err((_status, batch)) = batch.abort(io_manager_mut()) {
                        owner.provider_batch = Some(batch);
                        return owner.pending();
                    }
                }
                let relation = match hosted_bus_relations_mut().prepare_bus_relations(
                    owner.claim.pdo_device_id, &owner.reported_children,
                ) {
                    Ok(relation) => relation,
                    Err(_) => return owner.pending(),
                };
                if owner.original_changes.as_ref().is_some_and(|original| {
                    relation.changes() != original.as_slice()
                }) {
                    // The retained CM journal described a different delta. A new semantic CM
                    // transaction is required; never ACK the old receipt for this relation.
                    return owner.pending();
                }
                let parent = match hosted_pnp_manager_mut().claim_started_parent_relation(
                    owner.claim.pdo_device_id, relation.relation_identity(),
                ) {
                    Ok(parent) if parent.parent() == owner.claim.parent => parent,
                    _ => return owner.pending(),
                };
                let devnodes = match prepare_hosted_relation_devnodes(
                    &owner.reported_children, &owner.child_properties, parent,
                ) {
                    Ok(devnodes) => devnodes,
                    Err(_) => return owner.pending(),
                };
                let catalog = if owner.catalog_update.is_some() {
                    match crate::hosted_pci_topology::prepare_hosted_acpi_pci_relation_facts(
                        owner.relation_owner, &owner.catalog_sources,
                        &owner.catalog_link_candidates,
                    ) {
                        Ok(catalog) => Some(catalog),
                        Err(_) => return owner.pending(),
                    }
                } else {
                    None
                };
                let providers = match hosted_accepted_pdo_provider_catalog().prepare_relation(
                    io_manager_mut(), parent, &owner.providers,
                ) {
                    Ok(providers) => providers,
                    Err(failure) => {
                        owner.provider_batch = Some(failure.into_rollback());
                        return owner.pending();
                    }
                };
                if owner.native_disk_required {
                    let published = owner.native_disk_refresh.map(|(previous, _)| previous)
                        .or_else(|| crate::driver_launch::native_disk_relation::native_storage_route());
                    let Some(published) = published else {
                        owner.provider_batch = Some(providers);
                        return owner.pending();
                    };
                    let next_generation = parent.relation().generation();
                    let mut key = published.key;
                    key.relation.generation = next_generation;
                    if crate::boot_storage_dma_handoff::validate_native_disk_refresh(
                        published.key, key,
                    ).is_err()
                        || !owner.providers.iter().any(|(pdo, registration)| {
                            *pdo == published.scsi.pdo.raw()
                                && registration.domain() == published.scsi.provider
                                && registration.address() == published.scsi.provider_pdo
                        })
                    {
                        owner.provider_batch = Some(providers);
                        return owner.pending();
                    }
                    if owner.native_disk_refresh.is_none()
                        && crate::driver_launch::native_disk_relation::begin_native_storage_refresh(
                            published,
                        ).is_err()
                    {
                        owner.provider_batch = Some(providers);
                        return owner.pending();
                    }
                    let mut next = published;
                    next.key = key;
                    next.scsi.relation_generation = next_generation;
                    owner.native_disk_refresh = Some((published, next));
                }
                owner.parent_relation = parent;
                owner.prepared_relations = Some(relation);
                owner.prepared_devnodes = Some(devnodes);
                owner.provider_batch = Some(providers);
                owner.catalog_update = catalog;
                owner.phase = Phase::PostCommitRepair;
            }
            Phase::PostCommitRepair => {
                // This entire arm runs on the executive's single-threaded query pump. The
                // preflights and local commits below only touch in-memory owners; none enters
                // IPC, polls a callback, or yields before the terminal claim is consumed.
                if owner.catalog_update.as_ref().is_some_and(|catalog| {
                    crate::hosted_pci_topology::validate_hosted_acpi_pci_relation_sources(catalog)
                        .is_err()
                }) {
                    owner.phase = Phase::Reprepare;
                    return owner.pending();
                }
                if owner.prepared_devnodes.as_ref().zip(owner.prepared_relations.as_ref())
                    .is_some_and(|(devnodes, relation)| {
                        hosted_critical_child_starts_mut().validate_prospective_reservations(
                            hosted_pnp_manager_mut(), devnodes, relation,
                            owner.mount_identity, &owner.critical_starts,
                        ).is_err()
                    })
                {
                    owner.phase = Phase::Reprepare;
                    return owner.pending();
                }
                if owner.invalidation_completion.is_none() {
                    let completion = match hosted_device_relation_invalidations_mut()
                        .preview_complete_terminal(owner.claim, nt_status::NtStatus::SUCCESS)
                    {
                        Ok(completion) => completion,
                        Err(_) => return owner.pending(),
                    };
                    if crate::hosted_pci_topology::validate_hosted_pci_relation_completion(
                        owner.relation_owner, owner.claim, completion,
                        owner.catalog_update.is_some(),
                    ).is_err() {
                        return owner.pending();
                    }
                }
                if owner.prepared_devnodes.is_none() || owner.prepared_relations.is_none()
                    || owner.provider_batch.is_none()
                {
                    return owner.pending();
                }
                let devnodes = owner.prepared_devnodes.take().unwrap();
                let relation = owner.prepared_relations.take().unwrap();
                let providers = owner.provider_batch.take().unwrap();
                match hosted_accepted_pdo_provider_catalog().commit_prospective_relation_with_lease(
                    hosted_pnp_manager_mut(), hosted_bus_relations_mut(), io_manager_mut(),
                    devnodes, relation, providers,
                    owner.bus_lease.expect("retained same-bus CM lease"),
                ) {
                    Ok(()) => {
                        owner.phase = Phase::FinishLocalPublication;
                        if !finish_hosted_relation_local_publication(owner) {
                            return owner.pending();
                        }
                        return owner.pending();
                    }
                    Err((_status, devnodes, relation, providers)) => {
                        owner.prepared_devnodes = Some(devnodes);
                        owner.prepared_relations = Some(relation);
                        owner.provider_batch = Some(providers);
                        owner.phase = Phase::Reprepare;
                        return owner.pending();
                    }
                }
            }
            Phase::FinishLocalPublication => {
                if !finish_hosted_relation_local_publication(owner) {
                    return owner.pending();
                }
                continue;
            }
            Phase::Acknowledge => {
                if owner.acknowledgement.is_none() {
                    let acknowledgement = match crate::cm_mutation_transport::acknowledge(
                        owner.receipt.expect("retained relation COMMIT receipt"),
                    ) {
                        Ok(acknowledgement) => acknowledgement,
                        Err(_) => return owner.pending(),
                    };
                    owner.acknowledgement = Some(acknowledgement);
                }
                owner.phase = Phase::Release;
            }
            Phase::Release => {
                if owner.persistence.release_after_publication(
                    owner.acknowledgement.expect("retained relation COMMIT acknowledgement"),
                ).is_err() {
                    return owner.pending();
                }
                owner.phase = Phase::ReleaseBus;
            }
            Phase::ReleaseBus => {
                if let Some(lease) = owner.bus_lease {
                    if hosted_bus_relations_mut().release_publication_lease(lease).is_err() {
                        return owner.pending();
                    }
                    owner.bus_lease = None;
                }
                owner.phase = Phase::Published;
            }
            Phase::Rollback => {
                if owner.persistence.rollback().is_err() {
                    return owner.pending();
                }
                owner.phase = Phase::Abort;
            }
            Phase::Abort => {
                let receipt = match crate::cm_mutation_transport::abort(
                    owner.prepared.as_ref().expect("retained relation abort"),
                ) {
                    Ok(receipt) => receipt,
                    Err(_) => return owner.pending(),
                };
                owner.abort_receipt = Some(receipt);
                owner.phase = Phase::AbortStorage;
            }
            Phase::AbortStorage => {
                if owner.persistence.abort_after_receipt(
                    owner.abort_receipt.expect("retained relation ABORT receipt"),
                ).is_err() {
                    return owner.pending();
                }
                owner.phase = Phase::AcknowledgeAbort;
            }
            Phase::AcknowledgeAbort => {
                if owner.abort_acknowledgement.is_none() {
                    let acknowledgement = match crate::cm_mutation_transport::acknowledge_abort(
                        owner.abort_receipt.expect("retained relation abort receipt"),
                    ) {
                        Ok(acknowledgement) => acknowledgement,
                        Err(_) => return owner.pending(),
                    };
                    owner.abort_acknowledgement = Some(acknowledgement);
                }
                owner.phase = Phase::ReleaseRollback;
            }
            Phase::ReleaseRollback => {
                if owner.persistence.release_rolled_back(
                    owner.abort_acknowledgement.expect("retained relation ABORT acknowledgement"),
                ).is_err() {
                    return owner.pending();
                }
                owner.phase = Phase::AbortProvider;
            }
            Phase::AbortProvider => {
                if let Some((previous, _)) = owner.native_disk_refresh.take() {
                    crate::driver_launch::native_disk_relation::abort_native_storage_refresh(previous);
                }
                if let Some(batch) = owner.provider_batch.take() {
                    match batch.abort(io_manager_mut()) {
                        Ok(()) => {}
                        Err((_status, batch)) => {
                            owner.provider_batch = Some(batch);
                            return owner.pending();
                        }
                    }
                }
                owner.phase = Phase::ReleaseRefusedBus;
            }
            Phase::ReleaseRefusedBus => {
                if let Some(lease) = owner.bus_lease {
                    if hosted_bus_relations_mut().release_publication_lease(lease).is_err() {
                        return owner.pending();
                    }
                    owner.bus_lease = None;
                }
                owner.phase = Phase::Refused;
            }
            Phase::Published => return HostedRelationPublicationProgress::Published,
            Phase::Refused => return HostedRelationPublicationProgress::Refused(owner.refusal),
        }
    }
    owner.pending()
}
