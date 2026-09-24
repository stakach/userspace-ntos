//! Provider-local IO_SECURITY_CONTEXT for a retained cross-domain CREATE subject.

use super::*;
use nt_kernel_abi::{
    security_create_x64::{
        encode_create_security_graph, CreateSecurityFields, CREATE_SECURITY_GRAPH_SIZE,
    },
    GuestAddr,
};

const STATUS_INVALID_HANDLE_LOCAL: i32 = 0xc000_0008u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: i32 = 0xc000_009au32 as i32;

// A pre-entry rollback can fail to free provider pool storage. Keep the exact owner until an
// explicit retry; neither the token receipt nor the graph allocation may be silently dropped.
static mut PREENTRY_ROLLBACKS: Vec<RetainedProviderCreateSecurityGraph> = Vec::new();

#[must_use = "retain until exact provider terminal or prove dispatch was not entered"]
pub(super) struct RetainedProviderCreateSecurityGraph {
    source: DriverInstance,
    provider: DriverInstance,
    identity: hosted_source_create_security::SourceSecurityIdentity,
    graph_address: u64,
    primary_address: u64,
    client_address: u64,
    primary_retiring: Option<driver_hosted_token_projection::RetiringTokenProjection>,
    client_retiring: Option<driver_hosted_token_projection::RetiringTokenProjection>,
}

impl RetainedProviderCreateSecurityGraph {
    pub(super) fn io_security_context_address(&self) -> u64 {
        self.graph_address
    }

    /// Call only after exact provider terminal or proven pre-entry. The token projections remain
    /// owned by the outer CREATE until its own terminal completion.
    pub(super) unsafe fn retire(
        self,
    ) -> Result<(), (i32, RetainedProviderCreateSecurityGraph)> {
        if self.primary_retiring.is_some() || self.client_retiring.is_some() {
            return Err((nt_status::NtStatus::DEVICE_BUSY.raw(), self));
        }
        if !free_hosted_instance_pool_allocation_exact(self.provider, self.graph_address) {
            return Err((STATUS_INVALID_HANDLE_LOCAL, self));
        }
        Ok(())
    }

    /// Roll back only while the caller still proves native/provider dispatch was not entered.
    /// This also revokes both token projections so a later provider attempt can bind anew.
    pub(super) unsafe fn abort_unentered(
        mut self,
    ) -> Result<(), (i32, RetainedProviderCreateSecurityGraph)> {
        for address in [self.client_address, self.primary_address] {
            if address == 0 {
                continue;
            }
            let saved = if address == self.client_address {
                self.client_retiring.take()
            } else {
                self.primary_retiring.take()
            };
            let retiring = saved.map(Ok).unwrap_or_else(|| {
                crate::with_provider_security_managers(|_, tokens| {
                    hosted_source_create_security::abort_unentered_projection_binding(
                        self.source, self.provider, self.identity, address, tokens,
                    ).map_err(|status| status as u32)
                })
            });
            let retiring = match retiring {
                Ok(retiring) => retiring,
                Err(status) => return Err((status as i32, self)),
            };
            if let Err((status, retiring)) = driver_hosted_token_projection::free_retired(retiring) {
                if address == self.client_address {
                    self.client_retiring = Some(retiring);
                } else {
                    self.primary_retiring = Some(retiring);
                }
                return Err((status, self));
            }
            if address == self.client_address {
                self.client_address = 0;
            } else {
                self.primary_address = 0;
            }
        }
        self.retire()
    }
}

unsafe fn quarantine_preentry(owner: RetainedProviderCreateSecurityGraph) {
    let rows = &mut *core::ptr::addr_of_mut!(PREENTRY_ROLLBACKS);
    assert!(rows.len() < rows.capacity(), "pre-entry rollback reservation missing");
    rows.push(owner);
}

pub(super) unsafe fn retry_preentry_for_source(
    source: DriverInstance,
    identity: hosted_source_create_security::SourceSecurityIdentity,
) -> Result<(), i32> {
    loop {
        let index = (&*core::ptr::addr_of!(PREENTRY_ROLLBACKS))
            .iter()
            .position(|row| row.source.driver_id == source.driver_id
                && row.source.pml4 == source.pml4
                && row.source.exec_pool_va == source.exec_pool_va
                && row.identity == identity);
        let Some(index) = index else { return Ok(()); };
        let owner = (&mut *core::ptr::addr_of_mut!(PREENTRY_ROLLBACKS)).swap_remove(index);
        if let Err((status, owner)) = owner.abort_unentered() {
            quarantine_preentry(owner);
            return Err(status);
        }
    }
}

/// Copy a source-owned subject only after validating its exact ticket and domain. Every pointer
/// encoded into the result is allocated in `provider`; no source-domain address is forwarded.
pub(super) unsafe fn materialize(
    source: DriverInstance,
    identity: hosted_source_create_security::SourceSecurityIdentity,
    provider: DriverInstance,
) -> Result<RetainedProviderCreateSecurityGraph, i32> {
    (&mut *core::ptr::addr_of_mut!(PREENTRY_ROLLBACKS))
        .try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
    retry_preentry_for_source(source, identity)?;
    let subject = crate::with_provider_security_managers(|_, tokens| {
        hosted_source_create_security::subject(source, identity, tokens)
    }).map_err(|status| status as i32)?;
    let graph_address = hosted_instance_pool_alloc(provider, CREATE_SECURITY_GRAPH_SIZE as u64)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
    let graph_exec = match hosted_pool_allocation_exec_va(
        provider.exec_pool_va, graph_address, CREATE_SECURITY_GRAPH_SIZE as u64,
    ) {
        Some(exec) => exec,
        None => {
            assert!(free_hosted_instance_pool_allocation_exact(provider, graph_address));
            return Err(STATUS_INVALID_HANDLE_LOCAL);
        }
    };
    let mut graph = RetainedProviderCreateSecurityGraph {
        source,
        provider,
        identity,
        graph_address,
        primary_address: 0,
        client_address: 0,
        primary_retiring: None,
        client_retiring: None,
    };
    let reserved_primary = match driver_hosted_token_projection::reserve(provider) {
        Ok(reserved) => reserved,
        Err(status) => {
            assert!(free_hosted_instance_pool_allocation_exact(provider, graph_address));
            return Err(status);
        }
    };
    let mut reserved_primary = Some(reserved_primary);
    let primary = match crate::with_provider_security_managers(|_, tokens| {
        match hosted_source_create_security::bind_projection(
            source, identity, reserved_primary.take().expect("reserved primary token"),
            driver_hosted_token_projection::SubjectTokenRole::Primary, tokens,
        ) {
            Ok(primary) => Ok(primary),
            Err((status, reserved)) => {
                reserved_primary = Some(reserved);
                Err(status as u32)
            }
        }
    }) {
        Ok(primary) => primary,
        Err(status) => {
            let reserved = reserved_primary.expect("failed binding retained reservation");
            assert!(driver_hosted_token_projection::release_reserved(reserved).is_ok());
            assert!(free_hosted_instance_pool_allocation_exact(provider, graph_address));
            return Err(status as i32);
        }
    };
    graph.primary_address = primary.address;
    let client = if subject.client.is_some() {
        let reserved_client = match driver_hosted_token_projection::reserve(provider) {
            Ok(reserved) => reserved,
            Err(status) => {
                if let Err((rollback_status, owner)) = graph.abort_unentered() {
                    quarantine_preentry(owner);
                    return Err(rollback_status);
                }
                return Err(status);
            }
        };
        let mut reserved_client = Some(reserved_client);
        match crate::with_provider_security_managers(|_, tokens| {
            match hosted_source_create_security::bind_projection(
                source, identity, reserved_client.take().expect("reserved client token"),
                driver_hosted_token_projection::SubjectTokenRole::Client, tokens,
            ) {
                Ok(client) => Ok(client),
                Err((status, reserved)) => {
                    reserved_client = Some(reserved);
                    Err(status as u32)
                }
            }
        }) {
            Ok(client) => {
                graph.client_address = client.address;
                Some(client)
            }
            Err(status) => {
                let reserved = reserved_client.expect("failed binding retained reservation");
                assert!(driver_hosted_token_projection::release_reserved(reserved).is_ok());
                if let Err((rollback_status, owner)) = graph.abort_unentered() {
                    quarantine_preentry(owner);
                    return Err(rollback_status);
                }
                return Err(status as i32);
            }
        }
    } else {
        None
    };
    let verified = crate::with_provider_security_managers(|_, tokens| {
        let primary = driver_hosted_token_projection::verify_bound(provider, primary, tokens)
            .map_err(|status| status as u32)?;
        let client = client.map(|client| {
            driver_hosted_token_projection::verify_bound(provider, client, tokens)
                .map_err(|status| status as u32)
        }).transpose()?;
        Ok((primary, client))
    });
    let (primary, client) = match verified {
        Ok(verified) => verified,
        Err(status) => {
            if let Err((rollback_status, owner)) = graph.abort_unentered() {
                quarantine_preentry(owner);
                return Err(rollback_status);
            }
            return Err(status as i32);
        }
    };
    let fields = CreateSecurityFields {
        source: subject.proof,
        provider_domain_id: provider.hosted_domain_id,
        provider_domain_cookie: provider.hosted_domain_cookie,
        primary_token: primary,
        client_token: client.zip(subject.client).map(|(token, client)| (token, client.level as u32)),
        // ProcessAuditId is an opaque audit identity. This source owner captured the canonical
        // requestor PID, so preserve that value rather than treating it as an EPROCESS pointer.
        process_audit_id: GuestAddr(subject.process_audit_id),
        desired_access: subject.create_access.desired_access,
        full_create_options: subject.create_access.full_create_options,
        qos: subject.create_access.qos,
        access: subject.create_access.access,
    };
    let output = core::slice::from_raw_parts_mut(
        graph_exec as *mut u8, CREATE_SECURITY_GRAPH_SIZE,
    );
    if encode_create_security_graph(
        GuestAddr(graph_address), subject.proof, fields, output,
    ).is_err() {
        if let Err((rollback_status, owner)) = graph.abort_unentered() {
            quarantine_preentry(owner);
            return Err(rollback_status);
        }
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    Ok(graph)
}
