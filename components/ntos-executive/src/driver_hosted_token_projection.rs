//! Provider-local access-token projections for retained cross-domain CREATE subjects.
//!
//! This is a `driver_launch` child module. The caller supplies physical `DriverInstance`
//! snapshots obtained from authenticated ingress, never from a driver pointer or badge alone.

use super::*;
use nt_security::{
    hosted_token_projection::{
        HostedTokenProjection, HostedTokenProjectionDomain, HostedTokenProjectionError,
        HostedTokenProjectionRegistry,
    },
    source_create_security::{
        SourceCreateSecurityKey, SourceCreateSecurityOwner, SourceCreateSecurityPhase,
        SourceCreateSecurityTicket,
    },
    Luid, TokenId, TokenStore,
};

const TOKEN_PROJECTION_BYTES: u64 = 32;
const TOKEN_PROJECTION_MAGIC: u64 = 0x4e54_5052_4f4a_0001;
const STATUS_INVALID_HANDLE_LOCAL: i32 = 0xc000_0008u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: i32 = 0xc000_009au32 as i32;
const STATUS_DEVICE_BUSY_LOCAL: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SubjectTokenRole {
    Primary,
    Client,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProjectedToken {
    pub address: u64,
    pub receipt: HostedTokenProjection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProjectedTokenMetadata {
    pub session_id: u32,
    pub authentication_id: Luid,
}

struct Row {
    source_ticket: SourceCreateSecurityTicket,
    source_key: SourceCreateSecurityKey,
    source_pml4: u64,
    source_pool: u64,
    provider_domain: HostedTokenProjectionDomain,
    provider_pml4: u64,
    provider_pool: u64,
    provider_driver_id: u64,
    role: SubjectTokenRole,
    projection: Option<HostedTokenProjection>,
    retiring: bool,
    address: u64,
}

static mut REGISTRY: HostedTokenProjectionRegistry = HostedTokenProjectionRegistry::new();
static mut ROWS: Vec<Row> = Vec::new();

fn domain(inst: DriverInstance) -> Result<HostedTokenProjectionDomain, i32> {
    if inst.pml4 == 0 || inst.exec_pool_va == 0 || inst.driver_id == 0 {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    HostedTokenProjectionDomain::new(inst.hosted_domain_id, inst.hosted_domain_cookie)
        .ok_or(STATUS_INVALID_HANDLE_LOCAL)
}

fn source_matches(inst: DriverInstance, key: SourceCreateSecurityKey) -> bool {
    inst.pml4 != 0
        && inst.exec_pool_va != 0
        && inst.hosted_domain_id == key.domain_id()
        && inst.hosted_domain_cookie == key.domain_cookie()
}

fn provider_matches(row: &Row, inst: DriverInstance) -> bool {
    domain(inst).ok() == Some(row.provider_domain)
        && row.provider_pml4 == inst.pml4
        && row.provider_pool == inst.exec_pool_va
        && row.provider_driver_id == inst.driver_id
}

fn retirement_row(
    source_inst: DriverInstance,
    provider_inst: DriverInstance,
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
    address: u64,
) -> Option<usize> {
    unsafe {
        (&*core::ptr::addr_of!(ROWS)).iter().position(|row| {
            row.source_ticket == ticket
                && row.source_key == key
                && row.source_pml4 == source_inst.pml4
                && row.source_pool == source_inst.exec_pool_va
                && row.address == address
                && provider_matches(row, provider_inst)
        })
    }
}

fn projection_status(error: HostedTokenProjectionError) -> i32 {
    match error {
        HostedTokenProjectionError::InsufficientResources => STATUS_INSUFFICIENT_RESOURCES_LOCAL,
        HostedTokenProjectionError::Busy => STATUS_DEVICE_BUSY_LOCAL,
        _ => STATUS_INVALID_HANDLE_LOCAL,
    }
}

/// Allocate an opaque token object in the target's own pool and bind its canonical identity.
/// `source` must remain retained until this projection is retired after provider completion.
pub(super) unsafe fn project(
    source_inst: DriverInstance,
    provider_inst: DriverInstance,
    source: &SourceCreateSecurityOwner,
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
    role: SubjectTokenRole,
    tokens: &mut TokenStore,
) -> Result<ProjectedToken, i32> {
    if !source_matches(source_inst, key)
        || source.ticket() != ticket
        || source.key() != key
        || matches!(
            source.phase(),
            SourceCreateSecurityPhase::Terminal | SourceCreateSecurityPhase::Released
        )
    {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    let provider_domain = domain(provider_inst)?;
    let (primary, client) = source
        .token_ids(tokens, ticket, key)
        .map_err(|status| status as i32)?;
    let token: TokenId = match role {
        SubjectTokenRole::Primary => primary,
        SubjectTokenRole::Client => client.ok_or(STATUS_INVALID_HANDLE_LOCAL)?.token,
    };
    (&mut *core::ptr::addr_of_mut!(ROWS))
        .try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
    let address = hosted_instance_pool_alloc(provider_inst, TOKEN_PROJECTION_BYTES)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
    let Some(exec_va) =
        hosted_pool_allocation_exec_va(provider_inst.exec_pool_va, address, TOKEN_PROJECTION_BYTES)
    else {
        assert!(free_hosted_instance_pool_allocation_exact(
            provider_inst,
            address
        ));
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    };
    // Pool allocation may yield. Recheck after it completes, without holding a ledger borrow
    // across the yield, so a re-entrant projection cannot publish the same source role twice.
    let duplicate = (&*core::ptr::addr_of!(ROWS)).iter().any(|row| {
        row.source_ticket == ticket
            && row.source_key == key
            && row.source_pml4 == source_inst.pml4
            && row.source_pool == source_inst.exec_pool_va
            && provider_matches(row, provider_inst)
            && row.role == role
    });
    if duplicate {
        assert!(free_hosted_instance_pool_allocation_exact(
            provider_inst,
            address
        ));
        return Err(STATUS_DEVICE_BUSY_LOCAL);
    }
    if matches!(
        source.phase(),
        SourceCreateSecurityPhase::Terminal | SourceCreateSecurityPhase::Released
    ) || source.token_ids(tokens, ticket, key).map(
        |(current_primary, current_client)| match role {
            SubjectTokenRole::Primary => current_primary == token,
            SubjectTokenRole::Client => current_client.is_some_and(|client| client.token == token),
        },
    ) != Ok(true)
    {
        assert!(free_hosted_instance_pool_allocation_exact(
            provider_inst,
            address
        ));
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    let registry = &mut *core::ptr::addr_of_mut!(REGISTRY);
    let projection = match registry.bind(tokens, provider_domain, address, token) {
        Ok(projection) => projection,
        Err(error) => {
            assert!(free_hosted_instance_pool_allocation_exact(
                provider_inst,
                address
            ));
            return Err(projection_status(error));
        }
    };
    core::ptr::write_bytes(exec_va as *mut u8, 0, TOKEN_PROJECTION_BYTES as usize);
    core::ptr::write_unaligned(exec_va as *mut u64, TOKEN_PROJECTION_MAGIC);
    core::ptr::write_unaligned((exec_va + 8) as *mut u64, projection.generation());
    (&mut *core::ptr::addr_of_mut!(ROWS)).push(Row {
        source_ticket: ticket,
        source_key: key,
        source_pml4: source_inst.pml4,
        source_pool: source_inst.exec_pool_va,
        provider_domain,
        provider_pml4: provider_inst.pml4,
        provider_pool: provider_inst.exec_pool_va,
        provider_driver_id: provider_inst.driver_id,
        role,
        projection: Some(projection),
        retiring: false,
        address,
    });
    Ok(ProjectedToken {
        address,
        receipt: projection,
    })
}

/// Resolve a `PACCESS_TOKEN` query only inside the authenticated provider's physical VSpace.
/// The pointer bytes and their diagnostic marker are never authority; the exact registry receipt
/// and canonical TokenStore LUID are checked before returning either NT token field.
pub(super) unsafe fn query(
    provider_inst: DriverInstance,
    address: u64,
    tokens: &TokenStore,
) -> Result<ProjectedTokenMetadata, i32> {
    let row = (&*core::ptr::addr_of!(ROWS))
        .iter()
        .find(|row| {
            row.address == address
                && row.projection.is_some()
                && !row.retiring
                && provider_matches(row, provider_inst)
        })
        .ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    let projection = row.projection.expect("live token projection");
    let registry = &mut *core::ptr::addr_of_mut!(REGISTRY);
    if registry.registration(row.provider_domain, address) != Some(projection) {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    registry
        .reference(tokens, projection)
        .map_err(projection_status)?;
    let metadata = registry
        .resolve(tokens, projection)
        .map(|token| ProjectedTokenMetadata {
            session_id: token.session_id,
            authentication_id: token.authentication_id,
        })
        .map_err(projection_status);
    registry
        .dereference(projection)
        .expect("token query held exact reference");
    metadata
}

/// Quiesce a projection only once the exact source CREATE has a genuine terminal result.
/// A failed physical pool free leaves a retired, non-queryable row for explicit retry.
pub(super) unsafe fn retire(
    source_inst: DriverInstance,
    provider_inst: DriverInstance,
    source: &SourceCreateSecurityOwner,
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
    address: u64,
    tokens: &mut TokenStore,
) -> Result<(), i32> {
    if !source_matches(source_inst, key)
        || source.ticket() != ticket
        || source.key() != key
        || source.phase() != SourceCreateSecurityPhase::Terminal
    {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    let index = retirement_row(source_inst, provider_inst, ticket, key, address)
        .ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    if (&*core::ptr::addr_of!(ROWS))[index].retiring {
        return Err(STATUS_DEVICE_BUSY_LOCAL);
    }
    if let Some(projection) = (&*core::ptr::addr_of!(ROWS))[index].projection {
        (&mut *core::ptr::addr_of_mut!(REGISTRY))
            .retire(tokens, projection)
            .map_err(projection_status)?;
        (&mut *core::ptr::addr_of_mut!(ROWS))[index].projection = None;
    }
    (&mut *core::ptr::addr_of_mut!(ROWS))[index].retiring = true;
    if !free_hosted_instance_pool_allocation_exact(provider_inst, address) {
        let index = retirement_row(source_inst, provider_inst, ticket, key, address)
            .expect("retiring token projection retained across pool operation");
        (&mut *core::ptr::addr_of_mut!(ROWS))[index].retiring = false;
        return Err(STATUS_DEVICE_BUSY_LOCAL);
    }
    let index = retirement_row(source_inst, provider_inst, ticket, key, address)
        .expect("retiring token projection retained across pool operation");
    (&mut *core::ptr::addr_of_mut!(ROWS)).swap_remove(index);
    Ok(())
}
