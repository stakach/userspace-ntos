//! Provider-local access-token projections for retained cross-domain CREATE subjects.
//!
//! This is a `driver_launch` child module. The caller supplies physical `DriverInstance`
//! snapshots obtained from authenticated ingress, never from a driver pointer or badge alone.

use super::*;
use nt_kernel_abi::{security_create_x64::ProviderTokenProjection, GuestAddr};
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

#[must_use = "bind or release the reserved provider token allocation"]
pub(super) struct ReservedTokenProjection {
    provider_inst: DriverInstance,
    provider_domain: HostedTokenProjectionDomain,
    address: u64,
    exec_va: u64,
}

#[must_use = "free the retired provider token allocation"]
pub(super) struct RetiringTokenProjection {
    source_ticket: SourceCreateSecurityTicket,
    source_key: SourceCreateSecurityKey,
    source_inst: DriverInstance,
    provider_inst: DriverInstance,
    address: u64,
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

/// Reserve provider-local storage before borrowing TokenStore. The reservation is not a token;
/// it cannot be queried until `bind` validates and retains its canonical identity.
pub(super) unsafe fn reserve(
    provider_inst: DriverInstance,
) -> Result<ReservedTokenProjection, (i32, Option<ReservedTokenProjection>)> {
    let provider_domain = domain(provider_inst).map_err(|status| (status, None))?;
    let address = hosted_instance_pool_alloc(provider_inst, TOKEN_PROJECTION_BYTES)
        .ok_or((STATUS_INSUFFICIENT_RESOURCES_LOCAL, None))?;
    let Some(exec_va) =
        hosted_pool_allocation_exec_va(provider_inst.exec_pool_va, address, TOKEN_PROJECTION_BYTES)
    else {
        // The allocation is still ours if the mapping lookup fails. Return its exact receipt
        // so the source-keyed pre-entry rollback can retry a failed pool free.
        return Err((
            STATUS_INVALID_HANDLE_LOCAL,
            Some(ReservedTokenProjection {
                provider_inst,
                provider_domain,
                address,
                exec_va: 0,
            }),
        ));
    };
    Ok(ReservedTokenProjection {
        provider_inst,
        provider_domain,
        address,
        exec_va,
    })
}

pub(super) unsafe fn release_reserved(
    reserved: ReservedTokenProjection,
) -> Result<(), ReservedTokenProjection> {
    if free_hosted_instance_pool_allocation_exact(reserved.provider_inst, reserved.address) {
        Ok(())
    } else {
        Err(reserved)
    }
}

/// Bind one reserved provider-local address to an exact retained canonical token. This phase
/// performs no provider IPC or pool operation and may run under a short TokenStore borrow.
pub(super) unsafe fn bind(
    reserved: ReservedTokenProjection,
    source_inst: DriverInstance,
    source: &SourceCreateSecurityOwner,
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
    role: SubjectTokenRole,
    tokens: &mut TokenStore,
) -> Result<ProjectedToken, (i32, ReservedTokenProjection)> {
    if !source_matches(source_inst, key)
        || source.ticket() != ticket
        || source.key() != key
        || matches!(
            source.phase(),
            SourceCreateSecurityPhase::Terminal | SourceCreateSecurityPhase::Released
        )
    {
        return Err((STATUS_INVALID_HANDLE_LOCAL, reserved));
    }
    let provider_inst = reserved.provider_inst;
    let provider_domain = reserved.provider_domain;
    if domain(provider_inst).ok() != Some(provider_domain) {
        return Err((STATUS_INVALID_HANDLE_LOCAL, reserved));
    }
    let (primary, client) = match source.token_ids(tokens, ticket, key) {
        Ok(ids) => ids,
        Err(status) => return Err((status as i32, reserved)),
    };
    let token: TokenId = match role {
        SubjectTokenRole::Primary => primary,
        SubjectTokenRole::Client => match client {
            Some(client) => client.token,
            None => return Err((STATUS_INVALID_HANDLE_LOCAL, reserved)),
        },
    };
    if (&mut *core::ptr::addr_of_mut!(ROWS))
        .try_reserve(1)
        .is_err()
    {
        return Err((STATUS_INSUFFICIENT_RESOURCES_LOCAL, reserved));
    }
    let duplicate = (&*core::ptr::addr_of!(ROWS)).iter().any(|row| {
        row.source_ticket == ticket
            && row.source_key == key
            && row.source_pml4 == source_inst.pml4
            && row.source_pool == source_inst.exec_pool_va
            && provider_matches(row, provider_inst)
            && row.role == role
    });
    if duplicate {
        return Err((STATUS_DEVICE_BUSY_LOCAL, reserved));
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
        return Err((STATUS_INVALID_HANDLE_LOCAL, reserved));
    }
    let registry = &mut *core::ptr::addr_of_mut!(REGISTRY);
    let projection = match registry.bind(tokens, provider_domain, reserved.address, token) {
        Ok(projection) => projection,
        Err(error) => return Err((projection_status(error), reserved)),
    };
    core::ptr::write_bytes(
        reserved.exec_va as *mut u8,
        0,
        TOKEN_PROJECTION_BYTES as usize,
    );
    core::ptr::write_unaligned(reserved.exec_va as *mut u64, TOKEN_PROJECTION_MAGIC);
    core::ptr::write_unaligned((reserved.exec_va + 8) as *mut u64, projection.generation());
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
        address: reserved.address,
    });
    Ok(ProjectedToken {
        address: reserved.address,
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

pub(super) unsafe fn next_bound_for_source(
    source_inst: DriverInstance,
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
) -> Result<Option<(DriverInstance, u64)>, i32> {
    let row = (&*core::ptr::addr_of!(ROWS)).iter().find(|row| {
        row.source_ticket == ticket
            && row.source_key == key
            && row.source_pml4 == source_inst.pml4
            && row.source_pool == source_inst.exec_pool_va
    });
    let Some(row) = row else { return Ok(None); };
    if row.retiring || row.projection.is_none() {
        return Err(STATUS_DEVICE_BUSY_LOCAL);
    }
    let (_, provider) = instance_by_driver_id(row.provider_driver_id)
        .ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    if !provider_matches(row, provider) {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    Ok(Some((provider, row.address)))
}

pub(super) unsafe fn verify_bound(
    provider_inst: DriverInstance,
    projected: ProjectedToken,
    tokens: &TokenStore,
) -> Result<ProviderTokenProjection, i32> {
    let row = (&*core::ptr::addr_of!(ROWS))
        .iter()
        .find(|row| {
            row.address == projected.address
                && row.projection == Some(projected.receipt)
                && !row.retiring
                && provider_matches(row, provider_inst)
        })
        .ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    let registry = &mut *core::ptr::addr_of_mut!(REGISTRY);
    if registry.registration(row.provider_domain, projected.address) != Some(projected.receipt) {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    registry
        .reference(tokens, projected.receipt)
        .map_err(projection_status)?;
    let result = registry
        .resolve(tokens, projected.receipt)
        .map_err(projection_status)
        .and_then(|_| {
            let luid = projected.receipt.token_luid();
            let generation = (luid.low as u64) | ((luid.high as u32 as u64) << 32);
            if generation == 0 {
                return Err(STATUS_INVALID_HANDLE_LOCAL);
            }
            Ok(ProviderTokenProjection {
                address: GuestAddr(projected.address),
                token_id: u64::from(projected.receipt.token().raw()),
                token_generation: generation,
                domain_id: row.provider_domain.id(),
                domain_cookie: row.provider_domain.cookie(),
            })
        });
    registry
        .dereference(projected.receipt)
        .expect("verified token projection held exact reference");
    result
}

/// Quiesce a projection only after the outer CREATE is terminal. A nested query-path terminal
/// releases its provider-local graph, but the retained source subject still owns token bindings.
pub(super) unsafe fn retire_binding(
    source_inst: DriverInstance,
    provider_inst: DriverInstance,
    source: &SourceCreateSecurityOwner,
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
    address: u64,
    tokens: &mut TokenStore,
) -> Result<RetiringTokenProjection, i32> {
    retire_binding_in_phase(source_inst, provider_inst, source, ticket, key, address,
        false, tokens)
}

/// Only a retained graph with pre-entry proof may use this. Outer CREATE may have reached
/// Terminal before a failed no-entry cleanup is redriven; Indeterminate is never admitted.
pub(super) unsafe fn abort_unentered_binding(
    source_inst: DriverInstance,
    provider_inst: DriverInstance,
    source: &SourceCreateSecurityOwner,
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
    address: u64,
    tokens: &mut TokenStore,
) -> Result<RetiringTokenProjection, i32> {
    retire_binding_in_phase(source_inst, provider_inst, source, ticket, key, address,
        true, tokens)
}

unsafe fn retire_binding_in_phase(
    source_inst: DriverInstance,
    provider_inst: DriverInstance,
    source: &SourceCreateSecurityOwner,
    ticket: SourceCreateSecurityTicket,
    key: SourceCreateSecurityKey,
    address: u64,
    proven_unentered: bool,
    tokens: &mut TokenStore,
) -> Result<RetiringTokenProjection, i32> {
    if !source_matches(source_inst, key)
        || source.ticket() != ticket
        || source.key() != key
        || if proven_unentered {
            !matches!(source.phase(),
                SourceCreateSecurityPhase::Captured
                    | SourceCreateSecurityPhase::Pending
                    | SourceCreateSecurityPhase::Terminal)
        } else {
            source.phase() != SourceCreateSecurityPhase::Terminal
        }
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
    Ok(RetiringTokenProjection {
        source_ticket: ticket,
        source_key: key,
        source_inst,
        provider_inst,
        address,
    })
}

/// Free the now non-queryable storage outside the TokenStore borrow. A failed free keeps the
/// row and receipt for an explicit retry; it does not resurrect the token projection.
pub(super) unsafe fn free_retired(
    retiring: RetiringTokenProjection,
) -> Result<(), (i32, RetiringTokenProjection)> {
    let Some(index) = retirement_row(
        retiring.source_inst,
        retiring.provider_inst,
        retiring.source_ticket,
        retiring.source_key,
        retiring.address,
    ) else {
        return Err((STATUS_INVALID_HANDLE_LOCAL, retiring));
    };
    if !(&*core::ptr::addr_of!(ROWS))[index].retiring {
        return Err((STATUS_INVALID_HANDLE_LOCAL, retiring));
    }
    if !free_hosted_instance_pool_allocation_exact(retiring.provider_inst, retiring.address) {
        return Err((STATUS_DEVICE_BUSY_LOCAL, retiring));
    }
    let index = retirement_row(
        retiring.source_inst,
        retiring.provider_inst,
        retiring.source_ticket,
        retiring.source_key,
        retiring.address,
    )
    .expect("retiring projection row retained across pool free");
    (&mut *core::ptr::addr_of_mut!(ROWS)).swap_remove(index);
    Ok(())
}
