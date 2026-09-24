//! Retained subject authority for a hosted driver's outer CREATE IRP.
//!
//! The canonical CREATE owner supplies the token identities and IRP generation. The hosted
//! `IO_SECURITY_CONTEXT` address is only an equality key inside the authenticated source domain;
//! it never grants authority to a token and is never copied into another VSpace.

use super::driver_hosted_token_projection::{
    ProjectedToken, ReservedTokenProjection, RetiringTokenProjection, SubjectTokenRole,
};
use super::*;
use nt_io_manager::redir_query_path::{RetainedSecurityContextTicket, SourceSecurityContext};
use nt_kernel_abi::security_create_x64::SourceSecurityProof;
use nt_security::{
    source_create_security::{
        SourceCreateSecurityKey, SourceCreateSecurityOwner, SourceCreateSecurityPhase,
        SourceCreateSecurityTicket,
    },
    SubjectClientIdentity, TokenId, TokenStore,
};

const STATUS_INVALID_HANDLE_LOCAL: u32 = 0xc000_0008;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: u32 = 0xc000_009a;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SourceSecurityIdentity {
    pub ticket: SourceCreateSecurityTicket,
    pub key: SourceCreateSecurityKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SourceSecuritySubject {
    pub primary: TokenId,
    pub client: Option<SubjectClientIdentity>,
    pub process_audit_id: u64,
    pub proof: SourceSecurityProof,
}

struct Row {
    identity: SourceSecurityIdentity,
    source_pml4: u64,
    source_pool: u64,
    source_driver_id: u64,
    owner: SourceCreateSecurityOwner,
}

static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);
static mut ROWS: Vec<Row> = Vec::new();

fn live_source(inst: DriverInstance) -> bool {
    inst.driver_id != 0
        && inst.pml4 != 0
        && inst.exec_pool_va != 0
        && inst.hosted_domain_id != 0
        && inst.hosted_domain_cookie != 0
        && instance_by_driver_id(inst.driver_id).is_some_and(|(_, current)| {
            current.pml4 == inst.pml4
                && current.exec_pool_va == inst.exec_pool_va
                && current.hosted_domain_id == inst.hosted_domain_id
                && current.hosted_domain_cookie == inst.hosted_domain_cookie
        })
}

fn row_matches(row: &Row, inst: DriverInstance) -> bool {
    live_source(inst)
        && row.source_pml4 == inst.pml4
        && row.source_pool == inst.exec_pool_va
        && row.source_driver_id == inst.driver_id
        && row.identity.key.domain_id() == inst.hosted_domain_id
        && row.identity.key.domain_cookie() == inst.hosted_domain_cookie
}

fn row_index(inst: DriverInstance, identity: SourceSecurityIdentity) -> Option<usize> {
    unsafe {
        (&*core::ptr::addr_of!(ROWS))
            .iter()
            .position(|row| row.identity == identity && row_matches(row, inst))
    }
}

unsafe fn live_context(inst: DriverInstance, address: u64) -> bool {
    if address == 0 || address & 7 != 0 {
        return false;
    }
    let Some(exec) = hosted_instance_pool_allocation_exec_if_live(
        inst,
        address,
        nt_kernel_abi::security_create_x64::IO_SECURITY_CONTEXT_SIZE as u64,
    ) else {
        return false;
    };
    let access = read_unaligned((exec + 8) as *const u64);
    if Some(access)
        == address.checked_add(nt_kernel_abi::security_create_x64::ACCESS_STATE_OFFSET as u64)
    {
        hosted_instance_pool_allocation_exec_if_live(
            inst,
            address,
            nt_kernel_abi::security_create_x64::CREATE_SECURITY_GRAPH_SIZE as u64,
        )
        .is_some()
    } else {
        access != 0
            && hosted_instance_pool_allocation_exec_if_live(
                inst,
                access,
                nt_kernel_abi::security_create_x64::ACCESS_STATE_SIZE as u64,
            )
            .is_some()
    }
}

/// Called only while the canonical CREATE owner and its authenticated subject are retained.
/// `irp_generation` must come from that owner, not from the pointer or a badge. The source
/// context and ACCESS_STATE allocations must already exist in this exact hosted instance.
pub(super) unsafe fn capture(
    source: DriverInstance,
    irp_id: u64,
    irp_generation: u64,
    security_context_address: u64,
    primary: TokenId,
    client: Option<SubjectClientIdentity>,
    process_audit_id: u64,
    tokens: &mut TokenStore,
) -> Result<SourceSecurityIdentity, u32> {
    if !live_source(source) || !live_context(source, security_context_address) {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    let serial = NEXT_TICKET
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
    let ticket = SourceCreateSecurityTicket::new(serial, serial)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
    let key = SourceCreateSecurityKey::new(
        irp_id,
        irp_generation,
        source.hosted_domain_id,
        source.hosted_domain_cookie,
        security_context_address,
    )
    .ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    let identity = SourceSecurityIdentity { ticket, key };
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    if rows.iter().any(|row| {
        row_matches(row, source)
            && row.identity.key.security_context_address() == security_context_address
    }) {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    rows.try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
    let owner =
        SourceCreateSecurityOwner::capture(tokens, ticket, key, primary, client, process_audit_id)?;
    rows.push(Row {
        identity,
        source_pml4: source.pml4,
        source_pool: source.exec_pool_va,
        source_driver_id: source.driver_id,
        owner,
    });
    Ok(identity)
}

/// Resolve a nested Mup QUERY_PATH_REQUEST against a still-live outer CREATE owner. The caller
/// must obtain `source` from authenticated pump ingress; the request's pointer is not authority.
pub(super) unsafe fn lookup(
    source: DriverInstance,
    security_context_address: u64,
) -> Option<SourceSecurityIdentity> {
    let identity = (&*core::ptr::addr_of!(ROWS)).iter().find(|row| {
        row_matches(row, source)
            && row.identity.key.security_context_address() == security_context_address
            && !matches!(
                row.owner.phase(),
                SourceCreateSecurityPhase::Terminal | SourceCreateSecurityPhase::Released
            )
    })?.identity;
    live_context(source, security_context_address).then_some(identity)
}

pub(super) unsafe fn lookup_context(
    source: DriverInstance,
    security_context_address: u64,
) -> Option<SourceSecurityContext> {
    let identity = lookup(source, security_context_address)?;
    Some(SourceSecurityContext {
        address: core::num::NonZeroU64::new(security_context_address)?,
        ticket: RetainedSecurityContextTicket::new(
            identity.ticket.id(),
            identity.ticket.generation(),
        )?,
    })
}

fn token_luid(tokens: &TokenStore, id: TokenId) -> Option<u64> {
    let luid = tokens.statistics(id)?.token_id;
    let value = (luid.low as u64) | ((luid.high as u32 as u64) << 32);
    (value != 0).then_some(value)
}

/// Materialize a source proof only from the retained owner and the same canonical TokenStore.
/// The token LUID is the canonical generation; provider projection receipt generations are
/// separate bindings and must be checked independently before encoding provider-local pointers.
pub(super) fn subject(
    source: DriverInstance,
    identity: SourceSecurityIdentity,
    tokens: &TokenStore,
) -> Result<SourceSecuritySubject, u32> {
    let index = row_index(source, identity).ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    let row = unsafe { &(&*core::ptr::addr_of!(ROWS))[index] };
    let (primary, client) = row.owner.token_ids(tokens, identity.ticket, identity.key)?;
    let subject = row.owner.resolve(tokens, identity.ticket, identity.key)?;
    let primary_generation = token_luid(tokens, primary).ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    let client_generation = match client {
        Some(client) => token_luid(tokens, client.token).ok_or(STATUS_INVALID_HANDLE_LOCAL)?,
        None => 0,
    };
    let proof = SourceSecurityProof {
        ticket_id: identity.ticket.id(),
        ticket_generation: identity.ticket.generation(),
        irp_id: identity.key.irp_id(),
        irp_generation: identity.key.irp_generation(),
        domain_id: identity.key.domain_id(),
        domain_cookie: identity.key.domain_cookie(),
        security_context_address: identity.key.security_context_address(),
        primary_token_id: u64::from(primary.raw()),
        primary_token_generation: primary_generation,
        client_token_id: client.map_or(0, |client| u64::from(client.token.raw())),
        client_token_generation: client_generation,
    };
    Ok(SourceSecuritySubject {
        primary,
        client,
        process_audit_id: subject.process_audit_id,
        proof,
    })
}

pub(super) unsafe fn bind_projection(
    source: DriverInstance,
    identity: SourceSecurityIdentity,
    reserved: ReservedTokenProjection,
    role: SubjectTokenRole,
    tokens: &mut TokenStore,
) -> Result<ProjectedToken, (i32, ReservedTokenProjection)> {
    let Some(index) = row_index(source, identity) else {
        return Err((STATUS_INVALID_HANDLE_LOCAL as i32, reserved));
    };
    let row = &(&*core::ptr::addr_of!(ROWS))[index];
    driver_hosted_token_projection::bind(
        reserved,
        source,
        &row.owner,
        identity.ticket,
        identity.key,
        role,
        tokens,
    )
}

pub(super) unsafe fn retire_projection_binding(
    source: DriverInstance,
    provider: DriverInstance,
    identity: SourceSecurityIdentity,
    address: u64,
    tokens: &mut TokenStore,
) -> Result<RetiringTokenProjection, i32> {
    let index = row_index(source, identity).ok_or(STATUS_INVALID_HANDLE_LOCAL as i32)?;
    let row = &(&*core::ptr::addr_of!(ROWS))[index];
    driver_hosted_token_projection::retire_binding(
        source,
        provider,
        &row.owner,
        identity.ticket,
        identity.key,
        address,
        tokens,
    )
}

pub(super) fn mark_pending(source: DriverInstance, identity: SourceSecurityIdentity) -> bool {
    let Some(index) = row_index(source, identity) else {
        return false;
    };
    unsafe {
        (&mut *core::ptr::addr_of_mut!(ROWS))[index]
            .owner
            .mark_pending()
    };
    true
}

pub(super) fn mark_indeterminate(source: DriverInstance, identity: SourceSecurityIdentity) -> bool {
    let Some(index) = row_index(source, identity) else {
        return false;
    };
    unsafe {
        (&mut *core::ptr::addr_of_mut!(ROWS))[index]
            .owner
            .mark_indeterminate()
    };
    true
}

/// A genuine terminal result permits provider token projections to retire. Call `release` only
/// after all projections and source-local completion work have been retired.
pub(super) fn mark_terminal(source: DriverInstance, identity: SourceSecurityIdentity) -> bool {
    let Some(index) = row_index(source, identity) else {
        return false;
    };
    unsafe {
        (&mut *core::ptr::addr_of_mut!(ROWS))[index]
            .owner
            .mark_terminal()
    };
    true
}

pub(super) fn release(
    source: DriverInstance,
    identity: SourceSecurityIdentity,
    tokens: &mut TokenStore,
) -> Result<(), u32> {
    let index = row_index(source, identity).ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    unsafe {
        let rows = &mut *core::ptr::addr_of_mut!(ROWS);
        rows[index].owner.release(tokens)?;
        rows.swap_remove(index);
    }
    Ok(())
}
