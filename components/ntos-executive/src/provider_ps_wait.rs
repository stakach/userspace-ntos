//! Exact Ps thread references spanning a win32k provider dispatcher wait.

use alloc::vec::Vec;
use core::ptr::addr_of_mut;

use nt_process::{ProcessManager, ThreadLifetime};
use nt_provider_wait::{ProviderWaitObject, ProviderWaitObjectType, ProviderWaitOwner};

use crate::{ps_object_backing, ps_object_provider::ProviderRoot};

const INVALID: u32 = nt_process::STATUS_INVALID_HANDLE;
const RESOURCES: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;

struct WaitLease {
    token: u64,
    target: ProviderRoot,
    lifetime: ThreadLifetime,
    body: u64,
    client_pi: u64,
    client_generation: u64,
}

static mut LEASES: Vec<WaitLease> = Vec::new();
static mut NEXT_TOKEN: u64 = 1;

fn leases() -> &'static mut Vec<WaitLease> {
    // The authenticated provider ingress serializes the canonical PM and Ps page owner.
    unsafe { &mut *addr_of_mut!(LEASES) }
}

pub(crate) fn acquire(
    pm: &mut ProcessManager,
    target: ProviderRoot,
    body: u64,
    client_pi: u64,
    client_generation: u64,
) -> Result<(u64, u64, u64), u32> {
    if client_pi == 0 || client_generation == 0 || target.catalog_domain().is_none() {
        return Err(INVALID);
    }
    let tid = pm.tid_for_kernel_thread_object(body).ok_or(INVALID)?;
    let lifetime = pm.thread_lifetime(tid).ok_or(INVALID)?;
    ps_object_backing::verify_provider_thread_wait_body(pm, lifetime, body, target)?;
    let next = unsafe { NEXT_TOKEN.checked_add(1) }.ok_or(RESOURCES)?;
    leases().try_reserve(1).map_err(|_| RESOURCES)?;
    pm.retain_thread_wait_reference(tid)?;
    let token = unsafe { NEXT_TOKEN };
    leases().push(WaitLease { token, target, lifetime, body, client_pi, client_generation });
    unsafe { NEXT_TOKEN = next };
    Ok((u64::from(tid), lifetime.generation(), token))
}

/// Memory-local proof that the exact provider/client has a retained Ps alias lease for this
/// canonical Thread wait. The dispatcher then acquires its own PM reference before parking.
pub(crate) fn has_canonical(owner: ProviderWaitOwner, object: ProviderWaitObject) -> bool {
    let Some(client) = owner.hosted_client() else { return false };
    if object.typed() != Some(ProviderWaitObjectType::Thread) { return false; }
    leases().iter().any(|lease| {
        lease.target.catalog_domain().is_some_and(|domain|
            domain.domain == owner.provider_domain
                && domain.generation == owner.provider_generation)
            && lease.client_pi == client.client_pi as u64
            && lease.client_generation == client.client_generation
            && u64::from(lease.lifetime.thread_id()) == object.object_id
            && lease.lifetime.generation() == object.object_generation
    })
}

/// A provider VSpace cannot retire while it still owns an unreleased Ps wait reference.
/// Terminal/uncertain provider stops retain their VSpace and references for redrive.
pub(crate) fn has_target(target: ProviderRoot) -> bool {
    leases().iter().any(|lease| lease.target == target)
}

pub(crate) fn release(
    pm: &mut ProcessManager,
    target: ProviderRoot,
    token: u64,
) -> Result<(), u32> {
    let index = leases().iter().position(|lease| lease.token == token && lease.target == target)
        .ok_or(INVALID)?;
    let lease = &leases()[index];
    if !pm.validate_thread_lifetime(lease.lifetime)
        || pm.thread_kernel_object(lease.lifetime.thread_id()) != Some(lease.body)
    {
        return Err(INVALID);
    }
    pm.release_thread_wait_reference(lease.lifetime.thread_id())?;
    leases().remove(index);
    Ok(())
}
