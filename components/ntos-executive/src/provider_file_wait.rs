//! Exact FILE_OBJECT ownership while a provider dispatcher wait is suspended.

use alloc::vec::Vec;
use core::ptr::addr_of_mut;

use nt_io_completion::FileReferenceRelease;
use nt_io_manager::{FileReference, HostedFileIdentity, HostedFilePublicationLease};
use nt_provider_wait::{ProviderWaitObject, ProviderWaitObjectType, ProviderWaitOwner};

use crate::driver_launch::io_manager_mut;
use crate::{ExecFileCompletion, ExecNtHandler};

const STATUS_INVALID_HANDLE: u32 = nt_status::NtStatus::INVALID_HANDLE.raw() as u32;
const STATUS_INVALID_PARAMETER: u32 = nt_status::NtStatus::INVALID_PARAMETER.raw() as u32;
const STATUS_INSUFFICIENT_RESOURCES: u32 =
    nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32;

struct WaitLease {
    token: u64,
    owner: ProviderWaitOwner,
    identity: HostedFileIdentity,
    reference: FileReference,
    publication: HostedFilePublicationLease,
    retiring: bool,
    completion_released: bool,
    completion_followup: Option<FileReferenceRelease>,
}

static mut LEASES: Vec<WaitLease> = Vec::new();
static mut NEXT_TOKEN: u64 = 1;

fn leases() -> &'static mut Vec<WaitLease> {
    // The executive serializes provider dispatcher and completion work.
    unsafe { &mut *addr_of_mut!(LEASES) }
}

/// Acquire a wait-local File reference and pin the exact consumer projection.
pub(crate) fn acquire(
    owner: ProviderWaitOwner,
    object: ProviderWaitObject,
    file_completion: &mut ExecFileCompletion,
) -> Result<u64, u32> {
    if !owner.is_valid()
        || object.typed() != Some(ProviderWaitObjectType::File)
        || object.flags != 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let identity = unsafe {
        crate::driver_launch::win32k_file_owners::wait_identity_for_canonical(
            object.object_id,
            object.object_generation,
        )
    }
    .map_err(|status| status as u32)?;
    if identity.file_id().raw() != object.object_id
        || identity.binding_generation() != object.object_generation
    {
        return Err(STATUS_INVALID_HANDLE);
    }

    let next = unsafe { NEXT_TOKEN.checked_add(1) }.ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    leases()
        .try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let io = io_manager_mut();
    let mut publication = io
        .lease_hosted_file_identity(identity)
        .map_err(|status| status.raw() as u32)?;
    let mut reference = match io.retain_file_reference(identity.file_id()) {
        Ok(reference) => reference,
        Err(status) => {
            io.release_hosted_file_publication(&mut publication)
                .expect("File wait publication rollback");
            return Err(status.raw() as u32);
        }
    };
    if let Err(status) = file_completion.retain_file(identity.file_id().raw()) {
        io.release_file_reference(&mut reference)
            .expect("File wait reference rollback");
        io.release_hosted_file_publication(&mut publication)
            .expect("File wait publication rollback");
        return Err(status);
    }
    let token = unsafe { NEXT_TOKEN };
    leases().push(WaitLease {
        token,
        owner,
        identity,
        reference,
        publication,
        retiring: false,
        completion_released: false,
        completion_followup: None,
    });
    unsafe { NEXT_TOKEN = next };
    Ok(token)
}

pub(crate) fn is_ready(token: u64, file_completion: &ExecFileCompletion) -> bool {
    let Some(lease) = leases().iter().find(|lease| lease.token == token && !lease.retiring) else {
        return false;
    };
    lease.owner.is_valid()
        && io_manager_mut().hosted_file_identity_at(
            lease.identity.domain(),
            lease.identity.file_id(),
            lease.identity.address(),
        ) == Ok(Some(lease.identity))
        && file_completion.is_signaled(lease.identity.file_id().raw()) == Ok(true)
}

/// No provider effect is issued here. Failed completion release remains owned for redrive.
pub(crate) fn release(token: u64, file_completion: &mut ExecFileCompletion) {
    let lease = leases().iter_mut().find(|lease| lease.token == token)
        .expect("File wait lease token must be live on release");
    assert!(!lease.retiring, "File wait lease released twice");
    lease.retiring = true;
    if let Ok(release) = file_completion.release_file(lease.identity.file_id().raw()) {
        lease.completion_released = true;
        lease.completion_followup = Some(release);
    }
}

/// Complete deferred File lifecycle effects before unpinning its exact projection.
pub(crate) fn redrive(handler: &mut ExecNtHandler) {
    let mut cursor = 0;
    loop {
        let Some(token) = leases()
            .iter()
            .filter(|lease| lease.retiring && lease.token > cursor)
            .map(|lease| lease.token)
            .min()
        else {
            break;
        };
        cursor = token;
        let Some(index) = leases().iter().position(|lease| lease.token == token) else {
            continue;
        };
        if !leases()[index].completion_released {
            let file_id = leases()[index].identity.file_id().raw();
            let Ok(release) = handler.file_completion.release_file(file_id) else {
                continue;
            };
            leases()[index].completion_released = true;
            leases()[index].completion_followup = Some(release);
        }
        if let Some(release) = leases()[index].completion_followup.take() {
            handler.complete_file_reference_release(leases()[index].identity.file_id().raw(), release);
        }
        if leases()[index].reference.is_held()
            && io_manager_mut()
                .release_file_reference(&mut leases()[index].reference)
                .is_err()
        {
            continue;
        }
        if leases()[index].publication.is_held()
            && io_manager_mut()
                .release_hosted_file_publication(&mut leases()[index].publication)
                .is_err()
        {
            continue;
        }
        leases().swap_remove(index);
    }
}
