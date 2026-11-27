//! One retained capacity claim for the next durable SYSTEM checkpoint image.
//!
//! CM may publish many small WAL records before the image is folded. Charging a fresh image
//! reservation per record would count the same replacement repeatedly, so the mounted volume
//! owns one move-only claim and updates its target before each CM COMMIT. The claim survives
//! storage retries and uncertain effects; only an exact terminal ACK settles a candidate.

use super::*;
use nt_config_client::{PreparedSystemHiveMutation, SystemHiveMutationStorageBinding};
use nt_fs::SnapshotCapacityReservation;
use nt_memory_manager::SectionMountId;

#[derive(Clone, Copy)]
struct Pending {
    binding: SystemHiveMutationStorageBinding,
    candidate_len: usize,
}

struct Owner {
    mount: SectionMountId,
    token: SnapshotCapacityReservation,
    reserved_len: usize,
    accepted_len: Option<usize>,
    pending: Option<Pending>,
}

#[derive(Clone, Copy)]
struct FoldClaim {
    mount: SectionMountId,
    image_len: Option<usize>,
}

// The executive services this state from its serialized outer service turn. The filesystem's
// reservation ledger remains charged even if a token is lost; a blocked mount is never reused.
static mut OWNER: Option<Owner> = None;
static mut FOLDING: Option<FoldClaim> = None;

fn invariant_failure() -> u32 {
    block_uncertain_snapshot_reserve();
    nt_fs::STATUS_DATA_ERROR
}

fn mounted_identity() -> Result<SectionMountId, u32> {
    unsafe { *core::ptr::addr_of!(WRITABLE_MOUNT_ID) }.ok_or(nt_fs::STATUS_DEVICE_NOT_READY)
}

/// Admit the projected image before any batch slot, WAL header recheck, or CM COMMIT.
/// Repeating this with the same preparation after `DEVICE_BUSY` reuses the exact charge.
pub(crate) unsafe fn admit(prepared: &PreparedSystemHiveMutation) -> Result<bool, u32> {
    if (*core::ptr::addr_of!(FOLDING)).is_some() {
        return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32);
    }
    let binding = prepared.storage_binding();
    let candidate = prepared.projected_checkpoint_image_len();
    let mount = mounted_identity()?;
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    if let Some(owner) = slot.as_mut() {
        if owner.mount != mount {
            return Err(invariant_failure());
        }
        if let Some(pending) = owner.pending {
            return if pending.binding == binding && Some(pending.candidate_len) == candidate {
                Ok(true)
            } else {
                Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32)
            };
        }
    }
    let Some(candidate_len) = candidate else {
        return Ok(false);
    };
    let fs = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS))
        .as_mut()
        .ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    if let Some(mut owner) = slot.take() {
        // A tentative shrink must not release a previously committed image's charge: an
        // unrelated writer could consume it before this CM preparation aborts.
        let target = candidate_len.max(owner.accepted_len.unwrap_or(0));
        if target != owner.reserved_len {
            owner.token = match fs.update_snapshot_replacement_projection(owner.token, target) {
                Ok(token) => token,
                Err((status, token)) => {
                    owner.token = token;
                    *slot = Some(owner);
                    return Err(status);
                }
            };
            owner.reserved_len = target;
        }
        owner.pending = Some(Pending {
            binding,
            candidate_len,
        });
        *slot = Some(owner);
    } else {
        let token =
            fs.reserve_snapshot_replacement_by_path(CONFIG_SYSTEM_HIVE_PATH, candidate_len)?;
        *slot = Some(Owner {
            mount,
            token,
            reserved_len: candidate_len,
            accepted_len: None,
            pending: Some(Pending {
                binding,
                candidate_len,
            }),
        });
    }
    Ok(true)
}

/// A matching CM ACK and settled storage owner promote the projection. A deferred tentative
/// shrink releases its old charge only now, after the candidate has actually committed.
pub(crate) unsafe fn commit_after_ack(
    binding: SystemHiveMutationStorageBinding,
) -> Result<(), u32> {
    let mount = mounted_identity().map_err(|_| invariant_failure())?;
    let fs = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS))
        .as_mut()
        .ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    let Some(mut owner) = slot.take() else {
        return Err(invariant_failure());
    };
    let Some(pending) = owner.pending else {
        *slot = Some(owner);
        return Err(invariant_failure());
    };
    if owner.mount != mount
        || pending.binding != binding
        || (*core::ptr::addr_of!(FOLDING)).is_some()
    {
        *slot = Some(owner);
        return Err(invariant_failure());
    }
    if pending.candidate_len != owner.reserved_len {
        owner.token =
            match fs.update_snapshot_replacement_projection(owner.token, pending.candidate_len) {
                Ok(token) => token,
                Err((status, token)) => {
                    owner.token = token;
                    *slot = Some(owner);
                    return Err(status);
                }
            };
        owner.reserved_len = pending.candidate_len;
    }
    owner.accepted_len = Some(pending.candidate_len);
    owner.pending = None;
    *slot = Some(owner);
    Ok(())
}

/// Only the matching abort ACK with a released storage owner may restore or cancel a claim.
/// A refused filesystem operation returns its token and leaves this owner intact for retry.
pub(crate) unsafe fn abort_after_ack(binding: SystemHiveMutationStorageBinding) -> Result<(), u32> {
    let mount = mounted_identity().map_err(|_| invariant_failure())?;
    let fs = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS))
        .as_mut()
        .ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    let Some(mut owner) = slot.take() else {
        return Err(invariant_failure());
    };
    if owner.mount != mount
        || owner
            .pending
            .is_none_or(|pending| pending.binding != binding)
        || (*core::ptr::addr_of!(FOLDING)).is_some()
    {
        *slot = Some(owner);
        return Err(invariant_failure());
    }
    if let Some(accepted_len) = owner.accepted_len {
        if owner.reserved_len != accepted_len {
            owner.token = match fs.update_snapshot_replacement_projection(owner.token, accepted_len)
            {
                Ok(token) => token,
                Err((status, token)) => {
                    owner.token = token;
                    *slot = Some(owner);
                    return Err(status);
                }
            };
            owner.reserved_len = accepted_len;
        }
        owner.pending = None;
        *slot = Some(owner);
    } else if let Err((status, token)) = fs.cancel_snapshot_reservation(owner.token) {
        owner.token = token;
        *slot = Some(owner);
        return Err(status);
    }
    Ok(())
}

/// Reserve a recovered SYSTEM WAL suffix before the restored volume or WAL anchor is published.
/// The returned token belongs to the still-private filesystem until `install_boot` transfers it.
pub(crate) fn reserve_boot(
    fs: &mut nt_fs::FileSystem,
    image_len: usize,
) -> Result<SnapshotCapacityReservation, u32> {
    fs.reserve_snapshot_replacement_by_path(CONFIG_SYSTEM_HIVE_PATH, image_len)
}

pub(crate) unsafe fn install_boot(
    token: SnapshotCapacityReservation,
    image_len: usize,
) -> Result<(), u32> {
    let mount = mounted_identity().map_err(|_| invariant_failure())?;
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    if slot.is_some() {
        return Err(invariant_failure());
    }
    *slot = Some(Owner {
        mount,
        token,
        reserved_len: image_len,
        accepted_len: Some(image_len),
        pending: None,
    });
    Ok(())
}

/// Fence a fold against new CM admission while its physical and acknowledgement effects run.
/// A non-SYSTEM-only WAL epoch has no replacement claim to consume.
pub(crate) unsafe fn begin_fold(image_len: Option<usize>) -> Result<(), u32> {
    let mount = mounted_identity().map_err(|_| invariant_failure())?;
    let folding = &mut *core::ptr::addr_of_mut!(FOLDING);
    if folding.is_some() {
        return Err(snapshot_storage::BUSY);
    }
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    let Some(owner) = slot.as_mut() else {
        if image_len.is_some() {
            return Err(invariant_failure());
        }
        *folding = Some(FoldClaim { mount, image_len });
        return Ok(());
    };
    if owner.mount != mount {
        return Err(invariant_failure());
    }
    if owner.pending.is_some() {
        return Err(snapshot_storage::BUSY);
    }
    if let Some(image_len) = image_len {
        if owner.accepted_len != Some(image_len) || owner.reserved_len != image_len {
            return Err(invariant_failure());
        }
    }
    *folding = Some(FoldClaim { mount, image_len });
    Ok(())
}

/// Release the fold fence only after the physical pair, CM ACK, live image, and continuation
/// have all been installed. Failed or uncertain folds keep their claim and block new admission.
pub(crate) unsafe fn finish_fold() -> Result<(), u32> {
    let mount = mounted_identity().map_err(|_| invariant_failure())?;
    let folding = &mut *core::ptr::addr_of_mut!(FOLDING);
    let Some(claim) = *folding else {
        return Err(invariant_failure());
    };
    if claim.mount != mount {
        return Err(invariant_failure());
    }
    if claim.image_len.is_some() && (*core::ptr::addr_of!(OWNER)).is_some() {
        return Err(invariant_failure());
    }
    *folding = None;
    Ok(())
}

/// Consume the exact retained claim when the durable fold installs its CM image in the live
/// filesystem. A refused effect restores both the token and image to the caller.
pub(crate) unsafe fn replace_folded(
    fs: &mut nt_fs::FileSystem,
    handle: u64,
    image: alloc::vec::Vec<u8>,
) -> Result<(), (u32, alloc::vec::Vec<u8>)> {
    let mount = match mounted_identity() {
        Ok(mount) => mount,
        Err(_) => return Err((invariant_failure(), image)),
    };
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    let Some(owner) = slot.take() else {
        return Err((invariant_failure(), image));
    };
    let folding = *core::ptr::addr_of!(FOLDING);
    if owner.mount != mount
        || folding.is_none_or(|claim| claim.mount != mount || claim.image_len != Some(image.len()))
        || owner.reserved_len != image.len()
        || owner.pending.is_some()
    {
        *slot = Some(owner);
        return Err((invariant_failure(), image));
    }
    match fs.replace_file_data_owned_reserved(owner.token, handle, image) {
        Ok(()) => Ok(()),
        Err((status, token, image)) => {
            *slot = Some(Owner { token, ..owner });
            Err((status, image))
        }
    }
}
