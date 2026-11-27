//! Retained FileBasic mutations for Files opened on the mounted writable volume.
//!
//! The I/O Manager owns the canonical File and IRP through backend completion ACK. This queue
//! keeps their exact identities and the copied input beside the prepared mutation; CLEANUP may
//! close the handle, but CLOSE cannot release the File body until that ACK.

use super::*;

static BASIC_OWNER_RECEIPTS: AtomicU64 = AtomicU64::new(0);
const BASIC_OWNER_RECEIPT_LIMIT: u64 = 4096;

fn basic_owner_receipt(stage: &[u8], entry: &MountedBasicSet, status: NtStatus) {
    if BASIC_OWNER_RECEIPTS.fetch_add(1, Ordering::Relaxed) >= BASIC_OWNER_RECEIPT_LIMIT {
        return;
    }
    let stable = match &entry.phase {
        BasicPhase::Terminal { prepared: Some(prepared), .. } => prepared.stable_file_id(),
        _ => 0,
    };
    crate::print_str(b"[mounted-basic-owner] stage=");
    crate::print_str(stage);
    crate::print_str(b" irp=");
    crate::print_u64(entry.identity.irp.raw());
    crate::print_str(b" file=");
    crate::print_u64(entry.identity.file.raw());
    crate::print_str(b" context=");
    crate::print_u64(entry.identity.context.raw());
    crate::print_str(b" mount=");
    crate::print_u64(entry.identity.mount.value());
    crate::print_str(b" overlay_mount=");
    crate::print_u64(entry.identity.overlay_mount.value());
    crate::print_str(b" overlay_file=");
    crate::print_u64(entry.identity.overlay_file);
    crate::print_str(b" status=");
    crate::print_u64(u64::from(status.0 as u32));
    crate::print_str(b" stable=");
    crate::print_u64(stable);
    crate::print_str(b" attrs=");
    crate::print_u64(u64::from(u32::from_le_bytes(entry.input[32..36].try_into().unwrap())));
    crate::print_str(b"\n");
}

#[derive(Clone, Copy)]
pub(super) struct BasicIdentity {
    pub(super) irp: IrpId,
    file: nt_io_manager::FileId,
    context: nt_fs::LayeredOpenContextId,
    mount: nt_memory_manager::SectionMountId,
    overlay_mount: nt_memory_manager::SectionMountId,
    overlay_file: u64,
}

enum BasicPhase {
    Captured,
    Prepared(nt_io_manager::PendingBasicPreparedOwner<BasicIdentity>),
    Terminal {
        status: NtStatus,
        published: bool,
        /// The prepared plan and its File correlation stay until backend completion ACK.
        prepared: Option<nt_io_manager::PendingBasicPreparedOwner<BasicIdentity>>,
    },
}

pub(super) struct MountedBasicSet {
    pub(super) identity: BasicIdentity,
    input: [u8; 40],
    phase: BasicPhase,
}

impl MountedVolumeBackend {
    pub(super) fn park_basic(
        &mut self,
        irp: &IrpProjection,
        context: nt_fs::LayeredOpenContextId,
        overlay_file: u64,
        input: &[u8],
    ) -> Result<DispatchOutcome, NtStatus> {
        let file = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let input: [u8; 40] = input.get(..40).ok_or(NtStatus::INVALID_PARAMETER)?
            .try_into().expect("checked Basic input length");
        let mount = unsafe { crate::fs_loader::exec_fs_mount_identity() }
            .ok_or(NtStatus::DEVICE_NOT_READY)?;
        if crate::fs_loader::exec_block_route_kind(mount).is_none() {
            return Err(NtStatus::DEVICE_NOT_READY);
        }
        let overlay_mount = unsafe { crate::writable_fs::mounted_basic_namespace_identity() }
            .ok_or(NtStatus::DEVICE_NOT_READY)?;
        if self.pending_basic.iter().any(|entry| entry.identity.irp == irp.irp_id) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        // Reserve before publishing Pending: from this point the provider owns the copied input.
        self.pending_basic.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        self.pending_basic.push(MountedBasicSet {
            identity: BasicIdentity {
                irp: irp.irp_id, file, context, mount, overlay_mount, overlay_file,
            },
            input,
            phase: BasicPhase::Captured,
        });
        Ok(DispatchOutcome::Pending)
    }

    /// Revalidate the exact File/context/mount before entering the writable filesystem. The
    /// CLEANUP path preserves an overlay body reference until I/O Manager permits CLOSE.
    fn basic_owner_status(&self, owner: BasicIdentity) -> Result<(), NtStatus> {
        if unsafe { crate::fs_loader::exec_fs_mount_identity() } != Some(owner.mount) {
            return Err(NtStatus::DEVICE_NOT_READY);
        }
        if unsafe { crate::writable_fs::mounted_basic_namespace_identity() }
            != Some(owner.overlay_mount)
        {
            return Err(NtStatus::DEVICE_NOT_READY);
        }
        match crate::fs_loader::exec_block_route_kind(owner.mount) {
            Some(nt_fs::BlockSourceKind::Boot | nt_fs::BlockSourceKind::Native) => {}
            Some(nt_fs::BlockSourceKind::Draining) => return Err(RESIDENT_BUSY),
            _ => return Err(NtStatus::DEVICE_NOT_READY),
        }
        let record = self.opens.get(owner.context, owner.file.raw()).map_err(status)?;
        if !matches!(record.source,
            nt_fs::LayeredOpenSource::Overlay { file_id } if file_id == owner.overlay_file)
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let binding = self.bindings.get(context_index(owner.context)
            .ok_or(NtStatus::INVALID_HANDLE)?)
            .and_then(Option::as_ref)
            .filter(|binding| binding.context == owner.context)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        if !binding.overlay_open && !binding.overlay_body {
            return Err(NtStatus::INVALID_HANDLE);
        }
        Ok(())
    }

    pub(super) fn service_basic(&mut self) -> usize {
        let Some(index) = self.pending_basic.iter().position(|item| {
            !matches!(&item.phase, BasicPhase::Terminal { .. })
        }) else { return 0; };
        let owner = self.pending_basic[index].identity;
        match self.basic_owner_status(owner) {
            Err(RESIDENT_BUSY) => return 0,
            Err(error) => {
                self.pending_basic[index].phase = BasicPhase::Terminal {
                    status: error, published: false, prepared: None,
                };
                return 1;
            }
            Ok(()) => {}
        }
        match unsafe { crate::writable_fs::prepared_overlay_resident() } {
            Ok(false) => return 0,
            Err(raw) => {
                self.pending_basic[index].phase = BasicPhase::Terminal {
                    status: status(raw), published: false, prepared: None,
                };
                return 1;
            }
            Ok(true) => {}
        }
        // This swap moves the sidecar out of the queue while the single provider owner drives
        // it. A Busy result always puts the same owner back without repeating an entered effect.
        let phase = core::mem::replace(&mut self.pending_basic[index].phase, BasicPhase::Captured);
        let (phase, progress) = match phase {
            BasicPhase::Captured => {
                match unsafe { crate::writable_fs::prepare_basic_with_reference(
                    owner.overlay_file, self.pending_basic[index].input, owner,
                ) } {
                    Ok(prepared) => (BasicPhase::Prepared(prepared), 1),
                    Err((raw, _owner)) if status(raw) == RESIDENT_BUSY =>
                        (BasicPhase::Captured, 0),
                    Err((raw, _owner)) => (BasicPhase::Terminal {
                        status: status(raw), published: false, prepared: None,
                    }, 1),
                }
            }
            BasicPhase::Prepared(mut prepared) => {
                match unsafe { crate::writable_fs::apply_mounted_basic_snapshot_once(&mut prepared) } {
                    Ok(raw) => (BasicPhase::Terminal {
                        status: status(raw), published: false, prepared: Some(prepared),
                    }, 1),
                    Err(raw) if status(raw) == RESIDENT_BUSY =>
                        (BasicPhase::Prepared(prepared), 0),
                    Err(raw) => (BasicPhase::Terminal {
                        status: status(raw), published: false, prepared: Some(prepared),
                    }, 1),
                }
            }
            terminal @ BasicPhase::Terminal { .. } => (terminal, 0),
        };
        self.pending_basic[index].phase = phase;
        progress
    }

    pub(super) fn poll_basic_completion(&mut self) -> Option<DriverCompletion> {
        let entry = self.pending_basic.iter_mut().find(|item| {
            matches!(&item.phase, BasicPhase::Terminal { published: false, .. })
        })?;
        let BasicPhase::Terminal { status, published, .. } = &mut entry.phase else {
            unreachable!("selected a terminal Basic row");
        };
        *published = true;
        let status = *status;
        basic_owner_receipt(b"terminal", entry, status);
        Some(DriverCompletion {
            irp_id: entry.identity.irp,
            status,
            information: 0,
            file_context: None,
        })
    }

    pub(super) fn ack_basic_completion(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        let index = self.pending_basic.iter().position(|item| item.identity.irp == irp)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if !matches!(&self.pending_basic[index].phase,
            BasicPhase::Terminal { published: true, .. })
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let entry = self.pending_basic.swap_remove(index);
        if let BasicPhase::Terminal { status, .. } = &entry.phase {
            basic_owner_receipt(b"ack", &entry, *status);
        }
        if let BasicPhase::Terminal { prepared: Some(prepared), .. } = entry.phase {
            let owner = prepared.into_file();
            debug_assert_eq!(owner.irp, irp);
        }
        Ok(())
    }

    pub(super) fn cancel_basic(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        let entry = self.pending_basic.iter_mut().find(|item| item.identity.irp == irp)
            .ok_or(NtStatus::NOT_SUPPORTED)?;
        if matches!(&entry.phase, BasicPhase::Terminal { .. }) {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        entry.phase = BasicPhase::Terminal {
            status: NtStatus::CANCELLED, published: false, prepared: None,
        };
        Ok(())
    }
}
