//! Boot AHCI VT-d authority shared with a later hosted PCI DMA grant.
//!
//! The boot storage host remains the controller operator until a real block route is
//! published. This owner only admits disjoint DMA memory in the same RID domain.

use crate::*;
use nt_pnp_context::pci_dma_handoff::{
    BootIoTicket, ControllerState, PciController, PciDmaHandoff, WindowId, WindowPhase,
};
use nt_pnp_context::native_storage_handoff::{
    MountCommit, NativeStorageAdmissions, NativeStorageHandoff, SrbProofRequest,
    StorageHandoffKey, StoragePdo, StorageRelation,
};

const BOOT_GENERATION: u64 = 1;
pub(crate) const BOOT_DOMAIN: u64 = 2;
pub(crate) const HOSTED_BOOT_AHCI_IOVA: u64 = AHCI_IOVA + 0x1000;

pub(crate) struct BootStorageDmaAuthority {
    controller: PciController,
    abar_phys: u64,
    abar_frame: u64,
    io_space_cap: u64,
    // Retain the complete boot-owned tree and frame aliases for the controller lifetime.
    _iopt_caps: [u64; 4],
    _dma_frame: u64,
    _dma_frame_io: u64,
    ledger: PciDmaHandoff,
    ready: bool,
    native_lease: Option<nt_pnp_context::ContextLeaseIdentity>,
    native_window: Option<WindowId>,
    accepted_pdo: Option<u64>,
    uncertain_owner: Option<HostedPnpContextOwner>,
}

static mut BOOT_STORAGE_DMA: Option<BootStorageDmaAuthority> = None;
static mut NATIVE_STORAGE_ADMISSIONS: NativeStorageAdmissions = NativeStorageAdmissions::new();

fn authority() -> Option<&'static mut BootStorageDmaAuthority> {
    // The executive dispatches these admission operations on its single broker thread.
    unsafe { BOOT_STORAGE_DMA.as_mut() }
}

/// Consume the one native-disk admission for this physical controller only after the exact
/// boot mount and observed accepted LUN relation are available. The returned move-only owner
/// retains the pre-drain capacity/sector evidence through the three native SRB probes.
pub(crate) fn begin_native_disk_proof(
    relation: StorageRelation,
    pdo: StoragePdo,
) -> Result<NativeStorageHandoff, nt_status::NtStatus> {
    let (mount, expected) = unsafe { crate::fs_loader::exec_expected_disk() }
        .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    let owner = authority().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    if !owner.ready || owner.native_lease.is_none() || owner.native_window.is_none() {
        return Err(nt_status::NtStatus::DEVICE_NOT_READY);
    }
    let key = StorageHandoffKey {
        controller: owner.controller,
        dma_root: owner.io_space_cap,
        mount: mount.value(),
        relation,
        pdo,
    };
    unsafe {
        NativeStorageHandoff::new(
            &mut *core::ptr::addr_of_mut!(NATIVE_STORAGE_ADMISSIONS),
            &owner.ledger,
            key,
            expected,
        )
    }
    .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(crate) fn enter_native_disk_srb(
    handoff: &mut NativeStorageHandoff,
) -> Result<SrbProofRequest, nt_status::NtStatus> {
    let owner = authority().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    let key = handoff.key();
    handoff.enter_srb(&owner.ledger, key)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(crate) fn enter_native_disk_mount(
    handoff: &mut NativeStorageHandoff,
) -> Result<MountCommit, nt_status::NtStatus> {
    let owner = authority().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    let key = handoff.key();
    owner.ledger.can_activate_native(key.controller, key.dma_root, key.pdo.device)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    unsafe {
        handoff.enter_mount_commit(
            &mut *core::ptr::addr_of_mut!(NATIVE_STORAGE_ADMISSIONS),
            &owner.ledger,
            key,
        )
    }.map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(crate) fn complete_native_disk_mount(
    handoff: &mut NativeStorageHandoff,
    commit: MountCommit,
) -> Result<(), nt_status::NtStatus> {
    let owner = authority().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    handoff.complete_mount_commit(&mut owner.ledger, commit)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(crate) fn mark_native_disk_relation_published(
    handoff: &mut NativeStorageHandoff,
) -> Result<(), nt_status::NtStatus> {
    let owner = authority().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    let key = handoff.key();
    handoff.mark_relation_published(&owner.ledger, key)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(crate) fn validate_native_disk_refresh(
    published: StorageHandoffKey,
    candidate: StorageHandoffKey,
) -> Result<(), nt_status::NtStatus> {
    let owner = authority().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    nt_pnp_context::native_storage_handoff::validate_native_relation_refresh(
        &owner.ledger, published, candidate,
    ).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

/// A command is untracked only before the executive installs its controller owner, or in
/// the isolated storage host's separate address space. A refused admission issues no MMIO.
pub(crate) enum BootIoAdmission {
    Untracked,
    Ticket(BootIoTicket),
}

pub(crate) fn enter_boot_io() -> Result<BootIoAdmission, ()> {
    let Some(owner) = authority() else {
        return Ok(BootIoAdmission::Untracked);
    };
    if !owner.ready {
        return Err(());
    }
    owner
        .ledger
        .enter_boot_io(owner.controller, owner.io_space_cap)
        .map(BootIoAdmission::Ticket)
        .map_err(|_| ())
}

/// A cache miss may read the installed volume only while the exact boot controller still
/// accepts direct I/O. Once drain starts, callers must use resident source bytes.
pub(crate) fn boot_disk_reads_admitted() -> bool {
    let Some(owner) = authority() else {
        return true;
    };
    owner.ready
        && matches!(
            owner.ledger.state(owner.controller, owner.io_space_cap),
            Ok(ControllerState::BootActive)
        )
}

/// Result of redriving the exact boot-controller transition. A pending boot command keeps
/// the controller in BootDraining; it never reopens direct AHCI admission.
pub(crate) enum NativeStartAdmission {
    Draining,
    Ready,
}

/// Fence direct AHCI only after the registry-selected driver source closure is resident and
/// the exact hosted controller lease has a mapped native DMA window. The same caller may
/// redrive this while an entered boot command is still retiring; uncertain commands retain
/// their ledger tickets and cannot be treated as retired by a timeout or Reply ACK.
pub(crate) fn begin_native_start_after_preload(
    receipt: driver_launch::PreloadReceipt,
    lease: nt_pnp_context::ContextLeaseIdentity,
) -> Result<NativeStartAdmission, nt_status::NtStatus> {
    // Snapshot recovery may read and repair the reserve. Do it while direct AHCI admission
    // remains open; BusRelations publication must never discover a lazy mount after drain.
    unsafe { crate::writable_fs::ensure_mounted() }
        .map_err(|status| nt_status::NtStatus(status as i32))?;
    if !unsafe { driver_launch::boot_driver_preload_receipt_is_current(receipt) } {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let owner = authority().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    if !owner.ready || owner.native_lease != Some(lease) {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let window = owner.native_window.ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    if owner
        .ledger
        .window_phase(owner.controller, owner.io_space_cap, window)
        != Ok(WindowPhase::Mapped)
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    // Reject an absent/unpublished mount before the controller enters its irreversible drain.
    if !crate::fs_loader::exec_mount_can_drain() {
        return Err(nt_status::NtStatus::DEVICE_NOT_READY);
    }
    match owner.ledger.state(owner.controller, owner.io_space_cap) {
        Ok(ControllerState::BootActive) => owner
            .ledger
            .begin_drain(owner.controller, owner.io_space_cap)
            .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?,
        Ok(ControllerState::BootDraining) => {}
        Ok(ControllerState::NativeStarting) => return Ok(NativeStartAdmission::Ready),
        _ => return Err(nt_status::NtStatus::DEVICE_BUSY),
    }
    // The controller's exact boot tickets remain the command authority. A separate mount
    // fence prevents copied FAT handles and the snapshot reserve from entering new boot I/O.
    crate::fs_loader::begin_exec_mount_drain()
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    match owner
        .ledger
        .begin_native_start_exact(owner.controller, owner.io_space_cap, window)
    {
        Ok(()) => Ok(NativeStartAdmission::Ready),
        Err(nt_pnp_context::pci_dma_handoff::Error::BootIoOutstanding) => {
            Ok(NativeStartAdmission::Draining)
        }
        Err(_) => Err(nt_status::NtStatus::DEVICE_BUSY),
    }
}

/// Complete only a command whose hardware retirement is known. An ambiguous timeout or
/// controller fault retains the ticket, so a later native-start attempt stays fenced.
pub(crate) fn finish_boot_io(admission: BootIoAdmission, retired: bool) {
    let BootIoAdmission::Ticket(ticket) = admission else {
        return;
    };
    if retired {
        let owner = authority().expect("boot AHCI DMA authority lost during I/O");
        owner
            .ledger
            .complete_boot_io(owner.controller, owner.io_space_cap, ticket)
            .expect("boot AHCI I/O ticket lost");
    }
}

pub(crate) fn install_boot_storage_dma_authority(
    bus: u8,
    dev: u8,
    func: u8,
    abar_phys: u64,
    abar_frame: u64,
    io_space_cap: u64,
    iopt_caps: [u64; 4],
    dma_frame: u64,
    dma_frame_io: u64,
    mapped: bool,
) -> bool {
    if authority().is_some() {
        return false;
    }
    let Some(controller) = PciController::new(bus, dev, func, BOOT_GENERATION) else {
        return false;
    };
    let mut ledger = PciDmaHandoff::new();
    let ready = mapped
        && ledger
            .register(controller, io_space_cap, AHCI_IOVA, 1)
            .is_ok();
    unsafe {
        BOOT_STORAGE_DMA = Some(BootStorageDmaAuthority {
            controller,
            abar_phys,
            abar_frame,
            io_space_cap,
            _iopt_caps: iopt_caps,
            _dma_frame: dma_frame,
            _dma_frame_io: dma_frame_io,
            ledger,
            ready,
            native_lease: None,
            native_window: None,
            accepted_pdo: None,
            uncertain_owner: None,
        });
    }
    ready
}

pub(crate) fn is_boot_storage_controller(device: &nt_pnp::PciDevice) -> bool {
    authority().is_some_and(|owner| is_same_controller(owner, device))
}

pub(crate) fn is_boot_storage_bdf(device: &nt_pnp::PciDevice) -> bool {
    authority().is_some_and(|owner| {
        owner.controller.bus == device.bus
            && owner.controller.device == device.dev
            && owner.controller.function == device.func
    })
}

/// Called only after the independent PCI inventory and bus-owned PDO resource bytes match.
/// The PDO survives later missing property queries, so its disk relation remains proof-gated.
pub(crate) fn remember_boot_controller_pdo(
    pdo: u64,
    device: &nt_pnp::PciDevice,
) -> Result<(), nt_status::NtStatus> {
    if !is_boot_storage_bdf(device) { return Ok(()); }
    let owner = authority().ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    if pdo == 0 || !is_same_controller(owner, device) {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    owner.accepted_pdo = Some(pdo);
    Ok(())
}

pub(crate) fn relation_parent_requires_native_disk_proof(
    pdo: u64,
    observed_pci_location: Option<(u32, u32)>,
) -> bool {
    authority().is_some_and(|owner| {
        nt_pnp_context::pci_dma_handoff::relation_requires_native_disk_proof(
            owner.controller, pdo, owner.accepted_pdo, observed_pci_location,
        )
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControllerGrantAdmission {
    Current,
    Pending,
    Blocked(nt_status::NtStatus),
}

/// Check this before any BAR cap is copied into a hosted driver and again at handout.
/// A native-start transition is recorded only after all direct boot I/O is drained.
pub(crate) fn admit_hosted_pci_controller_grant(
    lease: nt_pnp_context::ContextLeaseIdentity,
    device: &nt_pnp::PciDevice,
    window: &HostedPnpPciResourceDescriptor,
) -> ControllerGrantAdmission {
    let Some(owner) = authority() else {
        return ControllerGrantAdmission::Current;
    };
    if owner.controller.bus != device.bus
        || owner.controller.device != device.dev
        || owner.controller.function != device.func
    {
        return ControllerGrantAdmission::Current;
    }
    if !owner.ready
        || !is_same_controller(owner, device)
        || !window.matches(device)
        || !window
            .memory_window(5)
            .is_some_and(|bar| bar.phys == owner.abar_phys && bar.frame_base == owner.abar_frame)
        || owner.native_lease.is_some_and(|accepted| accepted != lease)
    {
        return ControllerGrantAdmission::Blocked(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    owner.native_lease = Some(lease);
    match owner.ledger.state(owner.controller, owner.io_space_cap) {
        Ok(ControllerState::NativeStarting) => ControllerGrantAdmission::Current,
        Ok(ControllerState::BootActive | ControllerState::BootDraining) => {
            ControllerGrantAdmission::Pending
        }
        _ => ControllerGrantAdmission::Blocked(nt_status::NtStatus::DEVICE_BUSY),
    }
}

pub(crate) fn reserve_hosted_boot_dma_window(
    lease: nt_pnp_context::ContextLeaseIdentity,
    device: &nt_pnp::PciDevice,
    pages: u64,
) -> Result<(u64, WindowId), nt_status::NtStatus> {
    let owner = authority().ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if !owner.ready
        || !is_same_controller(owner, device)
        || owner.native_lease.is_some_and(|accepted| accepted != lease)
        || owner.native_window.is_some()
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let id = owner
        .ledger
        .reserve_window(
            owner.controller,
            owner.io_space_cap,
            HOSTED_BOOT_AHCI_IOVA,
            pages,
        )
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    owner.native_lease = Some(lease);
    owner.native_window = Some(id);
    Ok((owner.io_space_cap, id))
}

fn is_same_controller(owner: &BootStorageDmaAuthority, device: &nt_pnp::PciDevice) -> bool {
    owner.controller.bus == device.bus
        && owner.controller.device == device.dev
        && owner.controller.function == device.func
        && device.bars.iter().any(|bar| {
            bar.index == 5 && bar.is_present() && !bar.is_io && bar.base == owner.abar_phys
        })
}

pub(crate) fn begin_hosted_boot_dma_map(id: WindowId) -> Result<(), nt_status::NtStatus> {
    let owner = authority().ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    owner
        .ledger
        .begin_map(owner.controller, owner.io_space_cap, id)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(crate) fn cancel_prepared_hosted_boot_dma_window(id: WindowId) {
    let owner = authority().expect("boot AHCI DMA authority lost");
    owner
        .ledger
        .cancel_window(owner.controller, owner.io_space_cap, id)
        .expect("boot AHCI DMA preparation phase lost");
    assert_eq!(owner.native_window, Some(id));
    owner.native_window = None;
}

pub(crate) fn confirm_hosted_boot_dma_map(id: WindowId) -> Result<(), nt_status::NtStatus> {
    let owner = authority().ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    owner
        .ledger
        .confirm_map(owner.controller, owner.io_space_cap, id)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(crate) fn quarantine_hosted_boot_dma_map(id: WindowId, staged: HostedPnpContextOwner) {
    let owner = authority().expect("boot AHCI DMA authority lost");
    owner
        .ledger
        .quarantine(owner.controller, owner.io_space_cap, id)
        .expect("boot AHCI DMA mapping phase lost");
    assert!(owner.uncertain_owner.replace(staged).is_none());
}

pub(crate) fn quarantine_hosted_boot_dma_owner(staged: HostedPnpContextOwner) {
    let owner = authority().expect("boot AHCI DMA authority lost");
    assert!(owner.uncertain_owner.replace(staged).is_none());
}

pub(crate) fn quarantine_hosted_boot_dma_phase(id: WindowId) {
    let owner = authority().expect("boot AHCI DMA authority lost");
    owner
        .ledger
        .quarantine(owner.controller, owner.io_space_cap, id)
        .expect("boot AHCI DMA mapping phase lost");
}
