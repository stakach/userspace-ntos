//! Exact native disk route published only after the retained media proof and mount cutover.

use super::*;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    scsi_block_command::ScsiBlockCommand,
    scsi_srb_transport::ScsiParameters,
    scsi_srb_wire::decode_scsi_completion,
    IoParameters, StackFlags,
};
use nt_pnp_context::native_storage_handoff::{
    HandoffPhase, NativeStorageHandoff, ProofStep, SrbProofRequest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeStorageRoute {
    pub mount: nt_memory_manager::SectionMountId,
    pub scsi: nt_io_manager::scsi_srb_transport::ScsiSrbRoute,
    pub driver_id: DriverId,
    pub key: nt_pnp_context::native_storage_handoff::StorageHandoffKey,
}

static mut NATIVE_STORAGE_ROUTE: Option<NativeStorageRoute> = None;
static mut NATIVE_STORAGE_REFRESHING: bool = false;

struct ProofTerminal {
    status: nt_status::NtStatus,
    packet: Vec<u8>,
}

struct EnteredProof {
    request: SrbProofRequest,
    command: ScsiBlockCommand,
    irp: IrpId,
    requestor_tid: u64,
    terminal: Option<ProofTerminal>,
}

/// The retained BusRelations publication owns this through every native completion and ACK.
/// A refused LUN may be followed by another distinct PDO; an uncertain IRP retains this owner.
pub(super) struct NativeDiskProof {
    handoff: NativeStorageHandoff,
    route: NativeStorageRoute,
    reserved: Option<(SrbProofRequest, ScsiBlockCommand)>,
    entered: Option<EnteredProof>,
}

pub(super) enum ProofProgress {
    Pending,
    Refused,
    Mounted,
}

impl NativeDiskProof {
    pub(super) fn new(handoff: NativeStorageHandoff, route: NativeStorageRoute) -> Self {
        Self { handoff, route, reserved: None, entered: None }
    }

    fn packet_capacity(command: &ScsiBlockCommand) -> Option<usize> {
        64usize.checked_add(nt_io_manager::scsi_srb_transport::WDM_X64_LEGACY_SRB_SIZE)?
            .checked_add(command.data_len() as usize)?
            .checked_add(command.sense_len() as usize)
    }

    fn command(request: SrbProofRequest) -> Option<ScsiBlockCommand> {
        match request.step {
            ProofStep::Capacity => Some(ScsiBlockCommand::read_capacity()),
            ProofStep::SectorZero | ProofStep::VolumeSector =>
                ScsiBlockCommand::read(request.lba, 1).ok(),
        }
    }

    fn observe(&mut self, entered: EnteredProof, terminal: ProofTerminal) -> ProofProgress {
        let decoded = if terminal.status.is_success() {
            decode_scsi_completion(&terminal.packet, self.route.scsi, entered.irp).ok()
        } else { None };
        let valid = decoded.as_ref().is_some_and(|packet| {
            entered.command.verify_completion(packet.srb, packet.data.len()).is_ok()
        });
        if !valid {
            self.handoff.refuse_srb(entered.request)
                .expect("retained native disk proof request lost");
            return ProofProgress::Refused;
        }
        let data = decoded.unwrap().data;
        let result = match entered.request.step {
            ProofStep::Capacity => entered.command.parse_capacity(data)
                .map_err(|_| ())
                .and_then(|(size, count)| self.handoff.complete_capacity(entered.request, size, count)
                    .map_err(|_| ())),
            ProofStep::SectorZero | ProofStep::VolumeSector =>
                self.handoff.complete_sector(entered.request, data).map_err(|_| ()),
        };
        if result.is_err() { ProofProgress::Refused } else { ProofProgress::Pending }
    }

    unsafe fn poll_entered(&mut self) -> ProofProgress {
        let Some(entered) = self.entered.as_mut() else { return ProofProgress::Pending; };
        if entered.terminal.is_none() {
            let Some(completion) = completed_device_control_irp_exact(entered.irp.raw()) else {
                return ProofProgress::Pending;
            };
            if completion.client_id != IO_MANAGER_COMPONENT_ID
                || completion.driver_id != self.route.driver_id.raw()
                || completion.completion_driver_id != self.route.driver_id.raw()
                || completion.device_id != self.route.scsi.pdo.raw()
                || completion.completion_device_id != self.route.scsi.pdo.raw()
                || completion.requestor_tid != entered.requestor_tid
                || completion.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
            { return ProofProgress::Pending; }
            let status = nt_status::NtStatus(completion.status as i32);
            let mut packet = Vec::new();
            if status.is_success() {
                let Some(capacity) = Self::packet_capacity(&entered.command) else {
                    return ProofProgress::Pending;
                };
                if packet.try_reserve_exact(capacity).is_err() { return ProofProgress::Pending; }
                packet.resize(capacity, 0);
                if copy_completed_irp_output_exact(entered.irp.raw(), 0, &mut packet) != Ok(capacity) {
                    return ProofProgress::Pending;
                }
            }
            entered.terminal = Some(ProofTerminal { status, packet });
        }
        if acknowledge_completed_irp_strict(entered.irp.raw()).is_err() {
            return ProofProgress::Pending;
        }
        let mut entered = self.entered.take().expect("acknowledged disk proof disappeared");
        let terminal = entered.terminal.take().expect("retained disk proof terminal disappeared");
        self.observe(entered, terminal)
    }

    unsafe fn dispatch_reserved(&mut self) -> ProofProgress {
        let Some((_, command)) = self.reserved.as_ref() else {
            return ProofProgress::Pending;
        };
        let Some(capacity) = Self::packet_capacity(command) else { return ProofProgress::Pending; };
        let mut output = Vec::new();
        if output.try_reserve_exact(capacity).is_err() { return ProofProgress::Pending; }
        output.resize(capacity, 0);
        let mut input = Vec::new();
        if input.try_reserve_exact(command.data_len() as usize).is_err() {
            return ProofProgress::Pending;
        }
        input.resize(command.data_len() as usize, 0);
        let parameters = ScsiParameters::from_wire(
            self.route.scsi, *command.srb(), command.data_len(), command.sense_len(),
        ).expect("constructed block SRB is malformed");
        let caller = crate::initial_system_driver_caller();
        let requestor_tid = u64::from(caller.original_thread().thread_id());
        let native = ExternalFileIrpRequest {
            client: ClientId(IO_MANAGER_COMPONENT_ID),
            device_id: self.route.scsi.pdo,
            file_id: None,
            user_data: 0,
            requestor_tid,
            major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
            parameters: IoParameters::Scsi(parameters),
            stack_flags: StackFlags::empty(),
            initial_information: 0,
        };
        match hosted_file_owners::dispatch(
            caller, native, &input, &output, ExternalFileIrpDispatchPolicy::ScsiAtDevice,
        ) {
            Ok(hosted_file_owners::DispatchResult::Returned { irp_id, status, buffers, .. }) => {
                let (request, command) = self.reserved.take().unwrap();
                let (_, packet) = buffers.into_parts();
                self.observe(EnteredProof {
                    request, command, irp: irp_id, requestor_tid, terminal: None,
                }, ProofTerminal { status, packet })
            }
            Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {
                let (request, command) = self.reserved.take().unwrap();
                self.entered = Some(EnteredProof {
                    request, command, irp: irp_id, requestor_tid, terminal: None,
                });
                ProofProgress::Pending
            }
            Err(status) if status == nt_status::NtStatus::DEVICE_BUSY
                || status == nt_status::NtStatus::INSUFFICIENT_RESOURCES => ProofProgress::Pending,
            Err(_) => {
                let (request, _) = self.reserved.take().unwrap();
                self.handoff.refuse_srb(request)
                    .expect("certainly unentered disk proof refusal lost");
                ProofProgress::Refused
            }
        }
    }

    unsafe fn mount_proven(&mut self) -> ProofProgress {
        if native_storage_route().is_some()
            || crate::fs_loader::exec_block_route_kind(self.route.mount)
                != Some(nt_fs::BlockSourceKind::Draining)
        { return ProofProgress::Pending; }
        let Ok(commit) = crate::boot_storage_dma_handoff::enter_native_disk_mount(&mut self.handoff)
        else { return ProofProgress::Pending; };
        if crate::fs_loader::commit_exec_block_route(self.route.mount, self.route.scsi.pdo).is_err() {
            self.handoff.lose_mount_commit(commit)
                .expect("entered native mount failure owner lost");
            return ProofProgress::Pending;
        }
        if crate::boot_storage_dma_handoff::complete_native_disk_mount(&mut self.handoff, commit).is_err() {
            return ProofProgress::Pending;
        }
        publish_native_storage_route(self.route)
            .expect("proven native disk route was already published");
        ProofProgress::Mounted
    }

    pub(super) unsafe fn progress(&mut self) -> ProofProgress {
        if self.entered.is_some() { return self.poll_entered(); }
        if self.reserved.is_some() { return self.dispatch_reserved(); }
        match self.handoff.phase() {
            HandoffPhase::NeedCapacity | HandoffPhase::NeedSectorZero
                | HandoffPhase::NeedVolumeSector => {
                let Ok(request) = crate::boot_storage_dma_handoff::enter_native_disk_srb(&mut self.handoff)
                else { return ProofProgress::Pending; };
                let Some(command) = Self::command(request) else {
                    self.handoff.refuse_srb(request)
                        .expect("invalid native disk proof request lost");
                    return ProofProgress::Refused;
                };
                self.reserved = Some((request, command));
                self.dispatch_reserved()
            }
            HandoffPhase::Proven => self.mount_proven(),
            HandoffPhase::Refused => ProofProgress::Refused,
            HandoffPhase::NativeMounted | HandoffPhase::RelationPublished => ProofProgress::Mounted,
            _ => ProofProgress::Pending,
        }
    }

    pub(super) fn mark_published(&mut self) -> Result<(), nt_status::NtStatus> {
        match self.handoff.phase() {
            HandoffPhase::RelationPublished => Ok(()),
            HandoffPhase::NativeMounted =>
                crate::boot_storage_dma_handoff::mark_native_disk_relation_published(&mut self.handoff),
            _ => Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
        }?;
        complete_initial_native_storage_publication(self.route)
    }
}

pub(crate) fn native_storage_route() -> Option<NativeStorageRoute> {
    unsafe {
        if *core::ptr::addr_of!(NATIVE_STORAGE_REFRESHING) { None }
        else { *core::ptr::addr_of!(NATIVE_STORAGE_ROUTE) }
    }
}

pub(super) fn begin_native_storage_refresh(
    previous: NativeStorageRoute,
) -> Result<(), nt_status::NtStatus> {
    unsafe {
        if *core::ptr::addr_of!(NATIVE_STORAGE_REFRESHING)
            || *core::ptr::addr_of!(NATIVE_STORAGE_ROUTE) != Some(previous)
            || crate::fs_loader::exec_native_block_pending(previous.mount).is_some()
        { return Err(nt_status::NtStatus::DEVICE_BUSY); }
        *core::ptr::addr_of_mut!(NATIVE_STORAGE_REFRESHING) = true;
        Ok(())
    }
}

pub(super) fn abort_native_storage_refresh(previous: NativeStorageRoute) {
    unsafe {
        if *core::ptr::addr_of!(NATIVE_STORAGE_ROUTE) == Some(previous) {
            *core::ptr::addr_of_mut!(NATIVE_STORAGE_REFRESHING) = false;
        }
    }
}

/// Only the completed `NativeStorageHandoff::MountCommit` path may call this. A second
/// candidate cannot silently replace the mounted disk even if it reports identical bytes.
pub(super) fn publish_native_storage_route(route: NativeStorageRoute) -> Result<(), nt_status::NtStatus> {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(NATIVE_STORAGE_ROUTE);
        if slot.is_some() || route.scsi.pdo.is_null() || route.driver_id.is_null() {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        *slot = Some(route);
        // The mount is committed, but the accepted PDO catalog and relation-local
        // publication still have to finish before new file requests may enter.
        *core::ptr::addr_of_mut!(NATIVE_STORAGE_REFRESHING) = true;
        Ok(())
    }
}

pub(super) fn complete_initial_native_storage_publication(
    route: NativeStorageRoute,
) -> Result<(), nt_status::NtStatus> {
    unsafe {
        if *core::ptr::addr_of!(NATIVE_STORAGE_ROUTE) != Some(route)
            || !*core::ptr::addr_of!(NATIVE_STORAGE_REFRESHING)
            || crate::fs_loader::exec_native_block_pending(route.mount).is_some()
        { return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST); }
        *core::ptr::addr_of_mut!(NATIVE_STORAGE_REFRESHING) = false;
        Ok(())
    }
}

pub(super) fn commit_refreshed_native_storage_route(
    previous: NativeStorageRoute,
    next: NativeStorageRoute,
) -> Result<(), nt_status::NtStatus> {
    validate_refreshed_native_storage_route(previous, next)?;
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(NATIVE_STORAGE_ROUTE);
        *slot = Some(next);
        *core::ptr::addr_of_mut!(NATIVE_STORAGE_REFRESHING) = false;
        Ok(())
    }
}

pub(super) fn validate_refreshed_native_storage_route(
    previous: NativeStorageRoute,
    next: NativeStorageRoute,
) -> Result<(), nt_status::NtStatus> {
    unsafe {
        if *core::ptr::addr_of!(NATIVE_STORAGE_ROUTE) != Some(previous)
            || !*core::ptr::addr_of!(NATIVE_STORAGE_REFRESHING)
            || crate::fs_loader::exec_native_block_pending(previous.mount).is_some()
            || crate::boot_storage_dma_handoff::validate_native_disk_refresh(previous.key, next.key)
                .is_err()
            || next.mount != previous.mount
            || next.scsi.pdo != previous.scsi.pdo
            || next.scsi.provider != previous.scsi.provider
            || next.scsi.provider_pdo != previous.scsi.provider_pdo
            || next.scsi.relation_generation != next.key.relation.generation
            || next.driver_id != previous.driver_id
        { return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST); }
        Ok(())
    }
}
