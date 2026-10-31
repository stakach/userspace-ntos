//! One top-level native block continuation for mounted FAT and snapshot I/O.
//!
//! Mounted backends and snapshot journals own their logical cursors. This owner retains a
//! single physical block ticket and canonical SCSI packet until the provider's exact terminal
//! and acknowledgement. It never enters a completion pump from backend dispatch.

use super::*;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    scsi_block_command::ScsiBlockCommand,
    scsi_srb_transport::ScsiParameters,
    scsi_srb_wire::decode_scsi_completion,
    IoParameters, StackFlags,
};

#[derive(Clone, Copy)]
enum SectorClaim {
    Create(crate::mounted_volume_backend::mounted_create_lookup::CreateSectorClaim),
    Read(crate::mounted_volume_backend::mounted_installed_read::ReadSectorClaim),
    Directory(crate::mounted_volume_backend::mounted_directory_lookup::DirectorySectorClaim),
}

impl SectorClaim {
    fn mount(self) -> u64 {
        match self {
            Self::Create(c) => c.mount,
            Self::Read(c) => c.mount,
            Self::Directory(c) => c.mount,
        }
    }

    fn sector(self) -> u32 {
        match self {
            Self::Create(c) => c.request.sector,
            Self::Read(c) => c.request.sector,
            Self::Directory(c) => c.request.sector,
        }
    }

    fn release_unentered(self) {
        match self {
            Self::Create(c) => crate::mounted_volume::release_unentered_mounted_create_sector(c)
                .expect("unentered CREATE sector claim lost"),
            Self::Read(c) => crate::mounted_volume::release_unentered_mounted_read_sector(c)
                .expect("unentered READ sector claim lost"),
            Self::Directory(c) => crate::mounted_volume::release_unentered_mounted_directory_sector(c)
                .expect("unentered DIRECTORY sector claim lost"),
        }
    }

    fn complete(self, bytes: Result<&[u8], nt_fs::FatPathError>) {
        match self {
            Self::Create(c) => {
                let sector = bytes.and_then(|bytes| <&[u8; 512]>::try_from(bytes)
                    .map_err(|_| nt_fs::FatPathError::Corrupt));
                crate::mounted_volume::complete_mounted_create_sector(c, sector)
                    .expect("entered CREATE sector claim lost");
            }
            Self::Read(c) => {
                crate::mounted_volume::complete_mounted_read_sectors(c, bytes)
                    .expect("entered READ sector claim lost");
            }
            Self::Directory(c) => {
                let sector = bytes.and_then(|bytes| <&[u8; 512]>::try_from(bytes)
                    .map_err(|_| nt_fs::FatPathError::Corrupt));
                crate::mounted_volume::complete_mounted_directory_sector(c, sector)
                    .expect("entered DIRECTORY sector claim lost");
            }
        }
    }
}

enum WorkClaim {
    Sector(SectorClaim),
    Snapshot(crate::writable_fs::native_snapshot_io::SnapshotClaim),
}

impl WorkClaim {
    fn mount(&self) -> u64 {
        match self {
            Self::Sector(claim) => claim.mount(),
            Self::Snapshot(claim) => claim.mount.value(),
        }
    }

    fn source(&self) -> nt_fs::BlockSource {
        match self {
            Self::Sector(_) => nt_fs::BlockSource::Fat,
            Self::Snapshot(_) => nt_fs::BlockSource::Snapshot,
        }
    }

    fn operation(&self) -> Option<nt_fs::BlockOperation> {
        match self {
            Self::Sector(SectorClaim::Read(claim)) => {
                let fs = unsafe { crate::fs_loader::exec_fs()? };
                claim.block_read_operation(fs.volume_start_lba)
            }
            Self::Sector(claim) => {
                let fs = unsafe { crate::fs_loader::exec_fs()? };
                let lba = nt_fs::checked_partition_lba(fs.volume_start_lba, claim.sector())?;
                Some(nt_fs::BlockOperation::Read { lba, sectors: 1 })
            }
            Self::Snapshot(claim) => Some(claim.operation),
        }
    }

    fn mark_entered(&self) {
        if let Self::Snapshot(claim) = self {
            unsafe { crate::writable_fs::native_snapshot_io::mark_entered_native_snapshot_io(claim) }
                .expect("entered snapshot claim lost");
        }
    }

    fn release_unentered(self) {
        match self {
            Self::Sector(claim) => claim.release_unentered(),
            Self::Snapshot(claim) => unsafe {
                crate::writable_fs::native_snapshot_io::release_unentered_native_snapshot_io(claim)
            }.expect("unentered snapshot claim lost"),
        }
    }

    fn refuse_unentered(self, status: nt_status::NtStatus) {
        match self {
            Self::Sector(claim) => claim.complete(Err(nt_fs::FatPathError::Corrupt)),
            Self::Snapshot(claim) => unsafe {
                crate::writable_fs::native_snapshot_io::refuse_unentered_native_snapshot_io(claim, status)
            }.expect("refused unentered snapshot claim lost"),
        }
    }

    fn complete(self, result: Result<&[u8], nt_status::NtStatus>) {
        match self {
            Self::Sector(claim) => claim.complete(result.map_err(|_| nt_fs::FatPathError::Corrupt)),
            Self::Snapshot(claim) => unsafe {
                crate::writable_fs::native_snapshot_io::complete_native_snapshot_io(claim, result)
            }.expect("acknowledged snapshot claim lost"),
        }
    }

    fn write_input(&self) -> Option<&[u8]> {
        match self {
            Self::Snapshot(claim) => Some(&claim.input),
            Self::Sector(_) => None,
        }
    }
}

struct Terminal {
    status: nt_status::NtStatus,
    packet: Vec<u8>,
}

struct Pending {
    claim: WorkClaim,
    ticket: nt_fs::NativeBlockTicket,
    route: native_disk_relation::NativeStorageRoute,
    command: ScsiBlockCommand,
    irp: IrpId,
    requestor_tid: u64,
    terminal: Option<Terminal>,
}

static mut PENDING: Option<Pending> = None;
static mut SNAPSHOT_FIRST: bool = false;

fn next_sector_claim() -> Option<WorkClaim> {
    crate::mounted_volume::claim_mounted_create_sector()
        .map(SectorClaim::Create)
        .or_else(|| crate::mounted_volume::claim_mounted_read_sectors().map(SectorClaim::Read))
        .or_else(|| crate::mounted_volume::claim_mounted_directory_sector().map(SectorClaim::Directory))
        .map(WorkClaim::Sector)
}

unsafe fn next_claim() -> Option<WorkClaim> {
    let snapshot = || crate::writable_fs::native_snapshot_io::claim_next_native_snapshot_io()
        .map(WorkClaim::Snapshot);
    let claim = if *core::ptr::addr_of!(SNAPSHOT_FIRST) {
        snapshot().or_else(next_sector_claim)
    } else {
        next_sector_claim().or_else(snapshot)
    };
    if claim.is_some() {
        *core::ptr::addr_of_mut!(SNAPSHOT_FIRST) = !*core::ptr::addr_of!(SNAPSHOT_FIRST);
    }
    claim
}

fn packet_capacity(command: &ScsiBlockCommand) -> Option<usize> {
    64usize.checked_add(nt_io_manager::scsi_srb_transport::WDM_X64_LEGACY_SRB_SIZE)?
        .checked_add(command.data_len() as usize)?
        .checked_add(command.sense_len() as usize)
}

fn terminal_data<'a>(
    command: &ScsiBlockCommand,
    route: nt_io_manager::scsi_srb_transport::ScsiSrbRoute,
    irp: IrpId,
    terminal: &'a Terminal,
) -> Result<&'a [u8], nt_status::NtStatus> {
    if !terminal.status.is_success() {
        return Err(terminal.status);
    }
    let packet = decode_scsi_completion(&terminal.packet, route, irp)
        .map_err(|_| nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32))?;
    command.verify_completion(packet.srb, packet.data.len())
        .map_err(|_| nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32))?;
    match command.kind() {
        nt_io_manager::scsi_block_command::BlockCommandKind::Read => Ok(packet.data),
        nt_io_manager::scsi_block_command::BlockCommandKind::Write
        | nt_io_manager::scsi_block_command::BlockCommandKind::Flush => Ok(&[]),
        nt_io_manager::scsi_block_command::BlockCommandKind::Capacity =>
            Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
    }
}

fn settle(pending: Pending, terminal: Terminal) {
    let result = terminal_data(&pending.command, pending.route.scsi, pending.irp, &terminal);
    if result.is_ok() {
        crate::fs_loader::complete_exec_native_block(pending.ticket, pending.command.data_len() as u64)
            .expect("exact native block ticket lost");
    } else {
        crate::fs_loader::complete_exec_native_block_failure(pending.ticket)
            .expect("exact failed native block ticket lost");
    }
    pending.claim.complete(result);
}

unsafe fn poll_pending() -> usize {
    let slot = &mut *core::ptr::addr_of_mut!(PENDING);
    let Some(pending) = slot.as_mut() else { return 0; };
    if pending.terminal.is_none() {
        let Some(completion) = completed_device_control_irp_exact(pending.irp.raw()) else {
            return 0;
        };
        if completion.client_id != IO_MANAGER_COMPONENT_ID
            || completion.driver_id != pending.route.driver_id.raw()
            || completion.completion_driver_id != pending.route.driver_id.raw()
            || completion.device_id != pending.route.scsi.pdo.raw()
            || completion.completion_device_id != pending.route.scsi.pdo.raw()
            || completion.requestor_tid != pending.requestor_tid
            || completion.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        {
            // Identity uncertainty retains the ticket and packet; a numeric IRP is not proof.
            return 0;
        }
        let status = nt_status::NtStatus(completion.status as i32);
        let mut packet = Vec::new();
        if status.is_success() {
            let Some(capacity) = packet_capacity(&pending.command) else { return 0; };
            if packet.try_reserve_exact(capacity).is_err() { return 0; }
            packet.resize(capacity, 0);
            if copy_completed_irp_output_exact(pending.irp.raw(), 0, &mut packet) != Ok(capacity) {
                return 0;
            }
        }
        pending.terminal = Some(Terminal { status, packet });
    }
    if acknowledge_completed_irp_strict(pending.irp.raw()).is_err() {
        return 0;
    }
    let mut pending = slot.take().expect("acknowledged native sector owner disappeared");
    let terminal = pending.terminal.take().unwrap();
    settle(pending, terminal);
    1
}

/// Drive at most one physical command per outer service turn. Backends only publish claims.
pub(super) unsafe fn service() -> usize {
    if (&*core::ptr::addr_of!(PENDING)).is_some() {
        return poll_pending();
    }
    let Some(route) = native_disk_relation::native_storage_route() else { return 0; };
    let Some(claim) = next_claim() else { return 0; };
    if claim.mount() != route.mount.value() {
        claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return 1;
    }
    let Some(operation) = claim.operation() else {
        claim.refuse_unentered(nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32));
        return 1;
    };
    let Ok(ticket) = crate::fs_loader::enter_exec_native_block(
        route.mount, claim.source(), operation,
    ) else {
        claim.release_unentered();
        return 0;
    };
    let command = match operation {
        nt_fs::BlockOperation::Read { lba, sectors } => ScsiBlockCommand::read(lba, sectors),
        nt_fs::BlockOperation::Write { lba, sectors } => ScsiBlockCommand::write(lba, sectors),
        nt_fs::BlockOperation::Flush => Ok(ScsiBlockCommand::flush()),
    };
    let Ok(command) = command else {
        crate::fs_loader::cancel_unentered_exec_native_block(ticket)
            .expect("unentered invalid native command ticket lost");
        claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return 1;
    };
    let Some(capacity) = packet_capacity(&command) else {
        crate::fs_loader::cancel_unentered_exec_native_block(ticket)
            .expect("unentered native packet ticket lost");
        claim.release_unentered();
        return 0;
    };
    let mut output = Vec::new();
    if output.try_reserve_exact(capacity).is_err() {
        crate::fs_loader::cancel_unentered_exec_native_block(ticket)
            .expect("unentered native packet ticket lost");
        claim.release_unentered();
        return 0;
    }
    output.resize(capacity, 0);
    let Ok(parameters) = ScsiParameters::from_wire(
        route.scsi, *command.srb(), command.data_len(), command.sense_len(),
    ) else {
        crate::fs_loader::cancel_unentered_exec_native_block(ticket)
            .expect("unentered native SCSI parameters ticket lost");
        claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return 1;
    };
    let mut read_input = Vec::new();
    let input = if matches!(operation, nt_fs::BlockOperation::Write { .. }) {
        let Some(bytes) = claim.write_input() else {
            crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                .expect("unentered native write ticket lost");
            claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            return 1;
        };
        if bytes.len() != command.data_len() as usize {
            crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                .expect("unentered native write length ticket lost");
            claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            return 1;
        }
        bytes
    } else {
        if read_input.try_reserve_exact(command.data_len() as usize).is_err() {
            crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                .expect("unentered native input ticket lost");
            claim.release_unentered();
            return 0;
        }
        read_input.resize(command.data_len() as usize, 0);
        read_input.as_slice()
    };
    let caller = crate::initial_system_driver_caller();
    let requestor_tid = u64::from(caller.original_thread().thread_id());
    let request = ExternalFileIrpRequest {
        client: ClientId(IO_MANAGER_COMPONENT_ID),
        device_id: route.scsi.pdo,
        file_id: None,
        user_data: 0,
        requestor_tid,
        major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
        parameters: IoParameters::Scsi(parameters),
        stack_flags: StackFlags::empty(),
        initial_information: 0,
    };
    match hosted_file_owners::dispatch(
        caller, request, input, &output, ExternalFileIrpDispatchPolicy::ScsiAtDevice,
    ) {
        Ok(hosted_file_owners::DispatchResult::Returned { irp_id, status, buffers, .. }) => {
            claim.mark_entered();
            crate::fs_loader::mark_entered_exec_native_block(ticket)
                .expect("returned native block ticket lost");
            let (_, packet) = buffers.into_parts();
            settle(Pending { claim, ticket, route, command, irp: irp_id,
                requestor_tid, terminal: None }, Terminal { status, packet });
            1
        }
        Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {
            claim.mark_entered();
            crate::fs_loader::mark_entered_exec_native_block(ticket)
                .expect("pending native block ticket lost");
            *core::ptr::addr_of_mut!(PENDING) = Some(Pending {
                claim, ticket, route, command, irp: irp_id, requestor_tid, terminal: None,
            });
            1
        }
        Err(status) => {
            crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                .expect("refused native block ticket lost");
            if status == nt_status::NtStatus::DEVICE_BUSY
                || status == nt_status::NtStatus::INSUFFICIENT_RESOURCES {
                claim.release_unentered();
                0
            } else {
                claim.refuse_unentered(status);
                1
            }
        }
    }
}
