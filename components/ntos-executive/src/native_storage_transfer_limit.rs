//! The published native storage route's transfer limit, queried from its port driver.
//!
//! Until the answer is known, native commands keep the size they were proven with:
//! [`UNQUERIED_TRANSFER_SECTORS`]. Once the route is published, one exact
//! `IOCTL_STORAGE_QUERY_PROPERTY(StorageAdapterProperty)` IRP is sent to its disk PDO. Storport's
//! PDO forwards it to the adapter FDO, which reports the miniport's `MaximumTransferLength` and
//! `NumberOfPhysicalBreaks`. The limit is that answer clamped to the executive's own ceiling.
//! A refused query keeps the proven size and is traced; the IRP is owned through its exact
//! terminal and strict ACK, and is never reissued for the same route.

use super::*;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    storage_adapter_limit::{
        adapter_property_query, max_transfer_sectors, parse_adapter_descriptor,
        IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_ADAPTER_DESCRIPTOR_QUERY_LEN,
        STORAGE_PROPERTY_QUERY_LEN,
    },
    DeviceControlParameters, IoParameters, StackFlags,
};

/// The command size every native path used before the adapter was asked: one 32-sector batch.
pub(crate) const UNQUERIED_TRANSFER_SECTORS: u32 = 32;
/// The largest command the executive's buffers accept: the async snapshot commit's write buffer.
const EXECUTIVE_TRANSFER_CEILING_SECTORS: u32 = nt_fs::ASYNC_SNAPSHOT_MAX_BATCH_SECTORS;

enum State {
    Unqueried,
    Entered { irp: IrpId, requestor_tid: u64 },
    Known { sectors: u32 },
    Refused,
}

struct Owner {
    route: native_disk_relation::NativeStorageRoute,
    state: State,
}

/// Root-only: driven from the top-level native block service under its guard.
static mut OWNER: Option<Owner> = None;

/// The limit `route`'s adapter reported, once known.
pub(super) fn reported_transfer_sectors(route: native_disk_relation::NativeStorageRoute)
    -> Option<u32>
{
    match unsafe { (*core::ptr::addr_of!(OWNER)).as_ref() } {
        Some(Owner { route: queried, state: State::Known { sectors } }) if *queried == route =>
            Some(*sectors),
        _ => None,
    }
}

/// Sectors one native command on `route` may move.
pub(crate) fn transfer_sectors(route: native_disk_relation::NativeStorageRoute) -> u32 {
    reported_transfer_sectors(route).unwrap_or(UNQUERIED_TRANSFER_SECTORS)
}

/// Sectors for the currently published route, or the proven size when none is published.
pub(crate) fn published_transfer_sectors() -> u32 {
    native_disk_relation::native_storage_route()
        .map_or(UNQUERIED_TRANSFER_SECTORS, transfer_sectors)
}

fn trace(outcome: &[u8], route: native_disk_relation::NativeStorageRoute, status: u32,
    sectors: u32)
{
    print_str(b"[native-disk-transfer] outcome=");
    print_str(outcome);
    print_str(b" pdo=");
    print_u64(route.scsi.pdo.raw());
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" sectors=");
    print_u64(u64::from(sectors));
    print_str(b"\n");
}

/// Advance the query for `route`. Returns 1 when it made progress.
///
/// # Safety
/// Root only, from the outer native block service with its guard held.
pub(super) unsafe fn service(route: native_disk_relation::NativeStorageRoute) -> usize {
    let slot = &mut *core::ptr::addr_of_mut!(OWNER);
    if slot.as_ref().is_none_or(|owner| owner.route != route) {
        // A previous route's IRP is still owned by its retained state; never drop it.
        if slot.as_ref().is_some_and(|owner| matches!(owner.state, State::Entered { .. })) {
            return 0;
        }
        *slot = Some(Owner { route, state: State::Unqueried });
    }
    let owner = slot.as_mut().expect("transfer-limit owner installed");
    match owner.state {
        State::Known { .. } | State::Refused => 0,
        State::Unqueried => dispatch(owner),
        State::Entered { irp, requestor_tid } => poll(owner, irp, requestor_tid),
    }
}

unsafe fn dispatch(owner: &mut Owner) -> usize {
    let route = owner.route;
    let caller = crate::initial_system_driver_caller();
    let requestor_tid = u64::from(caller.original_thread().thread_id());
    let request = ExternalFileIrpRequest {
        client: ClientId(IO_MANAGER_COMPONENT_ID),
        device_id: route.scsi.pdo,
        file_id: None,
        user_data: 0,
        requestor_tid,
        major: major::IRP_MJ_DEVICE_CONTROL,
        parameters: IoParameters::DeviceControl(DeviceControlParameters {
            ioctl_code: IOCTL_STORAGE_QUERY_PROPERTY,
            input_len: STORAGE_PROPERTY_QUERY_LEN as u32,
            output_len: STORAGE_ADAPTER_DESCRIPTOR_QUERY_LEN as u32,
        }),
        stack_flags: StackFlags::empty(),
        request_flags: nt_io_manager::irp_request_flags::IrpRequestFlags::NONE,
        initial_information: 0,
    };
    let output = [0u8; STORAGE_ADAPTER_DESCRIPTOR_QUERY_LEN];
    match hosted_file_owners::dispatch_unretained(
        caller, request, &adapter_property_query(), &output,
        ExternalFileIrpDispatchPolicy::BufferedDeviceControlAtDevice,
    ) {
        Ok(hosted_file_owners::DispatchResult::Returned { status, information, buffers, .. }) => {
            let (_, output) = buffers.into_parts();
            settle(owner, status, &output, information);
            1
        }
        Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {
            owner.state = State::Entered { irp: irp_id, requestor_tid };
            1
        }
        Err(status) if status == nt_status::NtStatus::DEVICE_BUSY
            || status == nt_status::NtStatus::INSUFFICIENT_RESOURCES => 0,
        Err(status) => {
            trace(b"dispatch-refused", route, status.raw() as u32, UNQUERIED_TRANSFER_SECTORS);
            owner.state = State::Refused;
            1
        }
    }
}

unsafe fn poll(owner: &mut Owner, irp: IrpId, requestor_tid: u64) -> usize {
    let Some(completion) = completed_device_control_irp_exact(irp.raw()) else { return 0; };
    // The query targets the disk PDO; its port driver may complete it at the adapter FDO.
    if completion.client_id != IO_MANAGER_COMPONENT_ID
        || completion.device_id != owner.route.scsi.pdo.raw()
        || completion.requestor_tid != requestor_tid
        || completion.major != major::IRP_MJ_DEVICE_CONTROL
    { return 0; }
    let status = nt_status::NtStatus(completion.status as i32);
    let mut output = [0u8; STORAGE_ADAPTER_DESCRIPTOR_QUERY_LEN];
    if status.is_success() {
        let wanted = usize::try_from(completion.information).unwrap_or(usize::MAX)
            .min(output.len());
        if copy_completed_irp_output_exact(irp.raw(), 0, &mut output[..wanted]) != Ok(wanted) {
            return 0;
        }
    }
    if acknowledge_completed_irp_strict(irp.raw()).is_err() { return 0; }
    settle(owner, status, &output, completion.information);
    1
}

fn settle(owner: &mut Owner, status: nt_status::NtStatus, output: &[u8], information: u64) {
    let route = owner.route;
    if !status.is_success() {
        trace(b"query-refused", route, status.raw() as u32, UNQUERIED_TRANSFER_SECTORS);
        owner.state = State::Refused;
        return;
    }
    match parse_adapter_descriptor(output, information) {
        Ok(limits) => {
            let sectors = max_transfer_sectors(limits, EXECUTIVE_TRANSFER_CEILING_SECTORS);
            trace(b"known", route, 0, sectors);
            owner.state = State::Known { sectors };
        }
        Err(_) => {
            trace(b"descriptor-invalid", route, 0, UNQUERIED_TRANSFER_SECTORS);
            owner.state = State::Refused;
        }
    }
}
