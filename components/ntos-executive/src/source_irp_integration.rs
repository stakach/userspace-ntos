//! Validation-only source execution through the genuine win32k lane and source routers.
//!
//! The probe is a retained service-loop work item. Its checked source image is read through the
//! mounted-volume Device by the shared `MountedImageClosure` once the native block handoff has
//! started; the Boot inline reader is used only while that Device does not yet own installed
//! names. Retirement evidence arrives through ordinary service-loop I/O, never a private pump.

use super::*;
use alloc::string::String;
use nt_component_suspension::peer_registry::PeerRoute;
use nt_io_manager::{DeviceId, HostedDevicePointerReference, HostedDevicePointerRegistration};
use crate::mounted_image_closure::{ClosureStep, MountedImageClosure};
use crate::spawn_hosts::shared_ingress::owner::runtime::{self, PhysicalSource};

#[repr(C)]
#[derive(Clone, Copy)]
struct Observation {
    call: i32,
    wait: i32,
    iosb_status: i32,
    bytes_valid: u32,
    information: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Evidence {
    attempts: [[u32; 6]; 2],
    completed: [[u32; 6]; 2],
    failed: u32,
    padding: u32,
    observations: [[Observation; 6]; 2],
}

const _: () = {
    assert!(core::mem::size_of::<Observation>() == 24);
    assert!(core::mem::offset_of!(Observation, information) == 16);
    assert!(core::mem::size_of::<Evidence>() == 392);
    assert!(core::mem::align_of::<Evidence>() == 8);
    assert!(core::mem::offset_of!(Evidence, completed) == 48);
    assert!(core::mem::offset_of!(Evidence, failed) == 96);
    assert!(core::mem::offset_of!(Evidence, observations) == 104);
};

/// Read only after the exact lane returned: the source is no longer writing its evidence,
/// and the retained checked module owns the shared backing throughout this snapshot.
unsafe fn observe(handle: u64, mode: usize, returned: i32) -> Result<(), i32> {
    let address = image_loader::probe_export(
        handle, "SourceIrpEvidence", core::mem::size_of::<Evidence>() as u64, false,
    ).ok_or(0xc000_0139u32 as i32)?;
    if address % core::mem::align_of::<Evidence>() as u64 != 0 {
        return Err(0xc000_000du32 as i32);
    }
    let evidence = core::ptr::read_volatile(address as *const Evidence);
    let mut valid = returned == 0 && evidence.failed == 0;
    for row in 0..2 {
        let expected = u32::from(row <= mode);
        valid &= evidence.attempts[row].iter().all(|count| *count == expected)
            && evidence.completed[row].iter().all(|count| *count == expected);
    }
    for (operation, record) in evidence.observations[mode].iter().enumerate() {
        // Unattempted records contain zero initialization, not successful observations.
        if evidence.attempts[mode][operation] == 0 { continue; }
        print_str(b"[source-irp-proof] mode="); print_u64(mode as u64);
        print_str(b" op="); print_u64(operation as u64);
        print_str(b" call="); print_hex(record.call as u32);
        print_str(b" wait="); print_hex(record.wait as u32);
        print_str(b" iosb="); print_hex(record.iosb_status as u32);
        print_str(b" info="); print_u64(record.information);
        print_str(b" bytes="); print_u64(record.bytes_valid as u64); print_str(b"\n");
        valid &= record.call == (if mode == 0 { 0 } else { 0x103 })
            && record.wait == 0 && record.iosb_status == 0
            && record.information == 16 && record.bytes_valid == 1;
    }
    if !valid { return Err(0xc000_0001u32 as i32); }
    print_str(b"[source-irp-proof-complete] mode="); print_u64(mode as u64);
    print_str(b" operations="); print_u64(evidence.completed[mode].iter().map(|count| *count as u64).sum());
    print_str(b"\n");
    Ok(())
}

enum Phase {
    Start,
    /// The mounted Device owns installed names; exact File I/O is retained by the closure.
    MountedImage(MountedImageClosure),
    Dispatch { entry: u64, mode: usize },
    Retire,
    Release,
    Done,
}

struct Owner {
    device: DeviceId,
    source_leaf: String,
    export: String,
    lane: Option<(PeerRoute, PhysicalSource)>,
    module: Option<u64>,
    registration: Option<HostedDevicePointerRegistration>,
    reference: Option<HostedDevicePointerReference>,
    baseline: Option<nt_compat_exports::source_probe_metrics::Snapshot>,
    returned: [Option<i32>; 2],
    indeterminate: bool,
    phase: Phase,
}

const RETRY_100NS: u64 = 1_000_000;
const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;
static STARTED: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_RETRY: AtomicU64 = AtomicU64::new(0);
static mut OWNER: Option<Owner> = None;

unsafe fn owner() -> &'static mut Owner {
    (&mut *core::ptr::addr_of_mut!(OWNER)).as_mut().expect("probe ownership recorded before effects")
}

fn parameter(key: &nt_config_client::HiveKeySnapshot, name: &str) -> Result<Option<String>, i32> {
    let Some(value) = key.values.iter().find(|value| value.name.eq_ignore_ascii_case(name))
        else { return Ok(None); };
    nt_config_client::decode_terminated_reg_sz(value.value_type, &value.data)
        .map(Some).ok_or(0xc000_000du32 as i32)
}

unsafe fn report(status: i32) {
    let owner = (&*core::ptr::addr_of!(OWNER)).as_ref();
    print_str(b"[source-irp-integration] returned status=0x"); print_hex(status as u32);
    print_str(b" immediate=");
    print_u64(u64::from(owner.is_some_and(|owner| owner.returned[0].is_some())));
    print_str(b" pending=");
    print_u64(u64::from(owner.is_some_and(|owner| owner.returned[1].is_some())));
    print_str(b" indeterminate=");
    print_u64(u64::from(owner.is_some_and(|owner| owner.indeterminate))); print_str(b"\n");
}

/// Profile metadata selects both the real service-created target and checked source image.
/// Neither source packet dispatch nor production routing recognizes a fixture image/name.
/// Records the retained owner; the service loop performs every effect through `redrive`.
pub(crate) unsafe fn submit_configured() -> i32 {
    if STARTED.swap(true, Ordering::AcqRel) { return 0xc000_009eu32 as i32; }
    let _durable = crate::allocator::enter_durable();
    match configured() {
        Ok((device, source_leaf, export)) => {
            *core::ptr::addr_of_mut!(OWNER) = Some(Owner {
                device, source_leaf, export, lane: None, module: None, registration: None,
                reference: None, baseline: None, returned: [None; 2], indeterminate: false,
                phase: Phase::Start,
            });
            NEXT_RETRY.store(crate::monotonic_time_100ns(), Ordering::Release);
            0
        }
        Err(status) => {
            report(status);
            status
        }
    }
}

unsafe fn configured() -> Result<(DeviceId, String, String), i32> {
    let services = crate::config_manager_query_system_hive_key(
        r"\Registry\Machine\System\CurrentControlSet\Services")?;
    let mut selection = None;
    for service in services.subkeys {
        let path = alloc::format!(r"\Registry\Machine\System\CurrentControlSet\Services\{}\Parameters", service.name);
        let Ok(parameters) = crate::config_manager_query_system_hive_key(&path) else { continue; };
        let Some(device_name) = parameter(&parameters, "ProbeDeviceName")? else { continue; };
        let source = parameter(&parameters, "ProbeSourceImage")?.ok_or(0xc000_000du32 as i32)?;
        let export = parameter(&parameters, "ProbeSourceExport")?.ok_or(0xc000_000du32 as i32)?;
        if selection.is_some() { return Err(0xc000_000du32 as i32); }
        let units: Vec<u16> = device_name.encode_utf16().collect();
        let path = nt_types::NtPath::parse(&units).map_err(|status| status.raw())?;
        let device = crate::driver_launch::io_manager_mut().device_id_by_name(&path)
            .ok_or(0xc000_0034u32 as i32)?;
        let io = crate::driver_launch::io_manager_mut();
        let record = io.device(device).ok_or(0xc000_0008u32 as i32)?;
        let driver = io.driver(record.driver_id).ok_or(0xc000_0008u32 as i32)?;
        if record.delete_pending || [3, 4, 14].iter().any(|major| {
            driver.dispatch.get(*major).driver_peer_id().is_none()
        }) {
            return Err(0xc000_00a3u32 as i32);
        }
        selection = Some((device, source, export));
    }
    selection.ok_or(0xc000_0034u32 as i32)
}

pub(crate) fn next_deadline() -> Option<u64> {
    // An indeterminate owner is retained but cannot make autonomous progress.
    unsafe { (&*core::ptr::addr_of!(OWNER)).as_ref() }
        .is_some_and(|owner| !owner.indeterminate && !matches!(owner.phase, Phase::Done))
        .then(|| NEXT_RETRY.load(Ordering::Acquire))
}

pub(crate) fn has_outstanding() -> bool {
    ACTIVE.load(Ordering::Acquire)
        || unsafe { (&*core::ptr::addr_of!(OWNER)).as_ref() }
            .is_some_and(|owner| !matches!(owner.phase, Phase::Done))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

enum Step { Progress, Wait, Finished(Result<(), i32>) }

/// Advance the retained probe from the service loop. Each native lane dispatch is entered with
/// no owner borrow held; uncertain effects keep every module, projection and File owner.
pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) -> bool {
    if handler.is_null() || next_deadline().is_none() { return false; }
    if ACTIVE.swap(true, Ordering::AcqRel) { return false; }
    let _durable = crate::allocator::enter_durable();
    let mut progressed = false;
    for _ in 0..8 {
        match step(handler) {
            Step::Progress => progressed = true,
            Step::Wait => break,
            Step::Finished(result) => {
                progressed = true;
                let status = result.err().unwrap_or(0);
                if !owner().indeterminate && owner().reference.is_none()
                    && owner().registration.is_none()
                {
                    owner().phase = Phase::Done;
                } else {
                    // Retain the exact owners; no autonomous retry or replay follows.
                    owner().indeterminate = true;
                }
                report(status);
                assert_eq!(status, 0, "native source IRP fixture did not prove completion");
                break;
            }
        }
    }
    NEXT_RETRY.store(crate::monotonic_time_100ns().saturating_add(RETRY_100NS), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
    progressed
}

unsafe fn step(handler: *mut ExecNtHandler) -> Step {
    let phase = core::mem::replace(&mut owner().phase, Phase::Done);
    match phase {
        Phase::Start => match start() {
            Ok(step) => step,
            Err(status) => Step::Finished(Err(status)),
        },
        Phase::MountedImage(closure) => mounted_image(closure),
        Phase::Dispatch { entry, mode } => dispatch(entry, mode),
        Phase::Retire => retire(handler),
        Phase::Release => Step::Finished(release()),
        Phase::Done => Step::Wait,
    }
}

unsafe fn lane() -> Result<(PeerRoute, PhysicalSource), i32> {
    let route = (&*core::ptr::addr_of!(WIN32K_PHYSICAL_LANES)).as_ref()
        .and_then(|lanes| lanes.iter().find(|lane| lane.primary.is_some()))
        .and_then(|lane| lane.route).ok_or(0xc000_00a3u32 as i32)?;
    let source = runtime::physical_source(route).map_err(|_| 0xc000_00a3u32 as i32)?;
    Ok((route, source))
}

unsafe fn start() -> Result<Step, i32> {
    let (route, source) = lane()?;
    owner().lane = Some((route, source));
    let block_route = crate::fs_loader::exec_fs_mount_identity()
        .and_then(crate::fs_loader::exec_block_route_kind);
    match nt_fs::installed_image_reader(block_route) {
        Some(nt_fs::InstalledImageReader::MountedVolume) => {
            let closure = MountedImageClosure::new(&owner().source_leaf)
                .map_err(|status| status as i32)?;
            print_str(b"[source-irp-integration] image route=mounted-volume\n");
            owner().phase = Phase::MountedImage(closure);
            Ok(Step::Progress)
        }
        // The mounted Device does not yet own installed names: the Boot inline reader does.
        _ => {
            let (base, size) = image_loader::load_installed(&owner().source_leaf, source.pml4)
                .map_err(|error| error.ntstatus())?;
            print_str(b"[source-irp-integration] image route=boot-reader\n");
            loaded(base, size)
        }
    }
}

unsafe fn mounted_image(mut closure: MountedImageClosure) -> Step {
    let Some((route, source)) = owner().lane else {
        owner().phase = Phase::MountedImage(closure);
        owner().indeterminate = true;
        return Step::Finished(Err(0xc000_0001u32 as i32));
    };
    if runtime::physical_source(route).ok() != Some(source) {
        // The provider lane changed under exact File I/O; keep every owner.
        owner().phase = Phase::MountedImage(closure);
        owner().indeterminate = true;
        return Step::Finished(Err(0xc000_0001u32 as i32));
    }
    match closure.advance(source.pml4) {
        ClosureStep::Progress => {
            owner().phase = Phase::MountedImage(closure);
            Step::Progress
        }
        ClosureStep::Wait => {
            owner().phase = Phase::MountedImage(closure);
            Step::Wait
        }
        ClosureStep::Indeterminate => {
            owner().phase = Phase::MountedImage(closure);
            owner().indeterminate = true;
            Step::Finished(Err(0xc000_0001u32 as i32))
        }
        ClosureStep::Failed(status) => {
            let mapped = closure.mapped_effect();
            if mapped {
                // Mapped dependencies have no teardown operation; keep their catalog owner.
                owner().phase = Phase::MountedImage(closure);
                owner().indeterminate = true;
            }
            Step::Finished(Err(status as i32))
        }
        ClosureStep::Mapped => {
            let image = image_loader::load_installed_from_catalog(
                closure.root(), source.pml4, closure.catalog(),
            );
            match image {
                Ok((base, size)) => loaded(base, size).unwrap_or_else(|status| Step::Finished(Err(status))),
                Err(error) => {
                    owner().phase = Phase::MountedImage(closure);
                    owner().indeterminate = true;
                    Step::Finished(Err(error.ntstatus()))
                }
            }
        }
    }
}

/// The checked image is mapped: retain its load, resolve the entry and pin the exact target.
unsafe fn loaded(base: u64, size: u32) -> Result<Step, i32> {
    let handle = image_loader::module_handle(base, size).ok_or(0xc000_0008u32 as i32)?;
    image_loader::acquire_load(handle)?;
    owner().module = Some(handle);
    let entry = image_loader::probe_export(handle, &owner().export, 1, true)
        .ok_or(0xc000_0139u32 as i32)?;
    let registration = crate::driver_launch::win32k_device_consumer::retain_probe_projection(
        owner().device,
    )?;
    owner().registration = Some(registration);
    // Keep one reference in the projection ledger (fences projection retirement), plus an
    // independently owned canonical receipt (fences target destruction on uncertain dispatch).
    let io = crate::driver_launch::io_manager_mut();
    io.reference_hosted_device_pointer(registration).map_err(|status| status.raw())?;
    let reference = io.take_hosted_device_pointer_reference(registration).map_err(|status| status.raw())?;
    owner().reference = Some(reference);
    owner().baseline = Some(crate::driver_launch::source_observability::probe_snapshot());
    owner().phase = Phase::Dispatch { entry, mode: 0 };
    Ok(Step::Progress)
}

unsafe fn dispatch(entry: u64, mode: usize) -> Step {
    let (Some(handle), Some(registration)) = (owner().module, owner().registration) else {
        owner().indeterminate = true;
        return Step::Finished(Err(0xc000_0001u32 as i32));
    };
    let mut entered = false;
    // Do not hold any registry or owner borrow across the native lane dispatch.
    let Win32kDispatchOutcome::Known { value, completed } = win32k_dispatch_kernel_job_observed(
        win32k_subsystem::WIN32K_REQUEST_SOURCE_IRP_PROBE,
        [entry, registration.address(), mode as u64, 0], &mut entered,
    );
    if !completed {
        if !entered && value as u32 == STATUS_DEVICE_BUSY {
            // Another retained owner holds the shared publication; no provider effect entered.
            owner().phase = Phase::Dispatch { entry, mode };
            return Step::Wait;
        }
        owner().indeterminate = entered;
        return Step::Finished(Err(0xc000_0001u32 as i32));
    }
    let status = value as u32 as i32;
    owner().returned[mode] = Some(status);
    let observation = observe(handle, mode, status);
    if status != 0 { return Step::Finished(Err(status)); }
    if let Err(status) = observation { return Step::Finished(Err(status)); }
    owner().phase = if mode == 0 { Phase::Dispatch { entry, mode: 1 } } else { Phase::Retire };
    Step::Progress
}

/// Event visibility precedes retirement of the retained semantic Reply. The service loop owns
/// completion delivery; this owner only observes the evidence and nudges source work once.
unsafe fn retire(handler: *mut ExecNtHandler) -> Step {
    owner().phase = Phase::Retire;
    let Some(baseline) = owner().baseline else {
        owner().indeterminate = true;
        return Step::Finished(Err(0xc000_0001u32 as i32));
    };
    let Some(delta) = crate::driver_launch::source_observability::probe_snapshot()
        .delta_since(baseline) else { return Step::Finished(Err(0xc000_0001u32 as i32)); };
    if delta.proves_twelve_operations() {
        report_probe_milestones(delta);
        owner().phase = Phase::Release;
        return Step::Progress;
    }
    // Keep the module and target receipts while waiting; no request is replayed.
    if crate::driver_launch::redrive_win32k_source_work(handler) { Step::Progress } else { Step::Wait }
}

unsafe fn release() -> Result<(), i32> {
    let registration = owner().registration.ok_or(0xc000_0001u32 as i32)?;
    let reference = owner().reference.as_mut().ok_or(0xc000_0001u32 as i32)?;
    reference.release(crate::driver_launch::io_manager_mut()).map_err(|status| status.raw())?;
    owner().reference = None;
    crate::driver_launch::io_manager_mut().dereference_hosted_device_pointer(registration)
        .map_err(|status| status.raw())?;
    owner().registration = None;
    // The loader's honest unload contract is currently unsupported. Keep the module load
    // receipt recorded instead of pretending a reference decrement retired native mappings.
    Ok(())
}

fn report_probe_milestones(delta: nt_compat_exports::source_probe_metrics::Snapshot) {
    print_str(b"[source-irp-milestones]");
    for (name, values) in [
        (b" ioctl=".as_slice(), delta.ioctl),
        (b" read=".as_slice(), delta.read),
        (b" write=".as_slice(), delta.write),
        (b" methods=".as_slice(), delta.methods),
    ] {
        print_str(name);
        for (index, value) in values.into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
    }
    print_str(b"\n");
}

/// Only the root's feature-only, authenticated kernel request can reach this branch. The entry
/// was resolved from a checked executable export and its module/target owners remain held.
pub(crate) unsafe fn component_probe(entry: u64, device: u64, mode: u64) -> i32 {
    if entry == 0 || device == 0 || mode > 1 { return 0xc000_000du32 as i32; }
    let probe: unsafe extern "win64" fn(u64, u32) -> i32 = core::mem::transmute(entry);
    probe(device, mode as u32)
}
