//! Validation-only source execution through the genuine win32k lane and source routers.

use super::*;
use alloc::string::String;
use nt_io_manager::{DeviceId, HostedDevicePointerReference, HostedDevicePointerRegistration};

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

struct Owner {
    module: Option<u64>,
    registration: Option<HostedDevicePointerRegistration>,
    reference: Option<HostedDevicePointerReference>,
    returned: [Option<i32>; 2],
    indeterminate: bool,
}

static STARTED: AtomicBool = AtomicBool::new(false);
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

/// Profile metadata selects both the real service-created target and checked source image.
/// Neither source packet dispatch nor production routing recognizes a fixture image/name.
pub(crate) unsafe fn run_configured(handler: *mut ExecNtHandler) -> i32 {
    if handler.is_null() { return 0xc000_000du32 as i32; }
    if STARTED.swap(true, Ordering::AcqRel) { return 0xc000_009eu32 as i32; }
    let _durable = crate::allocator::enter_durable();
    *core::ptr::addr_of_mut!(OWNER) = Some(Owner {
        module: None, registration: None, reference: None,
        returned: [None; 2], indeterminate: false,
    });
    let result = configured().and_then(|(device, source, export)| run(device, &source, &export, handler));
    let status = result.err().unwrap_or(0);
    print_str(b"[source-irp-integration] returned status=0x"); print_hex(status as u32);
    print_str(b" immediate="); print_u64(u64::from(owner().returned[0].is_some()));
    print_str(b" pending="); print_u64(u64::from(owner().returned[1].is_some()));
    print_str(b" indeterminate="); print_u64(u64::from(owner().indeterminate)); print_str(b"\n");
    status
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

unsafe fn run(device: DeviceId, source_leaf: &str, export_name: &str, handler: *mut ExecNtHandler) -> Result<(), i32> {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let route = (&*core::ptr::addr_of!(WIN32K_PHYSICAL_LANES)).as_ref()
        .and_then(|lanes| lanes.iter().find(|lane| lane.primary.is_some()))
        .and_then(|lane| lane.route).ok_or(0xc000_00a3u32 as i32)?;
    let source = runtime::physical_source(route).map_err(|_| 0xc000_00a3u32 as i32)?;
    let (base, size) = image_loader::load_installed(source_leaf, source.pml4).map_err(|error| error.ntstatus())?;
    let handle = image_loader::module_handle(base, size).ok_or(0xc000_0008u32 as i32)?;
    image_loader::acquire_load(handle)?;
    owner().module = Some(handle);
    let entry = image_loader::probe_export(handle, export_name, 1, true).ok_or(0xc000_0139u32 as i32)?;
    let registration = crate::driver_launch::win32k_device_consumer::retain_probe_projection(device)?;
    owner().registration = Some(registration);
    // Keep one reference in the projection ledger (fences projection retirement), plus an
    // independently owned canonical receipt (fences target destruction on uncertain dispatch).
    let io = crate::driver_launch::io_manager_mut();
    io.reference_hosted_device_pointer(registration).map_err(|status| status.raw())?;
    let reference = io.take_hosted_device_pointer_reference(registration).map_err(|status| status.raw())?;
    owner().reference = Some(reference);
    let baseline = crate::driver_launch::source_observability::probe_snapshot();
    for mode in 0..2usize {
        let mut entered = false;
        let (value, completed) = win32k_dispatch_kernel_job_observed(
            win32k_subsystem::WIN32K_REQUEST_SOURCE_IRP_PROBE,
            [entry, registration.address(), mode as u64, 0], &mut entered,
        );
        if !completed {
            owner().indeterminate = entered;
            return Err(0xc000_0001u32 as i32);
        }
        let status = value as u32 as i32;
        owner().returned[mode] = Some(status);
        let observation = observe(handle, mode, status);
        if status != 0 { return Err(status); }
        observation?;
    }
    prove_retirement(baseline, handler)?;
    // Do not hold any registry or owner borrow across the native lane dispatch above.
    let reference = owner().reference.as_mut().expect("canonical target reference");
    reference.release(crate::driver_launch::io_manager_mut()).map_err(|status| status.raw())?;
    owner().reference = None;
    crate::driver_launch::io_manager_mut().dereference_hosted_device_pointer(registration)
        .map_err(|status| status.raw())?;
    owner().registration = None;
    // The loader's honest unload contract is currently unsupported. Keep the module load
    // receipt recorded instead of pretending a reference decrement retired native mappings.
    Ok(())
}

/// Event visibility precedes retirement of the retained semantic Reply. Continue the ordinary
/// owned work pump only while it makes real progress, without borrowing the handler across IPC.
unsafe fn prove_retirement(
    baseline: nt_compat_exports::source_probe_metrics::Snapshot,
    handler: *mut ExecNtHandler,
) -> Result<(), i32> {
    loop {
        let delta = crate::driver_launch::source_observability::probe_snapshot()
            .delta_since(baseline).ok_or(0xc000_0001u32 as i32)?;
        if delta.proves_twelve_operations() {
            report_probe_milestones(delta);
            return Ok(());
        }
        if !crate::driver_launch::redrive_win32k_source_work(handler) {
            // Keep the module and target receipts on failure; no request is replayed.
            let final_delta = crate::driver_launch::source_observability::probe_snapshot()
                .delta_since(baseline).ok_or(0xc000_0001u32 as i32)?;
            report_probe_milestones(final_delta);
            return if final_delta.proves_twelve_operations() {
                Ok(())
            } else {
                Err(0xc000_0001u32 as i32)
            };
        }
    }
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
