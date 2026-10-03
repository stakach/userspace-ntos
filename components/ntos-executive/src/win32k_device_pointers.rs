//! Native Device pointer operations through the authenticated consumer registration ledger.

use super::*;
use nt_io_abi::device_pointer::{DevicePointerOperation, DevicePointerReply};

static REQUESTS: AtomicU64 = AtomicU64::new(0);
static REFERENCES: AtomicU64 = AtomicU64::new(0);
static DEREFERENCES: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn stats() -> (u64, u64, u64, u64) {
    (
        REQUESTS.load(Ordering::Relaxed),
        REFERENCES.load(Ordering::Relaxed),
        DEREFERENCES.load(Ordering::Relaxed),
        FAILURES.load(Ordering::Relaxed),
    )
}

pub(crate) unsafe fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    operation: u64,
    address: u64,
) -> (i32, u64) {
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    let result = (|| {
        let operation =
            DevicePointerOperation::from_raw(operation).ok_or(STATUS_INVALID_PARAMETER)?;
        let access = super::win32k_device_consumer::authenticate(ch, reply_cap, address)?;
        let registration = access.registration();
        if operation == DevicePointerOperation::Reference {
            io_manager_mut()
                .reference_hosted_device_pointer(registration)
                .map_err(|status| status.raw())?;
            REFERENCES.fetch_add(1, Ordering::Relaxed);
        } else {
            io_manager_mut()
                .dereference_hosted_device_pointer(registration)
                .map_err(|status| status.raw())?;
            DEREFERENCES.fetch_add(1, Ordering::Relaxed);
            record_device_pointer_dereference_commit(ch, registration);
        }
        Ok(io_manager_mut().device_reference_count(access.device()))
    })();
    match result {
        Ok(count) => (STATUS_SUCCESS, count),
        Err(status) => {
            FAILURES.fetch_add(1, Ordering::Relaxed);
            (status, 0)
        }
    }
}

unsafe fn exchange(operation: DevicePointerOperation, address: u64) -> Result<u64, i32> {
    let (info, status, count, _, _) = call_on4_raw(
        (crate::win32k_subsystem::W32_DEVICE_POINTER_LABEL << 12) | 2,
        operation.raw(),
        address,
        0,
        0,
    );
    // Mutating operations are never retried from an ambiguous response. The canonical ledger
    // retains ownership; a failed native call stops instead of inventing a count or double-applying.
    assert_eq!(info, 2, "ambiguous Device pointer reply envelope");
    let result = DevicePointerReply::decode(status, count)
        .expect("ambiguous Device pointer reply body")
        .into_result();
    if let Ok(count) = result {
        if operation == DevicePointerOperation::Dereference {
            crate::win32k_subsystem::record_device_pointer_dereference_ack(address, count);
        }
    }
    result
}

fn record_device_pointer_dereference_commit(
    ch: &crate::spawn_hosts::PumpChannel,
    registration: nt_io_manager::HostedDevicePointerRegistration,
) {
    #[cfg(feature = "source-irp-integration")]
    {
        let domain = registration.domain();
        print_str(b"[source-receipt] pdo-dereference-commit domain="); print_u64(domain.domain_id.raw());
        print_str(b" cookie="); print_u64(domain.cookie);
        print_str(b" device="); print_u64(registration.device_id().raw());
        print_str(b" address="); print_u64(registration.address());
        print_str(b" count="); print_u64(io_manager_mut().device_reference_count(registration.device_id()));
        if let Some(route) = ch.ingress_route {
            let identity = route.identity();
            print_str(b" physical-domain="); print_u64(identity.domain);
            print_str(b" physical-generation="); print_u64(identity.domain_generation);
            print_str(b" executor="); print_u64(identity.executor);
            if let Ok(dispatch) = unsafe {
                crate::spawn_hosts::shared_ingress::owner::runtime::dispatch(route)
            } {
                print_str(b" dispatch="); print_u64(dispatch.epoch());
            }
        }
        print_str(b"\n");
    }
    #[cfg(not(feature = "source-irp-integration"))]
    let _ = (ch, registration);
}

pub(crate) unsafe fn reference(address: u64) -> Result<u64, i32> {
    exchange(DevicePointerOperation::Reference, address)
}

pub(crate) unsafe fn dereference(address: u64) -> Result<u64, i32> {
    exchange(DevicePointerOperation::Dereference, address)
}
