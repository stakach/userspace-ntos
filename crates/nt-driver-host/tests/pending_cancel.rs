//! Pending + cancel (M8): a driver returns STATUS_PENDING, the I/O Manager can
//! cancel, the completion/cancel race resolves to exactly one final state, and a
//! Driver Host fault fails pending IRPs safely (spec §10.2, §10.3, §17).

use nt_driver_host::{
    BridgeCreateDevice, BridgeDeviceIds, DhCompletion, DispatchInvoke, DispatchRequest,
    DispatchResult, DriverHost, DriverServices, DriverState, EntryContext, IoManagerBridge,
    MockDispatchGate, MockGate, NullBridge,
};
use nt_driver_test_fixtures::pe_importing;
use nt_kernel_abi::{major, DriverObject, GuestAddr};
use nt_status::NtStatus;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const ARENA_BASE: u64 = 0xFFFF_F800_0000_0000;
const TRAMP_BASE: u64 = 0x7F00_0000_0000;
const STATUS_PENDING: i32 = 0x0000_0103;
const STATUS_CANCELLED: i32 = 0xC000_0120u32 as i32;
const STATUS_DEVICE_REMOVED: i32 = 0xC000_02BFu32 as i32;

/// `DriverEntry`: create the device, install a DEVICE_CONTROL dispatch.
fn driver_entry(ctx: &EntryContext, s: &mut DriverServices) -> i32 {
    let name = s
        .runtime_mut()
        .alloc_unicode_string("\\Device\\SurtTest0")
        .unwrap();
    let out = s.runtime_mut().arena_mut().alloc(8, 8).unwrap();
    if s.io_create_device(ctx.driver_object, 0, name, 0x22, 0, false, out) != 0 {
        return -1;
    }
    let mut drv: DriverObject = s.arena_mut().read(ctx.driver_object).unwrap();
    drv.major_function[major::IRP_MJ_DEVICE_CONTROL as usize] = GuestAddr(0x1000);
    s.arena_mut().write(ctx.driver_object, drv);
    0
}

/// A dispatch that marks the IRP pending + returns STATUS_PENDING (no completion).
fn dispatch_pending(inv: &DispatchInvoke, s: &mut DriverServices) -> i32 {
    assert_eq!(s.io_mark_irp_pending(inv.irp), 0);
    STATUS_PENDING
}

struct FixedBridge;
impl IoManagerBridge for FixedBridge {
    fn create_device(&mut self, _r: &BridgeCreateDevice) -> Result<BridgeDeviceIds, NtStatus> {
        Ok(BridgeDeviceIds {
            device_id: 100,
            object_id: 0,
        })
    }
    fn delete_device(&mut self, _id: u64) -> NtStatus {
        NtStatus::SUCCESS
    }
    fn create_symbolic_link(&mut self, _l: &str, _t: &str) -> NtStatus {
        NtStatus::SUCCESS
    }
    fn delete_symbolic_link(&mut self, _l: &str) -> NtStatus {
        NtStatus::SUCCESS
    }
}

fn started_host() -> DriverHost {
    let mut host = DriverHost::new(ARENA_BASE, 128 * 1024, TRAMP_BASE);
    host.load(
        &pe_importing("ntoskrnl.exe", &["IoCreateDevice"]),
        IMAGE_BASE,
        "\\Registry\\...",
    )
    .unwrap();
    host.start(&MockGate(driver_entry), &mut FixedBridge)
        .unwrap();
    host
}

fn ioctl(irp_id: u64) -> DispatchRequest {
    DispatchRequest {
        irp_id,
        device_id: 100,
        major: major::IRP_MJ_DEVICE_CONTROL,
        minor: 0,
        ioctl_code: 0x0022_2000,
        input_len: 0,
        output_len: 0,
    }
}

fn dispatch_pending_irp(host: &mut DriverHost, irp_id: u64) {
    let mut nb = NullBridge;
    let r = host.dispatch_irp(
        &MockDispatchGate(dispatch_pending),
        &mut nb,
        ioctl(irp_id),
        &mut [],
    );
    assert_eq!(r, DispatchResult::Pending);
}

#[test]
fn driver_returns_pending_then_completes() {
    let mut host = started_host();
    dispatch_pending_irp(&mut host, 1);
    assert_eq!(host.pending_count(), 1);
    assert!(host.poll_completion().is_none());

    // The driver's deferred DPC completes it.
    assert!(host.complete_pending(1, 0, 42));
    assert_eq!(host.pending_count(), 0);
    assert_eq!(
        host.poll_completion(),
        Some(DhCompletion {
            irp_id: 1,
            status: 0,
            information: 42
        })
    );
    assert!(host.poll_completion().is_none());
}

#[test]
fn iomanager_cancels_a_pending_irp() {
    let mut host = started_host();
    dispatch_pending_irp(&mut host, 2);
    assert!(host.cancel_irp(2));
    assert_eq!(host.pending_count(), 0);
    assert_eq!(
        host.poll_completion(),
        Some(DhCompletion {
            irp_id: 2,
            status: STATUS_CANCELLED,
            information: 0
        })
    );
}

#[test]
fn completion_wins_the_cancel_race() {
    let mut host = started_host();
    dispatch_pending_irp(&mut host, 3);
    // Completion arrives first...
    assert!(host.complete_pending(3, 0, 9));
    // ...so the cancel is a no-op (exactly one final state).
    assert!(!host.cancel_irp(3));
    // Only the completion was delivered.
    assert_eq!(
        host.poll_completion(),
        Some(DhCompletion {
            irp_id: 3,
            status: 0,
            information: 9
        })
    );
    assert!(host.poll_completion().is_none());
}

#[test]
fn cancel_wins_the_completion_race() {
    let mut host = started_host();
    dispatch_pending_irp(&mut host, 4);
    // Cancel arrives first...
    assert!(host.cancel_irp(4));
    // ...so the driver's later completion is a no-op.
    assert!(!host.complete_pending(4, 0, 9));
    assert_eq!(
        host.poll_completion(),
        Some(DhCompletion {
            irp_id: 4,
            status: STATUS_CANCELLED,
            information: 0
        })
    );
    assert!(host.poll_completion().is_none());
}

#[test]
fn fault_fails_pending_irps_safely() {
    let mut host = started_host();
    dispatch_pending_irp(&mut host, 5);
    dispatch_pending_irp(&mut host, 6);
    assert_eq!(host.pending_count(), 2);

    host.fault();
    assert_eq!(host.state(), DriverState::Faulted);
    assert_eq!(host.pending_count(), 0);

    // Both pending IRPs were failed for the I/O Manager to finalize.
    let mut got = [
        host.poll_completion().unwrap(),
        host.poll_completion().unwrap(),
    ];
    got.sort_by_key(|c| c.irp_id);
    assert_eq!(got[0].irp_id, 5);
    assert_eq!(got[0].status, STATUS_DEVICE_REMOVED);
    assert_eq!(got[1].irp_id, 6);
    assert!(host.poll_completion().is_none());

    // A faulted driver rejects new dispatch.
    let mut nb = NullBridge;
    assert!(matches!(
        host.dispatch_irp(
            &MockDispatchGate(dispatch_pending),
            &mut nb,
            ioctl(7),
            &mut []
        ),
        DispatchResult::Failed { .. }
    ));
}
