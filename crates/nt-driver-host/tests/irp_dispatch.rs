//! IRP dispatch end-to-end (M7): the I/O Manager dispatches an IRP, the loaded
//! driver's `MajorFunction[major]` runs, does the `METHOD_BUFFERED` echo, and
//! completes the IRP exactly once.

use std::cell::RefCell;
use std::rc::Rc;

use nt_driver_host::{
    BridgeCreateDevice, BridgeDeviceIds, DispatchInvoke, DispatchRequest, DispatchResult,
    DriverHost, DriverServices, EntryContext, IoManagerBridge, MockDispatchGate, MockGate,
    NullBridge,
};
use nt_driver_test_fixtures::pe_importing;
use nt_io_manager::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, DispatchContext,
    DispatchOutcome, DriverDispatchBackend, DriverId, IoManager, IoParameters, IrpId,
    IrpProjection, MockObjectPort, ShareAccess,
};
use nt_kernel_abi::{major, DriverObject, GuestAddr, IoStackLocation, Irp};
use nt_status::NtStatus;
use nt_types::{AccessMask, NtPath};

const IMAGE_BASE: u64 = 0x1_4000_0000;
const ARENA_BASE: u64 = 0xFFFF_F800_0000_0000;
const TRAMP_BASE: u64 = 0x7F00_0000_0000;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;

fn npath(s: &str) -> NtPath {
    NtPath::parse_str(s).unwrap()
}

// --- the synthetic driver ----------------------------------------------------

/// `DriverEntry`: create `\Device\SurtTest0` + `\??\SurtTest0`, install dispatch.
fn driver_entry(ctx: &EntryContext, s: &mut DriverServices) -> i32 {
    let name = s
        .runtime_mut()
        .alloc_unicode_string("\\Device\\SurtTest0")
        .unwrap();
    let out = s.runtime_mut().arena_mut().alloc(8, 8).unwrap();
    let st = s.io_create_device(ctx.driver_object, 0, name, 0x22, 0, false, out);
    if st != 0 {
        return st;
    }
    let link = s
        .runtime_mut()
        .alloc_unicode_string("\\??\\SurtTest0")
        .unwrap();
    let target = s
        .runtime_mut()
        .alloc_unicode_string("\\Device\\SurtTest0")
        .unwrap();
    let st = s.io_create_symbolic_link(link, target);
    if st != 0 {
        return st;
    }
    let mut drv: DriverObject = s.arena_mut().read(ctx.driver_object).unwrap();
    for m in [
        major::IRP_MJ_CREATE,
        major::IRP_MJ_CLOSE,
        major::IRP_MJ_DEVICE_CONTROL,
    ] {
        drv.major_function[m as usize] = GuestAddr(0x1000 + m as u64);
    }
    s.arena_mut().write(ctx.driver_object, drv);
    0
}

fn set_iostatus(s: &mut DriverServices, irp: GuestAddr, status: i32, info: u64) {
    let mut i: Irp = s.runtime().arena().read(irp).unwrap();
    i.io_status.status = status;
    i.io_status.information = info;
    s.arena_mut().write(irp, i);
}

/// A dispatch routine: complete CREATE/CLOSE, echo DEVICE_CONTROL (METHOD_BUFFERED).
fn dispatch_echo(inv: &DispatchInvoke, s: &mut DriverServices) -> i32 {
    let sl_addr = s.io_get_current_irp_stack_location(inv.irp);
    let sl: IoStackLocation = s.runtime().arena().read(sl_addr).unwrap();
    match sl.major_function {
        m if m == major::IRP_MJ_CREATE || m == major::IRP_MJ_CLOSE => {
            set_iostatus(s, inv.irp, 0, 0);
            s.io_complete_request(inv.irp)
        }
        m if m == major::IRP_MJ_DEVICE_CONTROL => {
            // METHOD_BUFFERED: input already occupies the SystemBuffer; echo it.
            let p = sl.device_io_control();
            let n = p.input_buffer_length.min(p.output_buffer_length) as u64;
            set_iostatus(s, inv.irp, 0, n);
            s.io_complete_request(inv.irp)
        }
        _ => {
            set_iostatus(s, inv.irp, 0xC000_0010u32 as i32, 0);
            s.io_complete_request(inv.irp)
        }
    }
}

// --- a bridge that assigns a fixed DeviceId ----------------------------------

struct FixedBridge {
    device_id: u64,
}

impl IoManagerBridge for FixedBridge {
    fn create_device(&mut self, _req: &BridgeCreateDevice) -> Result<BridgeDeviceIds, NtStatus> {
        Ok(BridgeDeviceIds {
            device_id: self.device_id,
            object_id: 0,
        })
    }
    fn delete_device(&mut self, _id: u64) -> NtStatus {
        NtStatus::SUCCESS
    }
    fn create_symbolic_link(&mut self, _link: &str, _target: &str) -> NtStatus {
        NtStatus::SUCCESS
    }
    fn delete_symbolic_link(&mut self, _link: &str) -> NtStatus {
        NtStatus::SUCCESS
    }
}

fn started_host(device_id: u64) -> DriverHost {
    let mut host = DriverHost::new(ARENA_BASE, 128 * 1024, TRAMP_BASE);
    host.load(
        &pe_importing("ntoskrnl.exe", &["IoCreateDevice", "IoCreateSymbolicLink"]),
        IMAGE_BASE,
        "\\Registry\\...",
    )
    .unwrap();
    let mut bridge = FixedBridge { device_id };
    host.start(&MockGate(driver_entry), &mut bridge).unwrap();
    host
}

#[test]
fn dispatch_reaches_driver_and_buffered_echo_works() {
    let mut host = started_host(100);
    let gate = MockDispatchGate(dispatch_echo);
    let mut nb = NullBridge;

    // IRP_MJ_CREATE reaches the driver + completes.
    let r = host.dispatch_irp(
        &gate,
        &mut nb,
        DispatchRequest {
            irp_id: 1,
            device_id: 100,
            major: major::IRP_MJ_CREATE,
            minor: 0,
            ioctl_code: 0,
            input_len: 0,
            output_len: 0,
        },
        &mut [],
    );
    assert_eq!(
        r,
        DispatchResult::Completed {
            status: 0,
            information: 0
        }
    );

    // IRP_MJ_DEVICE_CONTROL: METHOD_BUFFERED echo of "ping".
    let mut buf = *b"ping\0\0\0\0";
    let r = host.dispatch_irp(
        &gate,
        &mut nb,
        DispatchRequest {
            irp_id: 2,
            device_id: 100,
            major: major::IRP_MJ_DEVICE_CONTROL,
            minor: 0,
            ioctl_code: 0x0022_2000,
            input_len: 4,
            output_len: 8,
        },
        &mut buf,
    );
    assert_eq!(
        r,
        DispatchResult::Completed {
            status: 0,
            information: 4
        }
    );
    assert_eq!(&buf[..4], b"ping");

    // Unknown device is rejected.
    let r = host.dispatch_irp(
        &gate,
        &mut nb,
        DispatchRequest {
            irp_id: 3,
            device_id: 999,
            major: major::IRP_MJ_CREATE,
            minor: 0,
            ioctl_code: 0,
            input_len: 0,
            output_len: 0,
        },
        &mut [],
    );
    assert!(matches!(r, DispatchResult::Failed { .. }));
}

#[test]
fn completion_is_exactly_once() {
    let mut host = started_host(100);
    let mut nb = NullBridge;
    // A dispatch that completes, then verifies re-completion + unknown-IRP are
    // both rejected (spec §10.2).
    let guard = MockDispatchGate(|inv: &DispatchInvoke, s: &mut DriverServices| {
        set_iostatus(s, inv.irp, 0, 7);
        assert_eq!(s.io_complete_request(inv.irp), 0);
        assert_eq!(s.io_complete_request(inv.irp), STATUS_INVALID_PARAMETER);
        assert_eq!(
            s.io_complete_request(GuestAddr(0xDEAD)),
            STATUS_INVALID_PARAMETER
        );
        0
    });
    let r = host.dispatch_irp(
        &guard,
        &mut nb,
        DispatchRequest {
            irp_id: 5,
            device_id: 100,
            major: major::IRP_MJ_CREATE,
            minor: 0,
            ioctl_code: 0,
            input_len: 0,
            output_len: 0,
        },
        &mut [],
    );
    assert_eq!(
        r,
        DispatchResult::Completed {
            status: 0,
            information: 7
        }
    );
}

// --- full integration: I/O Manager drives the loaded driver ------------------

struct IoMgrBridge<'a> {
    io: &'a mut IoManager<MockObjectPort>,
    driver: DriverId,
}

impl IoManagerBridge for IoMgrBridge<'_> {
    fn create_device(&mut self, req: &BridgeCreateDevice) -> Result<BridgeDeviceIds, NtStatus> {
        let name = req.name.as_ref().map(|n| npath(n));
        let dev = self.io.create_device(
            self.driver,
            name.as_ref(),
            DeviceType(req.device_type),
            DeviceCharacteristics::from_bits_truncate(req.characteristics),
            DeviceFlags::from_bits_truncate(req.flags),
            req.extension_size,
        )?;
        Ok(BridgeDeviceIds {
            device_id: dev.raw(),
            object_id: 0,
        })
    }
    fn delete_device(&mut self, _id: u64) -> NtStatus {
        NtStatus::SUCCESS
    }
    fn create_symbolic_link(&mut self, link: &str, target: &str) -> NtStatus {
        match self.io.create_symbolic_link(&npath(link), &npath(target)) {
            Ok(()) => NtStatus::SUCCESS,
            Err(e) => e,
        }
    }
    fn delete_symbolic_link(&mut self, _link: &str) -> NtStatus {
        NtStatus::SUCCESS
    }
}

/// The I/O Manager dispatch backend that drives the loaded driver.
struct DriverHostBackend {
    host: Rc<RefCell<DriverHost>>,
}

impl DriverDispatchBackend for DriverHostBackend {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (ioctl_code, input_len, output_len) = match &irp.parameters {
            IoParameters::DeviceControl(p) | IoParameters::InternalDeviceControl(p) => {
                (p.ioctl_code, p.input_len, p.output_len)
            }
            _ => (0, 0, 0),
        };
        let req = DispatchRequest {
            irp_id: irp.irp_id.raw(),
            device_id: irp.device_id.raw(),
            major: irp.major,
            minor: irp.minor,
            ioctl_code,
            input_len,
            output_len,
        };
        let gate = MockDispatchGate(dispatch_echo);
        let mut nb = NullBridge;
        let result = self
            .host
            .borrow_mut()
            .dispatch_irp(&gate, &mut nb, req, ctx.system_buffer);
        Ok(match result {
            DispatchResult::Completed {
                status,
                information,
            } => DispatchOutcome::Completed {
                status: NtStatus(status),
                information,
            },
            DispatchResult::Pending => DispatchOutcome::Pending,
            DispatchResult::Failed { status } => DispatchOutcome::Failed {
                status: NtStatus(status),
            },
        })
    }
    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Ok(())
    }
}

#[test]
fn iomanager_device_control_echoes_through_loaded_driver() {
    let host = Rc::new(RefCell::new(DriverHost::new(
        ARENA_BASE,
        256 * 1024,
        TRAMP_BASE,
    )));
    host.borrow_mut()
        .load(
            &pe_importing("ntoskrnl.exe", &["IoCreateDevice", "IoCreateSymbolicLink"]),
            IMAGE_BASE,
            "\\Registry\\...",
        )
        .unwrap();

    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io
        .create_driver_peer(
            &npath("\\Driver\\SurtTest"),
            Box::new(DriverHostBackend { host: host.clone() }),
        )
        .unwrap();

    {
        let mut bridge = IoMgrBridge {
            io: &mut io,
            driver,
        };
        host.borrow_mut()
            .start(&MockGate(driver_entry), &mut bridge)
            .unwrap();
    }

    // Open the device by symlink — IRP_MJ_CREATE reaches the driver.
    let client = io.register_client();
    let handle = io
        .open(
            client,
            &npath("\\??\\SurtTest0"),
            AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
            ShareAccess::empty(),
            CreateOptions::empty(),
            0,
        )
        .unwrap();

    // DEVICE_CONTROL echoes through the driver.
    let mut out = [0u8; 8];
    let n = io
        .device_control(client, handle, 0x0022_2000, b"ping", &mut out)
        .unwrap();
    assert_eq!(&out[..n as usize], b"ping");
}
