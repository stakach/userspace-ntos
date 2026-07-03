//! IoCreateDevice / IoCreateSymbolicLink bridge (M6): a synthetic driver creates
//! `\Device\SurtTest0` + `\??\SurtTest0`, and the real I/O Manager opens it by
//! symlink.

use nt_driver_host::{
    BridgeCreateDevice, BridgeDeviceIds, DriverHost, DriverServices, DriverState, EntryContext,
    IoManagerBridge, MockGate,
};
use nt_driver_runtime::ObjectKind;
use nt_driver_test_fixtures::pe_importing;
use nt_io_manager::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, DriverId, IoManager,
    MockDriverBackend, MockObjectPort, ShareAccess,
};
use nt_kernel_abi::{major, DriverObject, GuestAddr};
use nt_status::NtStatus;
use nt_types::{AccessMask, NtPath};

const IMAGE_BASE: u64 = 0x1_4000_0000;
const ARENA_BASE: u64 = 0xFFFF_F800_0000_0000;
const TRAMP_BASE: u64 = 0x7F00_0000_0000;

fn npath(s: &str) -> NtPath {
    NtPath::parse_str(s).unwrap()
}

/// The mock driver's `DriverEntry`: create the device + symlink, install dispatch.
fn driver_entry(ctx: &EntryContext, s: &mut DriverServices) -> i32 {
    let name = s
        .runtime_mut()
        .alloc_unicode_string("\\Device\\SurtTest0")
        .unwrap();
    let out = s.runtime_mut().arena_mut().alloc(8, 8).unwrap();

    // A bogus DriverObject pointer must be rejected (spec §19.2).
    let bad = s.io_create_device(GuestAddr(0xDEAD), 0, name, 0x22, 0, false, out);
    assert_eq!(bad, 0xC000_000Du32 as i32);

    let st = s.io_create_device(ctx.driver_object, 64, name, 0x22, 0, false, out);
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
    drv.major_function[major::IRP_MJ_CREATE as usize] = GuestAddr(0x1);
    drv.major_function[major::IRP_MJ_DEVICE_CONTROL as usize] = GuestAddr(0x2);
    s.arena_mut().write(ctx.driver_object, drv);
    0
}

// --- a recording bridge (checks the export forwards the right requests) -------

#[derive(Default)]
struct RecordBridge {
    created: Vec<String>,
    links: Vec<(String, String)>,
}

impl IoManagerBridge for RecordBridge {
    fn create_device(&mut self, req: &BridgeCreateDevice) -> Result<BridgeDeviceIds, NtStatus> {
        self.created.push(req.name.clone().unwrap_or_default());
        Ok(BridgeDeviceIds {
            device_id: 42,
            object_id: 7,
        })
    }
    fn delete_device(&mut self, _id: u64) -> NtStatus {
        NtStatus::SUCCESS
    }
    fn create_symbolic_link(&mut self, link: &str, target: &str) -> NtStatus {
        self.links.push((link.into(), target.into()));
        NtStatus::SUCCESS
    }
    fn delete_symbolic_link(&mut self, _link: &str) -> NtStatus {
        NtStatus::SUCCESS
    }
}

#[test]
fn exports_forward_requests_and_store_canonical_id() {
    let bytes = pe_importing("ntoskrnl.exe", &["IoCreateDevice", "IoCreateSymbolicLink"]);
    let mut host = DriverHost::new(ARENA_BASE, 64 * 1024, TRAMP_BASE);
    host.load(&bytes, IMAGE_BASE, "\\Registry\\...").unwrap();

    let mut bridge = RecordBridge::default();
    host.start(&MockGate(driver_entry), &mut bridge).unwrap();
    assert_eq!(host.state(), DriverState::Started);

    assert_eq!(bridge.created, vec!["\\Device\\SurtTest0"]);
    assert_eq!(
        bridge.links,
        vec![(
            "\\??\\SurtTest0".to_string(),
            "\\Device\\SurtTest0".to_string()
        )]
    );
    // The canonical DeviceId from the bridge was stored in the local projection.
    let dev = host
        .runtime()
        .objects()
        .of_kind(ObjectKind::DeviceObject)
        .next()
        .unwrap();
    assert_eq!(dev.canonical_id, 42);
}

// --- the real end-to-end path: I/O Manager opens the device by symlink --------

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

#[test]
fn driver_creates_device_and_iomanager_opens_by_symlink() {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io
        .create_driver_peer(
            &npath("\\Driver\\SurtTest"),
            Box::new(MockDriverBackend::default()),
        )
        .unwrap();

    let bytes = pe_importing("ntoskrnl.exe", &["IoCreateDevice", "IoCreateSymbolicLink"]);
    let mut host = DriverHost::new(ARENA_BASE, 64 * 1024, TRAMP_BASE);
    host.load(&bytes, IMAGE_BASE, "\\Registry\\...").unwrap();

    {
        let mut bridge = IoMgrBridge {
            io: &mut io,
            driver,
        };
        host.start(&MockGate(driver_entry), &mut bridge).unwrap();
    }
    assert_eq!(host.state(), DriverState::Started);

    // The I/O Manager can now open the device by its symbolic link.
    let client = io.register_client();
    let handle = io.open(
        client,
        &npath("\\??\\SurtTest0"),
        AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
        ShareAccess::empty(),
        CreateOptions::empty(),
        0,
    );
    assert!(handle.is_ok(), "open by symlink failed: {handle:?}");
}
