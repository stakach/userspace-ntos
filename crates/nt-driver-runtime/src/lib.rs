//! # `nt-driver-runtime` — the driver-local NT kernel runtime
//!
//! The local NT runtime visible inside one Driver Host (spec §7.4). It owns the
//! guest-memory [`Arena`], allocates the projected `DRIVER_OBJECT` /
//! `DEVICE_OBJECT` / `IRP` / `UNICODE_STRING` a loaded driver sees, runs the
//! driver [`Pool`], and provides IRQL/event/spinlock stubs. Every pointer the
//! driver hands back to an export is validated against the projection + pool
//! tables ([`DriverRuntime::validate`], spec §19.2) — a valid-looking pointer
//! grants access only to the local projection, never canonical authority
//! (§19.3). `no_std` + `alloc`, no `unsafe`.

#![no_std]

extern crate alloc;

mod arena;
mod pool;
mod projections;
mod strings;
mod sync;

pub use arena::Arena;
pub use pool::{Pool, PoolBlock, PoolError};
pub use projections::{ObjectEntry, ObjectKind, ObjectTable};
pub use sync::{EventState, EventTable, Irql, APC_LEVEL, DISPATCH_LEVEL, PASSIVE_LEVEL};

use alloc::string::String;
use alloc::vec::Vec;

use bytemuck::Zeroable;
use nt_kernel_abi::{DeviceObject, DriverObject, GuestAddr, IoStackLocation, Irp};

const DRIVER_OBJECT_SIZE: usize = 336;
const DEVICE_OBJECT_SIZE: usize = 336;
const IRP_SIZE: usize = 208;
const STACK_LOCATION_SIZE: usize = 72;
const OBJ_ALIGN: usize = 16;

/// A leak report produced on driver unload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnloadReport {
    /// `(addr, size, tag)` of each unfreed pool block.
    pub pool_leaks: Vec<(GuestAddr, usize, u32)>,
    /// Live device projections still present at unload.
    pub live_devices: usize,
}

impl UnloadReport {
    pub fn is_clean(&self) -> bool {
        self.pool_leaks.is_empty() && self.live_devices == 0
    }
}

/// The driver-local runtime.
pub struct DriverRuntime {
    arena: Arena,
    pool: Pool,
    objects: ObjectTable,
    irql: Irql,
    events: EventTable,
    driver_object: Option<GuestAddr>,
}

impl DriverRuntime {
    /// A runtime whose arena is `capacity` bytes based at guest address `base`.
    pub fn new(base: u64, capacity: usize) -> Self {
        Self {
            arena: Arena::new(base, capacity),
            pool: Pool::new(),
            objects: ObjectTable::new(),
            irql: Irql::default(),
            events: EventTable::new(),
            driver_object: None,
        }
    }

    pub fn arena(&self) -> &Arena {
        &self.arena
    }
    pub fn arena_mut(&mut self) -> &mut Arena {
        &mut self.arena
    }
    pub fn irql(&mut self) -> &mut Irql {
        &mut self.irql
    }
    pub fn events(&mut self) -> &mut EventTable {
        &mut self.events
    }
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    // --- projections -------------------------------------------------------

    /// Allocate the driver's `DRIVER_OBJECT` projection (spec §9 step 9).
    pub fn create_driver_object(&mut self) -> Option<GuestAddr> {
        let addr = self.arena.alloc(DRIVER_OBJECT_SIZE, OBJ_ALIGN)?;
        let mut drv = DriverObject::zeroed();
        drv.type_ = 4; // IO_TYPE_DRIVER
        drv.size = DRIVER_OBJECT_SIZE as i16;
        self.arena.write(addr, drv);
        self.objects.register(ObjectEntry {
            addr,
            size: DRIVER_OBJECT_SIZE,
            kind: ObjectKind::DriverObject,
            canonical_id: 0,
            extension: None,
            live: true,
        });
        self.driver_object = Some(addr);
        Some(addr)
    }

    pub fn driver_object_addr(&self) -> Option<GuestAddr> {
        self.driver_object
    }

    /// Read back the (driver-mutated) `DRIVER_OBJECT` — e.g. to capture the
    /// `MajorFunction` dispatch table + `DriverUnload` after `DriverEntry`.
    pub fn driver_object(&self) -> Option<DriverObject> {
        self.arena.read(self.driver_object?)
    }

    /// Allocate a `DEVICE_OBJECT` projection (+ `DeviceExtension` region) for
    /// `IoCreateDevice` (spec §11.1). The canonical `DeviceId` is set later, when
    /// the I/O Manager registers it (M6).
    pub fn create_device_object(
        &mut self,
        device_type: u32,
        characteristics: u32,
        flags: u32,
        extension_size: usize,
    ) -> Option<GuestAddr> {
        let addr = self.arena.alloc(DEVICE_OBJECT_SIZE, OBJ_ALIGN)?;
        let extension = if extension_size > 0 {
            Some(self.arena.alloc(extension_size, OBJ_ALIGN)?)
        } else {
            None
        };
        let mut dev = DeviceObject::zeroed();
        dev.type_ = 3; // IO_TYPE_DEVICE
        dev.size = DEVICE_OBJECT_SIZE as u16;
        dev.driver_object = self.driver_object.unwrap_or(GuestAddr::NULL);
        dev.device_type = device_type;
        dev.characteristics = characteristics;
        dev.flags = flags;
        dev.stack_size = 1;
        dev.device_extension = extension.unwrap_or(GuestAddr::NULL);
        self.arena.write(addr, dev);
        self.objects.register(ObjectEntry {
            addr,
            size: DEVICE_OBJECT_SIZE,
            kind: ObjectKind::DeviceObject,
            canonical_id: 0,
            extension,
            live: true,
        });
        Some(addr)
    }

    /// Allocate an `IRP` projection with `stack_count` stack locations, its
    /// `SystemBuffer` set + current stack location wired (spec §10.1 step 6).
    pub fn create_irp(
        &mut self,
        irp_id: u64,
        stack_count: u8,
        system_buffer: GuestAddr,
    ) -> Option<GuestAddr> {
        let n = stack_count.max(1) as usize;
        let addr = self.arena.alloc(IRP_SIZE, OBJ_ALIGN)?;
        let stacks = self.arena.alloc(STACK_LOCATION_SIZE * n, OBJ_ALIGN)?;

        let mut irp = Irp::zeroed();
        irp.type_ = 6; // IO_TYPE_IRP
        irp.size = (IRP_SIZE + STACK_LOCATION_SIZE * n) as u16;
        irp.stack_count = stack_count as i8;
        irp.current_location = stack_count as i8;
        irp.associated_irp_system_buffer = system_buffer;
        irp.current_stack_location = stacks;
        self.arena.write(addr, irp);

        self.objects.register(ObjectEntry {
            addr,
            size: IRP_SIZE,
            kind: ObjectKind::Irp,
            canonical_id: irp_id,
            extension: Some(stacks),
            live: true,
        });
        Some(addr)
    }

    /// The current stack location of an IRP projection.
    pub fn irp_current_stack(&self, irp: GuestAddr) -> Option<IoStackLocation> {
        let entry = self.objects.find_kind(irp, ObjectKind::Irp)?;
        self.arena.read(entry.extension?)
    }

    /// Write the current stack location of an IRP projection.
    pub fn set_irp_current_stack(&mut self, irp: GuestAddr, sl: IoStackLocation) -> bool {
        match self
            .objects
            .find_kind(irp, ObjectKind::Irp)
            .and_then(|e| e.extension)
        {
            Some(stacks) => self.arena.write(stacks, sl),
            None => false,
        }
    }

    // --- strings -----------------------------------------------------------

    /// Allocate a `UNICODE_STRING` + buffer for `s`; returns the struct address.
    pub fn alloc_unicode_string(&mut self, s: &str) -> Option<GuestAddr> {
        let (us_addr, _buf) = strings::alloc_unicode_string(&mut self.arena, s)?;
        self.objects.register(ObjectEntry {
            addr: us_addr,
            size: 16,
            kind: ObjectKind::UnicodeString,
            canonical_id: 0,
            extension: None,
            live: true,
        });
        Some(us_addr)
    }

    /// Read a `UNICODE_STRING` at `addr` (e.g. a driver's `DeviceName`).
    pub fn read_unicode_string(&self, addr: GuestAddr) -> Option<String> {
        strings::read_unicode_string(&self.arena, addr)
    }

    // --- pool --------------------------------------------------------------

    pub fn pool_alloc(&mut self, size: usize, tag: u32) -> Result<GuestAddr, PoolError> {
        self.pool.allocate(&mut self.arena, size, tag)
    }
    pub fn pool_free(&mut self, addr: GuestAddr) -> Result<(), PoolError> {
        self.pool.free(addr)
    }

    // --- pointer validation (spec §19.2) -----------------------------------

    /// Validate a driver-provided pointer as a live projection of `kind`.
    pub fn validate(&self, addr: GuestAddr, kind: ObjectKind) -> Option<&ObjectEntry> {
        self.objects.find_kind(addr, kind)
    }

    /// Validate that `addr` is the runtime's one driver object.
    pub fn validate_driver_object(&self, addr: GuestAddr) -> bool {
        self.driver_object == Some(addr)
            && self
                .objects
                .find_kind(addr, ObjectKind::DriverObject)
                .is_some()
    }

    /// Validate that `[addr, addr+len)` is writable local memory (for output
    /// pointer parameters, spec §19.2).
    pub fn validate_writable(&self, addr: GuestAddr, len: usize) -> bool {
        self.arena.contains(addr, len)
    }

    /// True if `addr` is any live projection or live pool block.
    pub fn is_known_pointer(&self, addr: GuestAddr) -> bool {
        self.objects.find(addr).is_some() || self.pool.is_live(addr)
    }

    pub fn objects(&self) -> &ObjectTable {
        &self.objects
    }
    pub fn objects_mut(&mut self) -> &mut ObjectTable {
        &mut self.objects
    }

    // --- teardown ----------------------------------------------------------

    /// Produce the unload leak report (spec §13).
    pub fn unload_report(&self) -> UnloadReport {
        UnloadReport {
            pool_leaks: self.pool.leaks().map(|b| (b.addr, b.size, b.tag)).collect(),
            live_devices: self.objects.of_kind(ObjectKind::DeviceObject).count(),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use nt_kernel_abi::major;

    const BASE: u64 = 0xFFFF_F800_0000_0000;

    fn runtime() -> DriverRuntime {
        DriverRuntime::new(BASE, 64 * 1024)
    }

    #[test]
    fn allocates_and_reads_back_driver_object() {
        let mut rt = runtime();
        let drv = rt.create_driver_object().unwrap();
        assert!(rt.validate_driver_object(drv));
        // The runtime wrote a valid DRIVER_OBJECT.
        let read = rt.driver_object().unwrap();
        assert_eq!(read.type_, 4);
        assert_eq!(read.size, 336);
    }

    #[test]
    fn driver_dispatch_table_capture() {
        // Simulate DriverEntry writing MajorFunction[IRP_MJ_DEVICE_CONTROL].
        let mut rt = runtime();
        let drv_addr = rt.create_driver_object().unwrap();
        let mut drv = rt.arena().read::<DriverObject>(drv_addr).unwrap();
        drv.major_function[major::IRP_MJ_DEVICE_CONTROL as usize] = GuestAddr(0xABCD);
        drv.driver_unload = GuestAddr(0x1234);
        assert!(rt.arena_mut().write(drv_addr, drv));
        // Runtime reads the captured table.
        let captured = rt.driver_object().unwrap();
        assert_eq!(
            captured.major_function[major::IRP_MJ_DEVICE_CONTROL as usize],
            GuestAddr(0xABCD)
        );
        assert_eq!(captured.driver_unload, GuestAddr(0x1234));
    }

    #[test]
    fn device_object_has_extension_and_fields() {
        let mut rt = runtime();
        rt.create_driver_object();
        let dev = rt
            .create_device_object(0x22, 0, nt_kernel_abi::device_flags::DO_BUFFERED_IO, 64)
            .unwrap();
        let entry = rt.validate(dev, ObjectKind::DeviceObject).unwrap();
        let ext = entry.extension.unwrap();
        let obj: DeviceObject = rt.arena().read(dev).unwrap();
        assert_eq!(obj.device_type, 0x22);
        assert_eq!(obj.flags, nt_kernel_abi::device_flags::DO_BUFFERED_IO);
        assert_eq!(obj.device_extension, ext);
        assert_eq!(obj.stack_size, 1);
    }

    #[test]
    fn stale_and_foreign_pointers_are_rejected() {
        let mut rt = runtime();
        rt.create_driver_object();
        let dev = rt.create_device_object(0, 0, 0, 0).unwrap();
        // A pointer inside the arena but not an object is not a valid device.
        assert!(rt
            .validate(GuestAddr(BASE + 8), ObjectKind::DeviceObject)
            .is_none());
        // A pointer outside the arena is unknown.
        assert!(!rt.is_known_pointer(GuestAddr(0x1000)));
        // Wrong kind is rejected.
        assert!(rt.validate(dev, ObjectKind::Irp).is_none());
        // After retiring the device, it is stale.
        assert!(rt.objects_mut().retire(dev));
        assert!(rt.validate(dev, ObjectKind::DeviceObject).is_none());
    }

    #[test]
    fn pool_double_free_and_leaks() {
        let mut rt = runtime();
        let a = rt.pool_alloc(128, u32::from_le_bytes(*b"tSeT")).unwrap();
        let b = rt.pool_alloc(64, 0).unwrap();
        assert!(rt.is_known_pointer(a));
        assert_eq!(rt.pool_free(a), Ok(()));
        assert_eq!(rt.pool_free(a), Err(PoolError::DoubleFree));
        assert_eq!(
            rt.pool_free(GuestAddr(BASE + 999999)),
            Err(PoolError::UnknownPointer)
        );
        // b leaks.
        let report = rt.unload_report();
        assert_eq!(report.pool_leaks.len(), 1);
        assert_eq!(report.pool_leaks[0].0, b);
        assert!(!report.is_clean());
    }

    #[test]
    fn unicode_string_roundtrip() {
        let mut rt = runtime();
        let us = rt.alloc_unicode_string("\\Device\\SurtTest0").unwrap();
        assert_eq!(
            rt.read_unicode_string(us).as_deref(),
            Some("\\Device\\SurtTest0")
        );
        assert!(rt.validate(us, ObjectKind::UnicodeString).is_some());
    }

    #[test]
    fn irql_transitions() {
        let mut rt = runtime();
        assert_eq!(rt.irql().current(), PASSIVE_LEVEL);
        let old = rt.irql().raise(DISPATCH_LEVEL);
        assert_eq!(old, PASSIVE_LEVEL);
        assert_eq!(rt.irql().current(), DISPATCH_LEVEL);
        rt.irql().lower(PASSIVE_LEVEL);
        assert_eq!(rt.irql().current(), PASSIVE_LEVEL);
        // A raise that lowers is invalid.
        rt.irql().raise(DISPATCH_LEVEL);
        rt.irql().raise(PASSIVE_LEVEL);
        assert_eq!(rt.irql().invalid_transitions(), 1);
    }

    #[test]
    fn events_track_local_state() {
        let mut rt = runtime();
        let ev = GuestAddr(BASE + 0x2000);
        rt.events().initialize(ev, false, false);
        assert!(!rt.events().set(ev)); // was clear
        assert!(rt.events().set(ev)); // now set
        assert!(rt.events().reset(ev)); // was set, now clear
        assert!(!rt.events().state(ev).unwrap().signaled);
    }

    #[test]
    fn out_of_memory_is_graceful() {
        let mut rt = DriverRuntime::new(BASE, 256);
        // Exhaust the tiny arena.
        assert!(rt.pool_alloc(200, 0).is_ok());
        assert_eq!(rt.pool_alloc(200, 0), Err(PoolError::OutOfMemory));
    }
}
