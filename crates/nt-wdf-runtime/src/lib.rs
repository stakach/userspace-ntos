//! # `nt-wdf-runtime` — the WDF runtime core
//!
//! Ties the object table, I/O queues, and requests into the KMDF vertical slice
//! (spec: NT KMDF/WDF Runtime, §10-§16): `WdfDriverCreate` → framework AddDevice →
//! `WdfDeviceCreate` → `WdfIoQueueCreate` → request presentation → completion, plus the
//! PnP/power callback bridge (§14). Every method operates on values the Driver Host
//! already extracted from driver memory (callback function pointers, IOCTL codes, buffer
//! address/length pairs) — this crate performs no raw driver-pointer dereferences, so it
//! is fully host-testable. It hands back the driver callbacks to invoke and the IRPs to
//! complete; the Driver Host runs them in driver context. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use nt_wdf_object::{PendingCallback, WdfHandle, WdfObjectError, WdfObjectTable, WdfObjectType};
use nt_wdf_queue::{DispatchType, WdfIoQueue};
use nt_wdf_request::{RequestBuffers, WdfRequest, WdfRequestError};

/// The PnP/power event callbacks a device registered (spec §14), as function pointers.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PnpCallbacks {
    pub prepare_hardware: u64,
    pub release_hardware: u64,
    pub d0_entry: u64,
    pub d0_exit: u64,
}

/// An in-flight AddDevice init record (`WDFDEVICE_INIT`, spec §11) — temporary state the
/// driver fills via `WdfDeviceInitSet*` before `WdfDeviceCreate` consumes it.
#[derive(Clone)]
struct DeviceInit {
    pdo: u64,
    io_type: u32,
    device_type: u32,
    pnp: PnpCallbacks,
    consumed: bool,
}

struct DeviceInfo {
    wdm_device: u64,
    pdo: u64,
    io_type: u32,
    pnp: PnpCallbacks,
    default_queue: Option<WdfHandle>,
    powered: bool,
}

struct QueueInfo {
    queue: WdfIoQueue,
    evt_io_device_control: u64,
    device: WdfHandle,
}

struct RequestInfo {
    request: WdfRequest,
    queue: WdfHandle,
}

/// What the Driver Host must do to present a request to the driver: invoke
/// `evt_io_device_control(Queue, Request, OutLen, InLen, IoControlCode)` (spec §15.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IoDispatch {
    pub queue: WdfHandle,
    pub request: WdfHandle,
    pub evt_io_device_control: u64,
    pub io_control_code: u32,
}

/// The result of completing a request: the IRP to complete + any next request to present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    pub irp: u64,
    pub status: i32,
    pub information: u64,
    pub next: Option<IoDispatch>,
}

/// Why a runtime call failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WdfRuntimeError {
    Object(WdfObjectError),
    Request(WdfRequestError),
    /// No driver has been created yet / no such init record / no default queue.
    InvalidState,
}

impl From<WdfObjectError> for WdfRuntimeError {
    fn from(e: WdfObjectError) -> Self {
        WdfRuntimeError::Object(e)
    }
}

/// The canonical WDF runtime state for one Driver Host.
pub struct WdfRuntime {
    objects: WdfObjectTable,
    driver: Option<WdfHandle>,
    driver_object: u64,
    evt_device_add: u64,
    device_inits: Vec<Option<DeviceInit>>,
    devices: BTreeMap<u64, DeviceInfo>,
    queues: BTreeMap<u64, QueueInfo>,
    requests: BTreeMap<u64, RequestInfo>,
}

impl Default for WdfRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WdfRuntime {
    pub fn new() -> Self {
        Self {
            objects: WdfObjectTable::new(),
            driver: None,
            driver_object: 0,
            evt_device_add: 0,
            device_inits: Vec::new(),
            devices: BTreeMap::new(),
            queues: BTreeMap::new(),
            requests: BTreeMap::new(),
        }
    }

    // --- WdfDriverCreate (§10) ------------------------------------------------

    /// `WdfDriverCreate` — record the driver object + its `EvtDriverDeviceAdd`, and return
    /// the `WDFDRIVER` handle. The runtime installs a framework AddDevice bridge (the
    /// Driver Host wires the WDM `AddDevice` to call [`WdfRuntime::add_device`]).
    pub fn create_driver(
        &mut self,
        driver_object: u64,
        evt_device_add: u64,
    ) -> Result<WdfHandle, WdfRuntimeError> {
        let driver = self.objects.create(WdfObjectType::Driver, None)?;
        self.driver = Some(driver);
        self.driver_object = driver_object;
        self.evt_device_add = evt_device_add;
        Ok(driver)
    }

    pub fn driver(&self) -> Option<WdfHandle> {
        self.driver
    }
    pub fn evt_device_add(&self) -> u64 {
        self.evt_device_add
    }

    // --- Framework AddDevice bridge (§10.3, §11) ------------------------------

    /// The WDM AddDevice bridge: allocate a `WDFDEVICE_INIT` for a new PDO. The Driver Host
    /// then invokes `EvtDriverDeviceAdd(Driver, DeviceInit)`; the driver fills the init via
    /// the `set_init_*` helpers and calls `WdfDeviceCreate`. Returns the init id.
    pub fn add_device(&mut self, pdo: u64) -> usize {
        let init = DeviceInit {
            pdo,
            io_type: 0,
            device_type: 0,
            pnp: PnpCallbacks::default(),
            consumed: false,
        };
        self.device_inits.push(Some(init));
        self.device_inits.len() - 1
    }

    fn init_mut(&mut self, id: usize) -> Result<&mut DeviceInit, WdfRuntimeError> {
        self.device_inits
            .get_mut(id)
            .and_then(|o| o.as_mut())
            .filter(|i| !i.consumed)
            .ok_or(WdfRuntimeError::InvalidState)
    }

    /// `WdfDeviceInitSetIoType`.
    pub fn set_init_io_type(&mut self, id: usize, io_type: u32) -> Result<(), WdfRuntimeError> {
        self.init_mut(id)?.io_type = io_type;
        Ok(())
    }
    /// `WdfDeviceInitSetDeviceType`.
    pub fn set_init_device_type(&mut self, id: usize, dt: u32) -> Result<(), WdfRuntimeError> {
        self.init_mut(id)?.device_type = dt;
        Ok(())
    }
    /// `WdfDeviceInitSetPnpPowerEventCallbacks`.
    pub fn set_init_pnp_callbacks(
        &mut self,
        id: usize,
        pnp: PnpCallbacks,
    ) -> Result<(), WdfRuntimeError> {
        self.init_mut(id)?.pnp = pnp;
        Ok(())
    }

    // --- WdfDeviceCreate (§12) ------------------------------------------------

    /// `WdfDeviceCreate` — consume the init, create a `WDFDEVICE` (parented to the driver)
    /// wrapping the WDM device object the Driver Host created. Returns the device handle.
    pub fn create_device(
        &mut self,
        init_id: usize,
        wdm_device: u64,
    ) -> Result<WdfHandle, WdfRuntimeError> {
        let driver = self.driver.ok_or(WdfRuntimeError::InvalidState)?;
        let init = self
            .device_inits
            .get(init_id)
            .and_then(|o| o.clone())
            .filter(|i| !i.consumed)
            .ok_or(WdfRuntimeError::InvalidState)?;
        let device = self.objects.create(WdfObjectType::Device, Some(driver))?;
        self.devices.insert(
            device.0,
            DeviceInfo {
                wdm_device,
                pdo: init.pdo,
                io_type: init.io_type,
                pnp: init.pnp,
                default_queue: None,
                powered: false,
            },
        );
        // Consume the init (spec §11.2 — later use is invalid).
        self.device_inits[init_id] = None;
        Ok(device)
    }

    pub fn device_wdm_object(&self, device: WdfHandle) -> Option<u64> {
        self.devices.get(&device.0).map(|d| d.wdm_device)
    }
    pub fn device_io_type(&self, device: WdfHandle) -> Option<u32> {
        self.devices.get(&device.0).map(|d| d.io_type)
    }
    /// The PDO the device attached to (`WdfDeviceWdmGetPhysicalDevice`, spec §12.3).
    pub fn device_pdo(&self, device: WdfHandle) -> Option<u64> {
        self.devices.get(&device.0).map(|d| d.pdo)
    }
    /// The device that owns a queue.
    pub fn queue_device(&self, queue: WdfHandle) -> Option<WdfHandle> {
        self.queues.get(&queue.0).map(|q| q.device)
    }

    // --- WdfIoQueueCreate (§15.2) ---------------------------------------------

    /// `WdfIoQueueCreate` — create a `WDFQUEUE` (parented to the device). If `is_default`,
    /// it becomes the device's default queue (receives all I/O not routed elsewhere).
    pub fn create_queue(
        &mut self,
        device: WdfHandle,
        dispatch: DispatchType,
        power_managed: bool,
        evt_io_device_control: u64,
        is_default: bool,
    ) -> Result<WdfHandle, WdfRuntimeError> {
        self.objects.validate(device, WdfObjectType::Device)?;
        let queue = self.objects.create(WdfObjectType::Queue, Some(device))?;
        self.queues.insert(
            queue.0,
            QueueInfo {
                queue: WdfIoQueue::new(dispatch, power_managed),
                evt_io_device_control,
                device,
            },
        );
        if is_default {
            self.devices
                .get_mut(&device.0)
                .ok_or(WdfRuntimeError::InvalidState)?
                .default_queue = Some(queue);
        }
        Ok(queue)
    }

    // --- PnP / power bridge (§14) ---------------------------------------------

    /// START_DEVICE → `EvtDevicePrepareHardware` (spec §14.1). Returns the callback pointer
    /// the Driver Host must invoke (0 if none registered).
    pub fn prepare_hardware(&self, device: WdfHandle) -> Result<u64, WdfRuntimeError> {
        self.objects.validate(device, WdfObjectType::Device)?;
        Ok(self
            .devices
            .get(&device.0)
            .map(|d| d.pnp.prepare_hardware)
            .unwrap_or(0))
    }

    /// REMOVE/STOP → `EvtDeviceReleaseHardware` (spec §14.2).
    pub fn release_hardware(&self, device: WdfHandle) -> Result<u64, WdfRuntimeError> {
        self.objects.validate(device, WdfObjectType::Device)?;
        Ok(self
            .devices
            .get(&device.0)
            .map(|d| d.pnp.release_hardware)
            .unwrap_or(0))
    }

    /// SET_POWER D0/D3 → `EvtDeviceD0Entry`/`EvtDeviceD0Exit` (spec §14.3-§14.4). Updates
    /// the device power state, gates the default (power-managed) queue, and returns the
    /// callback to invoke plus any requests the queue releases on D0 entry.
    pub fn set_device_power(
        &mut self,
        device: WdfHandle,
        on: bool,
    ) -> Result<(u64, Vec<IoDispatch>), WdfRuntimeError> {
        self.objects.validate(device, WdfObjectType::Device)?;
        let (callback, default_queue) = {
            let d = self
                .devices
                .get_mut(&device.0)
                .ok_or(WdfRuntimeError::InvalidState)?;
            d.powered = on;
            let cb = if on { d.pnp.d0_entry } else { d.pnp.d0_exit };
            (cb, d.default_queue)
        };
        let mut released = Vec::new();
        if let Some(q) = default_queue {
            let handles = self
                .queues
                .get_mut(&q.0)
                .ok_or(WdfRuntimeError::InvalidState)?
                .queue
                .set_power(on);
            for r in handles {
                released.push(self.io_dispatch_for(q, r));
            }
        }
        Ok((callback, released))
    }

    // --- Request path (§15.3, §16) --------------------------------------------

    /// Present an incoming IOCTL IRP to the device's default queue (spec §15.3). Creates a
    /// `WDFREQUEST` (parented to the queue) and returns the [`IoDispatch`] the Driver Host
    /// must run now, or `None` if the queue held the request. The request handle is always
    /// created; retrieve it with [`WdfRuntime::request_ref`].
    pub fn present_ioctl(
        &mut self,
        device: WdfHandle,
        irp: u64,
        io_control_code: u32,
        buffers: RequestBuffers,
    ) -> Result<(WdfHandle, Option<IoDispatch>), WdfRuntimeError> {
        self.objects.validate(device, WdfObjectType::Device)?;
        let queue = self
            .devices
            .get(&device.0)
            .and_then(|d| d.default_queue)
            .ok_or(WdfRuntimeError::InvalidState)?;
        let request = self.objects.create(WdfObjectType::Request, Some(queue))?;
        self.requests.insert(
            request.0,
            RequestInfo {
                request: WdfRequest::new(irp, io_control_code, buffers),
                queue,
            },
        );
        let presented = self
            .queues
            .get_mut(&queue.0)
            .ok_or(WdfRuntimeError::InvalidState)?
            .queue
            .present(request);
        let dispatch = presented.map(|r| self.io_dispatch_for(queue, r));
        Ok((request, dispatch))
    }

    fn io_dispatch_for(&self, queue: WdfHandle, request: WdfHandle) -> IoDispatch {
        let qi = &self.queues[&queue.0];
        let ioctl = self.requests[&request.0].request.io_control_code;
        IoDispatch {
            queue,
            request,
            evt_io_device_control: qi.evt_io_device_control,
            io_control_code: ioctl,
        }
    }

    /// A read-only view of a request for buffer retrieval (`WdfRequestRetrieve*`, §16.4).
    pub fn request_ref(&self, request: WdfHandle) -> Result<&WdfRequest, WdfRuntimeError> {
        self.objects.validate(request, WdfObjectType::Request)?;
        self.requests
            .get(&request.0)
            .map(|r| &r.request)
            .ok_or(WdfRuntimeError::InvalidState)
    }

    /// `WdfRequestCompleteWithInformation` (spec §16.3). Completes the request, returns the
    /// IRP + status + information for the Driver Host to complete, plus the next request the
    /// queue releases (sequential dispatch). The completed request object is deleted.
    pub fn complete_request(
        &mut self,
        request: WdfHandle,
        status: i32,
        information: u64,
    ) -> Result<Completion, WdfRuntimeError> {
        self.objects.validate(request, WdfObjectType::Request)?;
        let (irp, queue) = {
            let ri = self
                .requests
                .get_mut(&request.0)
                .ok_or(WdfRuntimeError::InvalidState)?;
            ri.request
                .complete(status, information)
                .map_err(WdfRuntimeError::Request)?;
            (ri.request.irp, ri.queue)
        };
        // The queue releases the next request (sequential) now that this one is done.
        let next_handle = self
            .queues
            .get_mut(&queue.0)
            .ok_or(WdfRuntimeError::InvalidState)?
            .queue
            .complete_one();
        let next = next_handle.map(|r| self.io_dispatch_for(queue, r));
        // The request object is finished — delete it (children: none).
        let _ = self.objects.delete(request);
        self.requests.remove(&request.0);
        Ok(Completion {
            irp,
            status,
            information,
            next,
        })
    }

    /// `WdfObjectDelete` — delete an object + return the driver cleanup/destroy callbacks to
    /// run after the borrow releases (spec §7.3). Prunes any runtime side-state.
    pub fn delete_object(
        &mut self,
        handle: WdfHandle,
    ) -> Result<Vec<PendingCallback>, WdfRuntimeError> {
        let pending = self.objects.delete(handle)?;
        self.devices.remove(&handle.0);
        self.queues.remove(&handle.0);
        self.requests.remove(&handle.0);
        Ok(pending)
    }

    pub fn set_object_context(
        &mut self,
        handle: WdfHandle,
        context_ptr: u64,
        context_type: u64,
    ) -> Result<(), WdfRuntimeError> {
        self.objects
            .set_context(handle, context_ptr, context_type)
            .map_err(WdfRuntimeError::Object)
    }
    pub fn object_context(
        &self,
        handle: WdfHandle,
        context_type: u64,
    ) -> Result<u64, WdfRuntimeError> {
        self.objects
            .get_context(handle, context_type)
            .map_err(WdfRuntimeError::Object)
    }

    pub fn live_object_count(&self) -> usize {
        self.objects.live_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffers() -> RequestBuffers {
        RequestBuffers {
            input_ptr: 0x5000,
            input_len: 8,
            output_ptr: 0x6000,
            output_len: 8,
        }
    }

    /// The full KMDF vertical slice (spec §22.1 / §1): driver → device → queue → IOCTL →
    /// complete.
    #[test]
    fn vertical_slice() {
        let mut rt = WdfRuntime::new();
        let driver = rt.create_driver(0xD000, 0xADDE).unwrap();
        assert_eq!(rt.driver(), Some(driver));
        assert_eq!(rt.evt_device_add(), 0xADDE);

        // Framework AddDevice → EvtDriverDeviceAdd fills the init → WdfDeviceCreate.
        let init = rt.add_device(0x9D0);
        rt.set_init_io_type(init, 1).unwrap();
        rt.set_init_pnp_callbacks(
            init,
            PnpCallbacks {
                prepare_hardware: 0xBEEF,
                d0_entry: 0xD0E,
                d0_exit: 0xD03,
                ..Default::default()
            },
        )
        .unwrap();
        let device = rt.create_device(init, 0xFD0).unwrap();
        assert_eq!(rt.device_wdm_object(device), Some(0xFD0));
        // The init is consumed — reuse fails (spec §11.2).
        assert!(rt.create_device(init, 0xFD0).is_err());

        // Default sequential power-managed queue with EvtIoDeviceControl.
        let queue = rt
            .create_queue(device, DispatchType::Sequential, true, 0xC70, true)
            .unwrap();
        let _ = queue;

        // START_DEVICE → PrepareHardware; then D0 entry powers the queue.
        assert_eq!(rt.prepare_hardware(device).unwrap(), 0xBEEF);
        let (d0cb, released) = rt.set_device_power(device, true).unwrap();
        assert_eq!(d0cb, 0xD0E);
        assert!(released.is_empty()); // nothing queued yet

        // IOCTL arrives → presented to EvtIoDeviceControl.
        let (req, disp) = rt
            .present_ioctl(device, 0x1234, 0x0022_2400, buffers())
            .unwrap();
        let disp = disp.expect("first request dispatches immediately");
        assert_eq!(disp.request, req);
        assert_eq!(disp.evt_io_device_control, 0xC70);
        assert_eq!(disp.io_control_code, 0x0022_2400);

        // Driver retrieves buffers + completes.
        let r = rt.request_ref(req).unwrap();
        assert_eq!(r.retrieve_output_buffer(4).unwrap(), (0x6000, 8));
        let done = rt.complete_request(req, 0, 8).unwrap();
        assert_eq!(done.irp, 0x1234);
        assert_eq!(done.information, 8);
        assert!(done.next.is_none());
        // Request object gone; driver + device + queue remain.
        assert!(rt.request_ref(req).is_err());
    }

    #[test]
    fn sequential_queue_serializes_ioctls() {
        let mut rt = WdfRuntime::new();
        rt.create_driver(1, 0).unwrap();
        let init = rt.add_device(0);
        let device = rt.create_device(init, 0xFD0).unwrap();
        rt.create_queue(device, DispatchType::Sequential, false, 0xC70, true)
            .unwrap();
        // First dispatches, second is held.
        let (r1, d1) = rt.present_ioctl(device, 0xA, 1, buffers()).unwrap();
        assert!(d1.is_some());
        let (_r2, d2) = rt.present_ioctl(device, 0xB, 1, buffers()).unwrap();
        assert!(d2.is_none()); // queued behind r1
                               // Completing r1 releases r2.
        let done = rt.complete_request(r1, 0, 0).unwrap();
        let next = done.next.expect("r2 released");
        assert_eq!(next.io_control_code, 1);
    }

    #[test]
    fn power_managed_queue_holds_until_d0() {
        let mut rt = WdfRuntime::new();
        rt.create_driver(1, 0).unwrap();
        let init = rt.add_device(0);
        rt.set_init_pnp_callbacks(
            init,
            PnpCallbacks {
                d0_entry: 0xD0E,
                ..Default::default()
            },
        )
        .unwrap();
        let device = rt.create_device(init, 0xFD0).unwrap();
        rt.create_queue(device, DispatchType::Sequential, true, 0xC70, true)
            .unwrap();
        // Device not yet in D0 → IOCTL is held.
        let (_r, disp) = rt.present_ioctl(device, 0xA, 1, buffers()).unwrap();
        assert!(disp.is_none());
        // D0 entry releases the held request.
        let (cb, released) = rt.set_device_power(device, true).unwrap();
        assert_eq!(cb, 0xD0E);
        assert_eq!(released.len(), 1);
    }

    #[test]
    fn delete_device_cascades_to_queue() {
        let mut rt = WdfRuntime::new();
        let driver = rt.create_driver(1, 0).unwrap();
        let init = rt.add_device(0);
        let device = rt.create_device(init, 0xFD0).unwrap();
        rt.create_queue(device, DispatchType::Sequential, false, 0, true)
            .unwrap();
        assert_eq!(rt.live_object_count(), 3); // driver, device, queue
        rt.delete_object(device).unwrap();
        // Device + its queue gone; driver remains.
        assert_eq!(rt.live_object_count(), 1);
        assert!(rt.prepare_hardware(device).is_err());
        assert_eq!(rt.driver(), Some(driver));
    }
}
