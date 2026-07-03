//! Driver-peer fault handling (spec §16.6).
//!
//! When a driver peer faults or disconnects, every IRP the I/O Manager has
//! in-flight at that driver is failed with `STATUS_DEVICE_NOT_CONNECTED`, the
//! driver is marked faulted, and its devices are marked delete-pending. Unrelated
//! drivers and devices are untouched. `pump` detects newly-faulted backends and
//! calls `fault_driver` automatically.

use alloc::vec::Vec;

use nt_status::NtStatus;

use crate::driver::DriverFlags;
use crate::irp::IrpState;
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, DriverId, IoManager, IrpId};

impl<P: ObjectManagerPort> IoManager<P> {
    /// Fault a driver (spec §16.6): mark it faulted, fail its in-flight IRPs, and
    /// mark its devices delete-pending. Idempotent-safe (skip if already faulted).
    pub fn fault_driver(&mut self, driver: DriverId) {
        match self.driver_mut(driver) {
            Some(d) if !d.flags.contains(DriverFlags::FAULTED) => {
                d.flags |= DriverFlags::FAULTED;
            }
            _ => return,
        }

        let devices: Vec<DeviceId> = self.devices_of(driver).to_vec();

        // Fail every IRP already handed to (or pending at) the driver.
        let irps: Vec<IrpId> = self
            .irps
            .iter()
            .filter(|(_, i)| {
                devices.contains(&i.device_id)
                    && matches!(
                        i.state,
                        IrpState::Dispatched
                            | IrpState::Pending
                            | IrpState::CancelRequested
                            | IrpState::Completing
                    )
            })
            .map(|(id, _)| id)
            .collect();
        for id in irps {
            if let Some(irp) = self.irp_mut(id) {
                irp.status = NtStatus::DEVICE_NOT_CONNECTED;
                irp.transition(IrpState::Failed);
            }
            self.free_irp(id);
        }

        for dev in devices {
            if let Some(d) = self.device_mut(dev) {
                d.delete_pending = true;
            }
        }
    }

    /// Detect backends that have faulted + fault their drivers (called by `pump`).
    pub(crate) fn detect_driver_faults(&mut self) {
        for driver in self.drivers.ids() {
            let (idx, already) = match self.driver(driver) {
                Some(d) => (d.backend.0 as usize, d.flags.contains(DriverFlags::FAULTED)),
                None => continue,
            };
            if already {
                continue;
            }
            if self
                .backends
                .get(idx)
                .map(|b| b.is_faulted())
                .unwrap_or(false)
            {
                self.fault_driver(driver);
            }
        }
    }
}
