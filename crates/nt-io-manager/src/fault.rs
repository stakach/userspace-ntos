//! Driver-peer fault handling (spec §16.6).
//!
//! When a driver peer faults or disconnects, every IRP the I/O Manager has
//! in-flight at that driver is failed with `STATUS_DEVICE_NOT_CONNECTED`, the
//! driver is marked faulted, and its devices are marked delete-pending. Unrelated
//! drivers and devices are untouched. `pump` detects newly-faulted backends and
//! calls `fault_driver` automatically.

use alloc::vec::Vec;

use nt_status::NtStatus;

use crate::dispatch::DriverCompletion;
use crate::driver::DriverFlags;
use crate::irp::IrpState;
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, DriverId, IoManager, IrpId};

impl<P: ObjectManagerPort> IoManager<P> {
    /// Fault a driver (spec §16.6): mark it faulted, fail its in-flight IRPs, and
    /// mark its devices delete-pending. Idempotent-safe (skip if already faulted).
    pub fn fault_driver(&mut self, driver: DriverId) -> usize {
        match self.driver_mut(driver) {
            Some(d) if !d.flags.contains(DriverFlags::FAULTED) => {
                d.flags |= DriverFlags::FAULTED;
            }
            _ => return 0,
        }

        let devices: Vec<DeviceId> = self.devices_of(driver).to_vec();

        // Fail every IRP already handed to (or pending at) the driver.
        let irps: Vec<IrpId> = self
            .irps
            .iter()
            .filter(|(_, i)| {
                i.current_stack()
                    .map(|stack| stack.driver_id == driver)
                    .unwrap_or(false)
                    && matches!(
                        i.state,
                        IrpState::Dispatched | IrpState::Pending | IrpState::CancelRequested
                    )
            })
            .map(|(id, _)| id)
            .collect();
        let mut published = 0;
        for id in irps {
            published += usize::from(self.publish_transport_fault_completion(
                driver,
                DriverCompletion {
                    irp_id: id,
                    status: NtStatus::DEVICE_NOT_CONNECTED,
                    information: 0,
                    file_context: None,
                },
            ));
        }

        for dev in devices {
            if let Some(d) = self.device_mut(dev) {
                d.delete_pending = true;
            }
        }
        published
    }

    /// Detect backends that have faulted + fault their drivers (called by `pump`).
    pub(crate) fn detect_driver_faults(&mut self) -> usize {
        let mut published = 0;
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
                published += self.fault_driver(driver);
            }
        }
        published
    }
}
