//! Provider-owned `PsSetCreateProcessNotifyRoutineEx` exit deliveries.
//!
//! The process manager records a callback only for a proven loaded-image instance. A terminal
//! process transition queues one delivery per registration while the EPROCESS is still owned by
//! the manager. The host invokes each callback at PASSIVE_LEVEL and acknowledges the exact ticket
//! before the process object or provider image may be retired. An uncertain callback result keeps
//! the ticket in flight; it must never be replayed.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::{ProcessId, STATUS_DEVICE_BUSY, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER};

/// Identity of the loaded image containing the callback, not merely its reusable address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessExitNotifyOwner {
    pub image_base: u64,
    pub image_generation: u64,
}

/// One exact invocation of `PCREATE_PROCESS_NOTIFY_ROUTINE_EX` with `CreateInfo == NULL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessExitNotification {
    pub owner: ProcessExitNotifyOwner,
    pub callback: u64,
    pub process_id: ProcessId,
    pub process_sequence: u64,
    pub process_object: u64,
    pub exit_status: u32,
    ticket: u64,
}

#[derive(Clone, Copy)]
struct Registration {
    owner: ProcessExitNotifyOwner,
    callback: u64,
    generation: u64,
}

#[derive(Clone, Copy)]
struct Delivery {
    notification: ProcessExitNotification,
    registration_generation: u64,
    in_flight: bool,
}

/// The PM-owned callback ledger. The host must prove the image range and generation before
/// calling `register`; the returned callback address is never authority by itself.
#[derive(Default)]
pub(super) struct ProcessExitNotifyLedger {
    registrations: Vec<Registration>,
    deliveries: VecDeque<Delivery>,
    next_generation: u64,
    next_ticket: u64,
}

impl ProcessExitNotifyLedger {
    pub fn has_registrations(&self) -> bool {
        !self.registrations.is_empty()
    }

    pub fn register(&mut self, owner: ProcessExitNotifyOwner, callback: u64) -> Result<(), u32> {
        if owner.image_base == 0 || owner.image_generation == 0 || callback == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.registrations.iter().any(|entry| entry.callback == callback) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let generation = self.next_generation.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        self.registrations.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.next_generation = generation;
        self.registrations.push(Registration { owner, callback, generation });
        Ok(())
    }

    pub fn unregister(&mut self, owner: ProcessExitNotifyOwner, callback: u64) -> Result<(), u32> {
        let index = self.registrations.iter().position(|entry| entry.owner == owner && entry.callback == callback)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let generation = self.registrations[index].generation;
        if self.deliveries.iter().any(|delivery| delivery.registration_generation == generation) {
            return Err(STATUS_DEVICE_BUSY);
        }
        self.registrations.remove(index);
        Ok(())
    }

    /// Reserve all deliveries before the irreversible terminal state change.
    pub fn preflight_exit(&mut self) -> Result<(), u32> {
        self.deliveries.try_reserve(self.registrations.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.next_ticket.checked_add(self.registrations.len() as u64)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    pub fn queue_exit(&mut self, process_id: ProcessId, process_sequence: u64, process_object: u64, exit_status: u32) {
        for registration in &self.registrations {
            self.next_ticket += 1; // preflighted before the process transition
            self.deliveries.push_back(Delivery {
                notification: ProcessExitNotification {
                    owner: registration.owner,
                    callback: registration.callback,
                    process_id,
                    process_sequence,
                    process_object,
                    exit_status,
                    ticket: self.next_ticket,
                },
                registration_generation: registration.generation,
                in_flight: false,
            });
        }
    }

    /// Claim once. An in-flight callback cannot be claimed again after an uncertain result.
    pub fn take(&mut self) -> Option<ProcessExitNotification> {
        let delivery = self.deliveries.iter_mut().find(|delivery| !delivery.in_flight)?;
        delivery.in_flight = true;
        Some(delivery.notification)
    }

    pub fn complete(&mut self, notification: ProcessExitNotification) -> Result<(), u32> {
        let index = self.deliveries.iter().position(|delivery| delivery.in_flight && delivery.notification == notification)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        self.deliveries.remove(index);
        Ok(())
    }

    pub fn pending_for_process(&self, process_id: ProcessId, sequence: u64) -> usize {
        self.deliveries.iter().filter(|delivery| {
            delivery.notification.process_id == process_id && delivery.notification.process_sequence == sequence
        }).count()
    }
}
