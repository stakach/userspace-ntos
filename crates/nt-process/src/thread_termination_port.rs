//! ETHREAD-owned termination-port references and their non-replayable terminal effects.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_REGISTRATION: AtomicU64 = AtomicU64::new(1);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThreadTerminationPortPhase {
    Reserved,
    Registered,
    DeliveryPending,
    Delivered,
    Refused,
    ReleasePending,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ThreadTerminationPortTicket {
    nonce: u64,
    lifetime: ThreadLifetime,
}

impl ThreadTerminationPortTicket {
    pub const fn lifetime(&self) -> ThreadLifetime {
        self.lifetime
    }
}

pub struct ThreadTerminationPortSnapshot {
    pub ticket: ThreadTerminationPortTicket,
    pub phase: ThreadTerminationPortPhase,
    pub endpoint: Option<u64>,
    pub create_time_100ns: i64,
    pub refusal_status: Option<u32>,
}

pub(super) struct ThreadTerminationPortRegistration {
    nonce: u64,
    lifetime: ThreadLifetime,
    endpoint: Option<u64>,
    phase: ThreadTerminationPortPhase,
    create_time_100ns: i64,
    refusal_status: Option<u32>,
}

impl ProcessManager {
    /// Reserve canonical durable metadata before native reference acquisition. A reservation
    /// fences reclamation even if the acquisition's result is indeterminate.
    pub fn prepare_thread_termination_port(
        &mut self,
        tid: ThreadId,
    ) -> Result<ThreadTerminationPortTicket, u32> {
        self.prepare_thread_termination_port_with_reserve(tid, 1)
    }

    pub(super) fn prepare_thread_termination_port_with_reserve(
        &mut self,
        tid: ThreadId,
        reserve: usize,
    ) -> Result<ThreadTerminationPortTicket, u32> {
        let lifetime = self.thread_lifetime(tid).ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.state == ThreadState::Terminated {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        if thread
            .termination_ports
            .iter()
            .any(|record| record.phase == ThreadTerminationPortPhase::Reserved)
        {
            return Err(STATUS_DEVICE_BUSY);
        }
        thread
            .termination_ports
            .try_reserve(reserve)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let nonce = NEXT_REGISTRATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        thread
            .termination_ports
            .push(ThreadTerminationPortRegistration {
                nonce,
                lifetime,
                endpoint: None,
                phase: ThreadTerminationPortPhase::Reserved,
                create_time_100ns: thread.create_time_100ns,
                refusal_status: None,
            });
        Ok(ThreadTerminationPortTicket { nonce, lifetime })
    }

    fn termination_port_record_mut(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
    ) -> Result<&mut ThreadTerminationPortRegistration, u32> {
        if !self.validate_thread_lifetime(ticket.lifetime) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.threads
            .get_mut(&ticket.lifetime.thread_id)
            .and_then(|thread| {
                thread.termination_ports.iter_mut().find(|record| {
                    record.nonce == ticket.nonce && record.lifetime == ticket.lifetime
                })
            })
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Bind an actually retained broker reference, never the caller's public port handle.
    pub fn register_thread_termination_port(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
        endpoint: u64,
    ) -> Result<(), u32> {
        if endpoint == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        let record = self.termination_port_record_mut(ticket)?;
        if record.phase != ThreadTerminationPortPhase::Reserved {
            return Err(STATUS_DEVICE_BUSY);
        }
        record.endpoint = Some(endpoint);
        record.phase = ThreadTerminationPortPhase::Registered;
        Ok(())
    }

    /// Only valid when the host proves that reference acquisition has not entered, or was
    /// rejected without effects. An uncertain acquisition must keep the reservation.
    pub fn cancel_thread_termination_port(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
    ) -> Result<(), u32> {
        let record = self.termination_port_record_mut(ticket)?;
        if record.phase != ThreadTerminationPortPhase::Reserved {
            return Err(STATUS_DEVICE_BUSY);
        }
        let thread = self.threads.get_mut(&ticket.lifetime.thread_id).unwrap();
        let index = thread
            .termination_ports
            .iter()
            .position(|record| record.nonce == ticket.nonce)
            .unwrap();
        thread.termination_ports.remove(index);
        Ok(())
    }

    pub fn peek_thread_termination_port(
        &self,
        tid: ThreadId,
    ) -> Result<Option<ThreadTerminationPortSnapshot>, u32> {
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(thread
            .termination_ports
            .last()
            .map(|record| ThreadTerminationPortSnapshot {
                ticket: ThreadTerminationPortTicket {
                    nonce: record.nonce,
                    lifetime: record.lifetime,
                },
                phase: record.phase,
                endpoint: record.endpoint,
                create_time_100ns: record.create_time_100ns,
                refusal_status: record.refusal_status,
            }))
    }

    fn transition_thread_termination_port(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
        from: ThreadTerminationPortPhase,
        to: ThreadTerminationPortPhase,
    ) -> Result<(), u32> {
        let record = self.termination_port_record_mut(ticket)?;
        if record.phase != from {
            return Err(STATUS_DEVICE_BUSY);
        }
        record.phase = to;
        Ok(())
    }

    pub fn begin_thread_termination_port_delivery(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
    ) -> Result<(), u32> {
        self.transition_thread_termination_port(
            ticket,
            ThreadTerminationPortPhase::Registered,
            ThreadTerminationPortPhase::DeliveryPending,
        )
    }
    pub fn acknowledge_thread_termination_port_delivery(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
    ) -> Result<(), u32> {
        self.transition_thread_termination_port(
            ticket,
            ThreadTerminationPortPhase::DeliveryPending,
            ThreadTerminationPortPhase::Delivered,
        )
    }
    /// The host must supply a checked broker certificate proving no message was queued.
    /// A raw transport status is not such proof.
    pub fn acknowledge_thread_termination_port_refusal(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
        status: u32,
    ) -> Result<(), u32> {
        if status >> 30 != 3 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let record = self.termination_port_record_mut(ticket)?;
        if record.phase != ThreadTerminationPortPhase::DeliveryPending {
            return Err(STATUS_DEVICE_BUSY);
        }
        record.refusal_status = Some(status);
        record.phase = ThreadTerminationPortPhase::Refused;
        Ok(())
    }

    pub fn begin_thread_termination_port_release(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
    ) -> Result<(), u32> {
        let record = self.termination_port_record_mut(ticket)?;
        if !matches!(
            record.phase,
            ThreadTerminationPortPhase::Delivered | ThreadTerminationPortPhase::Refused
        ) {
            return Err(STATUS_DEVICE_BUSY);
        }
        record.phase = ThreadTerminationPortPhase::ReleasePending;
        Ok(())
    }
    pub fn acknowledge_thread_termination_port_release(
        &mut self,
        ticket: &ThreadTerminationPortTicket,
    ) -> Result<(), u32> {
        let record = self.termination_port_record_mut(ticket)?;
        if record.phase != ThreadTerminationPortPhase::ReleasePending {
            return Err(STATUS_DEVICE_BUSY);
        }
        let thread = self.threads.get_mut(&ticket.lifetime.thread_id).unwrap();
        let index = thread
            .termination_ports
            .iter()
            .position(|record| record.nonce == ticket.nonce)
            .unwrap();
        thread.termination_ports.remove(index);
        Ok(())
    }
}
