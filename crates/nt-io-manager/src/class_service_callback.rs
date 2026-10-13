//! Retained port-to-class callback contract.
//!
//! ReactOS calls a class service with a class device, a half-open input record range,
//! and an output consumed count. The native adapter must pin its port allocation
//! while copying records, and retain the source continuation through the terminal
//! acknowledgement. Dropping an uncertain request never licenses a second call.

use alloc::vec::Vec;
use core::cell::Cell;

use crate::{
    hosted_forward_target::HostedForwardTarget,
    retained_connect_forward::{
        ConnectBufferAllocation, ConnectControl, ConnectForwardPhase, ConnectPayloadIdentity,
        RetainedConnectForward,
    },
    CompletionAcknowledgement, HostedDevicePointerRegistration, HostedDomainIdentity, IoManager,
};

/// Native code must bind this generation to the exact executable callback mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassServiceThunk {
    pub domain: HostedDomainIdentity,
    pub address: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassServiceBinding {
    pub class: HostedDevicePointerRegistration,
    pub port: HostedDevicePointerRegistration,
    pub control: ConnectControl,
    pub thunk: ClassServiceThunk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassCallbackIdentity {
    pub binding: ClassServiceBinding,
    pub source: ConnectBufferAllocation,
    pub input_start: u64,
    pub input_end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassCallbackError {
    WrongIdentity,
    InvalidInput,
    InsufficientResources,
    InvalidTransition,
    ConsumedBeyondOffered,
    Outstanding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Entered,
    Completed(u32),
    Acknowledged(u32),
    Indeterminate,
    Retired,
}

/// Survives successful CONNECT IRP completion until an explicit disconnect.
/// Two exact device references prevent either projected object from retiring.
#[must_use = "retain the endpoint across class callbacks until disconnect"]
#[derive(Debug)]
pub struct ClassServiceEndpoint {
    binding: ClassServiceBinding,
    class: HostedForwardTarget,
    port: HostedForwardTarget,
    outstanding: Cell<u64>,
    class_released: bool,
    port_released: bool,
}

impl ClassServiceEndpoint {
    pub fn bind<P>(
        io: &IoManager<P>,
        connect: &RetainedConnectForward,
        payload: ConnectPayloadIdentity,
        class: HostedForwardTarget,
        port: HostedForwardTarget,
        thunk: ClassServiceThunk,
    ) -> Result<Self, (ClassCallbackError, HostedForwardTarget, HostedForwardTarget)> {
        if !matches!(connect.phase(), ConnectForwardPhase::Terminal(status) if status.is_success())
            || connect.validate_payload(io, payload).is_err()
        {
            return Err((ClassCallbackError::WrongIdentity, class, port));
        }
        let class_registration = class.registration();
        let port_registration = port.registration();
        if class_registration != payload.class_device
            || class.validate(io).ok() != Some(class_registration.device_id())
            || port.validate(io).ok() != Some(payload.forward.target.device_id())
            || port_registration.device_id() != payload.forward.target.device_id()
            || port_registration.domain() == class_registration.domain()
            || thunk.domain != class_registration.domain()
            || thunk.address == 0
            || thunk.address != payload.class_service
            || thunk.generation == 0
        {
            return Err((ClassCallbackError::WrongIdentity, class, port));
        }
        Ok(Self {
            binding: ClassServiceBinding {
                class: class_registration,
                port: port_registration,
                control: payload.forward.control,
                thunk,
            },
            class,
            port,
            outstanding: Cell::new(0),
            class_released: false,
            port_released: false,
        })
    }

    pub const fn binding(&self) -> ClassServiceBinding {
        self.binding
    }

    pub fn validate<P>(&self, io: &IoManager<P>) -> Result<(), ClassCallbackError> {
        if self.class_released
            || self.port_released
            || self.class.registration() != self.binding.class
            || self.port.registration() != self.binding.port
            || self.class.validate(io).ok() != Some(self.binding.class.device_id())
            || self.port.validate(io).ok() != Some(self.binding.port.device_id())
        {
            return Err(ClassCallbackError::WrongIdentity);
        }
        Ok(())
    }

    /// Capture bytes only while the native adapter holds the exact port pool lease.
    /// The half-open range is bounded to 1,024 complete records per callback.
    pub fn capture<'a, P>(
        &'a self,
        io: &IoManager<P>,
        source: ConnectBufferAllocation,
        start: u64,
        end: u64,
        source_bytes: &[u8],
    ) -> Result<RetainedClassCallback<'a>, ClassCallbackError> {
        self.validate(io)?;
        let record_bytes = match self.binding.control {
            ConnectControl::Keyboard => 12_u64,
            ConnectControl::Mouse => 24_u64,
        };
        let length = end
            .checked_sub(start)
            .ok_or(ClassCallbackError::InvalidInput)?;
        let allocation_end = source
            .base
            .checked_add(source.bytes)
            .ok_or(ClassCallbackError::InvalidInput)?;
        let offered = length / record_bytes;
        if source.domain != self.binding.port.domain()
            || source.generation == 0
            || source.base == 0
            || source.bytes == 0
            || start == 0
            || start & 3 != 0
            || length == 0
            || length % record_bytes != 0
            || offered > 1024
            || start < source.base
            || end > allocation_end
            || usize::try_from(length).ok() != Some(source_bytes.len())
        {
            return Err(ClassCallbackError::InvalidInput);
        }
        let next = self
            .outstanding
            .get()
            .checked_add(1)
            .ok_or(ClassCallbackError::InsufficientResources)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(source_bytes.len())
            .map_err(|_| ClassCallbackError::InsufficientResources)?;
        bytes.extend_from_slice(source_bytes);
        self.outstanding.set(next);
        Ok(RetainedClassCallback {
            endpoint: self,
            identity: ClassCallbackIdentity {
                binding: self.binding,
                source,
                input_start: start,
                input_end: end,
            },
            bytes,
            offered: offered as u32,
            phase: Phase::Prepared,
        })
    }

    /// Only a disconnected endpoint with every callback acknowledged can release references.
    pub fn disconnect<P>(&mut self, io: &mut IoManager<P>) -> Result<(), ClassCallbackError> {
        if self.outstanding.get() != 0 {
            return Err(ClassCallbackError::Outstanding);
        }
        if self.class_released && self.port_released {
            return Err(ClassCallbackError::InvalidTransition);
        }
        if !self.port_released {
            self.port
                .release(io)
                .map_err(|_| ClassCallbackError::WrongIdentity)?;
            self.port_released = true;
        }
        if !self.class_released {
            self.class
                .release(io)
                .map_err(|_| ClassCallbackError::WrongIdentity)?;
            self.class_released = true;
        }
        Ok(())
    }
}

/// Owns a copy of the input range and a fail-closed slot in its endpoint.
#[must_use = "retain through terminal acknowledgement; uncertainty forbids replay and disconnect"]
#[derive(Debug)]
pub struct RetainedClassCallback<'a> {
    endpoint: &'a ClassServiceEndpoint,
    identity: ClassCallbackIdentity,
    bytes: Vec<u8>,
    offered: u32,
    phase: Phase,
}

impl RetainedClassCallback<'_> {
    pub const fn identity(&self) -> ClassCallbackIdentity {
        self.identity
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn offered(&self) -> u32 {
        self.offered
    }

    fn verify<P>(
        &self,
        io: &IoManager<P>,
        observed: ClassCallbackIdentity,
    ) -> Result<(), ClassCallbackError> {
        if observed != self.identity {
            return Err(ClassCallbackError::WrongIdentity);
        }
        self.endpoint.validate(io)
    }

    /// Reserve the callback before entering native code. No later transition returns here.
    pub fn enter<P>(
        &mut self,
        io: &IoManager<P>,
        observed: ClassCallbackIdentity,
    ) -> Result<(), ClassCallbackError> {
        self.verify(io, observed)?;
        if self.phase != Phase::Prepared {
            return Err(ClassCallbackError::InvalidTransition);
        }
        self.phase = Phase::Entered;
        Ok(())
    }

    pub fn complete<P>(
        &mut self,
        io: &IoManager<P>,
        observed: ClassCallbackIdentity,
        consumed: u32,
    ) -> Result<(), ClassCallbackError> {
        self.verify(io, observed)?;
        if self.phase != Phase::Entered {
            return Err(ClassCallbackError::InvalidTransition);
        }
        if consumed > self.offered {
            self.phase = Phase::Indeterminate;
            return Err(ClassCallbackError::ConsumedBeyondOffered);
        }
        self.phase = Phase::Completed(consumed);
        Ok(())
    }

    pub fn mark_indeterminate<P>(
        &mut self,
        io: &IoManager<P>,
        observed: ClassCallbackIdentity,
    ) -> Result<(), ClassCallbackError> {
        self.verify(io, observed)?;
        if self.phase != Phase::Entered {
            return Err(ClassCallbackError::InvalidTransition);
        }
        self.phase = Phase::Indeterminate;
        Ok(())
    }

    /// Provider completion alone is insufficient: the caller must publish its terminal result.
    pub fn acknowledge<P>(
        &mut self,
        io: &IoManager<P>,
        observed: ClassCallbackIdentity,
        acknowledgement: CompletionAcknowledgement,
    ) -> Result<u32, ClassCallbackError> {
        self.verify(io, observed)?;
        let Phase::Completed(consumed) = self.phase else {
            return Err(ClassCallbackError::InvalidTransition);
        };
        if acknowledgement != CompletionAcknowledgement::Acknowledged {
            self.phase = Phase::Indeterminate;
            return Err(ClassCallbackError::InvalidTransition);
        }
        self.phase = Phase::Acknowledged(consumed);
        Ok(consumed)
    }

    /// Native may release its source pool lease only after this transition.
    pub fn retire_after_ack(&mut self) -> Result<u32, ClassCallbackError> {
        let Phase::Acknowledged(consumed) = self.phase else {
            return Err(ClassCallbackError::InvalidTransition);
        };
        self.phase = Phase::Retired;
        self.endpoint
            .outstanding
            .set(self.endpoint.outstanding.get() - 1);
        Ok(consumed)
    }
}

#[cfg(test)]
#[path = "class_service_callback_tests.rs"]
mod tests;
