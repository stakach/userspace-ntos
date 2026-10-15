//! Port-to-class service callback lane. This is separate from provider/NDIS callbacks.
//!
//! ReactOS i8042prt calls ClassService(ClassDeviceObject, InputStart, InputEnd,
//! InputDataConsumed) from its DPC. Keyboard records are 12 bytes and mouse records are 24
//! bytes. The input range is half-open; the output is a four-byte count, often on the port
//! thread stack. The port's pointers cannot be passed into the class address space.
//!
//! This module defines the bounded transport and exact lease witnesses used by the dedicated
//! port thunk and class IRQ dispatch. The provider/NDIS callback gate has different authority
//! and argument marshalling rules.

use alloc::vec::Vec;
use nt_io_manager::{
    class_service_callback::{ClassServiceBinding, ClassServiceThunk},
    retained_connect_forward::{ConnectControl, ConnectStackRange},
    source_irp_auxiliary::SourcePoolAllocationIdentity,
    HostedDevicePointerRegistration, HostedDomainIdentity,
};

const MAX_RECORDS: usize = 1024;
pub(super) const MAX_RECORD_BYTES: usize = 24 * MAX_RECORDS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LaneError {
    WrongGeneration,
    InvalidRange,
    InsufficientResources,
    Busy,
}

/// A separately retained native pool pin, not merely a pool address observation. The eventual
/// adapter must construct it only after the pool free path recognizes this exact generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PortInputPin {
    pub(super) domain: HostedDomainIdentity,
    pub(super) allocation: SourcePoolAllocationIdentity,
}

/// The consumed-count destination is normally a DPC stack local in ReactOS. Both variants need
/// a free/unwind interlock through callback acknowledgement, not just a successful range read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConsumedOutputPin {
    Pool {
        domain: HostedDomainIdentity,
        allocation: SourcePoolAllocationIdentity,
    },
    Stack(ConnectStackRange),
    IrqStack(super::hosted_irq_stack_lease::IrqStackRange),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ClassCallbackRecord {
    pub(super) port_domain: HostedDomainIdentity,
    pub(super) class_domain: HostedDomainIdentity,
    pub(super) port_device: HostedDevicePointerRegistration,
    pub(super) class_device: HostedDevicePointerRegistration,
    pub(super) thunk: ClassServiceThunk,
    pub(super) input_pin: PortInputPin,
    pub(super) input_start: u64,
    pub(super) input_end: u64,
    pub(super) output_pin: ConsumedOutputPin,
    pub(super) output_address: u64,
    pub(super) control: ConnectControl,
}

impl ClassCallbackRecord {
    pub(super) fn validate(self, binding: ClassServiceBinding) -> Result<usize, LaneError> {
        let record_bytes = match self.control {
            ConnectControl::Keyboard => 12,
            ConnectControl::Mouse => 24,
        };
        let bytes = self
            .input_end
            .checked_sub(self.input_start)
            .ok_or(LaneError::InvalidRange)?;
        let allocation = self.input_pin.allocation;
        let input_end = allocation
            .component_address
            .checked_add(allocation.capacity)
            .ok_or(LaneError::InvalidRange)?;
        let count = usize::try_from(bytes / record_bytes).map_err(|_| LaneError::InvalidRange)?;
        if self.port_domain == self.class_domain
            || self.port_domain != self.input_pin.domain
            || self.port_domain != self.port_device.domain()
            || self.class_domain != self.class_device.domain()
            || self.class_device != binding.class
            || self.port_device != binding.port
            || self.thunk != binding.thunk
            || self.control != binding.control
            || allocation.pool_generation == 0
            || allocation.component_address == 0
            || self.input_start < allocation.component_address
            || self.input_end > input_end
            || self.input_start & 3 != 0
            || bytes == 0
            || bytes % record_bytes != 0
            || count > MAX_RECORDS
            || bytes > MAX_RECORD_BYTES as u64
            || !self
                .output_pin
                .contains(self.port_domain, self.output_address, 4)
        {
            return Err(LaneError::WrongGeneration);
        }
        Ok(bytes as usize)
    }
}

impl ConsumedOutputPin {
    fn contains(self, domain: HostedDomainIdentity, address: u64, length: u64) -> bool {
        if address == 0 || address & 3 != 0 {
            return false;
        }
        let (base, bytes) = match self {
            Self::Pool {
                domain: owner,
                allocation,
            } if owner == domain && allocation.pool_generation != 0 => {
                (allocation.component_address, allocation.capacity)
            }
            Self::Stack(stack)
                if stack.domain == domain && stack.thread != 0 && stack.generation != 0 =>
            {
                (stack.base, stack.bytes)
            }
            Self::IrqStack(stack) if stack.contains(domain, address, length) => {
                (stack.base, stack.bytes)
            }
            _ => return false,
        };
        base != 0
            && bytes != 0
            && base.checked_add(bytes).is_some_and(|end| {
                address >= base && address.checked_add(length).is_some_and(|last| last <= end)
            })
    }
}

/// Preallocate this outside IRQ dispatch. A successful copy under the retained port pool lock
/// owns exactly one callback's bytes; the class lane uses its own mapping of `bytes`, never a
/// port pointer. The caller retains both native pins and this slot through terminal ACK.
pub(super) struct ClassCallbackMarshal {
    bytes: Vec<u8>,
    occupied: bool,
}

impl ClassCallbackMarshal {
    pub(super) fn preallocate() -> Result<Self, LaneError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_RECORD_BYTES)
            .map_err(|_| LaneError::InsufficientResources)?;
        bytes.resize(MAX_RECORD_BYTES, 0);
        Ok(Self {
            bytes,
            occupied: false,
        })
    }

    /// `source` must be copied while the exact `record.input_pin` protects the allocation.
    /// A caller must not read from the foreign pointer after dropping its pool lock.
    pub(super) fn capture(
        &mut self,
        record: ClassCallbackRecord,
        binding: ClassServiceBinding,
        source: &[u8],
    ) -> Result<&[u8], LaneError> {
        if self.occupied {
            return Err(LaneError::Busy);
        }
        let length = record.validate(binding)?;
        if source.len() != length {
            return Err(LaneError::InvalidRange);
        }
        self.bytes[..length].copy_from_slice(source);
        self.occupied = true;
        Ok(&self.bytes[..length])
    }

    /// Called only after the pure callback ticket, class dispatch, output copyback, and source
    /// continuation have all reached a terminal acknowledgement.
    pub(super) fn retire_after_ack(&mut self) {
        self.occupied = false;
    }
}

/// Publication receipt for a class callback endpoint. The native thunk owner constructs this
/// only after its exact reverse aliases and class-domain record buffer are live.
#[must_use = "retain the exact port and class generations through callback acknowledgement"]
pub(super) struct ClassCallbackExecutionPermit {
    cookie: u64,
    port_address: u64,
    port_class_alias: HostedDevicePointerRegistration,
}

impl ClassCallbackExecutionPermit {
    pub(super) fn installed(
        cookie: u64,
        port_address: u64,
        port_class_alias: HostedDevicePointerRegistration,
    ) -> Option<Self> {
        (cookie != 0 && port_address != 0 && port_class_alias.address() != 0).then_some(Self {
            cookie,
            port_address,
            port_class_alias,
        })
    }

    pub(super) fn verifies(
        &self,
        cookie: u64,
        port_address: u64,
        port_class_alias: HostedDevicePointerRegistration,
    ) -> bool {
        self.cookie != 0
            && self.cookie == cookie
            && self.port_address == port_address
            && self.port_class_alias == port_class_alias
    }
}
