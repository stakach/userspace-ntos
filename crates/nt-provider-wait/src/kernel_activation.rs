//! Root-to-provider activation metadata, not proof of authority. The root must still validate
//! requests against its retained caller, live physical dispatch, and authenticated channel.

use crate::{LaneHandle, ProviderDomainIdentity, ProviderWaitOwner, SuspensionCaller};

pub const KERNEL_PROVIDER_ACTIVATION_MAGIC: u32 = 0x4b50_4143;
pub const KERNEL_PROVIDER_ACTIVATION_VERSION: u16 = 1;
pub const KERNEL_PROVIDER_ACTIVATION_BYTES: u16 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProviderActivationError {
    InvalidMagic,
    InvalidVersion,
    InvalidSize,
    ReservedFields,
    InvalidOwner,
    NotKernel,
    ProviderMismatch,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProviderActivationDescriptor {
    pub magic: u32,
    pub version: u16,
    pub size: u16,
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub lane_index: u32,
    pub reserved0: u32,
    pub lane_generation: u64,
    pub dispatch_epoch: u64,
    pub reserved: [u64; 2],
}

const _: () = assert!(
    core::mem::size_of::<KernelProviderActivationDescriptor>()
        == KERNEL_PROVIDER_ACTIVATION_BYTES as usize
);

impl KernelProviderActivationDescriptor {
    pub const EMPTY: Self = Self {
        magic: 0,
        version: 0,
        size: 0,
        provider_domain: 0,
        provider_generation: 0,
        lane_index: 0,
        reserved0: 0,
        lane_generation: 0,
        dispatch_epoch: 0,
        reserved: [0; 2],
    };

    pub fn new(owner: ProviderWaitOwner) -> Result<Self, KernelProviderActivationError> {
        if !owner.is_valid() {
            return Err(KernelProviderActivationError::InvalidOwner);
        }
        let SuspensionCaller::Kernel { lane } = owner.caller else {
            return Err(KernelProviderActivationError::NotKernel);
        };
        Ok(Self {
            magic: KERNEL_PROVIDER_ACTIVATION_MAGIC,
            version: KERNEL_PROVIDER_ACTIVATION_VERSION,
            size: KERNEL_PROVIDER_ACTIVATION_BYTES,
            provider_domain: owner.provider_domain,
            provider_generation: owner.provider_generation,
            lane_index: lane.index,
            reserved0: 0,
            lane_generation: lane.generation,
            dispatch_epoch: owner.dispatch_id,
            reserved: [0; 2],
        })
    }

    pub fn validate(
        self,
        expected_provider: ProviderDomainIdentity,
    ) -> Result<ProviderWaitOwner, KernelProviderActivationError> {
        if self.magic != KERNEL_PROVIDER_ACTIVATION_MAGIC {
            return Err(KernelProviderActivationError::InvalidMagic);
        }
        if self.version != KERNEL_PROVIDER_ACTIVATION_VERSION {
            return Err(KernelProviderActivationError::InvalidVersion);
        }
        if self.size != KERNEL_PROVIDER_ACTIVATION_BYTES {
            return Err(KernelProviderActivationError::InvalidSize);
        }
        if self.reserved0 != 0 || self.reserved != [0; 2] {
            return Err(KernelProviderActivationError::ReservedFields);
        }
        let owner = ProviderWaitOwner {
            provider_domain: self.provider_domain,
            provider_generation: self.provider_generation,
            dispatch_id: self.dispatch_epoch,
            caller: SuspensionCaller::Kernel {
                lane: LaneHandle {
                    index: self.lane_index,
                    generation: self.lane_generation,
                },
            },
        };
        if !expected_provider.is_valid() || !owner.is_valid() {
            return Err(KernelProviderActivationError::InvalidOwner);
        }
        if self.provider_domain != expected_provider.domain
            || self.provider_generation != expected_provider.generation
        {
            return Err(KernelProviderActivationError::ProviderMismatch);
        }
        Ok(owner)
    }
}
