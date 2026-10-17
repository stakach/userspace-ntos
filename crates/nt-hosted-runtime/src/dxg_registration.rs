//! Checked ABI and lifetime identity for hosted display-miniport registration.
//!
//! The prefix sizes come from LiberNT revision
//! `8e478a22a1e8f8a22bab17131f3184a7b4548c3d`,
//! `drivers/directx/dxgkrnl/adapter.c::DxgkpFullInitDataPrefixSize`.
//! Unknown selectors are rejected because a nearby selector is not evidence of
//! a compatible callback-table tail.

use crate::HostedProviderObjectOwner;

const VERSION_OFFSET: usize = 0;
const FIRST_CALLBACK_OFFSET: usize = 8;
const CALLBACK_POINTER_SIZE: usize = 8;
const WDDM_20_FULL_PREFIX: usize = 0x340;
const WDDM_32_FULL_PREFIX: usize = 0x608;
// Pinned sdk/include/ddk/dispmprt.h marks each of these PVOID cells
// "reserved, set to zero". They are not callable DDI entries.
const RESERVED_OFFSETS: [usize; 11] = [
    0x1f0, 0x1f8, 0x200, 0x208, 0x210, 0x218, 0x228, 0x318, 0x320, 0x4c0, 0x558,
];

fn is_reserved(offset: usize) -> bool {
    RESERVED_OFFSETS.contains(&offset)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DxgInitializationDataError {
    Truncated,
    UnknownVersion,
    NonZeroReserved,
}

/// The readable x64 callback-table prefix selected by the caller's DDI version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgInitializationData<'a> {
    bytes: &'a [u8],
    version: u32,
    prefix_len: usize,
}

impl<'a> DxgInitializationData<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DxgInitializationDataError> {
        let version_bytes = bytes
            .get(VERSION_OFFSET..VERSION_OFFSET + 4)
            .ok_or(DxgInitializationDataError::Truncated)?;
        let version = u32::from_le_bytes(version_bytes.try_into().unwrap());
        let prefix_len = match version {
            // Both selectors are listed by pinned LiberNT's displib.c and
            // classify as WDDM 2.0 in its caps_core interface contract.
            0x5022 | 0x5023 => WDDM_20_FULL_PREFIX,
            // Released BasicDisplay.sys sets this exact pinned LiberNT
            // WDDM 3.2 selector and initializes a 0x608-byte table.
            0x11007 => WDDM_32_FULL_PREFIX,
            _ => return Err(DxgInitializationDataError::UnknownVersion),
        };
        if bytes.len() < prefix_len {
            return Err(DxgInitializationDataError::Truncated);
        }
        for offset in RESERVED_OFFSETS {
            if offset >= prefix_len {
                continue;
            }
            if bytes[offset..offset + CALLBACK_POINTER_SIZE]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(DxgInitializationDataError::NonZeroReserved);
            }
        }
        Ok(Self {
            bytes,
            version,
            prefix_len,
        })
    }

    pub const fn version(&self) -> u32 {
        self.version
    }

    pub const fn prefix_len(&self) -> usize {
        self.prefix_len
    }

    pub const fn first_callback_offset(&self) -> usize {
        FIRST_CALLBACK_OFFSET
    }

    pub const fn callback_slot_count(&self) -> usize {
        let reserved = if self.prefix_len == WDDM_20_FULL_PREFIX {
            9
        } else {
            RESERVED_OFFSETS.len()
        };
        (self.prefix_len - FIRST_CALLBACK_OFFSET) / CALLBACK_POINTER_SIZE - reserved
    }

    /// Returns the pointer value, including zero, for one aligned slot in the
    /// versioned prefix. Padding and unknown tails have no callback authority.
    pub fn callback_at(&self, offset: usize) -> Option<u64> {
        if offset < FIRST_CALLBACK_OFFSET
            || offset % CALLBACK_POINTER_SIZE != 0
            || offset >= self.prefix_len
            || is_reserved(offset)
        {
            return None;
        }
        let end = offset.checked_add(CALLBACK_POINTER_SIZE)?;
        let value: [u8; CALLBACK_POINTER_SIZE] = self.bytes.get(offset..end)?.try_into().ok()?;
        Some(u64::from_le_bytes(value))
    }

    pub fn callbacks(&self) -> DxgCallbackSlots<'_, 'a> {
        DxgCallbackSlots {
            data: self,
            next_offset: FIRST_CALLBACK_OFFSET,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgCallbackSlot {
    pub offset: usize,
    pub target: u64,
}

pub struct DxgCallbackSlots<'data, 'bytes> {
    data: &'data DxgInitializationData<'bytes>,
    next_offset: usize,
}

impl Iterator for DxgCallbackSlots<'_, '_> {
    type Item = DxgCallbackSlot;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_offset < self.data.prefix_len {
            let offset = self.next_offset;
            self.next_offset += CALLBACK_POINTER_SIZE;
            let Some(target) = self.data.callback_at(offset) else {
                continue;
            };
            if target != 0 {
                return Some(DxgCallbackSlot { offset, target });
            }
        }
        None
    }
}

/// Exact authority for a provider's registration of one dependent DRIVER_OBJECT.
/// The numeric object address alone may be reused after driver retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgRegistrationKey {
    owner: HostedProviderObjectOwner,
    provider_publication_cookie: u64,
    dependent_driver_object: u64,
    dependent_driver_generation: u64,
}

impl DxgRegistrationKey {
    pub const fn new(
        owner: HostedProviderObjectOwner,
        provider_publication_cookie: u64,
        dependent_driver_object: u64,
        dependent_driver_generation: u64,
    ) -> Option<Self> {
        if owner.provider_domain_id == 0
            || owner.provider_domain_cookie == 0
            || owner.dependent_domain_id == 0
            || owner.dependent_domain_cookie == 0
            || provider_publication_cookie == 0
            || dependent_driver_object == 0
            || dependent_driver_generation == 0
        {
            return None;
        }
        Some(Self {
            owner,
            provider_publication_cookie,
            dependent_driver_object,
            dependent_driver_generation,
        })
    }

    pub const fn matches(
        self,
        owner: HostedProviderObjectOwner,
        provider_publication_cookie: u64,
        dependent_driver_object: u64,
        dependent_driver_generation: u64,
    ) -> bool {
        self.owner.pair_matches(
            owner.provider_domain_id,
            owner.provider_domain_cookie,
            owner.dependent_domain_id,
            owner.dependent_domain_cookie,
        ) && self.provider_publication_cookie == provider_publication_cookie
            && self.dependent_driver_object == dependent_driver_object
            && self.dependent_driver_generation == dependent_driver_generation
    }
}
