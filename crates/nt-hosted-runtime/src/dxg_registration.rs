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
const WDDM_32_START_INTERFACE_SIZE: usize = 0x240;
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
    pub const fn required_prefix_len(version: u32) -> Option<usize> {
        match version {
            0x5022 | 0x5023 => Some(WDDM_20_FULL_PREFIX),
            0x11007 => Some(WDDM_32_FULL_PREFIX),
            _ => None,
        }
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Self, DxgInitializationDataError> {
        let version_bytes = bytes
            .get(VERSION_OFFSET..VERSION_OFFSET + 4)
            .ok_or(DxgInitializationDataError::Truncated)?;
        let version = u32::from_le_bytes(version_bytes.try_into().unwrap());
        let prefix_len = Self::required_prefix_len(version)
            .ok_or(DxgInitializationDataError::UnknownVersion)?;
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

/// The x64 DXGKRNL_INTERFACE published by pinned LiberNT for a 0x11007
/// miniport. The provider retains this table after DxgkDdiStartDevice, so
/// native callers must replace every cross-domain function pointer they expose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgStartInterface<'a> {
    bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DxgStartInterfaceError {
    Truncated,
    UnknownVersion,
    BadSize,
    MissingRequired,
}

impl<'a> DxgStartInterface<'a> {
    pub const fn required_size(version: u32) -> Option<usize> {
        match version {
            0x11007 => Some(WDDM_32_START_INTERFACE_SIZE),
            _ => None,
        }
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Self, DxgStartInterfaceError> {
        let header = bytes.get(..16).ok_or(DxgStartInterfaceError::Truncated)?;
        let size = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let required = Self::required_size(version)
            .ok_or(DxgStartInterfaceError::UnknownVersion)?;
        if size != required {
            return Err(DxgStartInterfaceError::BadSize);
        }
        if bytes.len() < required {
            return Err(DxgStartInterfaceError::Truncated);
        }
        let data = Self { bytes: &bytes[..required] };
        if data.device_handle() == 0
            || [0x80, 0x88, 0xd8].iter().any(|offset| {
                data.callback_at(*offset).is_none_or(|target| target == 0)
            })
        {
            return Err(DxgStartInterfaceError::MissingRequired);
        }
        Ok(data)
    }

    pub const fn size(&self) -> usize { WDDM_32_START_INTERFACE_SIZE }
    pub fn version(&self) -> u32 {
        u32::from_le_bytes(self.bytes[4..8].try_into().unwrap())
    }
    pub fn device_handle(&self) -> u64 {
        u64::from_le_bytes(self.bytes[8..16].try_into().unwrap())
    }
    pub fn callback_at(&self, offset: usize) -> Option<u64> {
        if offset < 0x10 || offset % 8 != 0 || offset >= self.size() {
            return None;
        }
        Some(u64::from_le_bytes(self.bytes[offset..offset + 8].try_into().ok()?))
    }
    pub fn callbacks(&self) -> DxgStartInterfaceCallbacks<'_, 'a> {
        DxgStartInterfaceCallbacks { interface: self, next_offset: 0x10 }
    }
}

pub struct DxgStartInterfaceCallbacks<'data, 'bytes> {
    interface: &'data DxgStartInterface<'bytes>,
    next_offset: usize,
}

impl Iterator for DxgStartInterfaceCallbacks<'_, '_> {
    type Item = DxgCallbackSlot;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_offset < self.interface.size() {
            let offset = self.next_offset;
            self.next_offset += 8;
            let target = self.interface.callback_at(offset)?;
            if target != 0 { return Some(DxgCallbackSlot { offset, target }); }
        }
        None
    }
}

/// The lifecycle DDI prefix shared by DRIVER_INITIALIZATION_DATA and
/// KMDDOD_INITIALIZATION_DATA in pinned LiberNT adapter.c. Every other slot
/// needs its own marshal policy before it can cross a VSpace boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DxgDdiSignature {
    AddDevice,
    StartDevice,
    StopDevice,
    RemoveDevice,
}

impl DxgDdiSignature {
    pub const fn for_offset(version: u32, offset: usize) -> Option<Self> {
        if DxgInitializationData::required_prefix_len(version).is_none() {
            return None;
        }
        match offset {
            0x8 => Some(Self::AddDevice),
            0x10 => Some(Self::StartDevice),
            0x18 => Some(Self::StopDevice),
            0x20 => Some(Self::RemoveDevice),
            _ => None,
        }
    }

    pub const fn argument_count(self) -> usize {
        match self {
            Self::AddDevice => 2,
            Self::StartDevice => 5,
            Self::StopDevice | Self::RemoveDevice => 1,
        }
    }
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

/// Exact cross-domain alias for the PDO passed to DxgkDdiAddDevice. Both
/// native addresses can be recycled, so each observed registration generation
/// is part of the authority alongside the provider publication and device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgPdoAliasAuthority {
    owner: HostedProviderObjectOwner,
    provider_publication_cookie: u64,
    canonical_device_id: u64,
    provider_pdo_address: u64,
    provider_pdo_generation: u64,
    dependent_alias_address: u64,
    dependent_alias_generation: u64,
}

impl DxgPdoAliasAuthority {
    pub const fn new(
        owner: HostedProviderObjectOwner,
        provider_publication_cookie: u64,
        canonical_device_id: u64,
        provider_pdo_address: u64,
        provider_pdo_generation: u64,
        dependent_alias_address: u64,
        dependent_alias_generation: u64,
    ) -> Option<Self> {
        if owner.provider_domain_id == 0 || owner.provider_domain_cookie == 0
            || owner.dependent_domain_id == 0 || owner.dependent_domain_cookie == 0
            || provider_publication_cookie == 0 || canonical_device_id == 0
            || provider_pdo_address == 0 || provider_pdo_generation == 0
            || dependent_alias_address == 0 || dependent_alias_generation == 0
        {
            return None;
        }
        Some(Self { owner, provider_publication_cookie, canonical_device_id,
            provider_pdo_address, provider_pdo_generation,
            dependent_alias_address, dependent_alias_generation })
    }

    pub const fn matches(
        self, owner: HostedProviderObjectOwner,
        provider_publication_cookie: u64, canonical_device_id: u64,
        provider_pdo_address: u64, provider_pdo_generation: u64,
        dependent_alias_address: u64, dependent_alias_generation: u64,
    ) -> bool {
        self.owner.pair_matches(owner.provider_domain_id, owner.provider_domain_cookie,
            owner.dependent_domain_id, owner.dependent_domain_cookie)
            && self.provider_publication_cookie == provider_publication_cookie
            && self.canonical_device_id == canonical_device_id
            && self.provider_pdo_address == provider_pdo_address
            && self.provider_pdo_generation == provider_pdo_generation
            && self.dependent_alias_address == dependent_alias_address
            && self.dependent_alias_generation == dependent_alias_generation
    }
}

/// The source DriverObject is published in the component preamble before
/// DriverEntry, while the executive's post-entry snapshot is still zero.
/// Pool generation binds its address against reuse within that domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgSourceDriverObject {
    address: u64,
    pool_generation: u64,
    canonical_driver_id: u64,
}

impl DxgSourceDriverObject {
    pub const fn admit(
        post_entry_snapshot: u64,
        shared_bootstrap_address: u64,
        pool_generation: u64,
        canonical_driver_id: u64,
    ) -> Option<Self> {
        if shared_bootstrap_address == 0 || pool_generation == 0 || canonical_driver_id == 0
            || post_entry_snapshot != 0 && post_entry_snapshot != shared_bootstrap_address
        {
            return None;
        }
        Some(Self {
            address: shared_bootstrap_address,
            pool_generation,
            canonical_driver_id,
        })
    }

    pub const fn address(self) -> u64 { self.address }
    pub const fn generation(self) -> u64 { self.pool_generation }

    pub const fn matches(
        self,
        post_entry_snapshot: u64,
        shared_bootstrap_address: u64,
        pool_generation: u64,
        canonical_driver_id: u64,
    ) -> bool {
        (post_entry_snapshot == 0 || post_entry_snapshot == self.address)
            && shared_bootstrap_address == self.address
            && pool_generation == self.pool_generation
            && canonical_driver_id == self.canonical_driver_id
    }
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

/// Authority retained from the exact resolver IRP until a caller-side thunk
/// replaces its provider-space code pointer. The native adapter must supply
/// an executable PE section, not the enclosing image allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgEntryAuthority {
    registration: DxgRegistrationKey,
    target_device_id: u64,
    target_generation: u64,
    source_request_generation: u64,
    provider_entry_va: u64,
}

impl DxgEntryAuthority {
    pub fn new(
        registration: DxgRegistrationKey,
        target_device_id: u64,
        target_generation: u64,
        source_request_generation: u64,
        provider_entry_va: u64,
        executable_start: u64,
        executable_len: u64,
    ) -> Option<Self> {
        if target_device_id == 0
            || target_generation == 0
            || source_request_generation == 0
            || executable_start == 0
            || executable_len == 0
        {
            return None;
        }
        let executable_end = executable_start.checked_add(executable_len)?;
        if provider_entry_va < executable_start || provider_entry_va >= executable_end {
            return None;
        }
        Some(Self {
            registration,
            target_device_id,
            target_generation,
            source_request_generation,
            provider_entry_va,
        })
    }

    pub fn matches(
        self,
        registration: DxgRegistrationKey,
        target_device_id: u64,
        target_generation: u64,
        source_request_generation: u64,
        provider_entry_va: u64,
    ) -> bool {
        self.registration == registration
            && self.target_device_id == target_device_id
            && self.target_generation == target_generation
            && self.source_request_generation == source_request_generation
            && self.provider_entry_va == provider_entry_va
    }
}
