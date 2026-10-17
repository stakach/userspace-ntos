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
    QueryChildRelations,
    QueryAdapterInfo,
    GetStandardAllocationDriverData,
    CreateAllocation,
    DestroyAllocation,
    CreateDevice,
    DestroyDevice,
    CreateContext,
    DestroyContext,
    GetNodeMetadata,
    CreateProcess,
    DestroyProcess,
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
            0x40 => Some(Self::QueryChildRelations),
            0x88 => Some(Self::QueryAdapterInfo),
            0x90 => Some(Self::CreateDevice),
            0x98 => Some(Self::CreateAllocation),
            0xa0 => Some(Self::DestroyAllocation),
            0xb0 => Some(Self::GetStandardAllocationDriverData),
            0x190 => Some(Self::DestroyDevice),
            0x1d0 => Some(Self::CreateContext),
            0x1d8 => Some(Self::DestroyContext),
            0x298 => Some(Self::GetNodeMetadata),
            0x300 => Some(Self::CreateProcess),
            0x308 => Some(Self::DestroyProcess),
            _ => None,
        }
    }

    pub const fn argument_count(self) -> usize {
        match self {
            Self::AddDevice => 2,
            Self::StartDevice => 5,
            Self::QueryChildRelations => 3,
            Self::GetNodeMetadata => 3,
            Self::QueryAdapterInfo => 2,
            Self::CreateDevice | Self::CreateContext | Self::CreateAllocation
            | Self::DestroyAllocation
            | Self::GetStandardAllocationDriverData => 2,
            Self::DestroyDevice | Self::DestroyContext => 1,
            Self::CreateProcess | Self::DestroyProcess => 2,
            Self::StopDevice | Self::RemoveDevice => 1,
        }
    }
}

/// Pinned LiberNT x64 DXGKARG_CREATEALLOCATION and one DXGK_ALLOCATIONINFO.
/// This is the first shared-primary allocation path; multiple allocations or
/// an existing resource require distinct cookie ownership before admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgCreateAllocationLayout {
    info: u64,
    private: (u64, u32),
    allocation_private: (u64, u32),
    private_offset: u64,
    allocation_private_offset: u64,
    marshal_bytes: u64,
}

impl DxgCreateAllocationLayout {
    const REQUEST_BYTES: u64 = 0x28;
    const INFO_BYTES: u64 = 0x58;
    const PRIVATE_MAX: u32 = 0x1_0000;

    pub fn parse(version: u32, request_address: u64, request: &[u8],
        info: &[u8], marshal_capacity: u64) -> Option<Self>
    {
        if DxgInitializationData::required_prefix_len(version).is_none()
            || request.len() < Self::REQUEST_BYTES as usize
            || info.len() < Self::INFO_BYTES as usize
            || request_address == 0
            || u32::from_le_bytes(request[12..16].try_into().ok()?) != 1
            || u32::from_le_bytes(request[32..36].try_into().ok()?) != 1
            || u64::from_le_bytes(request[24..32].try_into().ok()?) != 0
            || u64::from_le_bytes(info[0x38..0x40].try_into().ok()?) != 0
            || u64::from_le_bytes(info[0x48..0x50].try_into().ok()?) != 0
        { return None; }
        let info_address = u64::from_le_bytes(request[16..24].try_into().ok()?);
        let private = (u64::from_le_bytes(request[..8].try_into().ok()?),
            u32::from_le_bytes(request[8..12].try_into().ok()?));
        let allocation_private = (u64::from_le_bytes(info[..8].try_into().ok()?),
            u32::from_le_bytes(info[8..12].try_into().ok()?));
        if info_address == 0
            || [(private.0, private.1), (allocation_private.0, allocation_private.1)]
                .iter().any(|(address, bytes)| (*address == 0) != (*bytes == 0)
                    || *bytes > Self::PRIVATE_MAX)
        { return None; }
        let regions = [
            (request_address, Self::REQUEST_BYTES),
            (info_address, Self::INFO_BYTES),
            (private.0, private.1 as u64),
            (allocation_private.0, allocation_private.1 as u64),
        ];
        for (index, (address, bytes)) in regions.iter().copied().enumerate() {
            if address.checked_add(bytes).is_none() { return None; }
            for (other, other_bytes) in regions[..index].iter().copied() {
                if !dxg_query_output_regions_disjoint(address, bytes, other, other_bytes) {
                    return None;
                }
            }
        }
        let private_offset = (Self::REQUEST_BYTES + Self::INFO_BYTES + 7) & !7;
        let allocation_private_offset = private_offset
            .checked_add(private.1 as u64)?.checked_add(7)? & !7;
        let marshal_bytes = allocation_private_offset
            .checked_add(allocation_private.1 as u64)?;
        if marshal_bytes > marshal_capacity { return None; }
        Some(Self { info: info_address, private, allocation_private,
            private_offset, allocation_private_offset, marshal_bytes })
    }

    pub const fn request_bytes(self) -> u64 { Self::REQUEST_BYTES }
    pub const fn info_bytes(self) -> u64 { Self::INFO_BYTES }
    pub const fn info_offset(self) -> u64 { Self::REQUEST_BYTES }
    pub const fn info_address(self) -> u64 { self.info }
    pub const fn private_driver_data(self) -> (u64, u32) { self.allocation_private }
    pub const fn allocation_count(self) -> u32 { 1 }
    pub const fn request_private(self) -> (u64, u32) { self.private }
    pub const fn private_offset(self) -> u64 { self.private_offset }
    pub const fn allocation_private_offset(self) -> u64 { self.allocation_private_offset }
    pub const fn marshal_bytes(self) -> u64 { self.marshal_bytes }
}

/// Pinned x64 DXGKARG_DESTROYALLOCATION with one immutable KMD cookie list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgDestroyAllocationLayout {
    list: u64,
    cookie: u64,
}

impl DxgDestroyAllocationLayout {
    pub fn parse(version: u32, request_address: u64,
        request: &[u8], cookie: u64, marshal_capacity: u64) -> Option<Self>
    {
        if DxgInitializationData::required_prefix_len(version).is_none()
            || request.len() < 0x20 || marshal_capacity < 0x28
            || request_address == 0 || cookie == 0
            || u32::from_le_bytes(request[..4].try_into().ok()?) != 1
            || u64::from_le_bytes(request[16..24].try_into().ok()?) != 0
            || u32::from_le_bytes(request[24..28].try_into().ok()?) != 1
        { return None; }
        let list = u64::from_le_bytes(request[8..16].try_into().ok()?);
        if list == 0 || !dxg_query_output_regions_disjoint(
            request_address, 0x20, list, 8) {
            return None;
        }
        Some(Self { list, cookie })
    }

    pub const fn request_bytes(self) -> u64 { 0x20 }
    pub const fn list_bytes(self) -> u64 { 8 }
    pub const fn list_address(self) -> u64 { self.list }
    pub const fn cookie(self) -> u64 { self.cookie }
    pub const fn marshal_bytes(self) -> u64 { 0x28 }
}

/// Pinned x64 WDDM system-context request. A private-data pointer requires
/// its own nested marshal contract and is rejected here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgCreateContextLayout {
    runtime_context: u64,
}

impl DxgCreateContextLayout {
    pub fn parse(version: u32, bytes: &[u8], marshal_capacity: u64) -> Option<Self> {
        if DxgInitializationData::required_prefix_len(version).is_none()
            || bytes.len() < 0x48 || marshal_capacity < 0x48
            || u64::from_le_bytes(bytes[..8].try_into().ok()?) != 0
            || u32::from_le_bytes(bytes[0x0c..0x10].try_into().ok()?) == 0
            || u32::from_le_bytes(bytes[0x10..0x14].try_into().ok()?) != 1
            || bytes[0x14..0x18] != [0; 4]
            || bytes[0x18..0x24] != [0; 12]
        { return None; }
        Some(Self { runtime_context: 0 })
    }

    pub const fn bytes(self) -> u64 { 0x48 }
    pub const fn runtime_context(self) -> u64 { self.runtime_context }

    pub fn copyback(self, output: &mut [u8], returned: &[u8]) -> bool {
        if output.len() < 0x48 || returned.len() < 0x48
            || returned[..8] == [0; 8]
        { return false; }
        output[..8].copy_from_slice(&returned[..8]);
        output[0x24..0x44].copy_from_slice(&returned[0x24..0x44]);
        true
    }
}

/// Pinned LiberNT x64 DXGKARG_CREATEDEVICE for the system-device path.
/// The miniport writes only the first eight-byte `hDevice` output. All other
/// fields are inputs and must retain their original bytes on copyback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgCreateDeviceLayout {
    kmd_process: u64,
}

impl DxgCreateDeviceLayout {
    pub fn parse(version: u32, bytes: &[u8], marshal_capacity: u64) -> Option<Self> {
        if DxgInitializationData::required_prefix_len(version).is_none()
            || bytes.len() < 0x20 || marshal_capacity < 0x20
            || bytes[..8] != [0; 8]
            || u32::from_le_bytes(bytes[8..12].try_into().ok()?) != 1
            || bytes[12..0x18] != [0; 12]
        { return None; }
        Some(Self { kmd_process: u64::from_le_bytes(bytes[0x18..0x20].try_into().ok()?) })
    }

    pub const fn bytes(self) -> u64 { 0x20 }
    pub const fn kmd_process(self) -> u64 { self.kmd_process }

    pub fn copyback_device(self, output: &mut [u8], kmd_device: u64) -> bool {
        if output.len() < 0x20 || kmd_device == 0 { return false; }
        output[..8].copy_from_slice(&kmd_device.to_le_bytes());
        true
    }
}

/// Pinned LiberNT x64 DXGKARG_GETSTANDARDALLOCATIONDRIVERDATA. The first
/// call reports private-data sizes; the second supplies bounded buffers.
/// Only the shared-primary and shadow surfaces used by adapter startup are
/// admitted. All caller buffers must be distinct before separate projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgStandardAllocationLayout {
    kind: u32,
    surface: u64,
    surface_bytes: u64,
    allocation: (u64, u32),
    resource: (u64, u32),
    allocation_offset: u64,
    resource_offset: u64,
    marshal_bytes: u64,
}

impl DxgStandardAllocationLayout {
    const REQUEST_BYTES: u64 = 0x30;
    const PRIVATE_MAX: u32 = 0x1_0000;

    pub fn parse(version: u32, request: &[u8], marshal_capacity: u64) -> Option<Self> {
        if DxgInitializationData::required_prefix_len(version).is_none()
            || request.len() < Self::REQUEST_BYTES as usize
            || request[4..8] != [0; 4]
            || request[0x1c..0x20] != [0; 4]
        { return None; }
        let kind = u32::from_le_bytes(request[..4].try_into().ok()?);
        let surface_bytes = match kind { 1 => 0x18, 2 => 0x10, _ => return None };
        let surface = u64::from_le_bytes(request[8..16].try_into().ok()?);
        let allocation = (
            u64::from_le_bytes(request[0x10..0x18].try_into().ok()?),
            u32::from_le_bytes(request[0x18..0x1c].try_into().ok()?),
        );
        let resource = (
            u64::from_le_bytes(request[0x20..0x28].try_into().ok()?),
            u32::from_le_bytes(request[0x28..0x2c].try_into().ok()?),
        );
        if surface == 0 || surface.checked_add(surface_bytes).is_none()
            || [allocation, resource].iter().any(|(address, bytes)|
                (*address == 0) != (*bytes == 0) || *bytes > Self::PRIVATE_MAX
                    || address.checked_add(*bytes as u64).is_none())
            || !Self::disjoint(surface, surface_bytes, allocation.0, allocation.1 as u64)
            || !Self::disjoint(surface, surface_bytes, resource.0, resource.1 as u64)
            || !Self::disjoint(allocation.0, allocation.1 as u64,
                resource.0, resource.1 as u64)
        { return None; }
        let surface_end = Self::REQUEST_BYTES.checked_add(surface_bytes)?;
        let allocation_offset = surface_end.checked_add(7)? & !7;
        let resource_offset = allocation_offset.checked_add(allocation.1 as u64)?
            .checked_add(7)? & !7;
        let marshal_bytes = resource_offset.checked_add(resource.1 as u64)?;
        if marshal_bytes > marshal_capacity { return None; }
        Some(Self { kind, surface, surface_bytes, allocation, resource,
            allocation_offset, resource_offset, marshal_bytes })
    }

    const fn disjoint(a: u64, a_bytes: u64, b: u64, b_bytes: u64) -> bool {
        if a_bytes == 0 || b_bytes == 0 { return true; }
        let Some(a_end) = a.checked_add(a_bytes) else { return false; };
        let Some(b_end) = b.checked_add(b_bytes) else { return false; };
        a_end <= b || b_end <= a
    }

    pub const fn kind(self) -> u32 { self.kind }
    pub const fn surface_address(self) -> u64 { self.surface }
    pub const fn surface_bytes(self) -> u64 { self.surface_bytes }
    pub const fn allocation_private(self) -> (u64, u32) { self.allocation }
    pub const fn resource_private(self) -> (u64, u32) { self.resource }
    pub const fn request_bytes(self) -> u64 { Self::REQUEST_BYTES }
    pub const fn surface_offset(self) -> u64 { Self::REQUEST_BYTES }
    pub const fn allocation_offset(self) -> u64 { self.allocation_offset }
    pub const fn resource_offset(self) -> u64 { self.resource_offset }
    pub const fn marshal_bytes(self) -> u64 { self.marshal_bytes }

    /// Preserve all pointers and inputs; only the two required-size fields
    /// may flow back to the provider after the miniport returns.
    pub fn copyback_sizes(self, provider: &mut [u8], returned: &[u8]) -> bool {
        if provider.len() < Self::REQUEST_BYTES as usize
            || returned.len() < Self::REQUEST_BYTES as usize
            || provider[..0x18] != returned[..0x18]
            || provider[0x1c..0x28] != returned[0x1c..0x28]
            || provider[0x2c..0x30] != returned[0x2c..0x30]
        { return false; }
        let allocation_size = u32::from_le_bytes(returned[0x18..0x1c].try_into().unwrap());
        let resource_size = u32::from_le_bytes(returned[0x28..0x2c].try_into().unwrap());
        if allocation_size > Self::PRIVATE_MAX || resource_size > Self::PRIVATE_MAX {
            return false;
        }
        provider[0x18..0x1c].copy_from_slice(&returned[0x18..0x1c]);
        provider[0x28..0x2c].copy_from_slice(&returned[0x28..0x2c]);
        true
    }
}

/// LiberNT WDDM 2.0 x64 DXGKARG_GETNODEMETADATA is the 0x4A-byte
/// DXGK_NODEMETADATA record. It contains no nested pointer fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgNodeMetadataLayout {
    ordinal: u32,
    output_address: u64,
}

impl DxgNodeMetadataLayout {
    pub const fn new(version: u32, ordinal: u64,
        output_address: u64, marshal_capacity: u64) -> Option<Self>
    {
        if DxgInitializationData::required_prefix_len(version).is_none()
            || ordinal > u32::MAX as u64 || output_address == 0
            || output_address.checked_add(0x4a).is_none()
            || marshal_capacity < 0x4a
        { return None; }
        Some(Self { ordinal: ordinal as u32, output_address })
    }

    pub const fn node_ordinal(self) -> u32 { self.ordinal }
    pub const fn output_address(self) -> u64 { self.output_address }
    pub const fn bytes(self) -> u64 { 0x4a }

    pub fn initialize_output(self, output: &mut [u8]) -> bool {
        if output.len() < 0x4a { return false; }
        output[..0x4a].fill(0);
        true
    }

    pub fn copyback(self, output: &mut [u8], returned: &[u8]) -> bool {
        if output.len() < 0x4a || returned.len() != 0x4a { return false; }
        output[..0x4a].copy_from_slice(returned);
        true
    }
}

/// `DXGK_CHILD_DESCRIPTOR` is 0x1c bytes in the pinned x64 dispmprt ABI. The provider
/// supplies the exact in/out byte count, including its trailing sentinel descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgChildRelationsLayout { bytes: u64 }

impl DxgChildRelationsLayout {
    pub const fn new(bytes: u64, marshal_capacity: u64) -> Option<Self> {
        if bytes < 0x1c || bytes > u32::MAX as u64 || bytes > marshal_capacity
            || bytes % 0x1c != 0 { return None; }
        Some(Self { bytes })
    }

    pub const fn bytes(self) -> u64 { self.bytes }
}

/// Pinned LiberNT x64 DXGKARG_CREATEPROCESS. WDDM 2.0 has a 0x20-byte
/// prefix; the published 0x11007 table uses the 0x38-byte WDDM 2.4+ form.
/// Nested PASID and process-name buffers need separate authority and are not
/// admitted by this minimal callback projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgCreateProcessLayout {
    bytes: usize,
    dxg_process: u64,
    flags: u32,
}

impl DxgCreateProcessLayout {
    pub fn parse(version: u32, request: &[u8], marshal_capacity: u64) -> Option<Self> {
        let bytes = match version {
            0x5022 | 0x5023 => 0x20,
            0x11007 => 0x38,
            _ => return None,
        };
        if request.len() < bytes || marshal_capacity < bytes as u64 { return None; }
        let dxg_process = u64::from_le_bytes(request[0..8].try_into().ok()?);
        let kmd_process = u64::from_le_bytes(request[8..16].try_into().ok()?);
        let flags = u32::from_le_bytes(request[0x10..0x14].try_into().ok()?);
        let pasid_count = u32::from_le_bytes(request[0x14..0x18].try_into().ok()?);
        let pasid = u64::from_le_bytes(request[0x18..0x20].try_into().ok()?);
        if dxg_process == 0 || kmd_process != 0 || flags & !1 != 0
            || pasid_count != 0 || pasid != 0
        { return None; }
        if bytes == 0x38 && request[0x20..0x38].iter().any(|&byte| byte != 0) {
            return None;
        }
        Some(Self { bytes, dxg_process, flags })
    }

    pub const fn bytes(self) -> usize { self.bytes }
    pub const fn dxg_process(self) -> u64 { self.dxg_process }
    pub const fn flags(self) -> u32 { self.flags }

    /// Only hKmdProcess at +8 is an output of the pinned miniport callback.
    pub fn copyback_kmd_process(self, request: &mut [u8], kmd_process: u64) -> bool {
        if request.len() < self.bytes { return false; }
        request[8..16].copy_from_slice(&kmd_process.to_le_bytes());
        true
    }
}

/// The pinned WDDM 2.0 x64 `DXGKARG_QUERYADAPTERINFO` common prefix. Later fields are
/// versioned and must not be copied without an explicit policy for the observed query type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgQueryAdapterInfoPrefix {
    kind: u32,
    input: (u64, u32),
    output: (u64, u32),
}

impl DxgQueryAdapterInfoPrefix {
    pub fn parse(bytes: &[u8], marshal_capacity: u64) -> Option<Self> {
        if bytes.len() < 0x28 { return None; }
        let kind = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let input = (u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            u32::from_le_bytes(bytes[0x10..0x14].try_into().ok()?));
        let output = (u64::from_le_bytes(bytes[0x18..0x20].try_into().ok()?),
            u32::from_le_bytes(bytes[0x20..0x24].try_into().ok()?));
        if (input.1 != 0 && input.0 == 0) || (output.1 != 0 && output.0 == 0)
            || input.1 as u64 > marshal_capacity
            || output.1 as u64 > marshal_capacity
            || input.0.checked_add(input.1 as u64).is_none()
            || output.0.checked_add(output.1 as u64).is_none() {
            return None;
        }
        Some(Self { kind, input, output })
    }

    pub const fn kind(self) -> u32 { self.kind }
    pub const fn input(self) -> (u64, u32) { self.input }
    pub const fn output(self) -> (u64, u32) { self.output }
}

/// Three segment queries implemented by the pinned BasicDisplay miniport. The
/// output header owns a second pointer to an array supplied by DxgKrnl. The
/// published WDDM x64 layouts put count at +0 and array pointer at +8; type 11
/// additionally supplies the descriptor stride at +0x20.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgSegmentQueryLayout {
    descriptors: (u64, u64),
    stride: u64,
}

/// The pinned BasicDisplay Type 1 branch writes the first 0x250 bytes of
/// DXGK_DRIVERCAPS. DxgKrnl may supply a larger versioned output allocation;
/// its full requested extent is retained and copied back without fabrication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgDriverCapsLayout { output_bytes: u64 }

impl DxgDriverCapsLayout {
    pub const fn parse(prefix: DxgQueryAdapterInfoPrefix,
        marshal_capacity: u64) -> Option<Self>
    {
        if prefix.kind != 1 || prefix.input.0 != 0 || prefix.input.1 != 0
            || prefix.output.1 < 0x250
            || prefix.output.1 as u64 > marshal_capacity
        { return None; }
        Some(Self { output_bytes: prefix.output.1 as u64 })
    }

    pub const fn output_bytes(self) -> u64 { self.output_bytes }
}

/// Only segment-query outputs use the +8 field as an array pointer. Type 1
/// DriverCaps stores ordinary capability data at that offset.
pub const fn dxg_query_restores_nested_pointer(kind: u32) -> bool {
    matches!(kind, 2 | 5 | 11)
}

/// Separate marshal regions cannot preserve aliasing between the fixed output
/// header and its nested descriptor array. Reject such caller buffers before
/// entering the miniport.
pub const fn dxg_query_output_regions_disjoint(
    output: u64, output_bytes: u64, nested: u64, nested_bytes: u64,
) -> bool {
    let Some(output_end) = output.checked_add(output_bytes) else { return false; };
    if nested_bytes == 0 { return true; }
    let Some(nested_end) = nested.checked_add(nested_bytes) else { return false; };
    output_end <= nested || nested_end <= output
}

impl DxgSegmentQueryLayout {
    pub fn parse(prefix: DxgQueryAdapterInfoPrefix, output: &[u8],
        marshal_capacity: u64) -> Option<Self>
    {
        let (input_min, output_min, descriptor_min) = match prefix.kind {
            2 => (0x18, 0x20, 0x38),
            5 => (0x18, 0x20, 0x48),
            11 => (4, 0x28, 0x60),
            _ => return None,
        };
        if prefix.input.1 < input_min || prefix.output.1 < output_min
            || output.len() < prefix.output.1 as usize
            || prefix.output.1 as u64 > marshal_capacity
        { return None; }
        let count = u32::from_le_bytes(output[0..4].try_into().ok()?) as u64;
        let address = u64::from_le_bytes(output[8..16].try_into().ok()?);
        let stride = if prefix.kind == 11 {
            u64::from_le_bytes(output[0x20..0x28].try_into().ok()?)
        } else { descriptor_min };
        // The released miniport emits one or two segments. Count is only an
        // array capacity supplied by the caller, not authority to map memory.
        if address == 0 { return Some(Self { descriptors: (0, 0), stride }); }
        if count == 0 || count > 2 || stride < descriptor_min
            || stride > marshal_capacity || address % 8 != 0
        { return None; }
        let bytes = count.checked_mul(stride)?;
        if bytes > marshal_capacity || address.checked_add(bytes).is_none() {
            return None;
        }
        Some(Self { descriptors: (address, bytes), stride })
    }

    pub const fn descriptors(self) -> (u64, u64) { self.descriptors }
    pub const fn stride(self) -> u64 { self.stride }
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

/// One real miniport process cookie returned across the Dxg provider boundary.
/// Address reuse is safe only when both process allocations and the started
/// adapter context still match their publication generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgProcessAliasKey {
    adapter: DxgPdoAliasAuthority,
    adapter_context: u64,
    adapter_generation: u64,
    dxg_process: u64,
    dxg_generation: u64,
    kmd_process: u64,
    kmd_generation: u64,
}

/// A device cookie belongs to one started adapter and one exact KMD process
/// allocation. The zero process/generation pair is the system-device case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgDeviceAliasKey {
    adapter: DxgPdoAliasAuthority,
    adapter_context: u64,
    adapter_generation: u64,
    kmd_process: u64,
    process_generation: u64,
    kmd_device: u64,
    device_generation: u64,
}

/// A real miniport allocation cookie belongs to one started adapter context
/// and one exact dependent pool allocation generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgAllocationAliasKey {
    adapter: DxgPdoAliasAuthority,
    adapter_context: u64,
    adapter_generation: u64,
    kmd_allocation: u64,
    allocation_generation: u64,
}

impl DxgAllocationAliasKey {
    pub const fn new(adapter: DxgPdoAliasAuthority,
        adapter_context: u64, adapter_generation: u64,
        kmd_allocation: u64, allocation_generation: u64) -> Option<Self>
    {
        if adapter_context == 0 || adapter_generation == 0
            || kmd_allocation == 0 || allocation_generation == 0
        { return None; }
        Some(Self { adapter, adapter_context, adapter_generation,
            kmd_allocation, allocation_generation })
    }

    pub fn matches_destroy(self, adapter: DxgPdoAliasAuthority,
        kmd_allocation: u64, allocation_generation: u64) -> bool
    {
        self.adapter == adapter && self.kmd_allocation == kmd_allocation
            && self.allocation_generation == allocation_generation
    }

    pub const fn cookie_address_conflicts(self, other: Self) -> bool {
        self.kmd_allocation == other.kmd_allocation
    }
}

impl DxgDeviceAliasKey {
    pub const fn new(adapter: DxgPdoAliasAuthority,
        adapter_context: u64, adapter_generation: u64,
        kmd_process: u64, process_generation: u64,
        kmd_device: u64, device_generation: u64) -> Option<Self>
    {
        if adapter_context == 0 || adapter_generation == 0
            || (kmd_process == 0) != (process_generation == 0)
            || kmd_device == 0 || device_generation == 0
        { return None; }
        Some(Self { adapter, adapter_context, adapter_generation,
            kmd_process, process_generation, kmd_device, device_generation })
    }

    pub fn matches_destroy(self, adapter: DxgPdoAliasAuthority,
        kmd_device: u64, device_generation: u64) -> bool
    {
        self.adapter == adapter && self.kmd_device == kmd_device
            && self.device_generation == device_generation
    }

    pub const fn kmd_process(self) -> u64 { self.kmd_process }
    pub const fn process_generation(self) -> u64 { self.process_generation }
    pub const fn cookie_address_conflicts(self, other: Self) -> bool {
        self.kmd_device == other.kmd_device
    }
}

/// One miniport context cookie belongs to an exact device allocation and,
/// when present, an exact runtime context allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgContextAliasKey {
    device: DxgDeviceAliasKey,
    runtime_context: u64,
    runtime_generation: u64,
    kmd_context: u64,
    context_generation: u64,
}

impl DxgContextAliasKey {
    pub const fn new(device: DxgDeviceAliasKey,
        runtime_context: u64, runtime_generation: u64,
        kmd_context: u64, context_generation: u64) -> Option<Self>
    {
        if (runtime_context == 0) != (runtime_generation == 0)
            || kmd_context == 0 || context_generation == 0
        { return None; }
        Some(Self { device, runtime_context, runtime_generation,
            kmd_context, context_generation })
    }

    pub fn matches_destroy(self, device: DxgDeviceAliasKey,
        kmd_context: u64, context_generation: u64) -> bool
    {
        self.device == device && self.kmd_context == kmd_context
            && self.context_generation == context_generation
    }

    pub const fn cookie_address_conflicts(self, other: Self) -> bool {
        self.kmd_context == other.kmd_context
    }
}

impl DxgProcessAliasKey {
    pub const fn new(adapter: DxgPdoAliasAuthority,
        adapter_context: u64, adapter_generation: u64,
        dxg_process: u64, dxg_generation: u64,
        kmd_process: u64, kmd_generation: u64) -> Option<Self>
    {
        if adapter_context == 0 || adapter_generation == 0
            || dxg_process == 0 || dxg_generation == 0
            || (kmd_process == 0) != (kmd_generation == 0)
        { return None; }
        Some(Self { adapter, adapter_context, adapter_generation,
            dxg_process, dxg_generation, kmd_process, kmd_generation })
    }

    pub fn matches_destroy(self, adapter: DxgPdoAliasAuthority,
        adapter_context: u64, adapter_generation: u64,
        kmd_process: u64, kmd_generation: u64) -> bool
    {
        self.adapter == adapter && self.adapter_context == adapter_context
            && self.adapter_generation == adapter_generation
            && self.kmd_process == kmd_process
            && self.kmd_generation == kmd_generation
    }

    pub const fn dxg_process(self) -> u64 { self.dxg_process }
    pub const fn dxg_generation(self) -> u64 { self.dxg_generation }
    pub const fn kmd_process(self) -> u64 { self.kmd_process }
    pub const fn cookie_address_conflicts(self, other: Self) -> bool {
        self.kmd_process != 0 && self.kmd_process == other.kmd_process
    }
}

/// The physical dependent callback route which may request the process
/// cookie's terminal free. Native code additionally compares the whole live
/// PeerRoute and current Reply before projecting this identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgProcessFreeRoute {
    domain_id: u64,
    domain_cookie: u64,
    endpoint: u64,
    badge: u64,
    domain_generation: u64,
    tcb: u64,
}

impl DxgProcessFreeRoute {
    pub const fn new(domain_id: u64, domain_cookie: u64, endpoint: u64,
        badge: u64, domain_generation: u64, tcb: u64) -> Option<Self>
    {
        if domain_id == 0 || domain_cookie == 0 || endpoint == 0
            || badge == 0 || domain_generation == 0 || tcb == 0
        { return None; }
        Some(Self { domain_id, domain_cookie, endpoint, badge,
            domain_generation, tcb })
    }
}

/// A miniport can free its cookie inside DestroyProcess. Root records that
/// request but completes the physical pool free only after the callback and
/// its Reply have both completed, retaining the allocation pin meanwhile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgProcessCookieRetirement {
    key: DxgProcessAliasKey,
    route: DxgProcessFreeRoute,
    free_requested: bool,
    callback_interval_open: bool,
    completed: bool,
}

impl DxgProcessCookieRetirement {
    pub const fn new(key: DxgProcessAliasKey, route: DxgProcessFreeRoute) -> Option<Self> {
        if key.kmd_process == 0 { return None; }
        Some(Self { key, route, free_requested: false,
            callback_interval_open: true, completed: false })
    }

    pub fn request_free(&mut self, key: DxgProcessAliasKey, route: DxgProcessFreeRoute,
        address: u64, generation: u64) -> bool
    {
        if self.free_requested || !self.callback_interval_open || self.completed
            || self.key != key || self.route != route
            || address != self.key.kmd_process || generation != self.key.kmd_generation
        { return false; }
        self.free_requested = true;
        true
    }

    pub const fn free_requested(self) -> bool { self.free_requested }

    pub fn close_callback_interval(&mut self) {
        self.callback_interval_open = false;
    }

    pub fn complete(&mut self, callback_completed: bool, reply_acknowledged: bool) -> bool {
        if !self.free_requested || self.callback_interval_open || self.completed
            || !callback_completed || !reply_acknowledged {
            return false;
        }
        self.completed = true;
        true
    }

    /// The miniport retained its own allocation and issued no in-callback
    /// free. Its completed Destroy ends root's temporary pin authority.
    pub fn release_without_free(&mut self,
        callback_completed: bool, reply_acknowledged: bool) -> bool
    {
        if self.free_requested || self.callback_interval_open || self.completed
            || !callback_completed || !reply_acknowledged
        { return false; }
        self.completed = true;
        true
    }
}

/// A DestroyDevice free is escrowed under the exact device-cookie generation
/// and dependent callback route until its callback and Reply both finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgDeviceCookieRetirement {
    key: DxgDeviceAliasKey,
    route: DxgProcessFreeRoute,
    free_requested: bool,
    callback_interval_open: bool,
    completed: bool,
}

impl DxgDeviceCookieRetirement {
    pub const fn new(key: DxgDeviceAliasKey, route: DxgProcessFreeRoute) -> Option<Self> {
        Some(Self { key, route, free_requested: false,
            callback_interval_open: true, completed: false })
    }

    pub fn request_free(&mut self, key: DxgDeviceAliasKey, route: DxgProcessFreeRoute,
        address: u64, generation: u64) -> bool
    {
        if self.free_requested || !self.callback_interval_open || self.completed
            || self.key != key || self.route != route
            || address != self.key.kmd_device || generation != self.key.device_generation
        { return false; }
        self.free_requested = true;
        true
    }

    pub const fn free_requested(self) -> bool { self.free_requested }
    pub fn close_callback_interval(&mut self) { self.callback_interval_open = false; }

    pub fn complete(&mut self, callback_completed: bool, reply_acknowledged: bool) -> bool {
        if !self.free_requested || self.callback_interval_open || self.completed
            || !callback_completed || !reply_acknowledged
        { return false; }
        self.completed = true;
        true
    }

    pub fn release_without_free(&mut self,
        callback_completed: bool, reply_acknowledged: bool) -> bool
    {
        if self.free_requested || self.callback_interval_open || self.completed
            || !callback_completed || !reply_acknowledged
        { return false; }
        self.completed = true;
        true
    }
}

/// A DestroyAllocation free is escrowed under its exact callback route until
/// the miniport's callback and retained Reply both finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgAllocationCookieRetirement {
    key: DxgAllocationAliasKey,
    route: DxgProcessFreeRoute,
    free_requested: bool,
    callback_interval_open: bool,
    completed: bool,
}

/// Terminal callback evidence determines whether a provisional allocation
/// owner can be released, retried, published, or permanently fenced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DxgAllocationCallbackDisposition {
    ReleaseProvisional,
    RetryWithCookie,
    Publish,
    RetireCookie,
    Retain,
}

impl DxgAllocationCallbackDisposition {
    pub const fn create(terminal_ack: bool, status: i32, returned_cookie: u64) -> Self {
        if !terminal_ack { return Self::Retain; }
        if status < 0 {
            if returned_cookie == 0 { Self::ReleaseProvisional } else { Self::Retain }
        } else if returned_cookie != 0 {
            Self::Publish
        } else {
            Self::Retain
        }
    }

    pub const fn destroy(terminal_ack: bool, status: i32, free_requested: bool) -> Self {
        if !terminal_ack { return Self::Retain; }
        if status < 0 {
            if free_requested { Self::Retain } else { Self::RetryWithCookie }
        } else if free_requested {
            Self::RetireCookie
        } else {
            Self::Retain
        }
    }
}

impl DxgAllocationCookieRetirement {
    pub const fn new(key: DxgAllocationAliasKey, route: DxgProcessFreeRoute) -> Option<Self> {
        Some(Self { key, route, free_requested: false,
            callback_interval_open: true, completed: false })
    }

    pub fn request_free(&mut self, key: DxgAllocationAliasKey,
        route: DxgProcessFreeRoute, address: u64, generation: u64) -> bool
    {
        if self.free_requested || !self.callback_interval_open || self.completed
            || self.key != key || self.route != route
            || address != self.key.kmd_allocation
            || generation != self.key.allocation_generation
        { return false; }
        self.free_requested = true;
        true
    }

    pub const fn free_requested(self) -> bool { self.free_requested }
    pub fn close_callback_interval(&mut self) { self.callback_interval_open = false; }

    pub fn complete(&mut self, callback_completed: bool, reply_acknowledged: bool) -> bool {
        if !self.free_requested || self.callback_interval_open || self.completed
            || !callback_completed || !reply_acknowledged
        { return false; }
        self.completed = true;
        true
    }

    pub fn release_without_free(&mut self,
        callback_completed: bool, reply_acknowledged: bool) -> bool
    {
        if self.free_requested || self.callback_interval_open || self.completed
            || !callback_completed || !reply_acknowledged
        { return false; }
        self.completed = true;
        true
    }
}

/// A DestroyContext free remains pinned until the exact callback and Reply
/// complete. No other worker can retire the cookie during that interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgContextCookieRetirement {
    key: DxgContextAliasKey,
    route: DxgProcessFreeRoute,
    free_requested: bool,
    callback_interval_open: bool,
    completed: bool,
}

impl DxgContextCookieRetirement {
    pub const fn new(key: DxgContextAliasKey, route: DxgProcessFreeRoute) -> Option<Self> {
        Some(Self { key, route, free_requested: false,
            callback_interval_open: true, completed: false })
    }

    pub fn request_free(&mut self, key: DxgContextAliasKey, route: DxgProcessFreeRoute,
        address: u64, generation: u64) -> bool
    {
        if self.free_requested || !self.callback_interval_open || self.completed
            || self.key != key || self.route != route
            || address != self.key.kmd_context || generation != self.key.context_generation
        { return false; }
        self.free_requested = true;
        true
    }

    pub const fn free_requested(self) -> bool { self.free_requested }
    pub fn close_callback_interval(&mut self) { self.callback_interval_open = false; }

    pub fn complete(&mut self, callback_completed: bool, reply_acknowledged: bool) -> bool {
        if !self.free_requested || self.callback_interval_open || self.completed
            || !callback_completed || !reply_acknowledged
        { return false; }
        self.completed = true;
        true
    }

    pub fn release_without_free(&mut self,
        callback_completed: bool, reply_acknowledged: bool) -> bool
    {
        if self.free_requested || self.callback_interval_open || self.completed
            || !callback_completed || !reply_acknowledged
        { return false; }
        self.completed = true;
        true
    }
}

/// Successful NULL process handles have no per-process miniport identity.
/// One Destroy(NULL) consumes one adapter-scoped credit after a real callback
/// completes; a failed or uncertain callback keeps the credit fenced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DxgNullProcessCredits {
    adapter: DxgPdoAliasAuthority,
    context: u64,
    generation: u64,
    count: u64,
    destroy_entered: bool,
}

impl DxgNullProcessCredits {
    pub const fn new(adapter: DxgPdoAliasAuthority,
        context: u64, generation: u64) -> Option<Self>
    {
        if context == 0 || generation == 0 { return None; }
        Some(Self { adapter, context, generation, count: 0,
            destroy_entered: false })
    }

    pub const fn count(self) -> u64 { self.count }

    pub fn record_create(&mut self, adapter: DxgPdoAliasAuthority,
        context: u64, generation: u64,
        callback_completed: bool, reply_acknowledged: bool) -> bool
    {
        if self.adapter != adapter || self.context != context
            || self.generation != generation || self.destroy_entered
            || !callback_completed || !reply_acknowledged
        { return false; }
        let Some(next) = self.count.checked_add(1) else { return false; };
        self.count = next;
        true
    }

    pub fn begin_destroy(&mut self, adapter: DxgPdoAliasAuthority,
        context: u64, generation: u64) -> bool
    {
        if self.adapter != adapter || self.context != context
            || self.generation != generation || self.destroy_entered
            || self.count == 0
        { return false; }
        self.destroy_entered = true;
        true
    }

    pub fn finish_destroy(&mut self,
        callback_succeeded: bool, reply_acknowledged: bool) -> bool
    {
        if !self.destroy_entered || !callback_succeeded || !reply_acknowledged {
            return false;
        }
        self.count -= 1;
        self.destroy_entered = false;
        true
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

/// A started Dxg miniport may use its delegated scanout during the active StartDevice call.
/// `blocked` alone is a reentry guard while that call runs, but after it returns in error it
/// fences an uncertain native effect and must deny new access.
pub const fn dxg_scanout_dependent_admitted(
    callback_entered: bool,
    start_entered: bool,
    start_succeeded: bool,
    start_callback_active: bool,
    blocked: bool,
    pointer_retired: bool,
    interface_handle: u64,
) -> bool {
    callback_entered && start_entered && !pointer_retired && interface_handle != 0
        && (start_callback_active || (start_succeeded && !blocked))
}

/// A blocked registration may expose its dependent's owned RAM only while CreateAllocation is
/// actively executing. Retained callback guards after an uncertain return confer no authority.
#[allow(clippy::too_many_arguments)]
pub const fn dxg_contiguous_dependent_admitted(
    callback_entered: bool, start_entered: bool, start_succeeded: bool,
    stop_entered: bool, blocked: bool, pointer_retired: bool,
    create_callback_active: bool, interface_handle: u64,
) -> bool {
    callback_entered && start_entered && start_succeeded && !stop_entered
        && !pointer_retired && interface_handle != 0
        && (!blocked || create_callback_active)
}

/// A provider worker's channel alone does not grant access to the boot scanout. Its exact
/// publication must also be the provider side of a currently live Dxg miniport registration.
#[allow(clippy::too_many_arguments)]
pub const fn dxg_scanout_provider_admitted(
    worker_instance: usize, worker_domain_id: u64, worker_domain_cookie: u64,
    worker_publication: u64, registered_instance: usize,
    registered_domain_id: u64, registered_domain_cookie: u64,
    registered_publication: u64, registration_live: bool,
) -> bool {
    registration_live && worker_domain_id != 0 && worker_domain_cookie != 0
        && worker_publication != 0 && worker_instance == registered_instance
        && worker_domain_id == registered_domain_id
        && worker_domain_cookie == registered_domain_cookie
        && worker_publication == registered_publication
}

/// StopDevice is an irreversible miniport operation for one live adapter context. Reject
/// retries and uncertain in-flight work before entering the dependent VSpace.
#[allow(clippy::too_many_arguments)]
pub const fn dxg_stop_device_admitted(
    start_entered: bool, start_succeeded: bool, start_callback_active: bool,
    blocked: bool, pointer_retired: bool, stop_entered: bool,
    retained_context: u64, supplied_context: u64,
) -> bool {
    start_entered && start_succeeded && !start_callback_active && !blocked
        && !pointer_retired && !stop_entered && retained_context != 0
        && retained_context == supplied_context
}
