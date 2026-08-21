//! Pure hosted-process runtime VA layout helpers.
//!
//! The executive owns seL4 caps, page-table installation, and the concrete address map. This crate
//! owns only the checked arithmetic: assigning a process index to a scratch/mirror lane and proving
//! that those lanes do not overlap.

#![no_std]

pub const PAGE_SIZE: u64 = 0x1000;
pub const PAGE_TABLE_SPAN: u64 = 0x20_0000;
pub const HOSTED_PROVIDER_IMPORT_THUNK_LEN: usize = 33;
pub const HOSTED_PROVIDER_CALLBACK_THUNK_LEN: usize = 23;
pub const HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN: u64 = 64;
pub const HOSTED_PROVIDER_EXPORT_ARG_CAP: usize = 12;
pub const NDIS_MINIPORT_CHARACTERISTICS_CALLBACK_CAP: usize = 25;
pub const NDIS_MINIPORT_CHARACTERISTICS_CALLBACK_BASE_X64: u64 = 0x08;
pub const NDIS_MINIPORT_CHARACTERISTICS_CALLBACK_STRIDE_X64: u64 = 0x08;
pub const NDIS30_MINIPORT_CHARACTERISTICS_LEN_X64: u64 = 0x70;
pub const NDIS40_MINIPORT_CHARACTERISTICS_LEN_X64: u64 = 0x88;
pub const NDIS50_MINIPORT_CHARACTERISTICS_LEN_X64: u64 = 0xb8;
pub const NDIS51_MINIPORT_CHARACTERISTICS_LEN_X64: u64 = 0xf0;
pub const NDIS_MINIPORT_INTERRUPT_LEN_X64: u64 = 0x98;
pub const NDIS_MINIPORT_TIMER_LEN_X64: u64 = 0xa0;
pub const NDIS_MINIPORT_BLOCK_MINIPORT_ADAPTER_CONTEXT_OFFSET_X64: u64 = 0x18;
pub const NDIS_MINIPORT_BLOCK_MINIPORT_NAME_OFFSET_X64: u64 = 0x20;
pub const NDIS_MINIPORT_BLOCK_ETH_DB_OFFSET_X64: u64 = 0x190;
pub const NDIS_MINIPORT_BLOCK_PACKET_INDICATE_HANDLER_OFFSET_X64: u64 = 0x1b0;
pub const NDIS_MINIPORT_BLOCK_SEND_COMPLETE_HANDLER_OFFSET_X64: u64 = 0x1b8;
pub const NDIS_MINIPORT_BLOCK_SEND_RESOURCES_HANDLER_OFFSET_X64: u64 = 0x1c0;
pub const NDIS_MINIPORT_BLOCK_RESET_COMPLETE_HANDLER_OFFSET_X64: u64 = 0x1c8;
pub const NDIS_MINIPORT_BLOCK_ETH_RX_INDICATE_HANDLER_OFFSET_X64: u64 = 0x280;
pub const NDIS_MINIPORT_BLOCK_ETH_RX_COMPLETE_HANDLER_OFFSET_X64: u64 = 0x298;
pub const NDIS_MINIPORT_BLOCK_STATUS_HANDLER_OFFSET_X64: u64 = 0x2b0;
pub const NDIS_MINIPORT_BLOCK_STATUS_COMPLETE_HANDLER_OFFSET_X64: u64 = 0x2b8;
pub const NDIS_MINIPORT_BLOCK_TD_COMPLETE_HANDLER_OFFSET_X64: u64 = 0x2c0;
pub const NDIS_MINIPORT_BLOCK_QUERY_COMPLETE_HANDLER_OFFSET_X64: u64 = 0x2c8;
pub const NDIS_MINIPORT_BLOCK_SET_COMPLETE_HANDLER_OFFSET_X64: u64 = 0x2d0;
pub const DC21X4_ADAPTER_CURRENT_RBD_OFFSET_X64: u64 = 0x118;
pub const DC21X4_ADAPTER_HEAD_RBD_OFFSET_X64: u64 = 0x120;
pub const DC21X4_ADAPTER_TAIL_RBD_OFFSET_X64: u64 = 0x128;
pub const NDIS_PROTOCOL_CHARACTERISTICS_CALLBACK_CAP: usize = 19;
pub const NDIS_PROTOCOL_CHARACTERISTICS_NAME_OFFSET_X64: u64 = 0x58;
pub const NDIS30_PROTOCOL_CHARACTERISTICS_LEN_X64: u64 = 0x68;
pub const NDIS40_PROTOCOL_CHARACTERISTICS_LEN_X64: u64 = 0x90;
pub const NDIS50_PROTOCOL_CHARACTERISTICS_LEN_X64: u64 = 0xd0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeRange {
    pub base: u64,
    pub len: u64,
}

impl RuntimeRange {
    pub const fn new(base: u64, len: u64) -> Self {
        Self { base, len }
    }

    pub const fn end(self) -> Option<u64> {
        self.base.checked_add(self.len)
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub const fn overlaps(self, other: Self) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        let Some(self_end) = self.end() else {
            return true;
        };
        let Some(other_end) = other.end() else {
            return true;
        };
        self.base < other_end && other.base < self_end
    }

    pub const fn contains(self, other: Self) -> bool {
        if other.is_empty() {
            return true;
        }
        let Some(self_end) = self.end() else {
            return false;
        };
        let Some(other_end) = other.end() else {
            return false;
        };
        self.base <= other.base && other_end <= self_end
    }

    pub const fn is_page_table_aligned(self) -> bool {
        self.base & (PAGE_TABLE_SPAN - 1) == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessRuntimeLayout {
    pub pi: usize,
    pub scratch_base: u64,
    pub env_scratch_va: u64,
    pub stack_mirror_va: u64,
    pub heap_mirror_va: u64,
    pub image_mirror_va: u64,
}

impl ProcessRuntimeLayout {
    pub const fn scratch_range(self, scratch_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.scratch_base, scratch_len)
    }

    pub const fn stack_range(self, stack_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.stack_mirror_va, stack_len)
    }

    pub const fn env_range(self, env_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.env_scratch_va, env_len)
    }

    pub const fn heap_range(self, heap_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.heap_mirror_va, heap_len)
    }

    pub const fn image_range(self, image_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.image_mirror_va, image_len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLayoutError {
    InvalidPi,
    InvalidArena,
    InvalidStride,
    InvalidOffset,
    Overflow,
    OutsideArena,
    Overlap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDriverImagePlan {
    pub primary_offset: u64,
    pub private_dependency_offset: u64,
    pub total_image_len: u64,
    pub total_frames: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedDriverImagePlanError {
    Overflow,
    ExceedsFrameCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderDomainDescriptor {
    pub image_offset: u64,
    pub image_len: u64,
    pub image_frames: u64,
    pub pool_base: u64,
    pub pool_frames: u64,
    pub export_call_gate: u64,
    pub provider_domain_cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderDomainBinding {
    pub image_offset: u64,
    pub image_len: u64,
    pub image_frames: u64,
    pub pool_base: u64,
    pub pool_frames: u64,
    pub export_call_gate: u64,
    pub provider_domain_cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderDomainStatus {
    Absent,
    MetadataOnly,
    Callable(HostedProviderDomainBinding),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderDomainError {
    ImageOffsetUnaligned,
    EmptyImage,
    EmptyImageFrames,
    ImageFrameCapacityOverflow,
    ImageExceedsFrames,
    EmptyPoolFrames,
    EmptyProviderDomainCookie,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderExportCallPlan {
    pub export_call_gate: u64,
    pub provider_domain_cookie: u64,
    pub provider_export_rva: u64,
    pub provider_export_offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderExportCallError {
    Overflow,
    ExportOutsideImage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderImportBinding {
    PrivateDependencyRequired,
    ProviderDomainCall(HostedProviderExportCallPlan),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderImportBindingError {
    Domain(HostedProviderDomainError),
    Export(HostedProviderExportCallError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderImportThunkPlan {
    pub thunk_va: u64,
    pub thunk_offset: u64,
    pub export_call_gate: u64,
    pub provider_domain_cookie: u64,
    pub provider_export_rva: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderCallbackThunkPlan {
    pub thunk_va: u64,
    pub thunk_offset: u64,
    pub callback_gate: u64,
    pub callback_cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderImportThunkError {
    Overflow,
    ThunkOutsideTable,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderArgumentMarshal {
    Scalar,
    ProviderHandle,
    CallerContext,
    CallerInDriverObject,
    CallerInUnicodeString,
    CallerInAnsiString,
    CallerOutUnicodeStringFromSource {
        source_arg: u8,
    },
    CallerInBuffer {
        length_arg: u8,
    },
    CallerInArray {
        count_arg: u8,
        element_size: u8,
        count_width: u8,
    },
    CallerInOwnedAllocation {
        length_arg: u8,
    },
    CallerOutBuffer {
        length_arg: u8,
    },
    CallerInMiniportCharacteristics {
        length_arg: u8,
    },
    CallerInProtocolCharacteristics {
        length_arg: u8,
    },
    CallerInNdisBuffer,
    CallerInPacket,
    CallerInOutPacket,
    CallerOutNdisPacket,
    CallerOutNdisBuffer {
        virtual_address_arg: u8,
        length_arg: u8,
    },
    CallerOutNdisBufferFromPacket,
    CallerOutNdisBufferVirtualAddress,
    CallerOutNdisConfigurationParameter,
    CallerOutNetworkAddress {
        length_arg: u8,
    },
    CallerInOutNdisWorkItem,
    CallerInOutRequest,
    CallerInOutResourceList {
        length_pointer_arg: u8,
    },
    CallerOutNdisDeviceProperty {
        kind: u8,
    },
    CallerInOutMiniportInterrupt,
    CallerInOutMiniportTimer {
        allow_create: bool,
    },
    CallerInMiniportTimerFunction,
    CallerInPointerArray {
        count_arg: u8,
    },
    CallerInOutPacketArray {
        count_arg: u8,
    },
    CallerOutStatus,
    CallerOutHandle,
    CallerOutU8,
    CallerOutPointer,
    CallerOutPointerFromLength {
        length_arg: u8,
    },
    CallerOutIoPortRange {
        initial_port_arg: u8,
        length_arg: u8,
    },
    CallerOutMmioMapping {
        physical_address_arg: u8,
        length_arg: u8,
    },
    CallerOutDmaCommonBuffer {
        length_arg: u8,
    },
    CallerInDmaCommonBuffer {
        length_arg: u8,
        physical_address_arg: u8,
    },
    CallerOutU32,
    CallerInOutU32,
    CallerOutPhysicalAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderExportSideEffect {
    None,
    NdisInitializeWrapper,
    NdisMiniportRegistration,
    NdisMiniportAttributes,
    NdisScatterGatherDmaInitialization,
    NdisMiniportInterruptDeregistration,
    NdisPacketFree,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderExportResultSemantics {
    NtStatus,
    Void,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderExportMarshalPolicy {
    pub argument_count: u8,
    pub stack_qwords: u8,
    pub side_effect: HostedProviderExportSideEffect,
    pub result_semantics: HostedProviderExportResultSemantics,
    pub args: [HostedProviderArgumentMarshal; HOSTED_PROVIDER_EXPORT_ARG_CAP],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NdisMiniportCharacteristicsLayout {
    pub required_len: u64,
    pub callback_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NdisMiniportCharacteristicsLayoutError {
    BadVersion,
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NdisProtocolCharacteristicsLayout {
    pub required_len: u64,
    pub callback_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NdisProtocolCharacteristicsLayoutError {
    BadVersion,
    BufferTooSmall,
}

impl NdisMiniportCharacteristicsLayout {
    pub const fn callback_offset(self, index: usize) -> Option<u64> {
        if index >= self.callback_count as usize {
            return None;
        }
        let Some(offset) =
            (index as u64).checked_mul(NDIS_MINIPORT_CHARACTERISTICS_CALLBACK_STRIDE_X64)
        else {
            return None;
        };
        NDIS_MINIPORT_CHARACTERISTICS_CALLBACK_BASE_X64.checked_add(offset)
    }
}

pub fn ndis_miniport_characteristics_layout(
    major: u8,
    minor: u8,
    supplied_len: u64,
) -> Result<NdisMiniportCharacteristicsLayout, NdisMiniportCharacteristicsLayoutError> {
    let layout = match major {
        0x03 => NdisMiniportCharacteristicsLayout {
            required_len: NDIS30_MINIPORT_CHARACTERISTICS_LEN_X64,
            callback_count: 13,
        },
        0x04 => NdisMiniportCharacteristicsLayout {
            required_len: NDIS40_MINIPORT_CHARACTERISTICS_LEN_X64,
            callback_count: 16,
        },
        0x05 => match minor {
            0x00 => NdisMiniportCharacteristicsLayout {
                required_len: NDIS50_MINIPORT_CHARACTERISTICS_LEN_X64,
                callback_count: 22,
            },
            0x01 => NdisMiniportCharacteristicsLayout {
                required_len: NDIS51_MINIPORT_CHARACTERISTICS_LEN_X64,
                callback_count: 25,
            },
            _ => return Err(NdisMiniportCharacteristicsLayoutError::BadVersion),
        },
        _ => return Err(NdisMiniportCharacteristicsLayoutError::BadVersion),
    };
    if supplied_len < layout.required_len {
        return Err(NdisMiniportCharacteristicsLayoutError::BufferTooSmall);
    }
    Ok(layout)
}

impl NdisProtocolCharacteristicsLayout {
    pub const fn callback_offset(self, index: usize) -> Option<u64> {
        if index >= self.callback_count as usize {
            return None;
        }
        match index {
            0..=9 => Some(0x08 + (index as u64) * 0x08),
            10..=14 => Some(0x68 + ((index as u64) - 10) * 0x08),
            15..=18 => Some(0xb0 + ((index as u64) - 15) * 0x08),
            _ => None,
        }
    }
}

pub fn ndis_protocol_characteristics_layout(
    major: u8,
    minor: u8,
    supplied_len: u64,
) -> Result<NdisProtocolCharacteristicsLayout, NdisProtocolCharacteristicsLayoutError> {
    let layout = match major {
        0x03 => NdisProtocolCharacteristicsLayout {
            required_len: NDIS30_PROTOCOL_CHARACTERISTICS_LEN_X64,
            callback_count: 10,
        },
        0x04 => NdisProtocolCharacteristicsLayout {
            required_len: NDIS40_PROTOCOL_CHARACTERISTICS_LEN_X64,
            callback_count: 15,
        },
        0x05 => match minor {
            0x00 | 0x01 => NdisProtocolCharacteristicsLayout {
                required_len: NDIS50_PROTOCOL_CHARACTERISTICS_LEN_X64,
                callback_count: NDIS_PROTOCOL_CHARACTERISTICS_CALLBACK_CAP as u8,
            },
            _ => return Err(NdisProtocolCharacteristicsLayoutError::BadVersion),
        },
        _ => return Err(NdisProtocolCharacteristicsLayoutError::BadVersion),
    };
    if supplied_len < layout.required_len {
        return Err(NdisProtocolCharacteristicsLayoutError::BufferTooSmall);
    }
    Ok(layout)
}

fn ascii_eq_ignore_case(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut index = 0usize;
    while index < ab.len() {
        if ab[index].to_ascii_lowercase() != bb[index].to_ascii_lowercase() {
            return false;
        }
        index += 1;
    }
    true
}

fn export_policy(
    args: &[HostedProviderArgumentMarshal],
) -> Option<HostedProviderExportMarshalPolicy> {
    export_policy_with_effect_and_result(
        args,
        HostedProviderExportSideEffect::None,
        HostedProviderExportResultSemantics::NtStatus,
    )
}

fn void_export_policy(
    args: &[HostedProviderArgumentMarshal],
) -> Option<HostedProviderExportMarshalPolicy> {
    export_policy_with_effect_and_result(
        args,
        HostedProviderExportSideEffect::None,
        HostedProviderExportResultSemantics::Void,
    )
}

fn export_policy_with_side_effect(
    args: &[HostedProviderArgumentMarshal],
    side_effect: HostedProviderExportSideEffect,
) -> Option<HostedProviderExportMarshalPolicy> {
    export_policy_with_effect_and_result(
        args,
        side_effect,
        HostedProviderExportResultSemantics::NtStatus,
    )
}

fn export_policy_with_effect_and_result(
    args: &[HostedProviderArgumentMarshal],
    side_effect: HostedProviderExportSideEffect,
    result_semantics: HostedProviderExportResultSemantics,
) -> Option<HostedProviderExportMarshalPolicy> {
    if args.len() > HOSTED_PROVIDER_EXPORT_ARG_CAP {
        return None;
    }
    let mut all = [HostedProviderArgumentMarshal::Scalar; HOSTED_PROVIDER_EXPORT_ARG_CAP];
    let mut index = 0usize;
    while index < args.len() {
        all[index] = args[index];
        index += 1;
    }
    Some(HostedProviderExportMarshalPolicy {
        argument_count: args.len() as u8,
        stack_qwords: args.len().saturating_sub(4) as u8,
        side_effect,
        result_semantics,
        args: all,
    })
}

const HOSTED_PROVIDER_EXPORT_POLICY_DLLS: [&str; 1] = ["ndis.sys"];

pub fn hosted_provider_has_export_marshal_policies(provider_dll: &str) -> bool {
    let mut index = 0usize;
    while index < HOSTED_PROVIDER_EXPORT_POLICY_DLLS.len() {
        if ascii_eq_ignore_case(provider_dll, HOSTED_PROVIDER_EXPORT_POLICY_DLLS[index]) {
            return true;
        }
        index += 1;
    }
    false
}

pub fn hosted_provider_export_marshal_policy(
    provider_dll: &str,
    export_name: &str,
) -> Option<HostedProviderExportMarshalPolicy> {
    use HostedProviderArgumentMarshal::*;

    if !hosted_provider_has_export_marshal_policies(provider_dll) {
        return None;
    }

    match export_name {
        "NdisAllocateMemoryWithTag" => {
            export_policy(&[CallerOutPointerFromLength { length_arg: 1 }, Scalar, Scalar])
        }
        "NdisMInitializeScatterGatherDma" => export_policy_with_side_effect(
            &[ProviderHandle, Scalar, Scalar],
            HostedProviderExportSideEffect::NdisScatterGatherDmaInitialization,
        ),
        "NdisInitializeWrapper" => export_policy_with_effect_and_result(
            &[
                CallerOutHandle,
                CallerInDriverObject,
                CallerInUnicodeString,
                Scalar,
            ],
            HostedProviderExportSideEffect::NdisInitializeWrapper,
            HostedProviderExportResultSemantics::Void,
        ),
        "NdisMRegisterMiniport" => export_policy_with_side_effect(
            &[
                ProviderHandle,
                CallerInMiniportCharacteristics { length_arg: 2 },
                Scalar,
            ],
            HostedProviderExportSideEffect::NdisMiniportRegistration,
        ),
        "NdisMSetAttributesEx" => export_policy_with_effect_and_result(
            &[ProviderHandle, CallerContext, Scalar, Scalar, Scalar],
            HostedProviderExportSideEffect::NdisMiniportAttributes,
            HostedProviderExportResultSemantics::Void,
        ),
        "NdisMRemoveMiniport" => export_policy(&[ProviderHandle]),
        "NdisMQueryAdapterResources" => void_export_policy(&[
            CallerOutStatus,
            ProviderHandle,
            CallerInOutResourceList {
                length_pointer_arg: 3,
            },
            CallerInOutU32,
        ]),
        "NdisMGetDeviceProperty" => void_export_policy(&[
            ProviderHandle,
            CallerOutNdisDeviceProperty { kind: 1 },
            CallerOutNdisDeviceProperty { kind: 2 },
            CallerOutNdisDeviceProperty { kind: 3 },
            CallerOutNdisDeviceProperty { kind: 4 },
            CallerOutNdisDeviceProperty { kind: 5 },
        ]),
        "NdisMSleep" => void_export_policy(&[Scalar]),
        "NdisGetSharedDataAlignment" => export_policy(&[]),
        "NdisOpenConfiguration" => {
            void_export_policy(&[CallerOutStatus, CallerOutHandle, ProviderHandle])
        }
        "NdisCloseConfiguration" => void_export_policy(&[ProviderHandle]),
        "NdisInitUnicodeString" => {
            void_export_policy(&[CallerOutUnicodeStringFromSource { source_arg: 1 }, Scalar])
        }
        "NdisReadConfiguration" => void_export_policy(&[
            CallerOutStatus,
            CallerOutNdisConfigurationParameter,
            ProviderHandle,
            CallerInUnicodeString,
            Scalar,
        ]),
        "NdisReadNetworkAddress" => void_export_policy(&[
            CallerOutStatus,
            CallerOutNetworkAddress { length_arg: 2 },
            Scalar,
            ProviderHandle,
        ]),
        "NdisScheduleWorkItem" => export_policy(&[CallerInOutNdisWorkItem]),
        "NdisTerminateWrapper" => void_export_policy(&[ProviderHandle, Scalar]),
        "NdisReadPciSlotInformation" => export_policy(&[
            ProviderHandle,
            Scalar,
            Scalar,
            CallerOutBuffer { length_arg: 4 },
            Scalar,
        ]),
        "NdisWritePciSlotInformation" => export_policy(&[
            ProviderHandle,
            Scalar,
            Scalar,
            CallerInBuffer { length_arg: 4 },
            Scalar,
        ]),
        "NdisMFreeSharedMemory" => void_export_policy(&[
            ProviderHandle,
            Scalar,
            Scalar,
            CallerInDmaCommonBuffer {
                length_arg: 1,
                physical_address_arg: 4,
            },
            Scalar,
        ]),
        "NdisMDeregisterInterrupt" => export_policy_with_effect_and_result(
            &[CallerInOutMiniportInterrupt],
            HostedProviderExportSideEffect::NdisMiniportInterruptDeregistration,
            HostedProviderExportResultSemantics::Void,
        ),
        "NdisMInitializeTimer" => void_export_policy(&[
            CallerInOutMiniportTimer { allow_create: true },
            ProviderHandle,
            CallerInMiniportTimerFunction,
            CallerContext,
        ]),
        "NdisMSetTimer" | "NdisMSetPeriodicTimer" => void_export_policy(&[
            CallerInOutMiniportTimer {
                allow_create: false,
            },
            Scalar,
        ]),
        "NdisMCancelTimer" => void_export_policy(&[
            CallerInOutMiniportTimer {
                allow_create: false,
            },
            CallerOutU8,
        ]),
        "NdisMRegisterInterrupt" => export_policy(&[
            CallerInOutMiniportInterrupt,
            ProviderHandle,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
        ]),
        "NdisMDeregisterIoPortRange" => {
            void_export_policy(&[ProviderHandle, Scalar, Scalar, Scalar])
        }
        "NdisMMapIoSpace" => export_policy(&[
            CallerOutMmioMapping {
                physical_address_arg: 2,
                length_arg: 3,
            },
            ProviderHandle,
            Scalar,
            Scalar,
        ]),
        "NdisMRegisterIoPortRange" => export_policy(&[
            CallerOutIoPortRange {
                initial_port_arg: 2,
                length_arg: 3,
            },
            ProviderHandle,
            Scalar,
            Scalar,
        ]),
        "NdisMUnmapIoSpace" => void_export_policy(&[ProviderHandle, Scalar, Scalar]),
        "NdisMAllocateSharedMemory" => void_export_policy(&[
            ProviderHandle,
            Scalar,
            Scalar,
            CallerOutDmaCommonBuffer { length_arg: 1 },
            CallerOutPhysicalAddress,
        ]),
        "NDIS_BUFFER_TO_SPAN_PAGES" => export_policy(&[CallerInNdisBuffer]),
        "NdisFreeMemory" => {
            void_export_policy(&[CallerInOwnedAllocation { length_arg: 1 }, Scalar, Scalar])
        }
        "NdisTransferData" => void_export_policy(&[
            CallerOutStatus,
            ProviderHandle,
            Scalar,
            Scalar,
            Scalar,
            CallerInOutPacket,
            CallerOutU32,
        ]),
        "NdisSend" => void_export_policy(&[CallerOutStatus, ProviderHandle, CallerInPacket]),
        "EthFilterDprIndicateReceive" => void_export_policy(&[
            ProviderHandle,
            Scalar,
            CallerInBuffer { length_arg: 4 },
            CallerInBuffer { length_arg: 4 },
            Scalar,
            CallerInBuffer { length_arg: 6 },
            Scalar,
            Scalar,
        ]),
        "EthFilterDprIndicateReceiveComplete" => void_export_policy(&[ProviderHandle]),
        "NdisMIndicateStatus" => void_export_policy(&[
            ProviderHandle,
            Scalar,
            CallerInBuffer { length_arg: 3 },
            Scalar,
        ]),
        "NdisWriteErrorLogEntry" => void_export_policy(&[
            ProviderHandle,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
            Scalar,
        ]),
        "NdisMIndicateStatusComplete" => void_export_policy(&[ProviderHandle]),
        "NdisMQueryInformationComplete" => void_export_policy(&[ProviderHandle, Scalar]),
        "NdisMSetInformationComplete" => void_export_policy(&[ProviderHandle, Scalar]),
        "NdisMResetComplete" => void_export_policy(&[ProviderHandle, Scalar, Scalar]),
        "NdisMSendComplete" => void_export_policy(&[ProviderHandle, CallerInOutPacket, Scalar]),
        "NdisMSendResourcesAvailable" => void_export_policy(&[ProviderHandle]),
        "NdisMTransferDataComplete" => {
            void_export_policy(&[ProviderHandle, CallerInOutPacket, Scalar, Scalar])
        }
        "NdisRequest" => void_export_policy(&[CallerOutStatus, ProviderHandle, CallerInOutRequest]),
        "NdisDeregisterProtocol" => void_export_policy(&[CallerOutStatus, ProviderHandle]),
        "NdisOpenAdapter" => void_export_policy(&[
            CallerOutStatus,
            CallerOutStatus,
            CallerOutHandle,
            CallerOutU32,
            CallerInArray {
                count_arg: 5,
                element_size: 4,
                count_width: 4,
            },
            Scalar,
            ProviderHandle,
            CallerContext,
            CallerInUnicodeString,
            Scalar,
            CallerInAnsiString,
        ]),
        "NdisCloseAdapter" => void_export_policy(&[CallerOutStatus, ProviderHandle]),
        "NdisRegisterProtocol" => void_export_policy(&[
            CallerOutStatus,
            CallerOutHandle,
            CallerInProtocolCharacteristics { length_arg: 3 },
            Scalar,
        ]),
        "NdisFreePacket" => export_policy_with_effect_and_result(
            &[CallerInOutPacket],
            HostedProviderExportSideEffect::NdisPacketFree,
            HostedProviderExportResultSemantics::Void,
        ),
        "NdisAllocatePacket" => {
            void_export_policy(&[CallerOutStatus, CallerOutNdisPacket, ProviderHandle])
        }
        "NdisGetFirstBufferFromPacket" => void_export_policy(&[
            CallerInPacket,
            CallerOutNdisBufferFromPacket,
            CallerOutNdisBufferVirtualAddress,
            CallerOutU32,
            CallerOutU32,
        ]),
        "NdisAllocateBufferPool" => void_export_policy(&[CallerOutStatus, CallerOutHandle, Scalar]),
        "NdisFreeBufferPool" => void_export_policy(&[ProviderHandle]),
        "NdisAllocatePacketPool" => {
            void_export_policy(&[CallerOutStatus, CallerOutHandle, Scalar, Scalar])
        }
        "NdisAllocatePacketPoolEx" => {
            void_export_policy(&[CallerOutStatus, CallerOutHandle, Scalar, Scalar, Scalar])
        }
        "NdisFreePacketPool" => void_export_policy(&[ProviderHandle]),
        "NdisAllocateBuffer" => void_export_policy(&[
            CallerOutStatus,
            CallerOutNdisBuffer {
                virtual_address_arg: 3,
                length_arg: 4,
            },
            Scalar,
            Scalar,
            Scalar,
        ]),
        "NdisReturnPackets" => void_export_policy(&[CallerInPointerArray { count_arg: 1 }, Scalar]),
        _ => None,
    }
}

pub fn hosted_provider_internal_marshal_policy(
    provider_dll: &str,
    internal_name: &str,
) -> Option<HostedProviderExportMarshalPolicy> {
    use HostedProviderArgumentMarshal::*;

    if !hosted_provider_has_export_marshal_policies(provider_dll) {
        return None;
    }

    if ascii_eq_ignore_case(provider_dll, "ndis.sys")
        && ascii_eq_ignore_case(internal_name, "MiniIndicateReceivePacket")
    {
        return void_export_policy(&[
            ProviderHandle,
            CallerInOutPacketArray { count_arg: 2 },
            Scalar,
        ]);
    }

    None
}

pub fn page_align_up(value: u64) -> Result<u64, HostedDriverImagePlanError> {
    match value.checked_add(PAGE_SIZE - 1) {
        Some(value) => Ok(value & !(PAGE_SIZE - 1)),
        None => Err(HostedDriverImagePlanError::Overflow),
    }
}

pub fn classify_hosted_provider_domain(
    descriptor: Option<HostedProviderDomainDescriptor>,
) -> Result<HostedProviderDomainStatus, HostedProviderDomainError> {
    let Some(descriptor) = descriptor else {
        return Ok(HostedProviderDomainStatus::Absent);
    };
    if descriptor.image_offset & (PAGE_SIZE - 1) != 0 {
        return Err(HostedProviderDomainError::ImageOffsetUnaligned);
    }
    if descriptor.image_len == 0 {
        return Err(HostedProviderDomainError::EmptyImage);
    }
    if descriptor.image_frames == 0 {
        return Err(HostedProviderDomainError::EmptyImageFrames);
    }
    let Some(image_frame_capacity) = descriptor.image_frames.checked_mul(PAGE_SIZE) else {
        return Err(HostedProviderDomainError::ImageFrameCapacityOverflow);
    };
    if descriptor.image_len > image_frame_capacity {
        return Err(HostedProviderDomainError::ImageExceedsFrames);
    }
    if descriptor.pool_frames == 0 {
        return Err(HostedProviderDomainError::EmptyPoolFrames);
    }
    if descriptor.export_call_gate == 0 {
        return Ok(HostedProviderDomainStatus::MetadataOnly);
    }
    if descriptor.provider_domain_cookie == 0 {
        return Err(HostedProviderDomainError::EmptyProviderDomainCookie);
    }
    Ok(HostedProviderDomainStatus::Callable(
        HostedProviderDomainBinding {
            image_offset: descriptor.image_offset,
            image_len: descriptor.image_len,
            image_frames: descriptor.image_frames,
            pool_base: descriptor.pool_base,
            pool_frames: descriptor.pool_frames,
            export_call_gate: descriptor.export_call_gate,
            provider_domain_cookie: descriptor.provider_domain_cookie,
        },
    ))
}

pub fn plan_hosted_provider_export_call(
    binding: HostedProviderDomainBinding,
    provider_export_rva: u64,
) -> Result<HostedProviderExportCallPlan, HostedProviderExportCallError> {
    if provider_export_rva >= binding.image_len {
        return Err(HostedProviderExportCallError::ExportOutsideImage);
    }
    let Some(provider_export_offset) = binding.image_offset.checked_add(provider_export_rva) else {
        return Err(HostedProviderExportCallError::Overflow);
    };
    Ok(HostedProviderExportCallPlan {
        export_call_gate: binding.export_call_gate,
        provider_domain_cookie: binding.provider_domain_cookie,
        provider_export_rva,
        provider_export_offset,
    })
}

pub fn plan_hosted_provider_import_binding(
    descriptor: Option<HostedProviderDomainDescriptor>,
    provider_export_rva: u64,
) -> Result<HostedProviderImportBinding, HostedProviderImportBindingError> {
    match classify_hosted_provider_domain(descriptor)
        .map_err(HostedProviderImportBindingError::Domain)?
    {
        HostedProviderDomainStatus::Absent | HostedProviderDomainStatus::MetadataOnly => {
            Ok(HostedProviderImportBinding::PrivateDependencyRequired)
        }
        HostedProviderDomainStatus::Callable(binding) => {
            Ok(HostedProviderImportBinding::ProviderDomainCall(
                plan_hosted_provider_export_call(binding, provider_export_rva)
                    .map_err(HostedProviderImportBindingError::Export)?,
            ))
        }
    }
}

pub fn plan_hosted_provider_import_thunk(
    thunk_table_va: u64,
    thunk_table_len: u64,
    thunk_index: u64,
    export_plan: HostedProviderExportCallPlan,
) -> Result<HostedProviderImportThunkPlan, HostedProviderImportThunkError> {
    let Some(thunk_offset) = thunk_index.checked_mul(HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN) else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    let Some(thunk_end) = thunk_offset.checked_add(HOSTED_PROVIDER_IMPORT_THUNK_LEN as u64) else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    if thunk_end > thunk_table_len {
        return Err(HostedProviderImportThunkError::ThunkOutsideTable);
    }
    let Some(thunk_va) = thunk_table_va.checked_add(thunk_offset) else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    Ok(HostedProviderImportThunkPlan {
        thunk_va,
        thunk_offset,
        export_call_gate: export_plan.export_call_gate,
        provider_domain_cookie: export_plan.provider_domain_cookie,
        provider_export_rva: export_plan.provider_export_rva,
    })
}

pub fn encode_hosted_provider_import_thunk(
    thunk: HostedProviderImportThunkPlan,
    out: &mut [u8],
) -> Result<(), HostedProviderImportThunkError> {
    if out.len() < HOSTED_PROVIDER_IMPORT_THUNK_LEN {
        return Err(HostedProviderImportThunkError::OutputTooSmall);
    }
    out[..HOSTED_PROVIDER_IMPORT_THUNK_LEN].copy_from_slice(&[
        0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, imm64
        0x49, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, // mov r10, imm64
        0x49, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, // mov r11, imm64
        0x41, 0xff, 0xe3, // jmp r11
    ]);
    out[2..10].copy_from_slice(&thunk.provider_export_rva.to_le_bytes());
    out[12..20].copy_from_slice(&thunk.provider_domain_cookie.to_le_bytes());
    out[22..30].copy_from_slice(&thunk.export_call_gate.to_le_bytes());
    Ok(())
}

pub fn plan_hosted_provider_callback_thunk(
    thunk_table_va: u64,
    thunk_table_len: u64,
    thunk_index: u64,
    callback_gate: u64,
    callback_cookie: u64,
) -> Result<HostedProviderCallbackThunkPlan, HostedProviderImportThunkError> {
    let Some(thunk_offset) = thunk_index.checked_mul(HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN) else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    let Some(thunk_end) = thunk_offset.checked_add(HOSTED_PROVIDER_CALLBACK_THUNK_LEN as u64)
    else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    if thunk_end > thunk_table_len {
        return Err(HostedProviderImportThunkError::ThunkOutsideTable);
    }
    let Some(thunk_va) = thunk_table_va.checked_add(thunk_offset) else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    Ok(HostedProviderCallbackThunkPlan {
        thunk_va,
        thunk_offset,
        callback_gate,
        callback_cookie,
    })
}

pub fn encode_hosted_provider_callback_thunk(
    thunk: HostedProviderCallbackThunkPlan,
    out: &mut [u8],
) -> Result<(), HostedProviderImportThunkError> {
    if out.len() < HOSTED_PROVIDER_CALLBACK_THUNK_LEN {
        return Err(HostedProviderImportThunkError::OutputTooSmall);
    }
    out[..HOSTED_PROVIDER_CALLBACK_THUNK_LEN].copy_from_slice(&[
        0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, imm64
        0x49, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, // mov r11, imm64
        0x41, 0xff, 0xe3, // jmp r11
    ]);
    out[2..10].copy_from_slice(&thunk.callback_cookie.to_le_bytes());
    out[12..20].copy_from_slice(&thunk.callback_gate.to_le_bytes());
    Ok(())
}

pub fn plan_hosted_driver_image(
    primary_image_len: u64,
    private_dependency_image_lens: &[u64],
    minimum_frames: u64,
    frame_capacity: u64,
) -> Result<HostedDriverImagePlan, HostedDriverImagePlanError> {
    let primary_offset = 0u64;
    let private_dependency_offset = primary_offset
        .checked_add(page_align_up(primary_image_len)?)
        .ok_or(HostedDriverImagePlanError::Overflow)?;
    let mut total_image_len = private_dependency_offset;
    for len in private_dependency_image_lens {
        total_image_len = total_image_len
            .checked_add(page_align_up(*len)?)
            .ok_or(HostedDriverImagePlanError::Overflow)?;
    }

    let planned_frames = page_align_up(total_image_len)? / PAGE_SIZE;
    let total_frames = if planned_frames < minimum_frames {
        minimum_frames
    } else {
        planned_frames
    };
    if total_frames > frame_capacity {
        return Err(HostedDriverImagePlanError::ExceedsFrameCapacity);
    }

    Ok(HostedDriverImagePlan {
        primary_offset,
        private_dependency_offset,
        total_image_len,
        total_frames,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicRuntimeArena {
    pub first_pi: usize,
    pub max_pi: usize,
    pub base: u64,
    pub limit: u64,
    pub stride: u64,
    pub scratch_offset: u64,
    pub stack_offset: u64,
    pub env_offset: u64,
    pub heap_offset: u64,
    pub image_offset: u64,
    pub scratch_len: u64,
    pub stack_len: u64,
    pub env_len: u64,
    pub heap_len: u64,
    pub image_len: u64,
}

impl DynamicRuntimeArena {
    pub const fn layout_for_pi(
        self,
        pi: usize,
    ) -> Result<ProcessRuntimeLayout, RuntimeLayoutError> {
        if pi < self.first_pi || pi >= self.max_pi {
            return Err(RuntimeLayoutError::InvalidPi);
        }
        if self.base >= self.limit || self.base & (PAGE_TABLE_SPAN - 1) != 0 {
            return Err(RuntimeLayoutError::InvalidArena);
        }
        if self.stride == 0 || self.stride & (PAGE_TABLE_SPAN - 1) != 0 {
            return Err(RuntimeLayoutError::InvalidStride);
        }
        if self.scratch_offset & (PAGE_TABLE_SPAN - 1) != 0
            || self.stack_offset & (PAGE_TABLE_SPAN - 1) != 0
            || self.heap_offset & (PAGE_TABLE_SPAN - 1) != 0
            || self.image_offset & (PAGE_TABLE_SPAN - 1) != 0
        {
            return Err(RuntimeLayoutError::InvalidOffset);
        }
        let index = pi - self.first_pi;
        let Some(offset) = (index as u64).checked_mul(self.stride) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(lane_base) = self.base.checked_add(offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(lane_end) = lane_base.checked_add(self.stride) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        if lane_end > self.limit {
            return Err(RuntimeLayoutError::OutsideArena);
        }
        let Some(scratch_base) = lane_base.checked_add(self.scratch_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(stack_mirror_va) = lane_base.checked_add(self.stack_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(env_scratch_va) = lane_base.checked_add(self.env_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(heap_mirror_va) = lane_base.checked_add(self.heap_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(image_mirror_va) = lane_base.checked_add(self.image_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let lane = RuntimeRange::new(lane_base, self.stride);
        let layout = ProcessRuntimeLayout {
            pi,
            scratch_base,
            env_scratch_va,
            stack_mirror_va,
            heap_mirror_va,
            image_mirror_va,
        };
        if !lane.contains(layout.scratch_range(self.scratch_len))
            || !lane.contains(layout.stack_range(self.stack_len))
            || !lane.contains(layout.env_range(self.env_len))
            || !lane.contains(layout.heap_range(self.heap_len))
            || !lane.contains(layout.image_range(self.image_len))
        {
            return Err(RuntimeLayoutError::OutsideArena);
        }
        if layout
            .scratch_range(self.scratch_len)
            .overlaps(layout.stack_range(self.stack_len))
            || layout
                .scratch_range(self.scratch_len)
                .overlaps(layout.env_range(self.env_len))
            || layout
                .scratch_range(self.scratch_len)
                .overlaps(layout.heap_range(self.heap_len))
            || layout
                .scratch_range(self.scratch_len)
                .overlaps(layout.image_range(self.image_len))
            || layout
                .stack_range(self.stack_len)
                .overlaps(layout.env_range(self.env_len))
            || layout
                .stack_range(self.stack_len)
                .overlaps(layout.heap_range(self.heap_len))
            || layout
                .stack_range(self.stack_len)
                .overlaps(layout.image_range(self.image_len))
            || layout
                .env_range(self.env_len)
                .overlaps(layout.heap_range(self.heap_len))
            || layout
                .env_range(self.env_len)
                .overlaps(layout.image_range(self.image_len))
            || layout
                .heap_range(self.heap_len)
                .overlaps(layout.image_range(self.image_len))
        {
            return Err(RuntimeLayoutError::Overlap);
        }
        Ok(layout)
    }
}

pub fn validate_non_overlapping(ranges: &[RuntimeRange]) -> Result<(), RuntimeLayoutError> {
    for (i, left) in ranges.iter().enumerate() {
        if left.end().is_none() {
            return Err(RuntimeLayoutError::Overflow);
        }
        for right in &ranges[i + 1..] {
            if right.end().is_none() {
                return Err(RuntimeLayoutError::Overflow);
            }
            if left.overlaps(*right) {
                return Err(RuntimeLayoutError::Overlap);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARENA: DynamicRuntimeArena = DynamicRuntimeArena {
        first_pi: 7,
        max_pi: 16,
        base: 0x0000_0101_6000_0000,
        limit: 0x0000_0101_A800_0000,
        stride: 0x0800_0000,
        scratch_offset: 0,
        stack_offset: 0x0400_0000,
        env_offset: 0x0410_0000,
        heap_offset: 0x0420_0000,
        image_offset: 0x0440_0000,
        scratch_len: 0x0400_0000,
        stack_len: 0x4000,
        env_len: 0x9000,
        heap_len: 0x20_0000,
        image_len: 0x20_0000,
    };

    #[test]
    fn dynamic_runtime_arena_assigns_dense_non_overlapping_lanes() {
        let first = ARENA.layout_for_pi(7).unwrap();
        let second = ARENA.layout_for_pi(8).unwrap();
        assert_eq!(first.scratch_base, ARENA.base);
        assert_eq!(first.stack_mirror_va, ARENA.base + ARENA.stack_offset);
        assert_eq!(second.scratch_base, ARENA.base + ARENA.stride);

        let mut ranges = [RuntimeRange::new(0, 0); 45];
        let mut n = 0;
        for pi in ARENA.first_pi..ARENA.max_pi {
            let layout = ARENA.layout_for_pi(pi).unwrap();
            ranges[n] = layout.scratch_range(ARENA.scratch_len);
            n += 1;
            ranges[n] = layout.stack_range(ARENA.stack_len);
            n += 1;
            ranges[n] = layout.env_range(ARENA.env_len);
            n += 1;
            ranges[n] = layout.heap_range(ARENA.heap_len);
            n += 1;
            ranges[n] = layout.image_range(ARENA.image_len);
            n += 1;
        }
        validate_non_overlapping(&ranges[..n]).unwrap();
    }

    #[test]
    fn arena_rejects_pi_outside_dynamic_range() {
        assert_eq!(ARENA.layout_for_pi(6), Err(RuntimeLayoutError::InvalidPi));
        assert_eq!(ARENA.layout_for_pi(16), Err(RuntimeLayoutError::InvalidPi));
    }

    #[test]
    fn arena_rejects_implicit_scratch_mirror_collision() {
        let colliding = DynamicRuntimeArena {
            stack_offset: 0x03e0_0000,
            ..ARENA
        };
        assert_eq!(colliding.layout_for_pi(7), Err(RuntimeLayoutError::Overlap));
    }

    #[test]
    fn validate_non_overlapping_reports_cross_lane_collision() {
        let ranges = [
            RuntimeRange::new(0x1000, 0x2000),
            RuntimeRange::new(0x2fff, 0x1000),
        ];
        assert_eq!(
            validate_non_overlapping(&ranges),
            Err(RuntimeLayoutError::Overlap)
        );
    }

    #[test]
    fn hosted_driver_image_plan_preserves_current_private_dependency_layout() {
        let plan = plan_hosted_driver_image(0x21_234, &[0x10], 64, 128).unwrap();
        assert_eq!(
            plan,
            HostedDriverImagePlan {
                primary_offset: 0,
                private_dependency_offset: 0x22_000,
                total_image_len: 0x23_000,
                total_frames: 64,
            }
        );
    }

    #[test]
    fn hosted_driver_image_plan_places_private_dependencies_after_primary() {
        let plan = plan_hosted_driver_image(0x8_400, &[0x41_000, 0x1], 0, 128).unwrap();
        assert_eq!(plan.primary_offset, 0);
        assert_eq!(plan.private_dependency_offset, 0x9_000);
        assert_eq!(plan.total_image_len, 0x4b_000);
        assert_eq!(plan.total_frames, 0x4b);
    }

    #[test]
    fn hosted_driver_image_plan_rejects_capacity_and_overflow() {
        assert_eq!(
            plan_hosted_driver_image(0x20_000, &[], 0, 0x1),
            Err(HostedDriverImagePlanError::ExceedsFrameCapacity)
        );
        assert_eq!(
            plan_hosted_driver_image(u64::MAX, &[], 0, u64::MAX),
            Err(HostedDriverImagePlanError::Overflow)
        );
    }

    #[test]
    fn ndis_provider_policy_covers_observed_e1000_imports() {
        assert!(hosted_provider_has_export_marshal_policies("NDIS.SYS"));
        assert!(hosted_provider_has_export_marshal_policies("ndis.sys"));
        assert!(!hosted_provider_has_export_marshal_policies("tcpip.sys"));

        for export in [
            "NdisAllocateMemoryWithTag",
            "NdisMInitializeScatterGatherDma",
            "NdisInitializeWrapper",
            "NdisMRegisterMiniport",
            "NdisMSetAttributesEx",
            "NdisMQueryAdapterResources",
            "NdisMGetDeviceProperty",
            "NdisOpenConfiguration",
            "NdisCloseConfiguration",
            "NdisInitUnicodeString",
            "NdisReadConfiguration",
            "NdisReadNetworkAddress",
            "NdisScheduleWorkItem",
            "NdisTerminateWrapper",
            "NdisReadPciSlotInformation",
            "NdisMFreeSharedMemory",
            "NdisMDeregisterInterrupt",
            "NdisMRegisterInterrupt",
            "EthFilterDprIndicateReceive",
            "EthFilterDprIndicateReceiveComplete",
            "NdisMIndicateStatus",
            "NdisMIndicateStatusComplete",
            "NdisMQueryInformationComplete",
            "NdisMSetInformationComplete",
            "NdisMResetComplete",
            "NdisMSendComplete",
            "NdisMSendResourcesAvailable",
            "NdisMTransferDataComplete",
            "NdisMDeregisterIoPortRange",
            "NdisMMapIoSpace",
            "NdisMRegisterIoPortRange",
            "NdisMUnmapIoSpace",
            "NdisMAllocateSharedMemory",
            "NdisFreeMemory",
        ] {
            let policy = hosted_provider_export_marshal_policy("NDIS.SYS", export)
                .unwrap_or_else(|| panic!("missing policy for {}", export));
            assert!(policy.argument_count as usize <= HOSTED_PROVIDER_EXPORT_ARG_CAP);
            assert!(policy.stack_qwords <= 8);
        }
        assert_eq!(
            hosted_provider_export_marshal_policy("ndis.sys", "NdisInitializeWrapper")
                .unwrap()
                .side_effect,
            HostedProviderExportSideEffect::NdisInitializeWrapper
        );
        assert_eq!(
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMRegisterMiniport")
                .unwrap()
                .side_effect,
            HostedProviderExportSideEffect::NdisMiniportRegistration
        );
        assert_eq!(
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMSetAttributesEx")
                .unwrap()
                .side_effect,
            HostedProviderExportSideEffect::NdisMiniportAttributes
        );
        assert_eq!(
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMInitializeScatterGatherDma")
                .unwrap()
                .side_effect,
            HostedProviderExportSideEffect::NdisScatterGatherDmaInitialization
        );
    }

    #[test]
    fn ndis_provider_policy_covers_observed_tcpip_imports() {
        for export in [
            "NdisTransferData",
            "NdisSend",
            "NdisMSendComplete",
            "NdisMTransferDataComplete",
            "NdisRequest",
            "NdisDeregisterProtocol",
            "NdisOpenAdapter",
            "NdisCloseAdapter",
            "NdisRegisterProtocol",
            "NDIS_BUFFER_TO_SPAN_PAGES",
            "NdisFreePacket",
            "NdisAllocatePacket",
            "NdisGetFirstBufferFromPacket",
            "NdisAllocateBufferPool",
            "NdisFreeBufferPool",
            "NdisAllocatePacketPool",
            "NdisAllocatePacketPoolEx",
            "NdisFreePacketPool",
            "NdisAllocateBuffer",
            "NdisReturnPackets",
        ] {
            let policy = hosted_provider_export_marshal_policy("ndis.sys", export)
                .unwrap_or_else(|| panic!("missing policy for {}", export));
            assert!(policy.argument_count as usize <= HOSTED_PROVIDER_EXPORT_ARG_CAP);
            assert!(policy.stack_qwords <= 8);
        }
    }

    #[test]
    fn ndis_provider_policy_pins_wide_open_adapter_shape() {
        let policy = hosted_provider_export_marshal_policy("ndis.sys", "NdisOpenAdapter").unwrap();
        assert_eq!(policy.argument_count, 11);
        assert_eq!(policy.stack_qwords, 7);
        assert_eq!(
            policy.args[4],
            HostedProviderArgumentMarshal::CallerInArray {
                count_arg: 5,
                element_size: 4,
                count_width: 4,
            }
        );
        assert_eq!(
            policy.args[8],
            HostedProviderArgumentMarshal::CallerInUnicodeString
        );
        assert_eq!(
            policy.args[10],
            HostedProviderArgumentMarshal::CallerInAnsiString
        );
        assert!(hosted_provider_export_marshal_policy("ndis.sys", "NdisMissing").is_none());
        assert!(hosted_provider_export_marshal_policy("tcpip.sys", "NdisOpenAdapter").is_none());
    }

    #[test]
    fn ndis_allocate_memory_policy_returns_caller_owned_pointer_from_length() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisAllocateMemoryWithTag").unwrap();
        assert_eq!(policy.argument_count, 3);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::CallerOutPointerFromLength { length_arg: 1 }
        );
        assert_eq!(policy.args[1], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(policy.args[2], HostedProviderArgumentMarshal::Scalar);
    }

    #[test]
    fn ndis_free_memory_policy_requires_owned_allocation() {
        let policy = hosted_provider_export_marshal_policy("ndis.sys", "NdisFreeMemory").unwrap();
        assert_eq!(policy.argument_count, 3);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::CallerInOwnedAllocation { length_arg: 1 }
        );
        assert_eq!(policy.args[1], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(policy.args[2], HostedProviderArgumentMarshal::Scalar);
    }

    #[test]
    fn ndis_configuration_policies_use_typed_copyouts() {
        let open =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisOpenConfiguration").unwrap();
        assert_eq!(open.argument_count, 3);
        assert_eq!(open.args[0], HostedProviderArgumentMarshal::CallerOutStatus);
        assert_eq!(open.args[1], HostedProviderArgumentMarshal::CallerOutHandle);
        assert_eq!(open.args[2], HostedProviderArgumentMarshal::ProviderHandle);

        let read =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisReadConfiguration").unwrap();
        assert_eq!(read.argument_count, 5);
        assert_eq!(read.args[0], HostedProviderArgumentMarshal::CallerOutStatus);
        assert_eq!(
            read.args[1],
            HostedProviderArgumentMarshal::CallerOutNdisConfigurationParameter
        );
        assert_eq!(read.args[2], HostedProviderArgumentMarshal::ProviderHandle);
        assert_eq!(
            read.args[3],
            HostedProviderArgumentMarshal::CallerInUnicodeString
        );
        assert_eq!(read.args[4], HostedProviderArgumentMarshal::Scalar);

        let network =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisReadNetworkAddress").unwrap();
        assert_eq!(network.argument_count, 4);
        assert_eq!(
            network.args[0],
            HostedProviderArgumentMarshal::CallerOutStatus
        );
        assert_eq!(
            network.args[1],
            HostedProviderArgumentMarshal::CallerOutNetworkAddress { length_arg: 2 }
        );
        assert_eq!(network.args[2], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(
            network.args[3],
            HostedProviderArgumentMarshal::ProviderHandle
        );

        let close =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisCloseConfiguration").unwrap();
        assert_eq!(close.argument_count, 1);
        assert_eq!(close.args[0], HostedProviderArgumentMarshal::ProviderHandle);

        let init =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisInitUnicodeString").unwrap();
        assert_eq!(init.argument_count, 2);
        assert_eq!(
            init.args[0],
            HostedProviderArgumentMarshal::CallerOutUnicodeStringFromSource { source_arg: 1 }
        );
        assert_eq!(init.args[1], HostedProviderArgumentMarshal::Scalar);
    }

    #[test]
    fn ndis_schedule_work_item_policy_uses_typed_shadow() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisScheduleWorkItem").unwrap();
        assert_eq!(policy.argument_count, 1);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::CallerInOutNdisWorkItem
        );
        assert_eq!(
            policy.result_semantics,
            HostedProviderExportResultSemantics::NtStatus
        );
    }

    #[test]
    fn ndis_read_pci_policy_copies_caller_output_buffer() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisReadPciSlotInformation")
                .unwrap();
        assert_eq!(policy.argument_count, 5);
        assert_eq!(policy.stack_qwords, 1);
        assert_eq!(
            policy.args[3],
            HostedProviderArgumentMarshal::CallerOutBuffer { length_arg: 4 }
        );

        let write =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisWritePciSlotInformation")
                .unwrap();
        assert_eq!(write.argument_count, 5);
        assert_eq!(write.stack_qwords, 1);
        assert_eq!(
            write.args[3],
            HostedProviderArgumentMarshal::CallerInBuffer { length_arg: 4 }
        );
    }

    #[test]
    fn ndis_remove_miniport_policy_maps_provider_handle() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMRemoveMiniport").unwrap();
        assert_eq!(policy.argument_count, 1);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::ProviderHandle
        );
    }

    #[test]
    fn ndis_query_adapter_resources_policy_uses_size_pointer() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMQueryAdapterResources")
                .unwrap();
        assert_eq!(policy.argument_count, 4);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::CallerOutStatus
        );
        assert_eq!(
            policy.args[2],
            HostedProviderArgumentMarshal::CallerInOutResourceList {
                length_pointer_arg: 3
            }
        );
        assert_eq!(
            policy.args[3],
            HostedProviderArgumentMarshal::CallerInOutU32
        );
        assert_eq!(
            policy.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
    }

    #[test]
    fn ndis_get_device_property_uses_nullable_typed_outputs() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMGetDeviceProperty").unwrap();
        assert_eq!(policy.argument_count, 6);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::ProviderHandle
        );
        let mut index = 1usize;
        while index < 6 {
            assert_eq!(
                policy.args[index],
                HostedProviderArgumentMarshal::CallerOutNdisDeviceProperty { kind: index as u8 }
            );
            index += 1;
        }
        assert_eq!(
            policy.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
    }

    #[test]
    fn ndis_port_and_mmio_mapping_policies_are_typed_resources() {
        let port =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMRegisterIoPortRange").unwrap();
        assert_eq!(port.argument_count, 4);
        assert_eq!(
            port.args[0],
            HostedProviderArgumentMarshal::CallerOutIoPortRange {
                initial_port_arg: 2,
                length_arg: 3,
            }
        );

        let mmio = hosted_provider_export_marshal_policy("ndis.sys", "NdisMMapIoSpace").unwrap();
        assert_eq!(mmio.argument_count, 4);
        assert_eq!(
            mmio.args[0],
            HostedProviderArgumentMarshal::CallerOutMmioMapping {
                physical_address_arg: 2,
                length_arg: 3,
            }
        );
    }

    #[test]
    fn ndis_shared_memory_policies_are_typed_dma_common_buffers() {
        let alloc =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMAllocateSharedMemory").unwrap();
        assert_eq!(alloc.argument_count, 5);
        assert_eq!(
            alloc.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
        assert_eq!(
            alloc.args[3],
            HostedProviderArgumentMarshal::CallerOutDmaCommonBuffer { length_arg: 1 }
        );
        assert_eq!(
            alloc.args[4],
            HostedProviderArgumentMarshal::CallerOutPhysicalAddress
        );

        let free =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMFreeSharedMemory").unwrap();
        assert_eq!(free.argument_count, 5);
        assert_eq!(
            free.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
        assert_eq!(
            free.args[3],
            HostedProviderArgumentMarshal::CallerInDmaCommonBuffer {
                length_arg: 1,
                physical_address_arg: 4,
            }
        );
    }

    #[test]
    fn ndis_packet_lifetime_policies_are_typed_shadows() {
        let alloc =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisAllocatePacket").unwrap();
        assert_eq!(alloc.argument_count, 3);
        assert_eq!(
            alloc.args[0],
            HostedProviderArgumentMarshal::CallerOutStatus
        );
        assert_eq!(
            alloc.args[1],
            HostedProviderArgumentMarshal::CallerOutNdisPacket
        );
        assert_eq!(alloc.args[2], HostedProviderArgumentMarshal::ProviderHandle);

        let free = hosted_provider_export_marshal_policy("ndis.sys", "NdisFreePacket").unwrap();
        assert_eq!(free.argument_count, 1);
        assert_eq!(
            free.args[0],
            HostedProviderArgumentMarshal::CallerInOutPacket
        );
        assert_eq!(
            free.side_effect,
            HostedProviderExportSideEffect::NdisPacketFree
        );

        let pool =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisAllocatePacketPool").unwrap();
        assert_eq!(pool.argument_count, 4);
        assert_eq!(pool.args[0], HostedProviderArgumentMarshal::CallerOutStatus);
        assert_eq!(pool.args[1], HostedProviderArgumentMarshal::CallerOutHandle);
        assert_eq!(pool.args[2], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(pool.args[3], HostedProviderArgumentMarshal::Scalar);

        let pool_ex =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisAllocatePacketPoolEx").unwrap();
        assert_eq!(pool_ex.argument_count, 5);
        assert_eq!(
            pool_ex.args[0],
            HostedProviderArgumentMarshal::CallerOutStatus
        );
        assert_eq!(
            pool_ex.args[1],
            HostedProviderArgumentMarshal::CallerOutHandle
        );
        assert_eq!(pool_ex.args[2], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(pool_ex.args[3], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(pool_ex.args[4], HostedProviderArgumentMarshal::Scalar);
    }

    #[test]
    fn ndis_buffer_lifetime_policies_are_typed_shadows() {
        let alloc =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisAllocateBuffer").unwrap();
        assert_eq!(alloc.argument_count, 5);
        assert_eq!(
            alloc.args[0],
            HostedProviderArgumentMarshal::CallerOutStatus
        );
        assert_eq!(
            alloc.args[1],
            HostedProviderArgumentMarshal::CallerOutNdisBuffer {
                virtual_address_arg: 3,
                length_arg: 4,
            }
        );
        assert_eq!(alloc.args[2], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(alloc.args[3], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(alloc.args[4], HostedProviderArgumentMarshal::Scalar);
    }

    #[test]
    fn ndis_get_first_buffer_policy_maps_typed_outputs() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisGetFirstBufferFromPacket")
                .unwrap();
        assert_eq!(policy.argument_count, 5);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::CallerInPacket
        );
        assert_eq!(
            policy.args[1],
            HostedProviderArgumentMarshal::CallerOutNdisBufferFromPacket
        );
        assert_eq!(
            policy.args[2],
            HostedProviderArgumentMarshal::CallerOutNdisBufferVirtualAddress
        );
        assert_eq!(policy.args[3], HostedProviderArgumentMarshal::CallerOutU32);
        assert_eq!(policy.args[4], HostedProviderArgumentMarshal::CallerOutU32);
    }

    #[test]
    fn ndis_return_packets_policy_maps_packet_arrays() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisReturnPackets").unwrap();
        assert_eq!(policy.argument_count, 2);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::CallerInPointerArray { count_arg: 1 }
        );
        assert_eq!(policy.args[1], HostedProviderArgumentMarshal::Scalar);
    }

    #[test]
    fn ndis_internal_packet_indicate_policy_maps_packet_arrays_with_copyback() {
        let policy =
            hosted_provider_internal_marshal_policy("ndis.sys", "MiniIndicateReceivePacket")
                .unwrap();
        assert_eq!(policy.argument_count, 3);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::ProviderHandle
        );
        assert_eq!(
            policy.args[1],
            HostedProviderArgumentMarshal::CallerInOutPacketArray { count_arg: 2 }
        );
        assert_eq!(policy.args[2], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(
            policy.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
    }

    #[test]
    fn ndis_send_complete_policy_maps_packet_completion() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMSendComplete").unwrap();
        assert_eq!(policy.argument_count, 3);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::ProviderHandle
        );
        assert_eq!(
            policy.args[1],
            HostedProviderArgumentMarshal::CallerInOutPacket
        );
        assert_eq!(policy.args[2], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(
            policy.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
    }

    #[test]
    fn ndis_transfer_data_complete_policy_maps_packet_completion() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMTransferDataComplete").unwrap();
        assert_eq!(policy.argument_count, 4);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::ProviderHandle
        );
        assert_eq!(
            policy.args[1],
            HostedProviderArgumentMarshal::CallerInOutPacket
        );
        assert_eq!(policy.args[2], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(policy.args[3], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(
            policy.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
    }

    #[test]
    fn ndis_interrupt_policies_use_typed_miniport_interrupt_storage() {
        assert_eq!(NDIS_MINIPORT_INTERRUPT_LEN_X64, 0x98);

        let register =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMRegisterInterrupt").unwrap();
        assert_eq!(register.argument_count, 7);
        assert_eq!(
            register.args[0],
            HostedProviderArgumentMarshal::CallerInOutMiniportInterrupt
        );
        assert_eq!(register.stack_qwords, 3);
        assert_eq!(
            register.result_semantics,
            HostedProviderExportResultSemantics::NtStatus
        );

        let deregister =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMDeregisterInterrupt").unwrap();
        assert_eq!(deregister.argument_count, 1);
        assert_eq!(
            deregister.args[0],
            HostedProviderArgumentMarshal::CallerInOutMiniportInterrupt
        );
        assert_eq!(
            deregister.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
        assert_eq!(
            deregister.side_effect,
            HostedProviderExportSideEffect::NdisMiniportInterruptDeregistration
        );
    }

    #[test]
    fn ndis_timer_policies_use_typed_miniport_timer_storage() {
        assert_eq!(NDIS_MINIPORT_TIMER_LEN_X64, 0xa0);

        let initialize =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMInitializeTimer").unwrap();
        assert_eq!(initialize.argument_count, 4);
        assert_eq!(
            initialize.args[0],
            HostedProviderArgumentMarshal::CallerInOutMiniportTimer { allow_create: true }
        );
        assert_eq!(
            initialize.args[1],
            HostedProviderArgumentMarshal::ProviderHandle
        );
        assert_eq!(
            initialize.args[2],
            HostedProviderArgumentMarshal::CallerInMiniportTimerFunction
        );
        assert_eq!(
            initialize.args[3],
            HostedProviderArgumentMarshal::CallerContext
        );
        assert_eq!(
            initialize.result_semantics,
            HostedProviderExportResultSemantics::Void
        );

        let set = hosted_provider_export_marshal_policy("ndis.sys", "NdisMSetTimer").unwrap();
        assert_eq!(set.argument_count, 2);
        assert_eq!(
            set.args[0],
            HostedProviderArgumentMarshal::CallerInOutMiniportTimer {
                allow_create: false
            }
        );
        assert_eq!(set.args[1], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(
            set.result_semantics,
            HostedProviderExportResultSemantics::Void
        );

        let periodic =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMSetPeriodicTimer").unwrap();
        assert_eq!(periodic.argument_count, 2);
        assert_eq!(periodic.args[0], set.args[0]);
        assert_eq!(periodic.args[1], HostedProviderArgumentMarshal::Scalar);

        let cancel = hosted_provider_export_marshal_policy("ndis.sys", "NdisMCancelTimer").unwrap();
        assert_eq!(cancel.argument_count, 2);
        assert_eq!(cancel.args[0], set.args[0]);
        assert_eq!(cancel.args[1], HostedProviderArgumentMarshal::CallerOutU8);
        assert_eq!(
            cancel.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
    }

    #[test]
    fn ndis_void_exports_do_not_treat_rax_as_status() {
        for export in [
            "NdisInitializeWrapper",
            "NdisMSetAttributesEx",
            "NdisMInitializeTimer",
            "NdisMSetTimer",
            "NdisMSetPeriodicTimer",
            "NdisMCancelTimer",
            "NdisMGetDeviceProperty",
            "NdisMSleep",
            "NdisOpenConfiguration",
            "NdisCloseConfiguration",
            "NdisInitUnicodeString",
            "NdisReadConfiguration",
            "NdisReadNetworkAddress",
            "NdisMAllocateSharedMemory",
            "NdisMFreeSharedMemory",
            "NdisMDeregisterInterrupt",
            "NdisMDeregisterIoPortRange",
            "NdisMUnmapIoSpace",
            "EthFilterDprIndicateReceive",
            "EthFilterDprIndicateReceiveComplete",
            "NdisMIndicateStatus",
            "NdisWriteErrorLogEntry",
            "NdisMIndicateStatusComplete",
            "NdisMQueryInformationComplete",
            "NdisMSetInformationComplete",
            "NdisMResetComplete",
            "NdisTerminateWrapper",
            "NdisFreeMemory",
            "NdisTransferData",
            "NdisSend",
            "NdisMSendComplete",
            "NdisMSendResourcesAvailable",
            "NdisMTransferDataComplete",
            "NdisRequest",
            "NdisDeregisterProtocol",
            "NdisOpenAdapter",
            "NdisCloseAdapter",
            "NdisRegisterProtocol",
            "NdisFreePacket",
            "NdisAllocatePacket",
            "NdisGetFirstBufferFromPacket",
            "NdisAllocateBufferPool",
            "NdisFreeBufferPool",
            "NdisAllocatePacketPool",
            "NdisAllocatePacketPoolEx",
            "NdisFreePacketPool",
            "NdisAllocateBuffer",
            "NdisReturnPackets",
        ] {
            let policy = hosted_provider_export_marshal_policy("ndis.sys", export)
                .unwrap_or_else(|| panic!("missing policy for {}", export));
            assert_eq!(
                policy.result_semantics,
                HostedProviderExportResultSemantics::Void
            );
        }
    }

    #[test]
    fn ndis_shared_data_alignment_policy_is_scalar_return_only() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisGetSharedDataAlignment")
                .unwrap();
        assert_eq!(policy.argument_count, 0);
        assert_eq!(
            policy.result_semantics,
            HostedProviderExportResultSemantics::NtStatus
        );
    }

    #[test]
    fn ndis_buffer_span_policy_treats_buffer_as_typed_mdl_header() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NDIS_BUFFER_TO_SPAN_PAGES").unwrap();
        assert_eq!(policy.argument_count, 1);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::CallerInNdisBuffer
        );
    }

    #[test]
    fn ndis_receive_indication_policies_map_real_provider_helpers() {
        let receive =
            hosted_provider_export_marshal_policy("ndis.sys", "EthFilterDprIndicateReceive")
                .unwrap();
        assert_eq!(receive.argument_count, 8);
        assert_eq!(receive.stack_qwords, 4);
        assert_eq!(
            receive.args[0],
            HostedProviderArgumentMarshal::ProviderHandle
        );
        assert_eq!(receive.args[1], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(
            receive.args[2],
            HostedProviderArgumentMarshal::CallerInBuffer { length_arg: 4 }
        );
        assert_eq!(
            receive.args[3],
            HostedProviderArgumentMarshal::CallerInBuffer { length_arg: 4 }
        );
        assert_eq!(receive.args[4], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(
            receive.args[5],
            HostedProviderArgumentMarshal::CallerInBuffer { length_arg: 6 }
        );
        assert_eq!(receive.args[6], HostedProviderArgumentMarshal::Scalar);
        assert_eq!(receive.args[7], HostedProviderArgumentMarshal::Scalar);

        let status =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisMIndicateStatus").unwrap();
        assert_eq!(status.argument_count, 4);
        assert_eq!(
            status.args[2],
            HostedProviderArgumentMarshal::CallerInBuffer { length_arg: 3 }
        );
    }

    #[test]
    fn ndis_error_log_policy_bounds_varargs() {
        let policy =
            hosted_provider_export_marshal_policy("ndis.sys", "NdisWriteErrorLogEntry").unwrap();
        assert_eq!(policy.argument_count, HOSTED_PROVIDER_EXPORT_ARG_CAP as u8);
        assert_eq!(policy.stack_qwords, 8);
        assert_eq!(
            policy.args[0],
            HostedProviderArgumentMarshal::ProviderHandle
        );
        let mut index = 1usize;
        while index < HOSTED_PROVIDER_EXPORT_ARG_CAP {
            assert_eq!(policy.args[index], HostedProviderArgumentMarshal::Scalar);
            index += 1;
        }
        assert_eq!(
            policy.result_semantics,
            HostedProviderExportResultSemantics::Void
        );
    }

    #[test]
    fn ndis_miniport_block_callback_offsets_match_reactos_nt5_x64() {
        assert_eq!(
            NDIS_MINIPORT_BLOCK_MINIPORT_ADAPTER_CONTEXT_OFFSET_X64,
            0x18
        );
        assert_eq!(NDIS_MINIPORT_BLOCK_MINIPORT_NAME_OFFSET_X64, 0x20);
        assert_eq!(NDIS_MINIPORT_BLOCK_ETH_DB_OFFSET_X64, 0x190);
        assert_eq!(
            NDIS_MINIPORT_BLOCK_PACKET_INDICATE_HANDLER_OFFSET_X64,
            0x1b0
        );
        assert_eq!(NDIS_MINIPORT_BLOCK_SEND_COMPLETE_HANDLER_OFFSET_X64, 0x1b8);
        assert_eq!(NDIS_MINIPORT_BLOCK_SEND_RESOURCES_HANDLER_OFFSET_X64, 0x1c0);
        assert_eq!(NDIS_MINIPORT_BLOCK_RESET_COMPLETE_HANDLER_OFFSET_X64, 0x1c8);
        assert_eq!(
            NDIS_MINIPORT_BLOCK_ETH_RX_INDICATE_HANDLER_OFFSET_X64,
            0x280
        );
        assert_eq!(
            NDIS_MINIPORT_BLOCK_ETH_RX_COMPLETE_HANDLER_OFFSET_X64,
            0x298
        );
        assert_eq!(NDIS_MINIPORT_BLOCK_STATUS_HANDLER_OFFSET_X64, 0x2b0);
        assert_eq!(
            NDIS_MINIPORT_BLOCK_STATUS_COMPLETE_HANDLER_OFFSET_X64,
            0x2b8
        );
        assert_eq!(NDIS_MINIPORT_BLOCK_TD_COMPLETE_HANDLER_OFFSET_X64, 0x2c0);
        assert_eq!(NDIS_MINIPORT_BLOCK_QUERY_COMPLETE_HANDLER_OFFSET_X64, 0x2c8);
        assert_eq!(NDIS_MINIPORT_BLOCK_SET_COMPLETE_HANDLER_OFFSET_X64, 0x2d0);
    }

    #[test]
    fn dc21x4_adapter_rx_ring_offsets_match_reactos_nt5_x64() {
        assert_eq!(DC21X4_ADAPTER_CURRENT_RBD_OFFSET_X64, 0x118);
        assert_eq!(DC21X4_ADAPTER_HEAD_RBD_OFFSET_X64, 0x120);
        assert_eq!(DC21X4_ADAPTER_TAIL_RBD_OFFSET_X64, 0x128);
    }

    #[test]
    fn ndis_miniport_characteristics_layout_follows_nt5_versions() {
        assert_eq!(
            ndis_miniport_characteristics_layout(3, 0, NDIS30_MINIPORT_CHARACTERISTICS_LEN_X64),
            Ok(NdisMiniportCharacteristicsLayout {
                required_len: NDIS30_MINIPORT_CHARACTERISTICS_LEN_X64,
                callback_count: 13,
            })
        );
        assert_eq!(
            ndis_miniport_characteristics_layout(4, 0, NDIS40_MINIPORT_CHARACTERISTICS_LEN_X64),
            Ok(NdisMiniportCharacteristicsLayout {
                required_len: NDIS40_MINIPORT_CHARACTERISTICS_LEN_X64,
                callback_count: 16,
            })
        );
        assert_eq!(
            ndis_miniport_characteristics_layout(5, 0, NDIS50_MINIPORT_CHARACTERISTICS_LEN_X64)
                .unwrap()
                .callback_count,
            22
        );
        assert_eq!(
            ndis_miniport_characteristics_layout(5, 1, NDIS51_MINIPORT_CHARACTERISTICS_LEN_X64)
                .unwrap()
                .callback_count,
            NDIS_MINIPORT_CHARACTERISTICS_CALLBACK_CAP as u8
        );
    }

    #[test]
    fn ndis_miniport_characteristics_callback_offsets_are_pointer_slots() {
        let layout =
            ndis_miniport_characteristics_layout(5, 1, NDIS51_MINIPORT_CHARACTERISTICS_LEN_X64)
                .unwrap();
        assert_eq!(layout.callback_offset(0), Some(0x08));
        assert_eq!(layout.callback_offset(15), Some(0x80));
        assert_eq!(layout.callback_offset(24), Some(0xc8));
        assert_eq!(layout.callback_offset(25), None);
    }

    #[test]
    fn ndis_miniport_characteristics_layout_rejects_bad_headers() {
        assert_eq!(
            ndis_miniport_characteristics_layout(5, 1, NDIS51_MINIPORT_CHARACTERISTICS_LEN_X64 - 1),
            Err(NdisMiniportCharacteristicsLayoutError::BufferTooSmall)
        );
        assert_eq!(
            ndis_miniport_characteristics_layout(5, 2, NDIS51_MINIPORT_CHARACTERISTICS_LEN_X64),
            Err(NdisMiniportCharacteristicsLayoutError::BadVersion)
        );
        assert_eq!(
            ndis_miniport_characteristics_layout(6, 0, NDIS51_MINIPORT_CHARACTERISTICS_LEN_X64),
            Err(NdisMiniportCharacteristicsLayoutError::BadVersion)
        );
    }

    #[test]
    fn ndis_protocol_characteristics_layout_follows_nt5_versions() {
        assert_eq!(
            ndis_protocol_characteristics_layout(3, 0, NDIS30_PROTOCOL_CHARACTERISTICS_LEN_X64),
            Ok(NdisProtocolCharacteristicsLayout {
                required_len: NDIS30_PROTOCOL_CHARACTERISTICS_LEN_X64,
                callback_count: 10,
            })
        );
        assert_eq!(
            ndis_protocol_characteristics_layout(4, 0, NDIS40_PROTOCOL_CHARACTERISTICS_LEN_X64),
            Ok(NdisProtocolCharacteristicsLayout {
                required_len: NDIS40_PROTOCOL_CHARACTERISTICS_LEN_X64,
                callback_count: 15,
            })
        );
        assert_eq!(
            ndis_protocol_characteristics_layout(5, 1, NDIS50_PROTOCOL_CHARACTERISTICS_LEN_X64)
                .unwrap()
                .callback_count,
            NDIS_PROTOCOL_CHARACTERISTICS_CALLBACK_CAP as u8
        );
    }

    #[test]
    fn ndis_protocol_characteristics_callback_offsets_match_x64_slots() {
        assert_eq!(NDIS_PROTOCOL_CHARACTERISTICS_NAME_OFFSET_X64, 0x58);

        let ndis40 =
            ndis_protocol_characteristics_layout(4, 0, NDIS40_PROTOCOL_CHARACTERISTICS_LEN_X64)
                .unwrap();
        assert_eq!(ndis40.callback_offset(0), Some(0x08));
        assert_eq!(ndis40.callback_offset(9), Some(0x50));
        assert_eq!(ndis40.callback_offset(10), Some(0x68));
        assert_eq!(ndis40.callback_offset(14), Some(0x88));
        assert_eq!(ndis40.callback_offset(15), None);

        let ndis50 =
            ndis_protocol_characteristics_layout(5, 0, NDIS50_PROTOCOL_CHARACTERISTICS_LEN_X64)
                .unwrap();
        assert_eq!(ndis50.callback_offset(15), Some(0xb0));
        assert_eq!(ndis50.callback_offset(18), Some(0xc8));
        assert_eq!(ndis50.callback_offset(19), None);
    }

    #[test]
    fn ndis_protocol_characteristics_layout_rejects_bad_headers() {
        assert_eq!(
            ndis_protocol_characteristics_layout(4, 0, NDIS40_PROTOCOL_CHARACTERISTICS_LEN_X64 - 1),
            Err(NdisProtocolCharacteristicsLayoutError::BufferTooSmall)
        );
        assert_eq!(
            ndis_protocol_characteristics_layout(5, 2, NDIS50_PROTOCOL_CHARACTERISTICS_LEN_X64),
            Err(NdisProtocolCharacteristicsLayoutError::BadVersion)
        );
        assert_eq!(
            ndis_protocol_characteristics_layout(6, 0, NDIS50_PROTOCOL_CHARACTERISTICS_LEN_X64),
            Err(NdisProtocolCharacteristicsLayoutError::BadVersion)
        );
    }

    #[test]
    fn provider_domain_classifies_absent_metadata_and_callable_domains() {
        assert_eq!(
            classify_hosted_provider_domain(None),
            Ok(HostedProviderDomainStatus::Absent)
        );

        let metadata_only = HostedProviderDomainDescriptor {
            image_offset: 0,
            image_len: 0x12_345,
            image_frames: 0x13,
            pool_base: 0x8800_0000,
            pool_frames: 4,
            export_call_gate: 0,
            provider_domain_cookie: 0,
        };
        assert_eq!(
            classify_hosted_provider_domain(Some(metadata_only)),
            Ok(HostedProviderDomainStatus::MetadataOnly)
        );

        let callable = HostedProviderDomainDescriptor {
            export_call_gate: 0xfeed,
            provider_domain_cookie: 0x55aa,
            ..metadata_only
        };
        assert_eq!(
            classify_hosted_provider_domain(Some(callable)),
            Ok(HostedProviderDomainStatus::Callable(
                HostedProviderDomainBinding {
                    image_offset: callable.image_offset,
                    image_len: callable.image_len,
                    image_frames: callable.image_frames,
                    pool_base: callable.pool_base,
                    pool_frames: callable.pool_frames,
                    export_call_gate: callable.export_call_gate,
                    provider_domain_cookie: callable.provider_domain_cookie,
                }
            ))
        );
    }

    #[test]
    fn provider_domain_rejects_invalid_metadata() {
        let valid = HostedProviderDomainDescriptor {
            image_offset: 0,
            image_len: 0x1000,
            image_frames: 1,
            pool_base: 0x8800_0000,
            pool_frames: 1,
            export_call_gate: 0,
            provider_domain_cookie: 0,
        };
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                image_offset: 1,
                ..valid
            })),
            Err(HostedProviderDomainError::ImageOffsetUnaligned)
        );
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                image_len: 0,
                ..valid
            })),
            Err(HostedProviderDomainError::EmptyImage)
        );
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                image_len: 0x1001,
                ..valid
            })),
            Err(HostedProviderDomainError::ImageExceedsFrames)
        );
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                pool_frames: 0,
                ..valid
            })),
            Err(HostedProviderDomainError::EmptyPoolFrames)
        );
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                export_call_gate: 0xbeef,
                ..valid
            })),
            Err(HostedProviderDomainError::EmptyProviderDomainCookie)
        );
    }

    #[test]
    fn provider_export_call_plan_uses_gate_without_direct_client_jump() {
        let binding = HostedProviderDomainBinding {
            image_offset: 0x40_000,
            image_len: 0x20_000,
            image_frames: 0x20,
            pool_base: 0x8800_0000,
            pool_frames: 8,
            export_call_gate: 0xbeef,
            provider_domain_cookie: 0xfeed_cafe,
        };
        assert_eq!(
            plan_hosted_provider_export_call(binding, 0x1234),
            Ok(HostedProviderExportCallPlan {
                export_call_gate: 0xbeef,
                provider_domain_cookie: 0xfeed_cafe,
                provider_export_rva: 0x1234,
                provider_export_offset: 0x41_234,
            })
        );
        assert_eq!(
            plan_hosted_provider_export_call(binding, binding.image_len),
            Err(HostedProviderExportCallError::ExportOutsideImage)
        );
    }

    #[test]
    fn provider_import_binding_requires_private_dependency_without_callable_domain() {
        assert_eq!(
            plan_hosted_provider_import_binding(None, 0x1234),
            Ok(HostedProviderImportBinding::PrivateDependencyRequired)
        );

        assert_eq!(
            plan_hosted_provider_import_binding(
                Some(HostedProviderDomainDescriptor {
                    image_offset: 0,
                    image_len: 0x20_000,
                    image_frames: 0x20,
                    pool_base: 0x9000_0000,
                    pool_frames: 8,
                    export_call_gate: 0,
                    provider_domain_cookie: 0,
                }),
                0x1234,
            ),
            Ok(HostedProviderImportBinding::PrivateDependencyRequired)
        );
    }

    #[test]
    fn provider_import_binding_uses_callable_domain_export_plan() {
        assert_eq!(
            plan_hosted_provider_import_binding(
                Some(HostedProviderDomainDescriptor {
                    image_offset: 0x60_000,
                    image_len: 0x20_000,
                    image_frames: 0x20,
                    pool_base: 0x9000_0000,
                    pool_frames: 8,
                    export_call_gate: 0xcafe,
                    provider_domain_cookie: 0xabcd,
                }),
                0x2345,
            ),
            Ok(HostedProviderImportBinding::ProviderDomainCall(
                HostedProviderExportCallPlan {
                    export_call_gate: 0xcafe,
                    provider_domain_cookie: 0xabcd,
                    provider_export_rva: 0x2345,
                    provider_export_offset: 0x62_345,
                }
            ))
        );
    }

    #[test]
    fn provider_import_binding_reports_domain_and_export_errors() {
        assert_eq!(
            plan_hosted_provider_import_binding(
                Some(HostedProviderDomainDescriptor {
                    image_offset: 1,
                    image_len: 0x20_000,
                    image_frames: 0x20,
                    pool_base: 0x9000_0000,
                    pool_frames: 8,
                    export_call_gate: 0xcafe,
                    provider_domain_cookie: 0xabcd,
                }),
                0x1234,
            ),
            Err(HostedProviderImportBindingError::Domain(
                HostedProviderDomainError::ImageOffsetUnaligned
            ))
        );

        assert_eq!(
            plan_hosted_provider_import_binding(
                Some(HostedProviderDomainDescriptor {
                    image_offset: 0,
                    image_len: 0x20_000,
                    image_frames: 0x20,
                    pool_base: 0x9000_0000,
                    pool_frames: 8,
                    export_call_gate: 0xcafe,
                    provider_domain_cookie: 0xabcd,
                }),
                0x20_000,
            ),
            Err(HostedProviderImportBindingError::Export(
                HostedProviderExportCallError::ExportOutsideImage
            ))
        );
    }

    #[test]
    fn provider_import_thunk_planner_assigns_fixed_slots() {
        let export_plan = HostedProviderExportCallPlan {
            export_call_gate: 0x1111_2222_3333_4444,
            provider_domain_cookie: 0xaaaa_bbbb_cccc_dddd,
            provider_export_rva: 0x4567,
            provider_export_offset: 0x84_567,
        };
        assert_eq!(
            plan_hosted_provider_import_thunk(0x7000_0000, 0x100, 3, export_plan),
            Ok(HostedProviderImportThunkPlan {
                thunk_va: 0x7000_00c0,
                thunk_offset: 0xc0,
                export_call_gate: export_plan.export_call_gate,
                provider_domain_cookie: export_plan.provider_domain_cookie,
                provider_export_rva: export_plan.provider_export_rva,
            })
        );
    }

    #[test]
    fn provider_import_thunk_planner_rejects_table_overflow() {
        let export_plan = HostedProviderExportCallPlan {
            export_call_gate: 0x1111_2222_3333_4444,
            provider_domain_cookie: 0xaaaa_bbbb_cccc_dddd,
            provider_export_rva: 0x4567,
            provider_export_offset: 0x84_567,
        };
        assert_eq!(
            plan_hosted_provider_import_thunk(0x7000_0000, 0x40, 2, export_plan),
            Err(HostedProviderImportThunkError::ThunkOutsideTable)
        );
        assert_eq!(
            plan_hosted_provider_import_thunk(0x7000_0000, u64::MAX, u64::MAX, export_plan),
            Err(HostedProviderImportThunkError::Overflow)
        );
        assert_eq!(
            plan_hosted_provider_import_thunk(u64::MAX, 0x100, 1, export_plan),
            Err(HostedProviderImportThunkError::Overflow)
        );
    }

    #[test]
    fn provider_import_thunk_encoder_preserves_win64_arguments_for_gate() {
        let thunk = HostedProviderImportThunkPlan {
            thunk_va: 0x7000_0040,
            thunk_offset: 0x40,
            export_call_gate: 0x1111_2222_3333_4444,
            provider_domain_cookie: 0x0102_0304_0506_0708,
            provider_export_rva: 0x5566_7788_99aa_bbcc,
        };
        let mut out = [0xcc; HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN as usize];
        encode_hosted_provider_import_thunk(thunk, &mut out).unwrap();
        assert_eq!(
            &out[..HOSTED_PROVIDER_IMPORT_THUNK_LEN],
            &[
                0x48, 0xb8, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x49, 0xba, 0x08, 0x07,
                0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x49, 0xbb, 0x44, 0x44, 0x33, 0x33, 0x22, 0x22,
                0x11, 0x11, 0x41, 0xff, 0xe3,
            ]
        );
        assert!(out[HOSTED_PROVIDER_IMPORT_THUNK_LEN..]
            .iter()
            .all(|byte| *byte == 0xcc));

        let mut too_small = [0u8; HOSTED_PROVIDER_IMPORT_THUNK_LEN - 1];
        assert_eq!(
            encode_hosted_provider_import_thunk(thunk, &mut too_small),
            Err(HostedProviderImportThunkError::OutputTooSmall)
        );
    }

    #[test]
    fn provider_callback_thunk_planner_assigns_fixed_slots() {
        assert_eq!(
            plan_hosted_provider_callback_thunk(
                0x7100_0000,
                0x100,
                2,
                0x1111_2222_3333_4444,
                0xfeed_cafe_dead_beef,
            ),
            Ok(HostedProviderCallbackThunkPlan {
                thunk_va: 0x7100_0080,
                thunk_offset: 0x80,
                callback_gate: 0x1111_2222_3333_4444,
                callback_cookie: 0xfeed_cafe_dead_beef,
            })
        );
        assert_eq!(
            plan_hosted_provider_callback_thunk(0x7100_0000, 0x40, 1, 0x1, 0x2),
            Err(HostedProviderImportThunkError::ThunkOutsideTable)
        );
        assert_eq!(
            plan_hosted_provider_callback_thunk(u64::MAX, 0x100, 1, 0x1, 0x2),
            Err(HostedProviderImportThunkError::Overflow)
        );
    }

    #[test]
    fn provider_callback_thunk_encoder_preserves_callback_arguments() {
        let thunk = HostedProviderCallbackThunkPlan {
            thunk_va: 0x7100_0040,
            thunk_offset: 0x40,
            callback_gate: 0x1111_2222_3333_4444,
            callback_cookie: 0x0102_0304_0506_0708,
        };
        let mut out = [0xcc; HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN as usize];
        encode_hosted_provider_callback_thunk(thunk, &mut out).unwrap();
        assert_eq!(
            &out[..HOSTED_PROVIDER_CALLBACK_THUNK_LEN],
            &[
                0x48, 0xb8, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x49, 0xbb, 0x44, 0x44,
                0x33, 0x33, 0x22, 0x22, 0x11, 0x11, 0x41, 0xff, 0xe3,
            ]
        );
        assert!(out[HOSTED_PROVIDER_CALLBACK_THUNK_LEN..]
            .iter()
            .all(|byte| *byte == 0xcc));

        let mut too_small = [0u8; HOSTED_PROVIDER_CALLBACK_THUNK_LEN - 1];
        assert_eq!(
            encode_hosted_provider_callback_thunk(thunk, &mut too_small),
            Err(HostedProviderImportThunkError::OutputTooSmall)
        );
    }
}
