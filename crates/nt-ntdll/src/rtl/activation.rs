//! Activation-context stack layouts and transition validation.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{guid::Guid, path::DosPathType};
use crate::NtStatus;

pub const FRAME_FLAG_RELEASE_ON_DEACTIVATION: u32 = 0x01;
pub const FRAME_FLAG_NO_DEACTIVATE: u32 = 0x02;
pub const FRAME_FLAG_HEAP_ALLOCATED: u32 = 0x08;
pub const FRAME_FLAG_NOT_REALLY_ACTIVATED: u32 = 0x10;
pub const FRAME_FLAG_ACTIVATED: u32 = 0x20;
pub const FRAME_FLAG_DEACTIVATED: u32 = 0x40;
pub const DEACTIVATE_FLAG_FORCE_EARLY: u32 = 0x01;
pub const ACTIVATE_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION: u32 = 0x01;
pub const CALLER_FRAME_FORMAT_WHISTLER: u32 = 1;

pub const STATUS_SXS_EARLY_DEACTIVATION: NtStatus = 0xC015_000F;
pub const STATUS_SXS_INVALID_DEACTIVATION: NtStatus = 0xC015_0010;
pub const STATUS_SXS_CANT_GEN_ACTCTX: NtStatus = 0xC015_0002;
pub const STATUS_SXS_INVALID_ACTCTXDATA_FORMAT: NtStatus = 0xC015_0003;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
pub const STATUS_END_OF_FILE: NtStatus = 0xC000_0011;
pub const INVALID_COOKIE: usize = usize::MAX;
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ACTIVATION_PE_BYTES: usize = u32::MAX as usize;

pub const ACTCTX_MAGIC: u32 = 0xC07E_3E11;
pub const ACTCTX_FAKE_HANDLE: usize = 0x00F0_0BAA;
pub const ACTIVATION_CONTEXT_ZOMBIFIED: u32 = 0x0000_0001;
pub const ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID: u32 = 0x01;
pub const ACTCTX_FLAG_LANGID_VALID: u32 = 0x02;
pub const ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID: u32 = 0x04;
pub const ACTCTX_FLAG_RESOURCE_NAME_VALID: u32 = 0x08;
pub const ACTCTX_FLAG_SET_PROCESS_DEFAULT: u32 = 0x10;
pub const ACTCTX_FLAG_APPLICATION_NAME_VALID: u32 = 0x20;
pub const ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF: u32 = 0x40;
pub const ACTCTX_FLAG_HMODULE_VALID: u32 = 0x80;
pub const ACTCTX_FLAGS_ALL: u32 = 0xff;

pub const QUERY_FLAG_USE_ACTIVE: u32 = 0x01;
pub const QUERY_FLAG_IS_HMODULE: u32 = 0x02;
pub const QUERY_FLAG_IS_ADDRESS: u32 = 0x04;
pub const QUERY_FLAG_NO_ADDREF: u32 = 0x8000_0000;
pub const QUERY_FLAGS_ALL: u32 =
    QUERY_FLAG_USE_ACTIVE | QUERY_FLAG_IS_HMODULE | QUERY_FLAG_IS_ADDRESS | QUERY_FLAG_NO_ADDREF;
pub const ACTIVATION_CONTEXT_BASIC_INFORMATION_CLASS: u32 = 1;
pub const ACTIVATION_CONTEXT_BASIC_INFORMATION_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActCtxDescriptor {
    pub size: u32,
    pub flags: u32,
    pub source: usize,
    pub processor_architecture: u16,
    pub language_id: u16,
    pub assembly_directory: usize,
    pub resource_name: usize,
    pub application_name: usize,
    pub module: usize,
}

impl ActCtxDescriptor {
    pub fn validate(&self) -> Result<(), NtStatus> {
        if self.flags & !ACTCTX_FLAGS_ALL != 0 || self.size < 16 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        let required = [
            (ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID, 18usize),
            (ACTCTX_FLAG_LANGID_VALID, 20),
            (ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID, 32),
            (ACTCTX_FLAG_RESOURCE_NAME_VALID, 40),
            (ACTCTX_FLAG_APPLICATION_NAME_VALID, 48),
            (ACTCTX_FLAG_HMODULE_VALID, 56),
        ];
        for (flag, size) in required {
            if self.flags & flag != 0 && self.size < size as u32 {
                return Err(crate::STATUS_INVALID_PARAMETER);
            }
        }
        if self.flags & ACTCTX_FLAG_RESOURCE_NAME_VALID != 0 && self.resource_name == 0 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    pub fn uses_unsupported_resolution(&self) -> bool {
        self.flags & (ACTCTX_FLAG_SET_PROCESS_DEFAULT | ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationContextSourceMode {
    ManifestFile,
    LoadedModuleResource,
    PeFileResource,
}

pub fn classify_source_mode(
    descriptor: &ActCtxDescriptor,
) -> Result<ActivationContextSourceMode, NtStatus> {
    let resource = descriptor.flags & ACTCTX_FLAG_RESOURCE_NAME_VALID != 0;
    let module = descriptor.flags & ACTCTX_FLAG_HMODULE_VALID != 0;
    match (
        resource,
        module,
        descriptor.source != 0,
        descriptor.module != 0,
    ) {
        (false, _, true, _) => Ok(ActivationContextSourceMode::ManifestFile),
        (true, true, _, true) => Ok(ActivationContextSourceMode::LoadedModuleResource),
        (true, false, true, _) => Ok(ActivationContextSourceMode::PeFileResource),
        _ => Err(crate::STATUS_INVALID_PARAMETER),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedManifestSource {
    pub dos_path: Vec<u16>,
    pub nt_path: Vec<u16>,
}

/// Construct the sidecar path for an external PE source. Only an originally numeric selector
/// contributes its decimal id; pointer-form selectors, including `#123`, use `.manifest`.
pub fn associated_manifest_source(
    source: &ResolvedManifestSource,
    numeric_resource: Option<u16>,
) -> Option<ResolvedManifestSource> {
    fn append_suffix(path: &[u16], numeric_resource: Option<u16>) -> Option<Vec<u16>> {
        let mut result = Vec::new();
        result.try_reserve(path.len().checked_add(16)?).ok()?;
        result.extend_from_slice(path);
        if let Some(id) = numeric_resource.filter(|id| *id != 1) {
            result.push(b'.' as u16);
            let mut divisor = 10_000u16;
            while divisor > 1 && id / divisor == 0 {
                divisor /= 10;
            }
            loop {
                result.push(b'0' as u16 + (id / divisor) % 10);
                if divisor == 1 {
                    break;
                }
                divisor /= 10;
            }
        }
        result.extend(".manifest".encode_utf16());
        Some(result)
    }

    Some(ResolvedManifestSource {
        dos_path: append_suffix(&source.dos_path, numeric_resource)?,
        nt_path: append_suffix(&source.nt_path, numeric_resource)?,
    })
}

/// Resolve a manifest filename the same way CreateActCtx does: only a plain relative source is
/// first based on `assembly_directory`; the resulting name is then resolved against the CWD.
pub fn resolve_manifest_source(
    source: &[u16],
    assembly_directory: Option<&[u16]>,
    current_directory: &[u16],
) -> Option<ResolvedManifestSource> {
    if source.is_empty()
        || matches!(
            super::path::determine_dos_path_name_type(source),
            DosPathType::DriveRelative | DosPathType::RootLocalDevice | DosPathType::Unknown
        )
    {
        return None;
    }

    let candidate = if super::path::determine_dos_path_name_type(source) == DosPathType::Relative {
        if let Some(directory) = assembly_directory.filter(|directory| !directory.is_empty()) {
            let mut joined = Vec::with_capacity(directory.len() + source.len() + 1);
            joined.extend_from_slice(directory);
            if !joined
                .last()
                .is_some_and(|unit| *unit == b'\\' as u16 || *unit == b'/' as u16)
            {
                joined.push(b'\\' as u16);
            }
            joined.extend_from_slice(source);
            joined
        } else {
            source.to_vec()
        }
    } else {
        source.to_vec()
    };
    let dos_path = super::environment::full_path_units(&candidate, current_directory);
    let nt_path = super::path::dos_path_name_to_nt_path_name(&dos_path)?;
    Some(ResolvedManifestSource { dos_path, nt_path })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestReadDisposition {
    Continue,
    Complete,
}

/// Validate one synchronous NtReadFile result before extending the manifest buffer.
pub fn manifest_read_disposition(
    total: usize,
    requested: usize,
    status: NtStatus,
    information: usize,
) -> Result<ManifestReadDisposition, NtStatus> {
    bounded_read_disposition(
        total,
        requested,
        status,
        information,
        MAX_MANIFEST_BYTES,
        STATUS_SXS_INVALID_ACTCTXDATA_FORMAT,
    )
}

/// Validate one synchronous bounded file read. The caller selects the maximum and overflow status.
pub fn bounded_read_disposition(
    total: usize,
    requested: usize,
    status: NtStatus,
    information: usize,
    maximum: usize,
    too_large_status: NtStatus,
) -> Result<ManifestReadDisposition, NtStatus> {
    if status == STATUS_END_OF_FILE {
        return if information == 0 {
            Ok(ManifestReadDisposition::Complete)
        } else {
            Err(too_large_status)
        };
    }
    if status != crate::STATUS_SUCCESS {
        return Err(status);
    }
    if information > requested
        || total
            .checked_add(information)
            .is_none_or(|length| length > maximum)
    {
        return Err(too_large_status);
    }
    if information == 0 {
        Ok(ManifestReadDisposition::Complete)
    } else {
        Ok(ManifestReadDisposition::Continue)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DllRedirect {
    pub name: Vec<u16>,
    /// `None` means no attribute; `Some(empty)` preserves an explicit `loadFrom=""` segment.
    pub load_from: Option<Vec<u16>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompatibilityElement {
    pub id: Guid,
    pub kind: u32,
    pub max_version_tested: u64,
}

pub const COMPATIBILITY_ELEMENT_TYPE_OS: u32 = 1;
pub const COMPATIBILITY_ELEMENT_TYPE_MAX_VERSION_TESTED: u32 = 3;
pub const RUN_LEVEL_UNSPECIFIED: u32 = 0;
pub const RUN_LEVEL_AS_INVOKER: u32 = 1;
pub const RUN_LEVEL_HIGHEST_AVAILABLE: u32 = 2;
pub const RUN_LEVEL_REQUIRE_ADMIN: u32 = 3;

#[repr(C)]
pub struct ActivationContextObject {
    magic: AtomicU32,
    references: AtomicU32,
    flags: AtomicU32,
    pub source: Vec<u16>,
    pub application_directory: Vec<u16>,
    pub assembly_directory: Vec<u16>,
    pub encoded_assembly_identity: Vec<u16>,
    pub file_count: u32,
    pub compatibility: Vec<CompatibilityElement>,
    pub run_level: u32,
    pub ui_access: u32,
    pub manifest: Vec<u8>,
    pub dll_redirects: Vec<DllRedirect>,
    pub dll_redirect_section: Vec<u8>,
    pub window_class_redirect_section: Vec<u8>,
    pub clr_surrogate_section: Vec<u8>,
    pub application_settings: Vec<super::activation_manifest::ManifestApplicationSetting>,
}

const _: () = assert!(core::mem::align_of::<ActivationContextObject>() <= 16);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationContextRegistry<const N: usize> {
    entries: [usize; N],
    len: usize,
}

impl<const N: usize> ActivationContextRegistry<N> {
    pub const fn new() -> Self {
        Self {
            entries: [0; N],
            len: 0,
        }
    }

    pub fn insert(&mut self, handle: usize) -> bool {
        if handle == 0 || handle == usize::MAX || self.contains(handle) {
            return false;
        }
        if self.len == N {
            return false;
        }
        self.entries[self.len] = handle;
        self.len += 1;
        true
    }

    pub fn contains(&self, handle: usize) -> bool {
        self.entries[..self.len].contains(&handle)
    }

    pub fn remove(&mut self, handle: usize) -> bool {
        let Some(index) = self.entries[..self.len]
            .iter()
            .position(|entry| *entry == handle)
        else {
            return false;
        };
        self.entries.copy_within(index + 1..self.len, index);
        self.len -= 1;
        self.entries[self.len] = 0;
        true
    }
}

impl<const N: usize> Default for ActivationContextRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivationContextObject {
    pub fn new(
        source: Vec<u16>,
        manifest: Vec<u8>,
        dll_redirects: Vec<DllRedirect>,
        dll_redirect_section: Vec<u8>,
        window_class_redirect_section: Vec<u8>,
        clr_surrogate_section: Vec<u8>,
        application_settings: Vec<super::activation_manifest::ManifestApplicationSetting>,
        encoded_assembly_identity: Vec<u16>,
    ) -> Self {
        let file_count = u32::try_from(dll_redirects.len()).unwrap_or(u32::MAX);
        Self {
            magic: AtomicU32::new(ACTCTX_MAGIC),
            references: AtomicU32::new(1),
            flags: AtomicU32::new(0),
            source,
            application_directory: Vec::new(),
            assembly_directory: Vec::new(),
            encoded_assembly_identity,
            file_count,
            compatibility: Vec::new(),
            run_level: RUN_LEVEL_UNSPECIFIED,
            ui_access: 0,
            manifest,
            dll_redirects,
            dll_redirect_section,
            window_class_redirect_section,
            clr_surrogate_section,
            application_settings,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic.load(Ordering::Acquire) == ACTCTX_MAGIC
    }

    pub fn reference_count(&self) -> u32 {
        self.references.load(Ordering::Acquire)
    }

    pub fn is_zombified(&self) -> bool {
        self.flags.load(Ordering::Acquire) & ACTIVATION_CONTEXT_ZOMBIFIED != 0
    }

    /// Mark the context zombified without changing its validity or reference lifetime.
    pub fn zombify(&self) {
        self.flags
            .fetch_or(ACTIVATION_CONTEXT_ZOMBIFIED, Ordering::AcqRel);
    }

    pub fn try_add_ref(&self) -> bool {
        if !self.is_valid() {
            return false;
        }
        let mut current = self.references.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(1) else {
                return false;
            };
            if current == 0 {
                return false;
            }
            match self.references.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Drop one reference. Returns `true` exactly once, when the owner must destroy the object.
    pub fn release_ref(&self) -> bool {
        if !self.is_valid() {
            return false;
        }
        let mut current = self.references.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return false;
            }
            match self.references.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) if current == 1 => {
                    self.magic.store(0, Ordering::Release);
                    return true;
                }
                Ok(_) => return false,
                Err(observed) => current = observed,
            }
        }
    }
}

pub fn validate_basic_query(flags: u32, buffer_size: usize) -> Result<(), NtStatus> {
    let _ = flags;
    if buffer_size < ACTIVATION_CONTEXT_BASIC_INFORMATION_SIZE {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationContextStackFrame {
    pub previous: u64,
    pub activation_context: u64,
    pub flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationContextStack {
    pub active_frame: u64,
    pub frame_list_cache_flink: u64,
    pub frame_list_cache_blink: u64,
    pub flags: u32,
    pub next_cookie_sequence_number: u32,
    pub stack_id: u32,
    pub padding: u32,
}

impl ActivationContextStack {
    pub const SIZE: usize = 40;

    pub fn new(address: u64) -> Self {
        Self {
            frame_list_cache_flink: address + 8,
            frame_list_cache_blink: address + 8,
            next_cookie_sequence_number: 1,
            stack_id: 1,
            ..Self::default()
        }
    }
}

impl ActivationContextStackFrame {
    pub const SIZE: usize = 24;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallerAllocatedFrameBasic {
    pub size: u64,
    pub format: u32,
    pub padding: u32,
    pub frame: ActivationContextStackFrame,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallerAllocatedFrameExtended {
    pub basic: CallerAllocatedFrameBasic,
    pub extra: [u64; 4],
}

impl CallerAllocatedFrameBasic {
    pub const SIZE: usize = 40;
}

impl CallerAllocatedFrameExtended {
    pub const SIZE: usize = 72;
}

const _: [(); ActivationContextStack::SIZE] = [(); core::mem::size_of::<ActivationContextStack>()];
const _: [(); ActivationContextStackFrame::SIZE] =
    [(); core::mem::size_of::<ActivationContextStackFrame>()];
const _: [(); CallerAllocatedFrameBasic::SIZE] =
    [(); core::mem::size_of::<CallerAllocatedFrameBasic>()];
const _: [(); CallerAllocatedFrameExtended::SIZE] =
    [(); core::mem::size_of::<CallerAllocatedFrameExtended>()];

pub fn heap_frame_flags(activate_flags: u32) -> u32 {
    FRAME_FLAG_HEAP_ALLOCATED
        | if activate_flags & ACTIVATE_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION != 0 {
            FRAME_FLAG_NO_DEACTIVATE | FRAME_FLAG_RELEASE_ON_DEACTIVATION
        } else {
            0
        }
}

pub fn release_count(flags: u32) -> usize {
    usize::from(flags & (FRAME_FLAG_HEAP_ALLOCATED | FRAME_FLAG_RELEASE_ON_DEACTIVATION) != 0)
}

pub fn validate_deactivation(
    frame_found: bool,
    frame_is_top: bool,
    frame_is_heap_allocated: bool,
    flags: u32,
) -> Result<(), NtStatus> {
    if flags & !DEACTIVATE_FLAG_FORCE_EARLY != 0 {
        return Err(crate::STATUS_INVALID_PARAMETER);
    }
    if !frame_found || !frame_is_heap_allocated {
        return Err(STATUS_SXS_INVALID_DEACTIVATION);
    }
    if !frame_is_top && flags & DEACTIVATE_FLAG_FORCE_EARLY == 0 {
        return Err(STATUS_SXS_EARLY_DEACTIVATION);
    }
    Ok(())
}

pub fn validate_activate_ex(flags: u32, teb_present: bool, context: usize) -> Result<(), NtStatus> {
    if flags & !ACTIVATE_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION != 0
        || !teb_present
        || context == usize::MAX
    {
        return Err(crate::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

pub fn validate_caller_frame(size: usize, format: u32) -> bool {
    size >= CallerAllocatedFrameBasic::SIZE && format == CALLER_FRAME_FORMAT_WHISTLER
}

pub fn caller_frame_can_deactivate(flags: u32) -> bool {
    flags & FRAME_FLAG_ACTIVATED != 0 && flags & FRAME_FLAG_DEACTIVATED == 0
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::*;

    #[test]
    fn stack_initializes_empty_cache_and_sequence() {
        let stack = ActivationContextStack::new(0x1000);
        assert_eq!(stack.active_frame, 0);
        assert_eq!(stack.frame_list_cache_flink, 0x1008);
        assert_eq!(stack.frame_list_cache_blink, 0x1008);
        assert_eq!(stack.next_cookie_sequence_number, 1);
        assert_eq!(stack.stack_id, 1);
    }

    #[test]
    fn deactivation_requires_a_live_cookie_and_top_order() {
        assert_eq!(
            validate_deactivation(false, false, false, 0),
            Err(STATUS_SXS_INVALID_DEACTIVATION)
        );
        assert_eq!(
            validate_deactivation(true, false, true, 0),
            Err(STATUS_SXS_EARLY_DEACTIVATION)
        );
        assert_eq!(
            validate_deactivation(true, false, true, DEACTIVATE_FLAG_FORCE_EARLY),
            Ok(())
        );
        assert_eq!(validate_deactivation(true, true, true, 0), Ok(()));
        assert_eq!(
            validate_deactivation(true, true, false, 0),
            Err(STATUS_SXS_INVALID_DEACTIVATION)
        );
        assert_eq!(
            validate_deactivation(true, true, true, 2),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn native_x64_frame_layouts_match_the_reactos_contract() {
        assert_eq!(
            core::mem::offset_of!(ActivationContextStack, active_frame),
            0
        );
        assert_eq!(
            core::mem::offset_of!(ActivationContextStack, frame_list_cache_flink),
            8
        );
        assert_eq!(core::mem::offset_of!(ActivationContextStack, flags), 24);
        assert_eq!(core::mem::offset_of!(ActivationContextStack, stack_id), 32);
        assert_eq!(core::mem::offset_of!(CallerAllocatedFrameBasic, frame), 16);
        assert_eq!(
            core::mem::offset_of!(CallerAllocatedFrameExtended, extra),
            40
        );
    }

    #[test]
    fn heap_frame_ownership_tracks_transferred_references() {
        let ordinary = heap_frame_flags(0);
        assert_eq!(release_count(ordinary), 1);

        let transferred = heap_frame_flags(ACTIVATE_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION);
        assert_ne!(transferred & FRAME_FLAG_RELEASE_ON_DEACTIVATION, 0);
        assert_ne!(transferred & FRAME_FLAG_NO_DEACTIVATE, 0);
        assert_eq!(release_count(transferred), 1);
        assert_eq!(release_count(FRAME_FLAG_ACTIVATED), 0);
    }

    #[test]
    fn activation_and_caller_frame_validation_rejects_invalid_native_inputs() {
        assert_eq!(validate_activate_ex(0, true, 1), Ok(()));
        assert_eq!(
            validate_activate_ex(2, true, 1),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            validate_activate_ex(0, false, 1),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            validate_activate_ex(0, true, usize::MAX),
            Err(crate::STATUS_INVALID_PARAMETER)
        );

        assert!(validate_caller_frame(CallerAllocatedFrameBasic::SIZE, 1));
        assert!(!validate_caller_frame(
            CallerAllocatedFrameBasic::SIZE - 1,
            1
        ));
        assert!(!validate_caller_frame(CallerAllocatedFrameBasic::SIZE, 0));
        assert!(caller_frame_can_deactivate(FRAME_FLAG_ACTIVATED));
        assert!(!caller_frame_can_deactivate(
            FRAME_FLAG_ACTIVATED | FRAME_FLAG_DEACTIVATED
        ));
    }

    #[test]
    fn actctx_descriptor_checks_flagged_field_boundaries() {
        for (flag, size) in [
            (ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID, 18),
            (ACTCTX_FLAG_LANGID_VALID, 20),
            (ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID, 32),
            (ACTCTX_FLAG_RESOURCE_NAME_VALID, 40),
            (ACTCTX_FLAG_APPLICATION_NAME_VALID, 48),
            (ACTCTX_FLAG_HMODULE_VALID, 56),
        ] {
            let descriptor = ActCtxDescriptor {
                size,
                flags: flag,
                source: 1,
                assembly_directory: 2,
                resource_name: 3,
                application_name: 4,
                module: 5,
                ..ActCtxDescriptor::default()
            };
            assert_eq!(descriptor.validate(), Ok(()));
            assert_eq!(
                ActCtxDescriptor {
                    size: size - 1,
                    ..descriptor
                }
                .validate(),
                Err(crate::STATUS_INVALID_PARAMETER)
            );
        }

        let mut descriptor = ActCtxDescriptor {
            size: 56,
            flags: ACTCTX_FLAG_RESOURCE_NAME_VALID,
            source: 1,
            resource_name: 2,
            ..ActCtxDescriptor::default()
        };
        descriptor.resource_name = 0;
        assert_eq!(descriptor.validate(), Err(crate::STATUS_INVALID_PARAMETER));
        descriptor.resource_name = 2;
        descriptor.flags |= 0x100;
        assert_eq!(descriptor.validate(), Err(crate::STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn activation_context_source_modes_require_real_inputs() {
        let manifest = ActCtxDescriptor {
            size: 56,
            source: 1,
            ..ActCtxDescriptor::default()
        };
        assert_eq!(
            classify_source_mode(&manifest),
            Ok(ActivationContextSourceMode::ManifestFile)
        );
        assert_eq!(
            classify_source_mode(&ActCtxDescriptor {
                flags: ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID,
                resource_name: 1,
                module: 2,
                ..manifest
            }),
            Ok(ActivationContextSourceMode::LoadedModuleResource)
        );
        assert_eq!(
            classify_source_mode(&ActCtxDescriptor {
                flags: ACTCTX_FLAG_RESOURCE_NAME_VALID,
                resource_name: 1,
                ..manifest
            }),
            Ok(ActivationContextSourceMode::PeFileResource)
        );
        assert_eq!(
            classify_source_mode(&ActCtxDescriptor {
                source: 0,
                ..manifest
            }),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn manifest_sources_resolve_against_assembly_directory_then_cwd() {
        let wide = |value: &str| value.encode_utf16().collect::<Vec<_>>();
        let resolved = resolve_manifest_source(
            &wide("service.manifest"),
            Some(&wide("side\\manifests")),
            &wide("C:\\ReactOS\\System32"),
        )
        .unwrap();
        assert_eq!(
            String::from_utf16_lossy(&resolved.dos_path),
            "C:\\ReactOS\\System32\\side\\manifests\\service.manifest"
        );
        assert_eq!(
            String::from_utf16_lossy(&resolved.nt_path),
            "\\??\\C:\\ReactOS\\System32\\side\\manifests\\service.manifest"
        );

        let absolute = resolve_manifest_source(
            &wide("D:\\manifests\\service.manifest"),
            Some(&wide("ignored")),
            &wide("C:\\ReactOS"),
        )
        .unwrap();
        assert_eq!(
            String::from_utf16_lossy(&absolute.dos_path),
            "D:\\manifests\\service.manifest"
        );
        assert!(
            resolve_manifest_source(&wide("C:relative.manifest"), None, &wide("C:\\x")).is_none()
        );
    }

    #[test]
    fn associated_manifest_suffix_uses_only_original_numeric_selectors() {
        let wide = |value: &str| value.encode_utf16().collect::<Vec<_>>();
        let source = ResolvedManifestSource {
            dos_path: wide("C:\\ReactOS\\app.exe"),
            nt_path: wide("\\??\\C:\\ReactOS\\app.exe"),
        };
        for (numeric, expected) in [
            (Some(1), "C:\\ReactOS\\app.exe.manifest"),
            (Some(2), "C:\\ReactOS\\app.exe.2.manifest"),
            (Some(u16::MAX), "C:\\ReactOS\\app.exe.65535.manifest"),
            (None, "C:\\ReactOS\\app.exe.manifest"),
        ] {
            let sidecar = associated_manifest_source(&source, numeric).unwrap();
            assert_eq!(String::from_utf16_lossy(&sidecar.dos_path), expected);
            assert!(String::from_utf16_lossy(&sidecar.nt_path).ends_with(&expected[3..]));
        }
    }

    #[test]
    fn manifest_read_results_are_bounded_and_require_consistent_counts() {
        assert_eq!(
            manifest_read_disposition(0, 4096, crate::STATUS_SUCCESS, 1024),
            Ok(ManifestReadDisposition::Continue)
        );
        assert_eq!(
            manifest_read_disposition(1024, 4096, crate::STATUS_SUCCESS, 0),
            Ok(ManifestReadDisposition::Complete)
        );
        assert_eq!(
            manifest_read_disposition(1024, 4096, STATUS_END_OF_FILE, 0),
            Ok(ManifestReadDisposition::Complete)
        );
        assert_eq!(
            manifest_read_disposition(0, 8, crate::STATUS_SUCCESS, 9),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        assert_eq!(
            manifest_read_disposition(MAX_MANIFEST_BYTES, 1, crate::STATUS_SUCCESS, 1),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        assert_eq!(
            manifest_read_disposition(0, 1, STATUS_END_OF_FILE, 1),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
        assert_eq!(
            bounded_read_disposition(7, 2, crate::STATUS_SUCCESS, 2, 8, 0xdead_beef),
            Err(0xdead_beef)
        );
    }

    #[test]
    fn activation_object_reference_lifetime_is_atomic_and_bounded() {
        let object = ActivationContextObject::new(
            Vec::new(),
            b"<assembly/>".to_vec(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(object.is_valid());
        assert_eq!(object.reference_count(), 1);
        assert!(object.try_add_ref());
        assert_eq!(object.reference_count(), 2);
        assert!(!object.release_ref());
        assert_eq!(object.reference_count(), 1);
        assert!(object.release_ref());
        assert!(!object.is_valid());
        assert!(!object.try_add_ref());
        assert!(!object.release_ref());
    }

    #[test]
    fn zombifying_activation_object_is_idempotent_and_preserves_lifetime() {
        let object = ActivationContextObject::new(
            Vec::new(),
            b"<assembly/>".to_vec(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(!object.is_zombified());
        assert_eq!(object.reference_count(), 1);

        object.zombify();
        object.zombify();
        assert!(object.is_zombified());
        assert!(object.is_valid());
        assert_eq!(object.reference_count(), 1);
        assert!(object.try_add_ref());
        assert_eq!(object.reference_count(), 2);
        assert!(!object.release_ref());
        assert!(object.is_zombified());
        assert!(object.release_ref());
        assert!(!object.is_valid());
    }

    #[test]
    fn basic_query_validates_flags_and_buffer_size() {
        assert_eq!(
            validate_basic_query(0, ACTIVATION_CONTEXT_BASIC_INFORMATION_SIZE - 1),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(validate_basic_query(u32::MAX, 16), Ok(()));
        assert_eq!(validate_basic_query(QUERY_FLAG_NO_ADDREF, 16), Ok(()));
    }

    #[test]
    fn activation_registry_rejects_unregistered_and_interior_handles() {
        let mut registry = ActivationContextRegistry::<2>::new();
        assert!(registry.insert(0x1000));
        assert!(registry.contains(0x1000));
        assert!(!registry.contains(0x1008));
        assert!(!registry.insert(0x1000));
        assert!(registry.insert(0x2000));
        assert!(!registry.insert(0x3000));
        assert!(registry.remove(0x1000));
        assert!(!registry.contains(0x1000));
        assert!(!registry.remove(0x1008));
    }
}
