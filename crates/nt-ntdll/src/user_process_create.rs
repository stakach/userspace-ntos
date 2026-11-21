//! `NtCreateUserProcess`: the combined process-and-initial-thread creation service.
//!
//! kernel32 takes this path instead of `NtCreateProcessEx` + `NtCreateThread` whenever a process
//! is created with an explicit user token, an attribute list, or a job list
//! (`BasepCreateUserProcess`). The pinned kernel implements the service as a fixed sequence of the
//! ordinary native services (`ntoskrnl/ps/process.c`, `NtCreateUserProcess`): open the image,
//! create its image section, create the process, read the image information and the PEB address,
//! assign the primary token, write the process parameters, create the initial thread. This module
//! owns that sequence, its argument decoding and its failure contract; every effect is one of the
//! native services behind [`UserProcessOps`], so the executive needs no second copy of process
//! creation.

use alloc::vec::Vec;
use core::fmt::Write;
use nt_printf::record::RecordBuffer;

/// `STATUS_INVALID_PARAMETER`.
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// `STATUS_ACCESS_DENIED`.
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// `STATUS_ACCESS_VIOLATION`.
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// `STATUS_NOT_SUPPORTED`.
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// `STATUS_INVALID_IMAGE_FORMAT`.
pub const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
/// `STATUS_INVALID_HANDLE`.
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// `sizeof(PS_CREATE_INFO)` on x64.
pub const PS_CREATE_INFO_SIZE: usize = 0x58;
/// `sizeof(PS_ATTRIBUTE)` on x64: Attribute, Size, Value, ReturnLength.
pub const PS_ATTRIBUTE_SIZE: usize = 0x20;
/// `FIELD_OFFSET(PS_ATTRIBUTE_LIST, Attributes)`.
pub const PS_ATTRIBUTE_LIST_HEADER: usize = 8;
/// `sizeof(SECTION_IMAGE_INFORMATION)` on x64.
pub const SECTION_IMAGE_INFORMATION_SIZE: usize = 0x40;

/// `PS_CREATE_STATE`.
pub const PS_CREATE_INITIAL_STATE: u32 = 0;
pub const PS_CREATE_FAIL_ON_FILE_OPEN: u32 = 1;
pub const PS_CREATE_FAIL_ON_SECTION_CREATE: u32 = 2;
pub const PS_CREATE_FAIL_EXE_FORMAT: u32 = 3;
pub const PS_CREATE_SUCCESS: u32 = 6;

/// `PS_ATTRIBUTE_NUM` values (the low 16 bits of `PS_ATTRIBUTE::Attribute`).
pub const PS_ATTRIBUTE_PARENT_PROCESS: u64 = 0;
pub const PS_ATTRIBUTE_DEBUG_PORT: u64 = 1;
pub const PS_ATTRIBUTE_TOKEN: u64 = 2;
pub const PS_ATTRIBUTE_CLIENT_ID: u64 = 3;
pub const PS_ATTRIBUTE_IMAGE_NAME: u64 = 5;
pub const PS_ATTRIBUTE_IMAGE_INFO: u64 = 6;
pub const PS_ATTRIBUTE_HANDLE_LIST: u64 = 11;
pub const PS_ATTRIBUTE_MITIGATION_OPTIONS: u64 = 16;
pub const PS_ATTRIBUTE_CHILD_PROCESS_POLICY: u64 = 20;
pub const PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: u64 = 21;
pub const PS_ATTRIBUTE_BNO_ISOLATION: u64 = 24;
pub const PS_ATTRIBUTE_COMPONENT_FILTER: u64 = 29;

/// `PROCESS_CREATE_FLAGS_LEGAL_MASK`.
pub const PROCESS_CREATE_FLAGS_LEGAL_MASK: u32 = 0x1F;
/// `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`.
pub const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x1;

/// `SYNCHRONIZE | FILE_EXECUTE`: what an image needs to back a `PAGE_EXECUTE` image section.
pub const IMAGE_FILE_ACCESS: u32 = 0x0010_0000 | 0x0020;

/// The caller's `PS_CREATE_INFO::InitState`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CreateInfoInput {
    /// `WriteOutputOnExit`: the caller wants the image File and Section handles back.
    pub write_output_on_exit: bool,
    /// `ProhibitedImageCharacteristics`: `IMAGE_FILE_*` bits the image must not carry.
    pub prohibited_image_characteristics: u16,
    /// `AdditionalFileAccess`, added to the image open when the handles are returned.
    pub additional_file_access: u32,
}

/// Decode `PS_CREATE_INFO` as the service receives it: exact size, initial state.
pub fn decode_create_info(bytes: &[u8]) -> Result<CreateInfoInput, u32> {
    if bytes.len() < PS_CREATE_INFO_SIZE
        || read_u64(bytes, 0) != PS_CREATE_INFO_SIZE as u64
        || read_u32(bytes, 8) != PS_CREATE_INITIAL_STATE
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let init_flags = read_u32(bytes, 0x10);
    Ok(CreateInfoInput {
        write_output_on_exit: init_flags & 1 != 0,
        prohibited_image_characteristics: (init_flags >> 16) as u16,
        additional_file_access: read_u32(bytes, 0x14),
    })
}

/// The attributes the service acts on.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Attributes {
    /// Address and byte length of the NT image path (`PsAttributeImageName`).
    pub image_name: (u64, usize),
    /// `PsAttributeParentProcess`; absent means the calling process.
    pub parent_process: Option<u64>,
    /// `PsAttributeDebugPort`.
    pub debug_port: u64,
    /// `PsAttributeToken`: the primary token the new process runs under.
    pub token: Option<u64>,
    /// Address that receives the initial thread's `CLIENT_ID` (`PsAttributeClientId`).
    pub client_id_out: u64,
    /// Address that receives `SECTION_IMAGE_INFORMATION` (`PsAttributeImageInfo`).
    pub image_info_out: u64,
    /// `PsAttributeHandleList`: address and byte size of the `HANDLE` array that restricts the
    /// handles the new process inherits.
    pub handle_list: Option<(u64, u64)>,
}

/// Decode a `PS_ATTRIBUTE_LIST` (`bytes` is exactly `TotalLength` bytes).
///
/// The image name is required. An explicit inherited-handle list is carried to process creation.
/// Attributes the pinned kernel acts on but this service cannot honour (mitigation and policy
/// options, object-directory isolation) are refused rather than dropped; attribute numbers the pinned kernel itself ignores stay
/// ignored.
pub fn decode_attribute_list(bytes: &[u8]) -> Result<Attributes, u32> {
    if bytes.len() < PS_ATTRIBUTE_LIST_HEADER + PS_ATTRIBUTE_SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut attributes = Attributes::default();
    for entry in bytes[PS_ATTRIBUTE_LIST_HEADER..].chunks_exact(PS_ATTRIBUTE_SIZE) {
        let number = read_u64(entry, 0) & 0xFFFF;
        let size = read_u64(entry, 8);
        let value = read_u64(entry, 0x10);
        match number {
            PS_ATTRIBUTE_IMAGE_NAME => {
                let Ok(size) = usize::try_from(size) else {
                    return Err(STATUS_INVALID_PARAMETER);
                };
                attributes.image_name = (value, size);
            }
            PS_ATTRIBUTE_PARENT_PROCESS => attributes.parent_process = Some(value),
            PS_ATTRIBUTE_DEBUG_PORT => attributes.debug_port = value,
            PS_ATTRIBUTE_TOKEN => attributes.token = Some(value),
            PS_ATTRIBUTE_CLIENT_ID => attributes.client_id_out = value,
            PS_ATTRIBUTE_IMAGE_INFO => attributes.image_info_out = value,
            // The executive validates the array (whole handles, inheritable, present).
            PS_ATTRIBUTE_HANDLE_LIST => attributes.handle_list = Some((value, size)),
            PS_ATTRIBUTE_MITIGATION_OPTIONS
            | PS_ATTRIBUTE_CHILD_PROCESS_POLICY
            | PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY
            | PS_ATTRIBUTE_BNO_ISOLATION
            | PS_ATTRIBUTE_COMPONENT_FILTER => return Err(STATUS_NOT_SUPPORTED),
            _ => {}
        }
    }
    let (name, length) = attributes.image_name;
    // A UNICODE_STRING length: non-empty, whole UTF-16 units, representable in a USHORT.
    if name == 0 || length == 0 || length & 1 != 0 || length > 0xFFFE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(attributes)
}

/// The fields of `SECTION_IMAGE_INFORMATION` the sequence reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageInformation {
    pub bytes: [u8; SECTION_IMAGE_INFORMATION_SIZE],
}

impl ImageInformation {
    pub fn transfer_address(&self) -> u64 {
        read_u64(&self.bytes, 0x00)
    }
    pub fn zero_bits(&self) -> u32 {
        read_u32(&self.bytes, 0x08)
    }
    pub fn maximum_stack_size(&self) -> u64 {
        read_u64(&self.bytes, 0x10)
    }
    pub fn committed_stack_size(&self) -> u64 {
        read_u64(&self.bytes, 0x18)
    }
    pub fn subsystem_type(&self) -> u32 {
        read_u32(&self.bytes, 0x20)
    }
    pub fn image_characteristics(&self) -> u16 {
        read_u16(&self.bytes, 0x2c)
    }
    pub fn dll_characteristics(&self) -> u16 {
        read_u16(&self.bytes, 0x2e)
    }
}

/// One `NtCreateUserProcess` call after argument capture.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The NT path of the image.
    pub image_name: &'a [u16],
    pub process_access: u32,
    pub thread_access: u32,
    /// `POBJECT_ATTRIBUTES` for the process and the thread (0 when absent).
    pub process_object_attributes: u64,
    pub thread_object_attributes: u64,
    pub process_flags: u32,
    pub thread_flags: u32,
    /// The caller's `RTL_USER_PROCESS_PARAMETERS` (0 when absent).
    pub process_parameters: u64,
    pub create_info: CreateInfoInput,
    pub attributes: Attributes,
}

/// The step of the sequence that failed, for the one diagnostic line a failure produces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    Arguments,
    OpenImage,
    CreateSection,
    CreateProcess,
    QueryImage,
    ImageCharacteristics,
    QueryProcess,
    AssignToken,
    WriteParameters,
    CreateThread,
}

impl Step {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::OpenImage => "open-image",
            Self::CreateSection => "create-section",
            Self::CreateProcess => "create-process",
            Self::QueryImage => "query-image",
            Self::ImageCharacteristics => "image-characteristics",
            Self::QueryProcess => "query-process",
            Self::AssignToken => "assign-token",
            Self::WriteParameters => "write-parameters",
            Self::CreateThread => "create-thread",
        }
    }
}

/// A successful creation: everything the caller's out-parameters receive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Created {
    pub process: u64,
    pub thread: u64,
    pub client_id: [u64; 2],
    pub image: ImageInformation,
    /// The image File and Section handles, non-zero only with `WriteOutputOnExit`.
    pub file: u64,
    pub section: u64,
    /// Address of the parameter block in the new process (0 when none was supplied).
    pub parameters: u64,
    pub peb: u64,
}

/// A failed creation. No handle survives it except `file`, which the caller owns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub status: u32,
    pub step: Step,
    /// The `PS_CREATE_STATE` to report, when the failing step has one.
    pub state: Option<u32>,
    /// `FailSection.FileHandle`: the image File, returned only for a section-creation failure
    /// under `WriteOutputOnExit`.
    pub file: u64,
    /// `ExeFormat.DllCharacteristics`, for a prohibited image.
    pub dll_characteristics: u16,
}

/// The native services the sequence is made of.
pub trait UserProcessOps {
    /// `NtOpenFile(FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT |
    /// FILE_NON_DIRECTORY_FILE)` on the image path.
    fn open_image(&mut self, name: &[u16], access: u32) -> Result<u64, u32>;
    /// `NtCreateSection(SECTION_ALL_ACCESS, PAGE_EXECUTE, SEC_IMAGE)`.
    fn create_image_section(&mut self, file: u64) -> Result<u64, u32>;
    /// `NtCreateProcessEx`.
    fn create_process(
        &mut self,
        access: u32,
        object_attributes: u64,
        parent: Option<u64>,
        flags: u32,
        section: u64,
        debug_port: u64,
        handle_list: Option<(u64, u64)>,
    ) -> Result<u64, u32>;
    /// `NtQuerySection(SectionImageInformation)`.
    fn query_image(&mut self, section: u64) -> Result<ImageInformation, u32>;
    /// `NtQueryInformationProcess(ProcessBasicInformation)`: the PEB address.
    fn query_peb(&mut self, process: u64) -> Result<u64, u32>;
    /// `NtSetInformationProcess(ProcessAccessToken)`.
    fn assign_primary_token(&mut self, process: u64, token: u64) -> Result<(), u32>;
    /// Copy the environment and the parameter block into the process and point its PEB at the
    /// copy. Returns the block's address in the new process.
    fn write_parameters(
        &mut self,
        process: u64,
        peb: u64,
        image: &ImageInformation,
        parameters: u64,
    ) -> Result<u64, u32>;
    /// Build the initial stack and `NtCreateThread` at the image's transfer address with the PEB
    /// as its argument.
    fn create_initial_thread(
        &mut self,
        process: u64,
        access: u32,
        object_attributes: u64,
        image: &ImageInformation,
        peb: u64,
        suspended: bool,
    ) -> Result<(u64, [u64; 2]), u32>;
    /// `NtTerminateProcess`.
    fn terminate_process(&mut self, process: u64, status: u32);
    /// `NtClose`.
    fn close(&mut self, handle: u64);
}

/// Run the creation sequence. On failure every handle the sequence opened is closed (a created
/// process is terminated first, so it cannot outlive its only handle) except the File the caller
/// is handed back.
pub fn create_user_process<O: UserProcessOps>(
    ops: &mut O,
    request: &Request<'_>,
) -> Result<Created, Failure> {
    let fail = |status, step| Failure { status, step, state: None, file: 0, dll_characteristics: 0 };
    if request.process_flags & !PROCESS_CREATE_FLAGS_LEGAL_MASK != 0 || request.image_name.is_empty()
    {
        return Err(fail(STATUS_INVALID_PARAMETER, Step::Arguments));
    }
    let return_handles = request.create_info.write_output_on_exit;
    let access = if return_handles {
        IMAGE_FILE_ACCESS | request.create_info.additional_file_access
    } else {
        IMAGE_FILE_ACCESS
    };
    let file = match ops.open_image(request.image_name, access) {
        Err(STATUS_ACCESS_DENIED) if access != IMAGE_FILE_ACCESS => {
            ops.open_image(request.image_name, IMAGE_FILE_ACCESS)
        }
        result => result,
    }
    .map_err(|status| Failure {
        state: Some(PS_CREATE_FAIL_ON_FILE_OPEN),
        ..fail(status, Step::OpenImage)
    })?;

    let section = match ops.create_image_section(file) {
        Ok(section) => section,
        Err(status) => {
            if !return_handles {
                ops.close(file);
            }
            return Err(Failure {
                state: Some(PS_CREATE_FAIL_ON_SECTION_CREATE),
                file: if return_handles { file } else { 0 },
                ..fail(status, Step::CreateSection)
            });
        }
    };

    let mut process = 0;
    let result = (|| {
        process = ops
            .create_process(
                request.process_access,
                request.process_object_attributes,
                request.attributes.parent_process,
                request.process_flags,
                section,
                request.attributes.debug_port,
                request.attributes.handle_list,
            )
            .map_err(|status| fail(status, Step::CreateProcess))?;
        let image = ops.query_image(section).map_err(|status| fail(status, Step::QueryImage))?;
        if image.image_characteristics() & request.create_info.prohibited_image_characteristics != 0
        {
            return Err(Failure {
                state: Some(PS_CREATE_FAIL_EXE_FORMAT),
                dll_characteristics: image.dll_characteristics(),
                ..fail(STATUS_INVALID_IMAGE_FORMAT, Step::ImageCharacteristics)
            });
        }
        let peb = ops.query_peb(process).map_err(|status| fail(status, Step::QueryProcess))?;
        // The token is in place before any thread of the process exists.
        if let Some(token) = request.attributes.token {
            ops.assign_primary_token(process, token)
                .map_err(|status| fail(status, Step::AssignToken))?;
        }
        let parameters = if request.process_parameters != 0 {
            ops.write_parameters(process, peb, &image, request.process_parameters)
                .map_err(|status| fail(status, Step::WriteParameters))?
        } else {
            0
        };
        let (thread, client_id) = ops
            .create_initial_thread(
                process,
                request.thread_access,
                request.thread_object_attributes,
                &image,
                peb,
                request.thread_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED != 0,
            )
            .map_err(|status| fail(status, Step::CreateThread))?;
        Ok((image, peb, parameters, thread, client_id))
    })();

    match result {
        Ok((image, peb, parameters, thread, client_id)) => {
            if !return_handles {
                ops.close(section);
                ops.close(file);
            }
            Ok(Created {
                process,
                thread,
                client_id,
                image,
                file: if return_handles { file } else { 0 },
                section: if return_handles { section } else { 0 },
                parameters,
                peb,
            })
        }
        Err(failure) => {
            if process != 0 {
                ops.terminate_process(process, failure.status);
                ops.close(process);
            }
            ops.close(section);
            ops.close(file);
            Err(failure)
        }
    }
}

/// Write a success into the caller's `PS_CREATE_INFO` image.
pub fn encode_success(create_info: &mut [u8], created: &Created) {
    create_info[8..PS_CREATE_INFO_SIZE].fill(0);
    write_u32(create_info, 8, PS_CREATE_SUCCESS);
    write_u64(create_info, 0x18, created.file);
    write_u64(create_info, 0x20, created.section);
    write_u64(create_info, 0x28, created.parameters);
    write_u64(create_info, 0x38, created.peb);
}

/// Write a failure into the caller's `PS_CREATE_INFO` image. A failure without a creation state
/// leaves the structure as the caller passed it.
pub fn encode_failure(create_info: &mut [u8], failure: &Failure) {
    let Some(state) = failure.state else {
        return;
    };
    create_info[8..PS_CREATE_INFO_SIZE].fill(0);
    write_u32(create_info, 8, state);
    match state {
        PS_CREATE_FAIL_ON_SECTION_CREATE => write_u64(create_info, 0x10, failure.file),
        PS_CREATE_FAIL_EXE_FORMAT => {
            create_info[0x10..0x12].copy_from_slice(&failure.dll_characteristics.to_le_bytes());
        }
        _ => {}
    }
}

/// The one line a failed creation leaves in the debug log.
pub fn failure_record(failure: &Failure) -> RecordBuffer<96> {
    let mut record = RecordBuffer::new();
    core::write!(
        &mut record,
        "[nt-create-user-process-failed] step={} status=0x{:08x}\n",
        failure.step.name(),
        failure.status
    )
    .expect("fixed creation failure record fits its bounded buffer");
    record
}

/// The parameter block as it is written into the new process: `length` bytes of the caller's
/// block, its `Environment` pointing at the copy in the new process, and its strings
/// de-normalized. The new process's loader normalizes the block against its own address before
/// anything reads it, exactly as it does for a block written by `RtlCreateUserProcess`.
pub fn child_parameter_block(caller_block: &[u8], caller_address: u64, environment: u64) -> Vec<u8> {
    let mut block = caller_block.to_vec();
    crate::rtl::process_params::set_environment_pointer(&mut block, environment);
    crate::rtl::process_params::denormalize(&mut block, caller_address);
    block
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "x86_64")]
mod native;
#[cfg(target_arch = "x86_64")]
pub use native::create_native;

#[cfg(test)]
mod tests;
