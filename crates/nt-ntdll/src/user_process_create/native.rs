//! The exported `NtCreateUserProcess`: argument capture and the native services behind
//! [`UserProcessOps`].

use super::*;
use crate::rtl::user_stack;
use crate::trap_stubs;

const NT_CURRENT_PROCESS: u64 = u64::MAX;
const SECTION_ALL_ACCESS: u64 = 0x000F_001F;
const PAGE_EXECUTE: u64 = 0x10;
const PAGE_READWRITE: u64 = 0x04;
const PAGE_GUARD: u64 = 0x100;
const SEC_IMAGE: u64 = 0x0100_0000;
const MEM_COMMIT: u64 = 0x1000;
const MEM_RESERVE: u64 = 0x2000;
const MEM_RELEASE: u64 = 0x8000;
const FILE_SHARE_READ_DELETE: u64 = 0x1 | 0x4;
const FILE_SYNCHRONOUS_NON_DIRECTORY: u64 = 0x20 | 0x40;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const PROCESS_BASIC_INFORMATION: u64 = 0;
const PROCESS_ACCESS_TOKEN: u64 = 9;
const SECTION_IMAGE_INFORMATION: u64 = 1;
/// `FIELD_OFFSET(PEB, ProcessParameters)`.
const PEB_PROCESS_PARAMETERS: u64 = 0x20;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: u64,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: u64,
    object_name: u64,
    attributes: u32,
    security_descriptor: u64,
    security_qos: u64,
}

fn checked(status: u64) -> Result<(), u32> {
    let status = status as u32;
    if (status as i32) < 0 { Err(status) } else { Ok(()) }
}

struct NativeUserProcessOps;

impl NativeUserProcessOps {
    unsafe fn allocate(
        process: u64,
        base: u64,
        size: usize,
        zero_bits: u32,
        allocation_type: u64,
        protection: u64,
    ) -> Result<(u64, usize), u32> {
        let mut base = base;
        let mut size = size as u64;
        // SAFETY: both in/out values are live locals for the duration of the service.
        checked(unsafe {
            trap_stubs::nt_allocate_virtual_memory(
                process,
                (&mut base as *mut u64) as u64,
                u64::from(zero_bits),
                (&mut size as *mut u64) as u64,
                allocation_type,
                protection,
            )
        })?;
        Ok((base, size as usize))
    }

    unsafe fn write(process: u64, address: u64, bytes: &[u8]) -> Result<(), u32> {
        // SAFETY: `bytes` is a live slice in the calling process.
        checked(unsafe {
            trap_stubs::nt_write_virtual_memory(
                process,
                address,
                bytes.as_ptr() as u64,
                bytes.len() as u64,
                0,
            )
        })
    }

    unsafe fn release(process: u64, base: u64) {
        let mut base = base;
        let mut size = 0u64;
        // SAFETY: both in/out values are live locals for the duration of the service.
        let _ = unsafe {
            trap_stubs::nt_free_virtual_memory(
                process,
                (&mut base as *mut u64) as u64,
                (&mut size as *mut u64) as u64,
                MEM_RELEASE,
            )
        };
    }

    /// Reserve the stack, commit its top and guard the page below, in the owning process.
    unsafe fn allocate_stack(
        process: u64,
        image: &ImageInformation,
    ) -> Result<user_stack::InitialTebFields, u32> {
        let zero_bits = image.zero_bits();
        let layout = user_stack::create_process_user_stack_layout(
            image.committed_stack_size() as usize,
            image.maximum_stack_size() as usize,
            zero_bits,
            user_stack::DEFAULT_PAGE_SIZE,
            user_stack::DEFAULT_RESERVE_ALIGNMENT,
        )?;
        // SAFETY: the process handle grants VM operation access to its creator.
        let (allocation_base, reserve) = unsafe {
            Self::allocate(process, 0, layout.reserve, zero_bits, MEM_RESERVE, PAGE_READWRITE)
        }?;
        let layout = user_stack::UserStackLayout { reserve, ..layout };
        let fields = user_stack::initial_teb_fields(allocation_base, layout);
        let commit_base = fields.stack_limit - layout.guard as u64;
        // SAFETY: the range lies inside the reservation made above.
        let committed = unsafe {
            Self::allocate(
                process,
                commit_base,
                layout.commit + layout.guard,
                0,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        }
        .and_then(|_| {
            if layout.guard == 0 {
                return Ok(());
            }
            let mut base = commit_base;
            let mut size = layout.guard as u64;
            let mut old_protection = 0u32;
            // SAFETY: the in/out values are live locals for the duration of the service.
            checked(unsafe {
                trap_stubs::nt_protect_virtual_memory(
                    process,
                    (&mut base as *mut u64) as u64,
                    (&mut size as *mut u64) as u64,
                    PAGE_READWRITE | PAGE_GUARD,
                    (&mut old_protection as *mut u32) as u64,
                )
            })
        });
        if let Err(status) = committed {
            // SAFETY: the reservation belongs to this call and no thread uses it.
            unsafe { Self::release(process, allocation_base) };
            return Err(status);
        }
        Ok(fields)
    }
}

impl UserProcessOps for NativeUserProcessOps {
    fn open_image(&mut self, name: &[u16], access: u32) -> Result<u64, u32> {
        let name = UnicodeString {
            length: (name.len() * 2) as u16,
            maximum_length: (name.len() * 2) as u16,
            buffer: name.as_ptr() as u64,
        };
        let attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: (&name as *const UnicodeString) as u64,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: 0,
            security_qos: 0,
        };
        let mut handle = 0u64;
        let mut iosb = [0u64; 2];
        // SAFETY: every pointer names a live local or the caller's captured image path.
        checked(unsafe {
            trap_stubs::nt_open_file(
                (&mut handle as *mut u64) as u64,
                u64::from(access),
                (&attributes as *const ObjectAttributes) as u64,
                iosb.as_mut_ptr() as u64,
                FILE_SHARE_READ_DELETE,
                FILE_SYNCHRONOUS_NON_DIRECTORY,
            )
        })?;
        if handle == 0 { Err(STATUS_INVALID_HANDLE) } else { Ok(handle) }
    }

    fn create_image_section(&mut self, file: u64) -> Result<u64, u32> {
        let mut section = 0u64;
        // SAFETY: the out handle is a live local.
        checked(unsafe {
            trap_stubs::nt_create_section(
                (&mut section as *mut u64) as u64,
                SECTION_ALL_ACCESS,
                0,
                0,
                PAGE_EXECUTE,
                SEC_IMAGE,
                file,
            )
        })?;
        if section == 0 { Err(STATUS_INVALID_HANDLE) } else { Ok(section) }
    }

    fn create_process(
        &mut self,
        access: u32,
        object_attributes: u64,
        parent: Option<u64>,
        flags: u32,
        section: u64,
        debug_port: u64,
        handle_list: Option<(u64, u64)>,
    ) -> Result<u64, u32> {
        let mut process = 0u64;
        let out = (&mut process as *mut u64) as u64;
        let parent = parent.unwrap_or(NT_CURRENT_PROCESS);
        // SAFETY: the out handle is a live local; the caller's OBJECT_ATTRIBUTES and handle array
        // are forwarded untouched for the service to capture.
        checked(unsafe {
            match handle_list {
                // NtCreateProcessEx cannot restrict inheritance to a list; the executive's private
                // service takes the same nine arguments plus the HANDLE array.
                Some((list, size)) => trap_stubs::nt_create_process_ex_with_handle_list(
                    out, u64::from(access), object_attributes, parent, u64::from(flags), section,
                    debug_port, 0, 0, list, size,
                ),
                None => trap_stubs::nt_create_process_ex(
                    out, u64::from(access), object_attributes, parent, u64::from(flags), section,
                    debug_port, 0, 0,
                ),
            }
        })?;
        if process == 0 { Err(STATUS_INVALID_HANDLE) } else { Ok(process) }
    }

    fn query_image(&mut self, section: u64) -> Result<ImageInformation, u32> {
        let mut image = ImageInformation { bytes: [0; SECTION_IMAGE_INFORMATION_SIZE] };
        // SAFETY: the buffer is a live local of the stated size.
        checked(unsafe {
            trap_stubs::nt_query_section(
                section,
                SECTION_IMAGE_INFORMATION,
                image.bytes.as_mut_ptr() as u64,
                SECTION_IMAGE_INFORMATION_SIZE as u64,
                0,
            )
        })?;
        Ok(image)
    }

    fn query_peb(&mut self, process: u64) -> Result<u64, u32> {
        // PROCESS_BASIC_INFORMATION: ExitStatus, PebBaseAddress, AffinityMask, BasePriority,
        // UniqueProcessId, InheritedFromUniqueProcessId.
        let mut basic = [0u64; 6];
        // SAFETY: the buffer is a live local of the stated size.
        checked(unsafe {
            trap_stubs::nt_query_information_process(
                process,
                PROCESS_BASIC_INFORMATION,
                basic.as_mut_ptr() as u64,
                core::mem::size_of_val(&basic) as u64,
                0,
            )
        })?;
        Ok(basic[1])
    }

    fn assign_primary_token(&mut self, process: u64, token: u64) -> Result<(), u32> {
        // PROCESS_ACCESS_TOKEN { Token, Thread }: the process has no thread yet.
        let access_token = [token, 0u64];
        // SAFETY: the structure is a live local of the stated size.
        checked(unsafe {
            trap_stubs::nt_set_information_process(
                process,
                PROCESS_ACCESS_TOKEN,
                access_token.as_ptr() as u64,
                core::mem::size_of_val(&access_token) as u64,
            )
        })
    }

    fn write_parameters(
        &mut self,
        process: u64,
        peb: u64,
        image: &ImageInformation,
        parameters: u64,
    ) -> Result<u64, u32> {
        use crate::rtl::process_params;
        // SAFETY: `parameters` is the caller's RTL_USER_PROCESS_PARAMETERS; its header carries
        // MaximumLength and Length, and Length bytes of it are initialized.
        let (maximum_length, caller_block) = unsafe {
            let header = parameters as *const u32;
            let maximum_length = header.read_unaligned() as usize;
            let length = header.add(1).read_unaligned() as usize;
            (maximum_length, core::slice::from_raw_parts(parameters as *const u8, length))
        };
        if caller_block.len() < process_params::PARAMS_HEADER_SIZE
            || maximum_length < caller_block.len()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let flags = u32::from_le_bytes([
            caller_block[process_params::OFF_FLAGS],
            caller_block[process_params::OFF_FLAGS + 1],
            caller_block[process_params::OFF_FLAGS + 2],
            caller_block[process_params::OFF_FLAGS + 3],
        ]);
        if let Some(request) =
            crate::rtl::process_launch::low_memory_reservation(image.subsystem_type(), flags)
        {
            // SAFETY: the process handle grants VM operation access to its creator.
            unsafe {
                Self::allocate(
                    process,
                    request.base,
                    request.size,
                    0,
                    u64::from(request.allocation_type),
                    u64::from(request.protection),
                )
            }?;
        }

        let caller_environment = process_params::environment_pointer(caller_block);
        let mut environment = 0;
        if caller_environment != 0 {
            // SAFETY: a process environment is a readable block of NUL-terminated UTF-16 strings
            // ended by an empty string.
            let block = unsafe {
                let start = caller_environment as *const u16;
                let mut units = 0usize;
                while start.add(units).read_unaligned() != 0 {
                    while start.add(units).read_unaligned() != 0 {
                        units += 1;
                    }
                    units += 1;
                }
                core::slice::from_raw_parts(caller_environment as *const u8, (units + 1) * 2)
            };
            // SAFETY: the process handle grants VM operation and write access to its creator.
            unsafe {
                let (base, _) = Self::allocate(
                    process,
                    0,
                    block.len(),
                    0,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )?;
                Self::write(process, base, block)?;
                environment = base;
            }
        }

        let child_block = child_parameter_block(caller_block, parameters, environment);
        // SAFETY: the process handle grants VM operation and write access to its creator.
        unsafe {
            let (base, _) = Self::allocate(
                process,
                0,
                maximum_length,
                0,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )?;
            Self::write(process, base, &child_block)?;
            Self::write(process, peb + PEB_PROCESS_PARAMETERS, &base.to_le_bytes())?;
            Ok(base)
        }
    }

    fn create_initial_thread(
        &mut self,
        process: u64,
        access: u32,
        object_attributes: u64,
        image: &ImageInformation,
        peb: u64,
        suspended: bool,
    ) -> Result<(u64, [u64; 2]), u32> {
        // SAFETY: the process handle grants VM operation access to its creator.
        let stack = unsafe { Self::allocate_stack(process, image) }?;
        let initial_teb = [
            stack.previous_stack_base,
            stack.previous_stack_limit,
            stack.stack_base,
            stack.stack_limit,
            stack.allocated_stack_base,
        ];
        let mut context = nt_thread_start::AlignedAmd64Context::zeroed();
        if !nt_thread_start::initialize_amd64_user_context(
            context.as_bytes_mut(),
            image.transfer_address(),
            peb,
            stack.stack_base,
        ) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut thread = 0u64;
        let mut client_id = [0u64; 2];
        // SAFETY: every pointer names a live local; the caller's OBJECT_ATTRIBUTES is forwarded
        // untouched for the service to capture.
        let created = checked(unsafe {
            trap_stubs::nt_create_thread(
                (&mut thread as *mut u64) as u64,
                u64::from(access),
                object_attributes,
                process,
                client_id.as_mut_ptr() as u64,
                context.as_ptr() as u64,
                initial_teb.as_ptr() as u64,
                u64::from(suspended),
            )
        });
        if let Err(status) = created {
            // SAFETY: no thread was created on the stack.
            unsafe { Self::release(process, stack.allocated_stack_base) };
            return Err(status);
        }
        Ok((thread, client_id))
    }

    fn terminate_process(&mut self, process: u64, status: u32) {
        // SAFETY: plain handle service.
        let _ = unsafe { trap_stubs::nt_terminate_process(process, u64::from(status)) };
    }

    fn close(&mut self, handle: u64) {
        // SAFETY: plain handle service.
        let _ = unsafe { trap_stubs::nt_close(handle) };
    }
}

/// The exported `NtCreateUserProcess`.
///
/// # Safety
/// Called with the native service's argument contract: the pointers are the caller's own.
#[allow(clippy::too_many_arguments)]
pub unsafe fn create_native(
    process_handle: u64,
    thread_handle: u64,
    process_access: u64,
    thread_access: u64,
    process_object_attributes: u64,
    thread_object_attributes: u64,
    process_flags: u64,
    thread_flags: u64,
    process_parameters: u64,
    create_info: u64,
    attribute_list: u64,
) -> u64 {
    if process_handle == 0 || thread_handle == 0 || create_info == 0 {
        return u64::from(STATUS_ACCESS_VIOLATION);
    }
    // SAFETY: PS_CREATE_INFO is a caller structure of at least its fixed size.
    let create_info =
        unsafe { core::slice::from_raw_parts_mut(create_info as *mut u8, PS_CREATE_INFO_SIZE) };
    let request = (|| {
        let info = decode_create_info(create_info)?;
        if attribute_list == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // SAFETY: PS_ATTRIBUTE_LIST begins with its own TotalLength, which bounds the list.
        let attributes = unsafe {
            let total = (attribute_list as *const u64).read_unaligned();
            let total = usize::try_from(total).map_err(|_| STATUS_INVALID_PARAMETER)?;
            if total < PS_ATTRIBUTE_LIST_HEADER {
                return Err(STATUS_INVALID_PARAMETER);
            }
            decode_attribute_list(core::slice::from_raw_parts(attribute_list as *const u8, total))?
        };
        Ok((info, attributes))
    })();
    let result = match request {
        Ok((info, attributes)) => {
            // SAFETY: the image name attribute names `length` bytes of UTF-16 in the caller.
            let image_name = unsafe {
                core::slice::from_raw_parts(
                    attributes.image_name.0 as *const u16,
                    attributes.image_name.1 / 2,
                )
            };
            create_user_process(
                &mut NativeUserProcessOps,
                &Request {
                    image_name,
                    process_access: process_access as u32,
                    thread_access: thread_access as u32,
                    process_object_attributes,
                    thread_object_attributes,
                    process_flags: process_flags as u32,
                    thread_flags: thread_flags as u32,
                    process_parameters,
                    create_info: info,
                    attributes,
                },
            )
            .map(|created| (created, attributes))
        }
        Err(status) => Err(Failure {
            status,
            step: Step::Arguments,
            state: None,
            file: 0,
            dll_characteristics: 0,
        }),
    };
    match result {
        Ok((created, attributes)) => {
            encode_success(create_info, &created);
            // SAFETY: the out-parameters are the caller's own writable locations.
            unsafe {
                (process_handle as *mut u64).write_unaligned(created.process);
                (thread_handle as *mut u64).write_unaligned(created.thread);
                if attributes.client_id_out != 0 {
                    (attributes.client_id_out as *mut [u64; 2]).write_unaligned(created.client_id);
                }
                if attributes.image_info_out != 0 {
                    (attributes.image_info_out as *mut [u8; SECTION_IMAGE_INFORMATION_SIZE])
                        .write_unaligned(created.image.bytes);
                }
            }
            0
        }
        Err(failure) => {
            encode_failure(create_info, &failure);
            let record = failure_record(&failure);
            // SAFETY: the record is a live local for the duration of the debug service.
            unsafe { crate::dbg::emit(record.bytes().as_ptr(), record.bytes().len()) };
            u64::from(failure.status)
        }
    }
}
