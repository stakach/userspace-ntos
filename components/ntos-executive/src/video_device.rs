//! Executive-owned video device publication for the current boot framebuffer route.
//!
//! ReactOS' normal path has videoprt create `\Device\Video0`, publish
//! `HARDWARE\DEVICEMAP\VIDEO`, and service the display driver's video IOCTLs through the I/O
//! manager. Until the real videoprt/miniport stack is hosted, this module owns the boot framebuffer
//! route as a canonical I/O Manager driver/device/open plus projected NT driver/device/file object
//! bodies that win32k can dereference. DeviceMap values are published through Configuration
//! Manager and retained in this route state so hosted win32k import shims can answer the same
//! values without crossing into executive-only service-ring clients.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::{read_unaligned, write_unaligned};

use nt_io_abi::major;
use nt_io_manager::{
    write_wdm_file_object, write_wdm_open_device_projection, DeviceCharacteristics, DeviceFlags,
    DeviceType, DispatchContext, DispatchOutcome, DriverDispatchBackend, IoParameters, IrpId,
    IrpProjection, WdmFileObjectInit, WdmOpenDeviceProjectionInit, WDM_X64_DEVICE_OBJECT_SIZE,
    WDM_X64_DRIVER_EXTENSION_SIZE, WDM_X64_DRIVER_OBJECT_SIZE, WDM_X64_FILE_OBJECT_SIZE,
};
use nt_status::NtStatus;
use nt_video_miniport::{
    dispatch_boot_video_buffered_io_control, dispatch_boot_video_io_control,
    BootFramebufferMiniport, FramebufferMapping, VideoMiniportError, IOCTL_VIDEO_MAP_VIDEO_MEMORY,
};

pub(crate) use nt_video_miniport::VideoModeSpec;

const VIDEO_DRIVER_NAME_CAP: usize = 32;
const VIDEO_DRIVER_OBJECT_PATH_PREFIX: &[u8] = b"\\Driver\\";
const VIDEO_DRIVER_OBJECT_PATH_CAP: usize =
    VIDEO_DRIVER_OBJECT_PATH_PREFIX.len() + VIDEO_DRIVER_NAME_CAP;
const VIDEO_SUPPORTED_MAJORS: [u8; 5] = [
    major::IRP_MJ_CREATE,
    major::IRP_MJ_CLEANUP,
    major::IRP_MJ_CLOSE,
    major::IRP_MJ_DEVICE_CONTROL,
    major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
];
const VIDEO_SERVICE_PATH_CAP: usize = 128;
const VIDEO_DEVICE_PATH_STR: &str = "\\Device\\Video0";
const VIDEO_DEVICE_PATH: &[u8] = b"\\Device\\Video0";
const VIDEO_DEVICE_MAP_KEY_STR: &str = "\\Registry\\Machine\\Hardware\\DeviceMap\\Video";
const VIDEO_DEVICE_MAP_MAX_OBJECT_VALUE: &str = "MaxObjectNumber";

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

pub(crate) struct VideoDeviceRegistration<'a> {
    pub(crate) driver_name: &'a [u8],
    pub(crate) service_registry_path: &'a [u8],
    pub(crate) framebuffer_va: u64,
    pub(crate) framebuffer_size: u64,
    pub(crate) mode: VideoModeSpec,
    /// Allocates the projected IO object bodies in the importing component's VSpace. Ownership stays
    /// in this module; the pointer values must still be dereferenceable by win32k.
    pub(crate) allocate_projection: unsafe fn(u64) -> u64,
}

static mut VIDEO_DRIVER_OBJECT: u64 = 0;
static mut VIDEO_DEVICE_OBJECT: u64 = 0;
static mut VIDEO_FILE_OBJECT: u64 = 0;
static mut VIDEO_DRIVER_OBJECT_PATH: [u8; VIDEO_DRIVER_OBJECT_PATH_CAP] =
    [0; VIDEO_DRIVER_OBJECT_PATH_CAP];
static mut VIDEO_DRIVER_NAME: [u8; VIDEO_DRIVER_NAME_CAP] = [0; VIDEO_DRIVER_NAME_CAP];
static mut VIDEO_DRIVER_NAME_LEN: u8 = 0;
static mut VIDEO_SERVICE_PATH: [u8; VIDEO_SERVICE_PATH_CAP] = [0; VIDEO_SERVICE_PATH_CAP];
static mut VIDEO_SERVICE_PATH_LEN: u8 = 0;
static mut VIDEO_MINIPORT: Option<BootFramebufferMiniport> = None;
static mut VIDEO_DRIVER_ID: u64 = 0;
static mut VIDEO_DEVICE_ID: u64 = 0;
static mut VIDEO_DEVICE_OBJECT_ID: u64 = 0;
static mut VIDEO_FILE_HANDLE: u64 = 0;
static mut VIDEO_FILE_ID: u64 = 0;
static mut VIDEO_FILE_OBJECT_ID: u64 = 0;
static mut VIDEO_DEVICE_READY: bool = false;

#[inline(never)]
pub(crate) unsafe fn publish_boot_framebuffer_video_device(
    reg: &VideoDeviceRegistration<'_>,
) -> bool {
    if !ascii_component_is_safe(reg.driver_name)
        || reg.driver_name.len() > VIDEO_DRIVER_NAME_CAP
        || reg.service_registry_path.is_empty()
        || reg.service_registry_path.len() > VIDEO_SERVICE_PATH_CAP
    {
        return false;
    }
    if !ensure_video_objects(reg.allocate_projection) {
        return false;
    }
    if !install_video_miniport(reg.framebuffer_va, reg.framebuffer_size, reg.mode) {
        return false;
    }
    if !ensure_video_io_route(reg.driver_name) {
        VIDEO_MINIPORT = None;
        return false;
    }
    if !publish_video_device_map(reg.service_registry_path) {
        teardown_video_io_route();
        VIDEO_MINIPORT = None;
        return false;
    }

    copy_video_registration_metadata(reg);
    VIDEO_DEVICE_READY = true;
    true
}

#[inline(never)]
unsafe fn install_video_miniport(
    framebuffer_va: u64,
    framebuffer_size: u64,
    mode: VideoModeSpec,
) -> bool {
    VIDEO_MINIPORT = None;
    let Ok(miniport) = BootFramebufferMiniport::new(
        FramebufferMapping {
            virtual_address: framebuffer_va,
            size_bytes: framebuffer_size,
        },
        mode,
    ) else {
        return false;
    };
    VIDEO_MINIPORT = Some(miniport);
    true
}

#[inline(never)]
unsafe fn copy_video_registration_metadata(reg: &VideoDeviceRegistration<'_>) {
    let driver_name = &mut *core::ptr::addr_of_mut!(VIDEO_DRIVER_NAME);
    driver_name.fill(0);
    driver_name[..reg.driver_name.len()].copy_from_slice(reg.driver_name);
    VIDEO_DRIVER_NAME_LEN = reg.driver_name.len() as u8;
    let path = &mut *core::ptr::addr_of_mut!(VIDEO_SERVICE_PATH);
    path.fill(0);
    path[..reg.service_registry_path.len()].copy_from_slice(reg.service_registry_path);
    VIDEO_SERVICE_PATH_LEN = reg.service_registry_path.len() as u8;
}

pub(crate) fn video_device_map_ready() -> bool {
    unsafe {
        VIDEO_DEVICE_READY
            && VIDEO_DRIVER_NAME_LEN != 0
            && VIDEO_SERVICE_PATH_LEN != 0
            && VIDEO_DRIVER_OBJECT != 0
            && VIDEO_DEVICE_OBJECT != 0
            && VIDEO_FILE_OBJECT != 0
            && core::ptr::read_volatile(core::ptr::addr_of!(VIDEO_MINIPORT)).is_some()
            && video_io_route_ready()
    }
}

pub(crate) fn video_device_map_published() -> bool {
    unsafe { VIDEO_DEVICE_READY && VIDEO_SERVICE_PATH_LEN != 0 }
}

pub(crate) unsafe fn query_video_device_map_value(
    name: &[u8],
    out: &mut [u8],
) -> Result<(u32, usize), i32> {
    if !video_device_map_published() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    if ascii_eq_ignore_case(name, VIDEO_DEVICE_MAP_MAX_OBJECT_VALUE.as_bytes()) {
        let data = 0u32.to_le_bytes();
        if data.len() > out.len() {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        out[..data.len()].copy_from_slice(&data);
        return Ok((REG_DWORD, data.len()));
    }
    if ascii_eq_ignore_case(name, VIDEO_DEVICE_PATH) {
        let path_len = VIDEO_SERVICE_PATH_LEN as usize;
        let path = &(&*core::ptr::addr_of!(VIDEO_SERVICE_PATH))[..path_len];
        let Some(data_len) = utf16le_nul_from_ascii_into(path, out) else {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        return Ok((REG_SZ, data_len));
    }
    Err(STATUS_OBJECT_NAME_NOT_FOUND)
}

pub(crate) fn video_device_projection_proofs() -> (u64, u64, u64, u64) {
    unsafe {
        (
            video_device_map_ready() as u64,
            VIDEO_DRIVER_OBJECT,
            VIDEO_DEVICE_OBJECT,
            VIDEO_FILE_OBJECT,
        )
    }
}

#[inline(never)]
unsafe fn ensure_video_objects(allocate_projection: unsafe fn(u64) -> u64) -> bool {
    if VIDEO_DRIVER_OBJECT != 0 && VIDEO_DEVICE_OBJECT != 0 && VIDEO_FILE_OBJECT != 0 {
        return true;
    }
    let driver_len = WDM_X64_DRIVER_OBJECT_SIZE + WDM_X64_DRIVER_EXTENSION_SIZE;
    let driver = allocate_projection(driver_len as u64);
    let device = allocate_projection(WDM_X64_DEVICE_OBJECT_SIZE as u64);
    let file = allocate_projection(WDM_X64_FILE_OBJECT_SIZE as u64);
    if driver == 0 || device == 0 || file == 0 {
        return false;
    }

    // win32k needs projected, dereferenceable WDM bodies for the I/O Manager route identities.
    if write_wdm_open_device_projection(
        core::slice::from_raw_parts_mut(driver as *mut u8, driver_len),
        core::slice::from_raw_parts_mut(device as *mut u8, WDM_X64_DEVICE_OBJECT_SIZE),
        core::slice::from_raw_parts_mut(file as *mut u8, WDM_X64_FILE_OBJECT_SIZE),
        WdmOpenDeviceProjectionInit {
            driver_object: driver,
            driver_extension: driver + WDM_X64_DRIVER_OBJECT_SIZE as u64,
            device_object: device,
            file_object_context: 0,
            device_type: nt_video_miniport::FILE_DEVICE_VIDEO,
        },
    )
    .is_err()
    {
        return false;
    }
    VIDEO_DRIVER_OBJECT = driver;
    VIDEO_DEVICE_OBJECT = device;
    VIDEO_FILE_OBJECT = file;
    true
}

#[inline(never)]
unsafe fn rewrite_video_file_projection(file_id: u64) -> bool {
    if VIDEO_FILE_OBJECT == 0 || VIDEO_DEVICE_OBJECT == 0 {
        return false;
    }
    write_wdm_file_object(
        core::slice::from_raw_parts_mut(VIDEO_FILE_OBJECT as *mut u8, WDM_X64_FILE_OBJECT_SIZE),
        WdmFileObjectInit {
            device_object: VIDEO_DEVICE_OBJECT,
            fs_context: file_id,
            file_name_len: 0,
            file_name_max_len: 0,
            file_name_buffer: 0,
        },
    )
    .is_ok()
}

#[inline(never)]
unsafe fn video_driver_object_path(driver_name: &[u8]) -> Option<&'static str> {
    if !ascii_component_is_safe(driver_name) {
        return None;
    }
    let Some(len) = VIDEO_DRIVER_OBJECT_PATH_PREFIX
        .len()
        .checked_add(driver_name.len())
    else {
        return None;
    };
    if len > VIDEO_DRIVER_OBJECT_PATH_CAP {
        return None;
    }
    let path = &mut *core::ptr::addr_of_mut!(VIDEO_DRIVER_OBJECT_PATH);
    path.fill(0);
    path[..VIDEO_DRIVER_OBJECT_PATH_PREFIX.len()].copy_from_slice(VIDEO_DRIVER_OBJECT_PATH_PREFIX);
    path[VIDEO_DRIVER_OBJECT_PATH_PREFIX.len()..len].copy_from_slice(driver_name);
    let bytes: &'static [u8] = core::slice::from_raw_parts(
        core::ptr::addr_of!(VIDEO_DRIVER_OBJECT_PATH) as *const u8,
        len,
    );
    Some(core::str::from_utf8_unchecked(bytes))
}

#[inline(never)]
unsafe fn ensure_video_io_route(driver_name: &[u8]) -> bool {
    if video_io_route_ids_present() {
        return true;
    }
    let Some(driver_id) = register_video_driver_route(driver_name) else {
        return false;
    };
    let Some((device_id, device_object_id)) = register_video_device_route(driver_id) else {
        crate::driver_launch::destroy_io_driver(driver_id);
        return false;
    };
    let Some((file_handle, file_id, file_object_id)) = open_video_device_route(device_id) else {
        teardown_video_driver_route(driver_id);
        return false;
    };
    if !rewrite_video_file_projection(file_id) {
        let _ = crate::driver_launch::close_io_handle(file_handle);
        teardown_video_driver_route(driver_id);
        return false;
    }
    commit_video_io_route(
        driver_id,
        device_id,
        device_object_id,
        file_handle,
        file_id,
        file_object_id,
    );
    true
}

#[inline(never)]
unsafe fn video_io_route_ids_present() -> bool {
    VIDEO_DRIVER_ID != 0
        && VIDEO_DEVICE_ID != 0
        && VIDEO_DEVICE_OBJECT_ID != 0
        && VIDEO_FILE_HANDLE != 0
        && VIDEO_FILE_ID != 0
        && VIDEO_FILE_OBJECT_ID != 0
}

#[inline(never)]
unsafe fn register_video_driver_route(driver_name: &[u8]) -> Option<u64> {
    let driver_path = video_driver_object_path(driver_name)?;
    crate::driver_launch::register_kernel_io_driver_with_majors(
        driver_path,
        Box::new(BootVideoDriverBackend),
        &VIDEO_SUPPORTED_MAJORS,
    )
    .ok()
}

#[inline(never)]
unsafe fn register_video_device_route(driver_id: u64) -> Option<(u64, u64)> {
    crate::driver_launch::register_kernel_io_device(
        driver_id,
        VIDEO_DEVICE_PATH_STR,
        DeviceType(nt_video_miniport::FILE_DEVICE_VIDEO),
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )
    .ok()
}

#[inline(never)]
unsafe fn open_video_device_route(device_id: u64) -> Option<(u64, u64, u64)> {
    let Ok((file_handle, file_id, opened_device_id, file_object_id)) =
        crate::driver_launch::open_io_device(
            VIDEO_DEVICE_PATH_STR,
            nt_types::AccessMask::GENERIC_READ | nt_types::AccessMask::GENERIC_WRITE,
        )
    else {
        return None;
    };
    if opened_device_id != device_id {
        let _ = crate::driver_launch::close_io_handle(file_handle);
        return None;
    }
    Some((file_handle, file_id, file_object_id))
}

#[inline(never)]
unsafe fn commit_video_io_route(
    driver_id: u64,
    device_id: u64,
    device_object_id: u64,
    file_handle: u64,
    file_id: u64,
    file_object_id: u64,
) {
    VIDEO_DRIVER_ID = driver_id;
    VIDEO_DEVICE_ID = device_id;
    VIDEO_DEVICE_OBJECT_ID = device_object_id;
    VIDEO_FILE_HANDLE = file_handle;
    VIDEO_FILE_ID = file_id;
    VIDEO_FILE_OBJECT_ID = file_object_id;
}

#[inline(never)]
unsafe fn teardown_video_driver_route(driver_id: u64) {
    crate::driver_launch::destroy_io_driver(driver_id);
}

unsafe fn video_io_route_ready() -> bool {
    VIDEO_DRIVER_ID != 0
        && VIDEO_DEVICE_ID != 0
        && VIDEO_DEVICE_OBJECT_ID != 0
        && VIDEO_FILE_HANDLE != 0
        && VIDEO_FILE_ID != 0
        && VIDEO_FILE_OBJECT_ID != 0
        && crate::driver_launch::device_id_by_name(VIDEO_DEVICE_PATH_STR) == Some(VIDEO_DEVICE_ID)
        && crate::driver_launch::device_object_id(VIDEO_DEVICE_ID) == VIDEO_DEVICE_OBJECT_ID
}

unsafe fn projected_video_route_ready() -> bool {
    VIDEO_DEVICE_READY
        && VIDEO_DRIVER_NAME_LEN != 0
        && VIDEO_SERVICE_PATH_LEN != 0
        && VIDEO_DRIVER_OBJECT != 0
        && VIDEO_DEVICE_OBJECT != 0
        && VIDEO_FILE_OBJECT != 0
        && VIDEO_DRIVER_ID != 0
        && VIDEO_DEVICE_ID != 0
        && VIDEO_DEVICE_OBJECT_ID != 0
        && VIDEO_FILE_HANDLE != 0
        && VIDEO_FILE_ID != 0
        && VIDEO_FILE_OBJECT_ID != 0
        && core::ptr::read_volatile(core::ptr::addr_of!(VIDEO_MINIPORT)).is_some()
}

unsafe fn teardown_video_io_route() {
    if VIDEO_FILE_HANDLE != 0 {
        let _ = crate::driver_launch::close_io_handle(VIDEO_FILE_HANDLE);
    }
    if VIDEO_DRIVER_ID != 0 {
        crate::driver_launch::destroy_io_driver(VIDEO_DRIVER_ID);
    }
    VIDEO_DRIVER_ID = 0;
    VIDEO_DEVICE_ID = 0;
    VIDEO_DEVICE_OBJECT_ID = 0;
    VIDEO_FILE_HANDLE = 0;
    VIDEO_FILE_ID = 0;
    VIDEO_FILE_OBJECT_ID = 0;
}

struct BootVideoDriverBackend;

impl DriverDispatchBackend for BootVideoDriverBackend {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        match irp.major {
            major::IRP_MJ_CREATE | major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE => {
                Ok(DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                })
            }
            major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL => {
                let Some(miniport) =
                    (unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VIDEO_MINIPORT)) })
                else {
                    return Ok(DispatchOutcome::Failed {
                        status: NtStatus::DEVICE_NOT_CONNECTED,
                    });
                };
                let (ioctl, input_len, output_len) = match &irp.parameters {
                    IoParameters::DeviceControl(params)
                    | IoParameters::InternalDeviceControl(params) => (
                        params.ioctl_code,
                        params.input_len as usize,
                        params.output_len as usize,
                    ),
                    _ => {
                        return Ok(DispatchOutcome::Failed {
                            status: NtStatus::INVALID_PARAMETER,
                        });
                    }
                };
                match dispatch_boot_video_buffered_io_control(
                    &miniport,
                    ioctl,
                    ctx.system_buffer,
                    input_len,
                    output_len,
                    unsafe { VIDEO_DEVICE_OBJECT },
                ) {
                    Ok(information) => Ok(DispatchOutcome::Completed {
                        status: NtStatus::SUCCESS,
                        information: information as u64,
                    }),
                    Err(error) => Ok(DispatchOutcome::Failed {
                        status: video_miniport_status(error),
                    }),
                }
            }
            _ => Ok(DispatchOutcome::Failed {
                status: NtStatus::INVALID_DEVICE_REQUEST,
            }),
        }
    }

    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::INVALID_PARAMETER)
    }
}

fn video_miniport_status(error: VideoMiniportError) -> NtStatus {
    match error {
        VideoMiniportError::BufferTooSmall { .. } => NtStatus::BUFFER_TOO_SMALL,
        VideoMiniportError::InvalidRegistration
        | VideoMiniportError::FramebufferTooLarge
        | VideoMiniportError::InvalidModeRequest => NtStatus::INVALID_PARAMETER,
        VideoMiniportError::UnsupportedMode | VideoMiniportError::UnsupportedIoctl => {
            NtStatus::INVALID_DEVICE_REQUEST
        }
    }
}

fn ascii_component_is_safe(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .copied()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && !name.windows(2).any(|w| w == b"..")
}

unsafe fn wstr_eq_ascii(buf: u64, len_bytes: usize, pat: &[u8]) -> bool {
    if buf == 0 || len_bytes / 2 != pat.len() {
        return false;
    }
    let low = |c: u16| -> u16 {
        if (b'A' as u16..=b'Z' as u16).contains(&c) {
            c + 32
        } else {
            c
        }
    };
    for k in 0..pat.len() {
        let c = low(read_unaligned((buf + (k * 2) as u64) as *const u16));
        if c != low(pat[k] as u16) {
            return false;
        }
    }
    true
}

fn utf16le_nul_from_ascii(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut data = Vec::with_capacity(bytes.len() * 2 + 2);
    for &b in bytes {
        if !b.is_ascii() {
            return None;
        }
        data.extend_from_slice(&(b as u16).to_le_bytes());
    }
    data.extend_from_slice(&[0, 0]);
    Some(data)
}

fn utf16le_nul_from_ascii_into(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let need = bytes.len().checked_mul(2)?.checked_add(2)?;
    if need > out.len() {
        return None;
    }
    for (idx, &b) in bytes.iter().enumerate() {
        if !b.is_ascii() {
            return None;
        }
        let unit = (b as u16).to_le_bytes();
        out[idx * 2] = unit[0];
        out[idx * 2 + 1] = unit[1];
    }
    out[need - 2] = 0;
    out[need - 1] = 0;
    Some(need)
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

#[inline(never)]
unsafe fn publish_video_device_map(service_registry_path: &[u8]) -> bool {
    let Some(service_path_data) = utf16le_nul_from_ascii(service_registry_path) else {
        return false;
    };
    crate::config_manager_create_key(VIDEO_DEVICE_MAP_KEY_STR).is_ok()
        && crate::config_manager_set_dword(
            VIDEO_DEVICE_MAP_KEY_STR,
            VIDEO_DEVICE_MAP_MAX_OBJECT_VALUE,
            0,
        )
        .is_ok()
        && crate::config_manager_set_value(
            VIDEO_DEVICE_MAP_KEY_STR,
            VIDEO_DEVICE_PATH_STR,
            REG_SZ,
            &service_path_data,
        )
        .is_ok()
}

pub(crate) unsafe fn video_get_device_object_pointer(
    name: u64,
    fileobj_out: *mut u64,
    devobj_out: *mut u64,
) -> i32 {
    if !projected_video_route_ready() || name == 0 {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let len = read_unaligned(name as *const u16) as usize;
    let buf = read_unaligned((name + 8) as *const u64);
    if !wstr_eq_ascii(buf, len, VIDEO_DEVICE_PATH) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if VIDEO_DRIVER_OBJECT == 0 || VIDEO_FILE_OBJECT == 0 || VIDEO_DEVICE_OBJECT == 0 {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if !fileobj_out.is_null() {
        write_unaligned(fileobj_out, VIDEO_FILE_OBJECT);
    }
    if !devobj_out.is_null() {
        write_unaligned(devobj_out, VIDEO_DEVICE_OBJECT);
    }
    0
}

pub(crate) unsafe fn video_device_io_control(
    hdev: u64,
    ioctl: u64,
    in_buf: u64,
    in_len: u64,
    out_buf: u64,
    out_len: u64,
    bytes_ret: *mut u32,
) -> u32 {
    if !projected_video_route_ready() || hdev != VIDEO_DEVICE_OBJECT {
        return 1;
    }
    if ioctl > u32::MAX as u64 {
        return 1;
    }
    let set_ret = |n: u32| {
        if !bytes_ret.is_null() {
            write_unaligned(bytes_ret, n);
        }
    };
    let input = if in_len == 0 {
        &[]
    } else if in_buf != 0 {
        core::slice::from_raw_parts(in_buf as *const u8, in_len as usize)
    } else {
        return 1;
    };
    let output = if out_len == 0 {
        &mut []
    } else if out_buf != 0 {
        core::slice::from_raw_parts_mut(out_buf as *mut u8, out_len as usize)
    } else {
        return 1;
    };
    let Some(miniport) = core::ptr::read_volatile(core::ptr::addr_of!(VIDEO_MINIPORT)) else {
        return 1;
    };
    match dispatch_boot_video_io_control(
        &miniport,
        ioctl as u32,
        input,
        output,
        VIDEO_DEVICE_OBJECT,
    ) {
        Ok(information) if information <= u32::MAX as usize => {
            set_ret(information as u32);
            if ioctl as u32 == IOCTL_VIDEO_MAP_VIDEO_MEMORY {
                let mapping = miniport.mapping();
                crate::print_str(
                    b"[video-device] IOCTL_VIDEO_MAP_VIDEO_MEMORY -> FrameBufferBase=0x",
                );
                crate::print_hex((mapping.virtual_address >> 32) as u32);
                crate::print_hex(mapping.virtual_address as u32);
                crate::print_str(b"\n");
            }
            0
        }
        _ => 1,
    }
}
