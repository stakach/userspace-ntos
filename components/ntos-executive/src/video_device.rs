//! Executive-owned video device publication for the current boot framebuffer route.
//!
//! ReactOS' normal path has videoprt create `\Device\Video0`, publish
//! `HARDWARE\DEVICEMAP\VIDEO`, and service the display driver's video IOCTLs through the I/O
//! manager. Until the real videoprt/miniport stack is hosted, this module owns that boundary as a
//! registered video route with projected NT driver/device/file object bodies that win32k can
//! dereference.

use core::ptr::{read_unaligned, write_unaligned};

use nt_io_manager::{
    write_wdm_device_object, write_wdm_driver_object, write_wdm_file_object, WdmDeviceObjectInit,
    WdmDriverObjectInit, WdmFileObjectInit, WDM_X64_DEVICE_OBJECT_SIZE,
    WDM_X64_DRIVER_EXTENSION_SIZE, WDM_X64_DRIVER_OBJECT_SIZE, WDM_X64_FILE_OBJECT_SIZE,
};
use nt_video_miniport::{
    BootFramebufferMiniport, FramebufferMapping, IOCTL_VIDEO_MAP_VIDEO_MEMORY,
};

pub(crate) use nt_video_miniport::VideoModeSpec;

const VIDEO_DRIVER_NAME_CAP: usize = 32;
const VIDEO_SERVICE_PATH_CAP: usize = 128;
const VIDEO_DEVICE_PATH: &[u8] = b"\\Device\\Video0";

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
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
static mut VIDEO_DRIVER_NAME: [u8; VIDEO_DRIVER_NAME_CAP] = [0; VIDEO_DRIVER_NAME_CAP];
static mut VIDEO_DRIVER_NAME_LEN: u8 = 0;
static mut VIDEO_SERVICE_PATH: [u8; VIDEO_SERVICE_PATH_CAP] = [0; VIDEO_SERVICE_PATH_CAP];
static mut VIDEO_SERVICE_PATH_LEN: u8 = 0;
static mut VIDEO_MINIPORT: Option<BootFramebufferMiniport> = None;
static mut VIDEO_DEVICE_READY: bool = false;

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
    let Ok(miniport) = BootFramebufferMiniport::new(
        FramebufferMapping {
            virtual_address: reg.framebuffer_va,
            size_bytes: reg.framebuffer_size,
        },
        reg.mode,
    ) else {
        return false;
    };
    if !ensure_video_objects(reg.allocate_projection) {
        return false;
    }

    let driver_name = &mut *core::ptr::addr_of_mut!(VIDEO_DRIVER_NAME);
    driver_name.fill(0);
    driver_name[..reg.driver_name.len()].copy_from_slice(reg.driver_name);
    VIDEO_DRIVER_NAME_LEN = reg.driver_name.len() as u8;
    let path = &mut *core::ptr::addr_of_mut!(VIDEO_SERVICE_PATH);
    path.fill(0);
    path[..reg.service_registry_path.len()].copy_from_slice(reg.service_registry_path);
    VIDEO_SERVICE_PATH_LEN = reg.service_registry_path.len() as u8;
    VIDEO_MINIPORT = Some(miniport);
    VIDEO_DEVICE_READY = true;
    true
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
    }
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

    // Minimal x64 IO object bodies. win32k needs stable identities, DEVICE_OBJECT.DriverObject, the
    // DriverObject.DeviceObject head link, and the FILE_OBJECT.DeviceObject back-link.
    if write_wdm_driver_object(
        core::slice::from_raw_parts_mut(driver as *mut u8, driver_len),
        WdmDriverObjectInit {
            size_field: WDM_X64_DRIVER_OBJECT_SIZE as u16,
            device_object: device,
            driver_extension: driver + WDM_X64_DRIVER_OBJECT_SIZE as u64,
            driver_unload: 0,
        },
    )
    .is_err()
    {
        return false;
    }
    if write_wdm_device_object(
        core::slice::from_raw_parts_mut(device as *mut u8, WDM_X64_DEVICE_OBJECT_SIZE),
        WdmDeviceObjectInit {
            driver_object: driver,
            next_device: 0,
            device_extension: 0,
            device_type: nt_video_miniport::FILE_DEVICE_VIDEO,
        },
    )
    .is_err()
    {
        return false;
    }
    if write_wdm_file_object(
        core::slice::from_raw_parts_mut(file as *mut u8, WDM_X64_FILE_OBJECT_SIZE),
        WdmFileObjectInit {
            device_object: device,
            fs_context: 0,
            file_name_len: 0,
            file_name_max_len: 0,
            file_name_buffer: 0,
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

fn ascii_component_is_safe(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .copied()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && !name.windows(2).any(|w| w == b"..")
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

unsafe fn emit_kvpi_wsz(kvi: u64, length: u64, result_len: *mut u32, rtype: u32, s: &[u8]) -> i32 {
    let nchars = s.len() + 1;
    let dbytes = (nchars * 2) as u64;
    let need = 0xC + dbytes;
    if !result_len.is_null() {
        write_unaligned(result_len, need as u32);
    }
    if kvi == 0 || length < need {
        return STATUS_BUFFER_OVERFLOW;
    }
    write_unaligned(kvi as *mut u32, 0);
    write_unaligned((kvi + 4) as *mut u32, rtype);
    write_unaligned((kvi + 8) as *mut u32, dbytes as u32);
    let d = kvi + 0xC;
    for (i, &b) in s.iter().enumerate() {
        write_unaligned((d + (i * 2) as u64) as *mut u16, b as u16);
    }
    write_unaligned((d + (s.len() * 2) as u64) as *mut u16, 0);
    0
}

unsafe fn emit_kvpi_dword(kvi: u64, length: u64, result_len: *mut u32, val: u32) -> i32 {
    let need = 0xC + 4;
    if !result_len.is_null() {
        write_unaligned(result_len, need as u32);
    }
    if kvi == 0 || length < need {
        return STATUS_BUFFER_OVERFLOW;
    }
    write_unaligned(kvi as *mut u32, 0);
    write_unaligned((kvi + 4) as *mut u32, REG_DWORD);
    write_unaligned((kvi + 8) as *mut u32, 4);
    write_unaligned((kvi + 0xC) as *mut u32, val);
    0
}

pub(crate) unsafe fn query_video_device_map_value(
    name: &[u8],
    kvi: u64,
    length: u64,
    result_len: *mut u32,
) -> i32 {
    if !video_device_map_ready() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if ascii_eq_ignore_case(name, b"maxobjectnumber") {
        return emit_kvpi_dword(kvi, length, result_len, 0);
    }
    if ascii_eq_ignore_case(name, b"\\device\\video0") {
        let service_path = &*core::ptr::addr_of!(VIDEO_SERVICE_PATH);
        let service_path_len = VIDEO_SERVICE_PATH_LEN as usize;
        if service_path_len == 0 {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        return emit_kvpi_wsz(
            kvi,
            length,
            result_len,
            REG_SZ,
            &service_path[..service_path_len],
        );
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

pub(crate) unsafe fn video_get_device_object_pointer(
    name: u64,
    fileobj_out: *mut u64,
    devobj_out: *mut u64,
) -> i32 {
    if !video_device_map_ready() || name == 0 {
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
    if !video_device_map_ready() || hdev != VIDEO_DEVICE_OBJECT {
        return 1;
    }
    let Some(miniport) = core::ptr::read_volatile(core::ptr::addr_of!(VIDEO_MINIPORT)) else {
        return 1;
    };
    if ioctl > u32::MAX as u64 {
        return 1;
    }
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
    let set_ret = |n: u32| {
        if !bytes_ret.is_null() {
            write_unaligned(bytes_ret, n);
        }
    };
    match miniport.dispatch_io_control(ioctl as u32, input, output) {
        Ok(bytes) => {
            set_ret(bytes as u32);
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
        Err(_) => 1,
    }
}
