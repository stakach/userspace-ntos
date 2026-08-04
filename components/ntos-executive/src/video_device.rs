//! Executive-owned video device publication for the current boot framebuffer route.
//!
//! ReactOS' normal path has videoprt create `\Device\Video0`, publish
//! `HARDWARE\DEVICEMAP\VIDEO`, and service the display driver's video IOCTLs through the I/O
//! manager. Until the real videoprt/miniport stack is hosted, this module owns that boundary as a
//! registered video route with projected NT driver/device/file object bodies that win32k can
//! dereference.

use core::ptr::{read_unaligned, write_unaligned};

const VIDEO_DRIVER_OBJECT_BYTES: u64 = 0x150;
const VIDEO_DRIVER_EXTENSION_BYTES: u64 = 0x50;
const VIDEO_DEVICE_OBJECT_BYTES: u64 = 0x150;
const VIDEO_FILE_OBJECT_BYTES: u64 = 0x100;
const VIDEO_DRIVER_NAME_CAP: usize = 32;
const VIDEO_SERVICE_PATH_CAP: usize = 128;
const VIDEO_DEVICE_PATH: &[u8] = b"\\Device\\Video0";
const FILE_DEVICE_VIDEO: u32 = 0x23;

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

// Video-miniport IOCTLs (ntddvdeo.h: FILE_DEVICE_VIDEO=0x23, METHOD_BUFFERED, FILE_ANY_ACCESS).
const IOCTL_VIDEO_QUERY_AVAIL_MODES: u64 = 0x0023_0400;
const IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES: u64 = 0x0023_0404;
const IOCTL_VIDEO_QUERY_CURRENT_MODE: u64 = 0x0023_0408;
const IOCTL_VIDEO_SET_CURRENT_MODE: u64 = 0x0023_040C;
const IOCTL_VIDEO_MAP_VIDEO_MEMORY: u64 = 0x0023_0458;

#[derive(Clone, Copy)]
pub(crate) struct VideoModeSpec {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) stride: u32,
    pub(crate) bits_per_plane: u32,
}

impl VideoModeSpec {
    const EMPTY: Self = Self {
        width: 0,
        height: 0,
        stride: 0,
        bits_per_plane: 0,
    };
}

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
static mut VIDEO_FRAMEBUFFER_VA: u64 = 0;
static mut VIDEO_FRAMEBUFFER_SIZE: u64 = 0;
static mut VIDEO_MODE: VideoModeSpec = VideoModeSpec::EMPTY;
static mut VIDEO_DEVICE_READY: bool = false;

pub(crate) unsafe fn publish_boot_framebuffer_video_device(
    reg: &VideoDeviceRegistration<'_>,
) -> bool {
    if !ascii_component_is_safe(reg.driver_name)
        || reg.driver_name.len() > VIDEO_DRIVER_NAME_CAP
        || reg.service_registry_path.is_empty()
        || reg.service_registry_path.len() > VIDEO_SERVICE_PATH_CAP
        || reg.framebuffer_va == 0
        || reg.framebuffer_size == 0
        || reg.mode.width == 0
        || reg.mode.height == 0
        || reg.mode.stride == 0
        || reg.mode.bits_per_plane == 0
    {
        return false;
    }
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
    VIDEO_FRAMEBUFFER_VA = reg.framebuffer_va;
    VIDEO_FRAMEBUFFER_SIZE = reg.framebuffer_size;
    VIDEO_MODE = reg.mode;
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
    let driver = allocate_projection(VIDEO_DRIVER_OBJECT_BYTES + VIDEO_DRIVER_EXTENSION_BYTES);
    let device = allocate_projection(VIDEO_DEVICE_OBJECT_BYTES);
    let file = allocate_projection(VIDEO_FILE_OBJECT_BYTES);
    if driver == 0 || device == 0 || file == 0 {
        return false;
    }
    let zero = |base: u64, len: u64| {
        let mut off = 0u64;
        while off < len {
            write_unaligned((base + off) as *mut u64, 0);
            off += 8;
        }
    };
    zero(
        driver,
        VIDEO_DRIVER_OBJECT_BYTES + VIDEO_DRIVER_EXTENSION_BYTES,
    );
    zero(device, VIDEO_DEVICE_OBJECT_BYTES);
    zero(file, VIDEO_FILE_OBJECT_BYTES);

    // Minimal x64 IO object bodies. win32k needs stable identities, DEVICE_OBJECT.DriverObject, the
    // DriverObject.DeviceObject head link, and the FILE_OBJECT.DeviceObject back-link.
    write_unaligned(driver as *mut i16, 4); // IO_TYPE_DRIVER
    write_unaligned((driver + 2) as *mut u16, VIDEO_DRIVER_OBJECT_BYTES as u16);
    write_unaligned(
        (driver + 0x68) as *mut u64,
        driver + VIDEO_DRIVER_OBJECT_BYTES,
    ); // DriverExtension
    write_unaligned((driver + 8) as *mut u64, device); // DriverObject.DeviceObject

    write_unaligned(device as *mut u16, 3); // IO_TYPE_DEVICE
    write_unaligned((device + 2) as *mut u16, VIDEO_DEVICE_OBJECT_BYTES as u16);
    write_unaligned((device + 8) as *mut u64, driver); // DriverObject
    write_unaligned((device + 0x48) as *mut u32, FILE_DEVICE_VIDEO); // DeviceType

    write_unaligned(file as *mut u16, 5); // IO_TYPE_FILE
    write_unaligned((file + 2) as *mut u16, VIDEO_FILE_OBJECT_BYTES as u16);
    write_unaligned((file + 8) as *mut u64, device);
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

unsafe fn fill_video_mode(out: u64) {
    let mode = VIDEO_MODE;
    let w = |off: u64, v: u32| write_unaligned((out + off) as *mut u32, v);
    w(0, 80); // Length (== ModeInformationLength; nonzero = a valid mode)
    w(4, 1); // ModeIndex
    w(8, mode.width); // VisScreenWidth
    w(12, mode.height); // VisScreenHeight
    w(16, mode.stride); // ScreenStride (bytes/scanline)
    w(20, 1); // NumberOfPlanes
    w(24, mode.bits_per_plane);
    w(28, 60); // Frequency
    w(32, 320); // XMillimeter
    w(36, 240); // YMillimeter
    w(40, 8); // NumberRedBits
    w(44, 8); // NumberGreenBits
    w(48, 8); // NumberBlueBits
    w(52, 0x00FF_0000); // RedMask
    w(56, 0x0000_FF00); // GreenMask
    w(60, 0x0000_00FF); // BlueMask
    w(64, 0x0000_0003); // VIDEO_MODE_COLOR | VIDEO_MODE_GRAPHICS
    w(68, mode.width); // VideoMemoryBitmapWidth
    w(72, mode.height); // VideoMemoryBitmapHeight
    w(76, 0); // DriverSpecificAttributeFlags
}

pub(crate) unsafe fn video_device_io_control(
    hdev: u64,
    ioctl: u64,
    _in_buf: u64,
    _in_len: u64,
    out_buf: u64,
    out_len: u64,
    bytes_ret: *mut u32,
) -> u32 {
    if !video_device_map_ready() || hdev != VIDEO_DEVICE_OBJECT {
        return 1;
    }
    let set_ret = |n: u32| {
        if !bytes_ret.is_null() {
            write_unaligned(bytes_ret, n);
        }
    };
    match ioctl {
        IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES => {
            if out_buf != 0 && out_len >= 8 {
                write_unaligned(out_buf as *mut u32, 1); // NumModes
                write_unaligned((out_buf + 4) as *mut u32, 80); // ModeInformationLength
                set_ret(8);
                return 0;
            }
        }
        IOCTL_VIDEO_QUERY_AVAIL_MODES | IOCTL_VIDEO_QUERY_CURRENT_MODE => {
            if out_buf != 0 && out_len >= 80 {
                fill_video_mode(out_buf);
                set_ret(80);
                return 0;
            }
        }
        IOCTL_VIDEO_SET_CURRENT_MODE => {
            set_ret(0);
            return 0;
        }
        IOCTL_VIDEO_MAP_VIDEO_MEMORY => {
            if out_buf != 0 && out_len >= 32 {
                write_unaligned(out_buf as *mut u64, VIDEO_FRAMEBUFFER_VA); // VideoRamBase
                write_unaligned((out_buf + 8) as *mut u32, VIDEO_FRAMEBUFFER_SIZE as u32);
                write_unaligned((out_buf + 16) as *mut u64, VIDEO_FRAMEBUFFER_VA);
                write_unaligned((out_buf + 24) as *mut u32, VIDEO_FRAMEBUFFER_SIZE as u32);
                set_ret(32);
                crate::print_str(
                    b"[video-device] IOCTL_VIDEO_MAP_VIDEO_MEMORY -> FrameBufferBase=0x",
                );
                crate::print_hex((VIDEO_FRAMEBUFFER_VA >> 32) as u32);
                crate::print_hex(VIDEO_FRAMEBUFFER_VA as u32);
                crate::print_str(b"\n");
                return 0;
            }
        }
        _ => {}
    }
    1
}
