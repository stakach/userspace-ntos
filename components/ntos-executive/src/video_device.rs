//! Executive-owned video device publication for the current video-port route.
//!
//! ReactOS' normal path has videoprt create `\Device\Video<N>`, publish
//! `HARDWARE\DEVICEMAP\VIDEO`, and service the display driver's video IOCTLs through the I/O
//! manager. This module owns the executive-side view of that hosted route: projected NT
//! driver/device/file object bodies that win32k can dereference, the live I/O Manager file handle,
//! and DeviceMap values mirrored through Configuration Manager for hosted win32k import shims.

use alloc::vec::Vec;
use core::ptr::{addr_of, addr_of_mut, read_unaligned, write_unaligned};

use nt_io_manager::{
    write_wdm_file_object, write_wdm_open_device_projection, WdmFileObjectInit,
    WdmOpenDeviceProjectionInit, WDM_X64_DEVICE_OBJECT_SIZE, WDM_X64_DRIVER_EXTENSION_SIZE,
    WDM_X64_DRIVER_OBJECT_SIZE, WDM_X64_FILE_OBJECT_SIZE,
};
use nt_status::NtStatus;
use nt_video_miniport::{
    VideoMiniportError, IOCTL_VIDEO_INIT_WIN32K_CALLBACKS, IOCTL_VIDEO_UNMAP_VIDEO_MEMORY,
    VIDEO_DEVICE_MAP_KEY, VIDEO_DEVICE_MAP_MAX_OBJECT_VALUE, VIDEO_WIN32K_CALLBACKS_SIZE_X64,
};

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_NO_MEMORY: i32 = 0xC000_0017u32 as i32;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

pub(crate) struct HostedVideoDeviceRegistration<'a> {
    pub(crate) device_id: u64,
    pub(crate) service_registry_path: &'a [u8],
    /// Allocates the projected IO object bodies in the importing component's VSpace. Ownership stays
    /// in this module; the pointer values must still be dereferenceable by win32k.
    pub(crate) allocate_projection: unsafe fn(u64) -> u64,
}

#[derive(Clone, Copy)]
struct VideoRegistrationMetadata {
    object_number: u32,
    driver_object_path_ptr: u64,
    driver_object_path_len: usize,
    device_path_ptr: u64,
    device_path_len: usize,
    service_registry_path_ptr: u64,
    service_registry_path_len: usize,
}

impl VideoRegistrationMetadata {
    fn ready(&self) -> bool {
        self.driver_object_path_ptr != 0
            && self.driver_object_path_len != 0
            && self.device_path_ptr != 0
            && self.device_path_len != 0
            && self.service_registry_path_ptr != 0
            && self.service_registry_path_len != 0
    }

    unsafe fn device_path(&self) -> &[u8] {
        core::slice::from_raw_parts(self.device_path_ptr as *const u8, self.device_path_len)
    }

    unsafe fn service_registry_path(&self) -> &[u8] {
        core::slice::from_raw_parts(
            self.service_registry_path_ptr as *const u8,
            self.service_registry_path_len,
        )
    }
}

#[derive(Clone, Copy)]
struct VideoProjectionObjects {
    driver: u64,
    device: u64,
    file: u64,
}

impl VideoProjectionObjects {
    const fn empty() -> Self {
        Self {
            driver: 0,
            device: 0,
            file: 0,
        }
    }

    fn ready(&self) -> bool {
        self.driver != 0 && self.device != 0 && self.file != 0
    }
}

#[derive(Clone, Copy)]
struct VideoIoRoute {
    driver_id: u64,
    device_id: u64,
    device_object_id: u64,
    file_handle: u64,
    file_id: u64,
    file_object_id: u64,
    backend: VideoRouteBackend,
}

impl VideoIoRoute {
    const fn empty() -> Self {
        Self {
            driver_id: 0,
            device_id: 0,
            device_object_id: 0,
            file_handle: 0,
            file_id: 0,
            file_object_id: 0,
            backend: VideoRouteBackend::Empty,
        }
    }

    fn ready(&self) -> bool {
        self.driver_id != 0
            && self.device_id != 0
            && self.device_object_id != 0
            && self.file_handle != 0
            && self.file_id != 0
            && self.file_object_id != 0
            && !matches!(self.backend, VideoRouteBackend::Empty)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VideoRouteBackend {
    Empty,
    HostedIoManager,
}

#[derive(Clone, Copy)]
struct VideoBridgeState {
    objects: VideoProjectionObjects,
    metadata: Option<VideoRegistrationMetadata>,
    route: VideoIoRoute,
    ready: bool,
}

impl VideoBridgeState {
    const fn empty() -> Self {
        Self {
            objects: VideoProjectionObjects::empty(),
            metadata: None,
            route: VideoIoRoute::empty(),
            ready: false,
        }
    }

    fn metadata_ready(&self) -> bool {
        match self.metadata {
            Some(metadata) => metadata.ready(),
            None => false,
        }
    }

    fn map_ready(&self) -> bool {
        self.ready
            && self.metadata_ready()
            && self.objects.ready()
            && self.route.ready()
            && self.route_backend_ready()
    }

    fn map_published(&self) -> bool {
        self.ready && self.metadata_ready()
    }

    fn projected_ready(&self) -> bool {
        self.ready
            && self.metadata_ready()
            && self.objects.ready()
            && self.route.ready()
            && self.route_backend_ready()
    }

    fn route_backend_ready(&self) -> bool {
        match self.route.backend {
            VideoRouteBackend::Empty => false,
            VideoRouteBackend::HostedIoManager => true,
        }
    }
}

static mut VIDEO_STATE: VideoBridgeState = VideoBridgeState::empty();

#[inline(never)]
pub(crate) unsafe fn publish_hosted_video_device_route(
    reg: &HostedVideoDeviceRegistration<'_>,
) -> bool {
    let Some(route_info) = crate::driver_launch::hosted_video_route_info(reg.device_id) else {
        print_hosted_video_publish_failure(b"route-info", None);
        return false;
    };
    if !ensure_video_objects(reg.allocate_projection) {
        print_hosted_video_publish_failure(b"objects", None);
        return false;
    }
    let Some(metadata) = video_registration_metadata_from_paths(
        route_info.object_number,
        route_info.driver_object_path.as_slice(),
        route_info.device_path.as_slice(),
        reg.service_registry_path,
        reg.allocate_projection,
    ) else {
        print_hosted_video_publish_failure(b"metadata", None);
        return false;
    };
    let (file_handle, file_id, file_object_id) =
        match open_video_device_route(route_info.device_id, metadata) {
            Ok(route) => route,
            Err(status) => {
                print_hosted_video_publish_failure(b"open", Some(status));
                return false;
            }
        };
    if !rewrite_video_file_projection(file_id) {
        let _ = crate::driver_launch::close_io_handle(file_handle);
        print_hosted_video_publish_failure(b"file-projection", None);
        return false;
    }
    teardown_video_io_route();
    (*addr_of_mut!(VIDEO_STATE)).metadata = Some(metadata);
    commit_video_io_route(
        route_info.driver_id,
        route_info.device_id,
        route_info.device_object_id,
        file_handle,
        file_id,
        file_object_id,
        VideoRouteBackend::HostedIoManager,
    );
    if !publish_video_device_map(metadata) {
        teardown_video_io_route();
        (*addr_of_mut!(VIDEO_STATE)).metadata = None;
        (*addr_of_mut!(VIDEO_STATE)).ready = false;
        print_hosted_video_publish_failure(b"devicemap", None);
        return false;
    }
    (*addr_of_mut!(VIDEO_STATE)).ready = true;
    true
}

fn print_hosted_video_publish_failure(stage: &[u8], status: Option<NtStatus>) {
    crate::print_str(b"[video-device] hosted publish failed stage=");
    crate::print_str(stage);
    if let Some(status) = status {
        crate::print_str(b" status=0x");
        crate::print_hex(status.raw() as u32);
    }
    crate::print_str(b"\n");
}

fn ascii_metadata_component_valid(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().copied().all(|byte| byte.is_ascii())
}

unsafe fn copy_ascii_metadata(src: &[u8], dst: u64) {
    for (idx, &byte) in src.iter().enumerate() {
        write_unaligned((dst + idx as u64) as *mut u8, byte);
    }
}

unsafe fn video_registration_metadata_from_paths(
    object_number: u32,
    driver_object_path: &[u8],
    device_path: &[u8],
    service_registry_path: &[u8],
    allocate_projection: unsafe fn(u64) -> u64,
) -> Option<VideoRegistrationMetadata> {
    if !ascii_metadata_component_valid(driver_object_path)
        || !ascii_metadata_component_valid(device_path)
        || !ascii_metadata_component_valid(service_registry_path)
    {
        return None;
    }
    let total_len = driver_object_path
        .len()
        .checked_add(device_path.len())?
        .checked_add(service_registry_path.len())?;
    let total_len_u64 = total_len as u64;
    if total_len_u64 as usize != total_len {
        return None;
    }
    let base = allocate_projection(total_len_u64);
    if base == 0 {
        return None;
    }
    let driver_object_path_ptr = base;
    copy_ascii_metadata(driver_object_path, driver_object_path_ptr);
    let device_path_ptr = driver_object_path_ptr + driver_object_path.len() as u64;
    copy_ascii_metadata(device_path, device_path_ptr);
    let service_registry_path_ptr = device_path_ptr + device_path.len() as u64;
    copy_ascii_metadata(service_registry_path, service_registry_path_ptr);
    Some(VideoRegistrationMetadata {
        object_number,
        driver_object_path_ptr,
        driver_object_path_len: driver_object_path.len(),
        device_path_ptr,
        device_path_len: device_path.len(),
        service_registry_path_ptr,
        service_registry_path_len: service_registry_path.len(),
    })
}

unsafe fn video_state_snapshot() -> VideoBridgeState {
    core::ptr::read_volatile(addr_of!(VIDEO_STATE))
}

pub(crate) fn video_device_map_ready() -> bool {
    unsafe {
        let state = video_state_snapshot();
        state.map_ready() && video_io_route_ready()
    }
}

pub(crate) fn video_device_map_published() -> bool {
    unsafe { video_state_snapshot().map_published() }
}

pub(crate) fn hosted_video_device_route_ready() -> bool {
    unsafe {
        let state = video_state_snapshot();
        state.projected_ready() && matches!(state.route.backend, VideoRouteBackend::HostedIoManager)
    }
}

pub(crate) unsafe fn query_video_device_map_value_owned(
    name: &[u8],
) -> Result<(u32, Vec<u8>), i32> {
    let state = video_state_snapshot();
    let Some(metadata) = state.metadata else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    if !state.ready {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    if ascii_eq_ignore_case(name, VIDEO_DEVICE_MAP_MAX_OBJECT_VALUE.as_bytes()) {
        let mut data = Vec::new();
        data.try_reserve_exact(4).map_err(|_| STATUS_NO_MEMORY)?;
        data.extend_from_slice(&metadata.object_number.to_le_bytes());
        return Ok((REG_DWORD, data));
    }
    if ascii_eq_ignore_case(name, metadata.device_path()) {
        let Some(data) = utf16le_nul_from_ascii(metadata.service_registry_path()) else {
            return Err(STATUS_NO_MEMORY);
        };
        return Ok((REG_SZ, data));
    }
    Err(STATUS_OBJECT_NAME_NOT_FOUND)
}

pub(crate) fn video_device_projection_proofs() -> (u64, u64, u64, u64) {
    unsafe {
        let state = video_state_snapshot();
        (
            video_device_map_ready() as u64,
            state.objects.driver,
            state.objects.device,
            state.objects.file,
        )
    }
}

#[inline(never)]
unsafe fn ensure_video_objects(allocate_projection: unsafe fn(u64) -> u64) -> bool {
    if video_state_snapshot().objects.ready() {
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
    (*addr_of_mut!(VIDEO_STATE)).objects = VideoProjectionObjects {
        driver,
        device,
        file,
    };
    true
}

#[inline(never)]
unsafe fn rewrite_video_file_projection(file_id: u64) -> bool {
    let objects = video_state_snapshot().objects;
    if !objects.ready() {
        return false;
    }
    write_wdm_file_object(
        core::slice::from_raw_parts_mut(objects.file as *mut u8, WDM_X64_FILE_OBJECT_SIZE),
        WdmFileObjectInit {
            device_object: objects.device,
            fs_context: file_id,
            file_name_len: 0,
            file_name_max_len: 0,
            file_name_buffer: 0,
        },
    )
    .is_ok()
}

#[inline(never)]
unsafe fn video_io_route_ids_present(metadata: VideoRegistrationMetadata) -> bool {
    let route = video_state_snapshot().route;
    if !route.ready() {
        return false;
    }
    let Some(device_path) = core::str::from_utf8(metadata.device_path()).ok() else {
        return false;
    };
    crate::driver_launch::device_id_by_name(device_path) == Some(route.device_id)
        && crate::driver_launch::device_object_id(route.device_id) == route.device_object_id
}

#[inline(never)]
unsafe fn open_video_device_route(
    device_id: u64,
    metadata: VideoRegistrationMetadata,
) -> Result<(u64, u64, u64), NtStatus> {
    let device_path =
        core::str::from_utf8(metadata.device_path()).map_err(|_| NtStatus::INVALID_PARAMETER)?;
    let (file_handle, file_id, opened_device_id, file_object_id) =
        crate::driver_launch::open_io_device(
            device_path,
            nt_types::AccessMask::GENERIC_READ | nt_types::AccessMask::GENERIC_WRITE,
        )?;
    if opened_device_id != device_id {
        let _ = crate::driver_launch::close_io_handle(file_handle);
        return Err(NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok((file_handle, file_id, file_object_id))
}

#[inline(never)]
unsafe fn commit_video_io_route(
    driver_id: u64,
    device_id: u64,
    device_object_id: u64,
    file_handle: u64,
    file_id: u64,
    file_object_id: u64,
    backend: VideoRouteBackend,
) {
    (*addr_of_mut!(VIDEO_STATE)).route = VideoIoRoute {
        driver_id,
        device_id,
        device_object_id,
        file_handle,
        file_id,
        file_object_id,
        backend,
    };
}

unsafe fn video_io_route_ready() -> bool {
    let state = video_state_snapshot();
    let Some(metadata) = state.metadata else {
        return false;
    };
    video_io_route_ids_present(metadata)
}

unsafe fn projected_video_route_ready() -> bool {
    video_state_snapshot().projected_ready()
}

unsafe fn teardown_video_io_route() {
    let route = video_state_snapshot().route;
    if route.file_handle != 0 {
        let _ = crate::driver_launch::close_io_handle(route.file_handle);
    }
    (*addr_of_mut!(VIDEO_STATE)).route = VideoIoRoute::empty();
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
    let need = bytes.len().checked_mul(2)?.checked_add(2)?;
    let mut data = Vec::new();
    data.try_reserve_exact(need).ok()?;
    for &b in bytes {
        if !b.is_ascii() {
            return None;
        }
        data.extend_from_slice(&(b as u16).to_le_bytes());
    }
    data.extend_from_slice(&[0, 0]);
    Some(data)
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
unsafe fn publish_video_device_map(metadata: VideoRegistrationMetadata) -> bool {
    let Some(service_path_data) = utf16le_nul_from_ascii(metadata.service_registry_path()) else {
        return false;
    };
    let Some(device_path) = core::str::from_utf8(metadata.device_path()).ok() else {
        return false;
    };
    crate::config_manager_create_key(VIDEO_DEVICE_MAP_KEY).is_ok()
        && crate::config_manager_set_dword(
            VIDEO_DEVICE_MAP_KEY,
            VIDEO_DEVICE_MAP_MAX_OBJECT_VALUE,
            metadata.object_number,
        )
        .is_ok()
        && crate::config_manager_set_value(
            VIDEO_DEVICE_MAP_KEY,
            device_path,
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
    let state = video_state_snapshot();
    let Some(metadata) = state.metadata else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    let len = read_unaligned(name as *const u16) as usize;
    let buf = read_unaligned((name + 8) as *const u64);
    if !wstr_eq_ascii(buf, len, metadata.device_path()) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let objects = state.objects;
    if !objects.ready() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if !fileobj_out.is_null() {
        write_unaligned(fileobj_out, objects.file);
    }
    if !devobj_out.is_null() {
        write_unaligned(devobj_out, objects.device);
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
    if !projected_video_route_ready() {
        return 1;
    }
    let state = video_state_snapshot();
    let objects = state.objects;
    if hdev != objects.device {
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
    if let Some(information) =
        dispatch_video_port_owned_control(ioctl as u32, input, output, objects.device)
    {
        match information {
            Ok(information) if information <= u32::MAX as usize => {
                set_ret(information as u32);
                return 0;
            }
            _ => return 1,
        }
    }
    match state.route.backend {
        VideoRouteBackend::HostedIoManager => {
            match crate::driver_launch::device_control_on_io_handle(
                state.route.file_handle,
                ioctl as u32,
                input,
                output,
            ) {
                Ok(information) if information <= u32::MAX as u64 => {
                    set_ret(information as u32);
                    0
                }
                _ => 1,
            }
        }
        VideoRouteBackend::Empty => 1,
    }
}

fn dispatch_video_port_owned_control(
    ioctl: u32,
    input: &[u8],
    output: &mut [u8],
    video_device_object: u64,
) -> Option<Result<usize, VideoMiniportError>> {
    match ioctl {
        IOCTL_VIDEO_INIT_WIN32K_CALLBACKS => {
            if input.len() < 16 {
                return Some(Err(VideoMiniportError::BufferTooSmall { needed: 16 }));
            }
            if output.len() < VIDEO_WIN32K_CALLBACKS_SIZE_X64 {
                return Some(Err(VideoMiniportError::BufferTooSmall {
                    needed: VIDEO_WIN32K_CALLBACKS_SIZE_X64,
                }));
            }
            let mut phys_disp = [0u8; 8];
            phys_disp.copy_from_slice(&input[..8]);
            let mut callout = [0u8; 8];
            callout.copy_from_slice(&input[8..16]);
            output[..VIDEO_WIN32K_CALLBACKS_SIZE_X64].fill(0);
            output[..8].copy_from_slice(&phys_disp);
            output[8..16].copy_from_slice(&callout);
            output[24..32].copy_from_slice(&video_device_object.to_le_bytes());
            Some(Ok(VIDEO_WIN32K_CALLBACKS_SIZE_X64))
        }
        IOCTL_VIDEO_UNMAP_VIDEO_MEMORY => Some(Ok(0)),
        _ => None,
    }
}
