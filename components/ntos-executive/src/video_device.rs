//! Executive-owned video device publication for the current video-port route.
//!
//! ReactOS' normal path has videoprt create `\Device\Video<N>`, publish
//! `HARDWARE\DEVICEMAP\VIDEO`, and service the display driver's video IOCTLs through the I/O
//! manager. This module owns the executive-side view of that hosted route: projected NT
//! driver/device/file object bodies that win32k can dereference, the live I/O Manager file handle,
//! and DeviceMap values mirrored through Configuration Manager for hosted win32k import shims.

use alloc::vec::Vec;
use core::ptr::{addr_of, addr_of_mut, read_unaligned, write_unaligned};
use core::sync::atomic::{AtomicU64, Ordering};

use nt_io_manager::{
    write_wdm_device_object, write_wdm_driver_object, WdmDeviceObjectInit, WdmDriverObjectInit,
    WDM_X64_DRIVER_EXTENSION_SIZE, WDM_X64_DRIVER_OBJECT_SIZE,
};
use nt_status::NtStatus;
use crate::win32k_subsystem::RootProviderPoolAllocation;
use nt_video_miniport::{VIDEO_DEVICE_MAP_KEY, VIDEO_DEVICE_MAP_MAX_OBJECT_VALUE};

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_NO_MEMORY: i32 = 0xC000_0017u32 as i32;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

#[path = "video_projection_owners.rs"]
mod video_projection_owners;
#[path = "video_projection_retirements.rs"]
mod video_projection_retirements;
pub(crate) use video_projection_retirements::{
    deadline as video_file_retirement_deadline, drain as drain_video_file_retirements,
    wake_due as video_file_retirement_wake_due,
};

pub(crate) struct HostedVideoDeviceRegistration<'a> {
    pub(crate) device_id: u64,
    pub(crate) service_registry_path: &'a [u8],
    /// Allocates the projected IO object bodies in the importing component's VSpace. Ownership stays
    /// in this module; the pointer values must still be dereferenceable by win32k.
    pub(crate) allocate_projection: unsafe fn(u64) -> Option<RootProviderPoolAllocation>,
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

// Published metadata may outlive route replacement; these session owners retain every backing.
static mut VIDEO_METADATA_ALLOCATIONS: Vec<RootProviderPoolAllocation> = Vec::new();

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
    driver_allocation: Option<RootProviderPoolAllocation>,
    device_allocation: Option<RootProviderPoolAllocation>,
    driver: u64,
    device: u64,
    initialized: bool,
}

impl VideoProjectionObjects {
    const fn empty() -> Self {
        Self {
            driver_allocation: None,
            device_allocation: None,
            driver: 0,
            device: 0,
            initialized: false,
        }
    }

    fn ready(&self) -> bool {
        self.initialized && self.driver != 0 && self.device != 0
    }
}

#[derive(Clone, Copy)]
struct VideoIoRoute {
    owner_id: u64,
    file_projection: u64,
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
            owner_id: 0,
            file_projection: 0,
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
        self.owner_id != 0
            && self.file_projection != 0
            && self.driver_id != 0
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
static VIDEO_PUBLICATION_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// The periodic census may run while a nested native CREATE or provider allocation is active.
// Publish only atomic observation, with an even sequence denoting a coherent snapshot.
static VIDEO_PUBLICATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static VIDEO_PUBLICATION_ENTRIES: AtomicU64 = AtomicU64::new(0);
static VIDEO_PUBLICATION_EXITS: AtomicU64 = AtomicU64::new(0);
static VIDEO_PUBLICATION_DEVICE: AtomicU64 = AtomicU64::new(0);
static VIDEO_PUBLICATION_OWNER: AtomicU64 = AtomicU64::new(0);
static VIDEO_PUBLICATION_STAGE: AtomicU64 = AtomicU64::new(0);

fn observe_video_publication(device_id: u64, owner_id: u64, stage: u64, entered: bool, exited: bool) {
    VIDEO_PUBLICATION_SEQUENCE.fetch_add(1, Ordering::AcqRel);
    VIDEO_PUBLICATION_DEVICE.store(device_id, Ordering::Relaxed);
    VIDEO_PUBLICATION_OWNER.store(owner_id, Ordering::Relaxed);
    VIDEO_PUBLICATION_STAGE.store(stage, Ordering::Relaxed);
    if entered {
        VIDEO_PUBLICATION_ENTRIES.fetch_add(1, Ordering::Relaxed);
    }
    if exited {
        VIDEO_PUBLICATION_EXITS.fetch_add(1, Ordering::Relaxed);
    }
    VIDEO_PUBLICATION_SEQUENCE.fetch_add(1, Ordering::Release);
}

struct PublicationObservation {
    device_id: u64,
    owner_id: u64,
}

impl PublicationObservation {
    fn enter(device_id: u64) -> Self {
        observe_video_publication(device_id, 0, 1, true, false);
        Self { device_id, owner_id: 0 }
    }

    fn stage(&self, stage: u64) {
        observe_video_publication(self.device_id, self.owner_id, stage, false, false);
    }

    fn owner_reserved(&mut self, owner_id: u64) {
        self.owner_id = owner_id;
        self.stage(9);
    }
}

impl Drop for PublicationObservation {
    fn drop(&mut self) {
        observe_video_publication(self.device_id, self.owner_id, 19, false, true);
    }
}

pub(crate) fn print_hosted_video_publication_census() {
    let sequence = VIDEO_PUBLICATION_SEQUENCE.load(Ordering::Acquire);
    let entries = VIDEO_PUBLICATION_ENTRIES.load(Ordering::Relaxed);
    if entries == 0 {
        return;
    }
    let exits = VIDEO_PUBLICATION_EXITS.load(Ordering::Relaxed);
    let device = VIDEO_PUBLICATION_DEVICE.load(Ordering::Relaxed);
    let owner = VIDEO_PUBLICATION_OWNER.load(Ordering::Relaxed);
    let stage = VIDEO_PUBLICATION_STAGE.load(Ordering::Relaxed);
    let stable = sequence & 1 == 0
        && VIDEO_PUBLICATION_SEQUENCE.load(Ordering::Acquire) == sequence;
    crate::print_str(b"[video-publication-census] entries/exits/device/owner/stage=");
    if stable {
        crate::print_u64(entries);
        crate::print_str(b"/");
        crate::print_u64(exits);
        crate::print_str(b"/");
        crate::print_u64(device);
        crate::print_str(b"/");
        crate::print_u64(owner);
        crate::print_str(b"/");
        crate::print_u64(stage);
    } else {
        crate::print_str(b"unstable");
    }
    crate::print_str(b"\n");
}

struct PublicationGuard;

impl PublicationGuard {
    fn enter() -> Option<Self> {
        VIDEO_PUBLICATION_ACTIVE
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .ok()
            .map(|_| Self)
    }
}

impl Drop for PublicationGuard {
    fn drop(&mut self) {
        VIDEO_PUBLICATION_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
    }
}

pub(crate) unsafe fn video_file_owners_quiesced() -> bool {
    !VIDEO_PUBLICATION_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
        && !video_projection_owners::has_owners()
}

pub(crate) unsafe fn video_file_retirement_pending() -> u64 {
    video_projection_owners::pending_count()
}

#[inline(never)]
pub(crate) unsafe fn publish_hosted_video_device_route(
    reg: &HostedVideoDeviceRegistration<'_>,
) -> bool {
    let Some(_publication) = PublicationGuard::enter() else {
        print_hosted_video_publish_failure(b"publication-busy", None);
        return false;
    };
    let mut observation = PublicationObservation::enter(reg.device_id);
    let old_route = video_state_snapshot().route;
    if old_route.owner_id != 0
        && video_projection_owners::pointer_reference_count(old_route.owner_id) != Some(0)
    {
        print_hosted_video_publish_failure(b"route-busy", None);
        return false;
    }
    let Some(route_info) = crate::driver_launch::hosted_video_route_info(reg.device_id) else {
        print_hosted_video_publish_failure(b"route-info", None);
        return false;
    };
    observation.stage(2); // before projected driver/device objects
    if !ensure_video_objects(reg.allocate_projection) {
        print_hosted_video_publish_failure(b"objects", None);
        return false;
    }
    observation.stage(3); // after projected driver/device objects
    observation.stage(4); // before device identity binding
    if let Err(status) = crate::driver_launch::win32k_device_consumer::bind_projection(
        (*addr_of!(VIDEO_STATE)).objects.device,
        nt_io_manager::DeviceId(route_info.device_id),
    ) {
        print_hosted_video_publish_failure(b"device-identity", Some(NtStatus(status)));
        return false;
    }
    observation.stage(5); // after device identity binding
    observation.stage(6); // before metadata allocation
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
    observation.stage(7); // after metadata allocation
    observation.stage(8); // before File owner reservation
    let owner_id = match video_projection_owners::reserve() {
        Ok(owner) => owner,
        Err(status) => {
            print_hosted_video_publish_failure(b"file-owner", Some(status));
            return false;
        }
    };
    observation.owner_reserved(owner_id); // after File owner reservation
    observation.stage(10); // before native IRP_MJ_CREATE
    let (file_handle, file_id, opened_device, file_object_id) =
        match open_video_device_route(metadata) {
            Ok(route) => route,
            Err(status) => {
                video_projection_owners::retire(owner_id);
                print_hosted_video_publish_failure(b"open", Some(status));
                return false;
            }
        };
    observation.stage(11); // after native IRP_MJ_CREATE
    video_projection_owners::attach_open(owner_id, file_handle, file_id)
        .expect("reserved video File owner disappeared during open");
    if opened_device != route_info.device_id {
        video_projection_owners::retire(owner_id);
        print_hosted_video_publish_failure(
            b"opened-device",
            Some(NtStatus::INVALID_DEVICE_REQUEST),
        );
        return false;
    }
    observation.stage(12); // before File projection preparation
    let file_projection = match video_projection_owners::prepare(
        owner_id,
        route_info.device_id,
        video_state_snapshot().objects.device,
        reg.allocate_projection,
    ) {
        Ok(address) => address,
        Err(status) => {
            video_projection_owners::retire(owner_id);
            print_hosted_video_publish_failure(b"file-projection", Some(status));
            return false;
        }
    };
    observation.stage(13); // after File projection preparation
    observation.stage(14); // before old route teardown
    if !teardown_video_io_route() {
        video_projection_owners::retire(owner_id);
        print_hosted_video_publish_failure(b"teardown", None);
        return false;
    }
    observation.stage(15); // after old route teardown
    (*addr_of_mut!(VIDEO_STATE)).metadata = Some(metadata);
    commit_video_io_route(
        owner_id,
        file_projection,
        route_info.driver_id,
        route_info.device_id,
        route_info.device_object_id,
        file_handle,
        file_id,
        file_object_id,
        VideoRouteBackend::HostedIoManager,
    );
    observation.stage(16); // before Configuration Manager DeviceMap writes
    if !publish_video_device_map(metadata) {
        let _ = teardown_video_io_route();
        (*addr_of_mut!(VIDEO_STATE)).metadata = None;
        (*addr_of_mut!(VIDEO_STATE)).ready = false;
        print_hosted_video_publish_failure(b"devicemap", None);
        return false;
    }
    observation.stage(17); // after Configuration Manager DeviceMap writes
    (*addr_of_mut!(VIDEO_STATE)).ready = true;
    observation.stage(18); // completed publication
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
    allocate_projection: unsafe fn(u64) -> Option<RootProviderPoolAllocation>,
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
    let _durable = crate::allocator::enter_durable();
    let owners = &mut *addr_of_mut!(VIDEO_METADATA_ALLOCATIONS);
    owners.try_reserve(1).ok()?;
    let allocation = allocate_projection(total_len_u64)?;
    owners.push(allocation);
    let base = allocation.address();
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
            state.route.file_projection,
        )
    }
}

#[inline(never)]
unsafe fn ensure_video_objects(allocate_projection: unsafe fn(u64) -> Option<RootProviderPoolAllocation>) -> bool {
    if video_state_snapshot().objects.ready() {
        return true;
    }
    let driver_len = WDM_X64_DRIVER_OBJECT_SIZE + WDM_X64_DRIVER_EXTENSION_SIZE;
    if video_state_snapshot().objects.driver == 0 {
        let Some(allocation) = allocate_projection(driver_len as u64) else { return false; };
        (*addr_of_mut!(VIDEO_STATE)).objects.driver_allocation = Some(allocation);
        (*addr_of_mut!(VIDEO_STATE)).objects.driver = allocation.address();
    }
    if video_state_snapshot().objects.device == 0 {
        let layout = nt_io_manager::WdmDeviceObjectAllocationLayout::plan(0)
            .expect("zero driver extension has a representable layout");
        let Some(allocation) = allocate_projection(layout.allocation_size() as u64) else { return false; };
        (*addr_of_mut!(VIDEO_STATE)).objects.device_allocation = Some(allocation);
        (*addr_of_mut!(VIDEO_STATE)).objects.device = allocation.address();
    }
    let objects = video_state_snapshot().objects;
    let driver = objects.driver;
    let device = objects.device;
    if driver == 0 || device == 0 {
        return false;
    }
    let device_layout = nt_io_manager::WdmDeviceObjectAllocationLayout::plan(0)
        .expect("zero driver extension has a representable layout");

    // win32k needs projected, dereferenceable WDM bodies for the I/O Manager route identities.
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
    let initialized = write_wdm_device_object(
        core::slice::from_raw_parts_mut(device as *mut u8, device_layout.allocation_size()),
        WdmDeviceObjectInit {
            device_object_address: device,
            driver_object: driver,
            device_type: nt_video_miniport::FILE_DEVICE_VIDEO,
            stack_size: 1,
            ..WdmDeviceObjectInit::default()
        },
    )
    .is_ok();
    (*addr_of_mut!(VIDEO_STATE)).objects.initialized = initialized;
    initialized
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
    metadata: VideoRegistrationMetadata,
) -> Result<(u64, u64, u64, u64), NtStatus> {
    let device_path =
        core::str::from_utf8(metadata.device_path()).map_err(|_| NtStatus::INVALID_PARAMETER)?;
    crate::driver_launch::open_io_device(
        device_path,
        nt_types::AccessMask::GENERIC_READ | nt_types::AccessMask::GENERIC_WRITE,
    )
}

#[inline(never)]
unsafe fn commit_video_io_route(
    owner_id: u64,
    file_projection: u64,
    driver_id: u64,
    device_id: u64,
    device_object_id: u64,
    file_handle: u64,
    file_id: u64,
    file_object_id: u64,
    backend: VideoRouteBackend,
) {
    (*addr_of_mut!(VIDEO_STATE)).route = VideoIoRoute {
        owner_id,
        file_projection,
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

unsafe fn teardown_video_io_route() -> bool {
    let route = video_state_snapshot().route;
    if route.owner_id != 0
        && video_projection_owners::pointer_reference_count(route.owner_id) != Some(0)
    {
        return false;
    }
    (*addr_of_mut!(VIDEO_STATE)).ready = false;
    if route.owner_id != 0 {
        if !video_projection_owners::retire(route.owner_id) {
            return false;
        }
    }
    (*addr_of_mut!(VIDEO_STATE)).route = VideoIoRoute::empty();
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

/// Resolve the current attachment top through the File's exact consumer projection.
pub(crate) unsafe fn video_related_device_object(
    domain: nt_io_manager::HostedDomainIdentity,
    file_object: u64,
) -> Result<u64, NtStatus> {
    if !projected_video_route_ready() {
        return Err(NtStatus::DEVICE_NOT_READY);
    }
    let state = video_state_snapshot();
    if file_object == 0 || file_object != state.route.file_projection {
        return Err(NtStatus::INVALID_HANDLE);
    }
    video_projection_owners::related_device_address(domain, state.route.owner_id, file_object)
}

pub(crate) unsafe fn video_file_projection_contains(object: u64) -> bool {
    let state = video_state_snapshot();
    state.ready && object != 0 && object == state.route.file_projection
}

pub(crate) unsafe fn reference_video_file_pointer(
    domain: nt_io_manager::HostedDomainIdentity,
    object: u64,
) -> Result<u64, i32> {
    let _operation = PublicationGuard::enter().ok_or(NtStatus::DEVICE_BUSY.raw())?;
    if !projected_video_route_ready() || !video_file_projection_contains(object) {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let owner = video_state_snapshot().route.owner_id;
    video_projection_owners::reference_by_pointer(domain, owner, object).map_err(|status| status.raw())
}

pub(crate) unsafe fn release_video_file_projection(
    domain: nt_io_manager::HostedDomainIdentity,
    object: u64,
) -> Result<u64, i32> {
    let _operation = PublicationGuard::enter().ok_or(NtStatus::DEVICE_BUSY.raw())?;
    if !video_file_projection_contains(object) {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    video_projection_owners::dereference(domain, video_state_snapshot().route.owner_id, object)
        .map_err(|status| status.raw())
}

pub(crate) unsafe fn video_file_projection_reference_count() -> u64 {
    let route = video_state_snapshot().route;
    video_projection_owners::pointer_reference_count(route.owner_id).unwrap_or(0) as u64
}
