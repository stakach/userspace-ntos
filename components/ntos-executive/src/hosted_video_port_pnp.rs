//! VideoPort's native FDO BusRelations callback and returned PDO graph.
//!
//! A child candidate is recorded before IoCreateDevice or the miniport callback can run. A
//! callback fault leaves that owner in place; only a returned Skip/Stop result permits deletion.

use super::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use nt_video_miniport::{
    classify_video_child_callback_status, VideoChildCallbackAction, VideoChildEnumInfoX64,
    VideoHardwareInitializationState, VideoPortDeviceStateCell, MonitorChildIdResult,
    write_monitor_child_id, VIDEO_CHILD_DESCRIPTOR_SIZE, VIDEO_CHILD_TYPE_MONITOR,
    VIDEO_CHILD_TYPE_VIDEO_CHIP, VIDEO_PORT_DEVICE_STATE_SIZE,
};

const MAX_CHILD_PROBES: u32 = 64;
const FILE_DEVICE_CONTROLLER: u32 = 4;
const FILE_DEVICE_SECURE_OPEN: u32 = 0x100;
const STATUS_DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;
const EDID_HEADER: [u8; 8] = [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0];

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Enumerating,
    Ready,
    Publishing,
    Published,
    Releasing,
    Blocked,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ChildPhase {
    Creating,
    Probing,
    Published,
    Deleting,
}

struct Child {
    device: u64,
    phase: ChildPhase,
    enum_info: VideoChildEnumInfoX64,
    child_type: u32,
    descriptor: [u8; VIDEO_CHILD_DESCRIPTOR_SIZE as usize],
    uid: u32,
    unused: u32,
}

#[derive(Clone, Copy)]
struct ChildSnapshot {
    parent_device: u64,
    child_type: u32,
    child_id: u32,
    descriptor: [u8; VIDEO_CHILD_DESCRIPTOR_SIZE as usize],
}

unsafe fn child_snapshot(device: u64) -> Option<ChildSnapshot> {
    let _guard = ParentsGuard::acquire();
    (*core::ptr::addr_of!(PARENTS)).iter().find_map(|parent| {
        parent.children.iter().find(|child| {
            child.device == device && child.phase == ChildPhase::Published
        }).map(|child| ChildSnapshot {
            parent_device: parent.device,
            child_type: child.child_type,
            child_id: child.enum_info.child_index,
            descriptor: child.descriptor,
        })
    })
}

struct Parent {
    device: u64,
    driver: u64,
    phase: Phase,
    children: Vec<Box<Child>>,
    /// A publication begun before native reference/complete effects remains owned on a fault.
    relation: u64,
    relation_generation: u64,
    referenced: usize,
    released: usize,
    release_in_flight: Option<usize>,
    /// False when the root has already copied and freed the published allocation.
    release_allocation: bool,
    release_allocation_in_flight: bool,
}

static mut PARENTS: Vec<Parent> = Vec::new();
static PARENTS_LOCK: AtomicBool = AtomicBool::new(false);

struct ParentsGuard;

impl ParentsGuard {
    fn acquire() -> Self {
        while PARENTS_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::yield_now();
        }
        Self
    }
}

impl Drop for ParentsGuard {
    fn drop(&mut self) {
        PARENTS_LOCK.store(false, Ordering::Release);
    }
}

unsafe fn parent_update<T>(device: u64, update: impl FnOnce(&mut Parent) -> T) -> Option<T> {
    let _guard = ParentsGuard::acquire();
    (*core::ptr::addr_of_mut!(PARENTS))
        .iter_mut()
        .find(|parent| parent.device == device)
        .map(update)
}

unsafe fn complete(irp: u64, status: i32, information: u64) -> i32 {
    write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32, status);
    write_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64, information);
    s_io_complete_request(irp, 0);
    status
}

/// Release one reference at a time. The in-flight index is recorded before each root RPC; a
/// fault or uncertain reply leaves it set, so a repeated ACK cannot issue the same dereference.
unsafe fn release_recorded_references(parent_device: u64, allocation: u64, generation: u64) -> bool {
    loop {
        let next = parent_update(parent_device, |parent| {
            if parent.phase != Phase::Releasing
                || parent.relation != allocation
                || parent.relation_generation != generation
                || parent.release_in_flight.is_some()
                || parent.release_allocation_in_flight
                || parent.released > parent.referenced
                || parent.referenced != parent.children.len()
            {
                return Err(());
            }
            if parent.released == parent.referenced {
                return Ok(None);
            }
            let index = parent.released;
            let child = &parent.children[index];
            if child.phase != ChildPhase::Published || child.device == 0 {
                return Err(());
            }
            let device = child.device;
            parent.release_in_flight = Some(index);
            Ok(Some((index, device)))
        }).unwrap_or(Err(()));
        let (index, device) = match next {
            Ok(Some(next)) => next,
            Ok(None) => break,
            Err(()) => return false,
        };
        s_obf_dereference_object(device);
        let recorded = parent_update(parent_device, |parent| {
            if parent.phase != Phase::Releasing
                || parent.relation != allocation
                || parent.relation_generation != generation
                || parent.release_in_flight != Some(index)
                || parent.released != index
                || parent.children[index].device != device
            {
                return false;
            }
            parent.released += 1;
            parent.release_in_flight = None;
            true
        }).unwrap_or(false);
        if !recorded {
            return false;
        }
    }
    let reclaim = parent_update(parent_device, |parent| {
        let eligible = parent.phase == Phase::Releasing
            && parent.relation == allocation
            && parent.relation_generation == generation
            && parent.release_in_flight.is_none()
            && parent.released == parent.referenced
            && !parent.release_allocation_in_flight;
        if eligible && parent.release_allocation {
            parent.release_allocation_in_flight = true;
            true
        } else {
            false
        }
    }).unwrap_or(false);
    if reclaim && !pool_free_exact(allocation, generation) {
        parent_update(parent_device, |parent| parent.phase = Phase::Blocked);
        return false;
    }
    if reclaim {
        parent_update(parent_device, |parent| {
            if parent.phase != Phase::Releasing
                || !parent.release_allocation_in_flight
                || parent.relation != allocation
                || parent.relation_generation != generation
            {
                return false;
            }
            parent.release_allocation = false;
            parent.release_allocation_in_flight = false;
            true
        }).unwrap_or(false);
    }
    parent_update(parent_device, |parent| {
        if parent.phase != Phase::Releasing
            || parent.relation != allocation
            || parent.relation_generation != generation
            || parent.release_in_flight.is_some()
            || parent.released != parent.referenced
            || parent.release_allocation
            || parent.release_allocation_in_flight
        {
            return false;
        }
        parent.relation = 0;
        parent.relation_generation = 0;
        parent.referenced = 0;
        parent.released = 0;
        parent.release_allocation = false;
        parent.release_allocation_in_flight = false;
        parent.phase = Phase::Ready;
        true
    }).unwrap_or(false)
}

/// The root may acknowledge only after it has copied and freed the exact relation allocation.
/// It authenticates this parent/device and physical generation before delivering these three
/// words; the component then releases its own counted child references. A repeated call may
/// resume after fully recorded releases but never retries a release still marked in flight.
pub(super) unsafe fn acknowledge_relation(parent_device: u64, allocation: u64, generation: u64) -> Option<bool> {
    let admitted = parent_update(parent_device, |parent| {
        if allocation == 0 || generation == 0 {
            return false;
        }
        if parent.relation != allocation
            || parent.relation_generation != generation
            || parent.referenced != parent.children.len()
            || parent.children.iter().any(|child| child.phase != ChildPhase::Published)
        {
            return false;
        }
        if parent.phase == Phase::Published {
            if parent.released != 0
                || parent.release_in_flight.is_some()
                || parent.release_allocation
                || parent.release_allocation_in_flight
            {
                return false;
            }
            parent.phase = Phase::Releasing;
            return true;
        }
        parent.phase == Phase::Releasing && !parent.release_allocation
    })?;
    Some(admitted && release_recorded_references(parent_device, allocation, generation))
}

/// Validate the FDO's exact native layout before reading its persistent VideoPort state.
unsafe fn opened_video_fdo(device: u64) -> Result<(u64, u64), i32> {
    let initialization = HOSTED_VIDEO_PORT_INITIALIZATION.ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    let capacity = component_pool_allocation_capacity(device)
        .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    if capacity < WDM_X64_DEVICE_OBJECT_SIZE as u64 {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let driver = read_unaligned((device + 8) as *const u64);
    let extension = read_unaligned((device + 0x40) as *const u64);
    let hw_size = initialization.data.hw_device_extension_size as u64;
    let required = (WDM_X64_DEVICE_OBJECT_SIZE as u64)
        .checked_add(VIDEO_PORT_DEVICE_STATE_SIZE as u64)
        .and_then(|size| size.checked_add(hw_size))
        .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    if initialization.driver_object != driver
        || hw_size == 0
        || read_unaligned(device as *const i16) != WDM_X64_IO_TYPE_DEVICE
        || read_unaligned((device + 2) as *const u16) as u64 != required
        || extension != device + WDM_X64_DEVICE_OBJECT_SIZE as u64
        || read_unaligned((device + 0x48) as *const u32) != nt_video_miniport::FILE_DEVICE_VIDEO
        || capacity < required
    {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let state = (&*(extension as *const VideoPortDeviceStateCell))
        .snapshot()
        .map_err(|_| STATUS_INVALID_DEVICE_REQUEST)?;
    if state.initialization_state() != VideoHardwareInitializationState::Succeeded {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    Ok((driver, extension + VIDEO_PORT_DEVICE_STATE_SIZE as u64))
}

/// Every child object has a stable Box owner before the native create and callback effects.
unsafe fn probe_child(parent_device: u64, driver: u64, hw_extension: u64, index: u32,
    child_extension_size: u32, callback: u64) -> Result<VideoChildCallbackAction, i32> {
    let child = Box::new(Child {
        device: 0,
        phase: ChildPhase::Creating,
        enum_info: VideoChildEnumInfoX64::new(index, 0),
        child_type: 0,
        descriptor: [0; VIDEO_CHILD_DESCRIPTOR_SIZE as usize],
        uid: 0,
        unused: 0,
    });
    let child_ptr = parent_update(parent_device, |parent| {
        if parent.phase != Phase::Enumerating || parent.children.try_reserve(1).is_err() {
            return None;
        }
        parent.children.push(child);
        parent.children.last_mut().map(|child| &mut **child as *mut Child)
    })
    .flatten()
    .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let status = s_io_create_device(
        driver, child_extension_size, 0, FILE_DEVICE_CONTROLLER,
        FILE_DEVICE_SECURE_OPEN, 0, (&mut (*child_ptr).device as *mut u64) as u64,
    );
    if status != STATUS_SUCCESS {
        // Rejected creation has no native device effect; a retained/uncertain create bugchecks.
        parent_update(parent_device, |parent| { parent.children.pop(); });
        return Err(status);
    }
    let child_device = (*child_ptr).device;
    if child_device == 0 {
        parent_update(parent_device, |parent| parent.phase = Phase::Blocked);
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    (*child_ptr).phase = ChildPhase::Probing;
    let child_hw_extension = if child_extension_size == 0 {
        0
    } else {
        read_unaligned((child_device + 0x40) as *const u64)
    };
    (*child_ptr).enum_info = VideoChildEnumInfoX64::new(index, child_hw_extension);
    let callback_status = call_hosted_pe(callback, &[
        hw_extension,
        (&(*child_ptr).enum_info as *const VideoChildEnumInfoX64) as u64,
        (&mut (*child_ptr).child_type as *mut u32) as u64,
        (*child_ptr).descriptor.as_mut_ptr() as u64,
        (&mut (*child_ptr).uid as *mut u32) as u64,
        (&mut (*child_ptr).unused as *mut u32) as u64,
    ]) as u32;
    let action = match classify_video_child_callback_status(callback_status) {
        Ok(action) => action,
        Err(_) => {
            // Unknown callback effects cannot justify deleting or reusing the candidate.
            parent_update(parent_device, |parent| parent.phase = Phase::Blocked);
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
    };
    match action {
        VideoChildCallbackAction::Publish => {
            (&*((child_device + 0x30) as *const AtomicU32))
                .fetch_and(!DeviceFlags::DEVICE_INITIALIZING.bits(), Ordering::AcqRel);
            (*child_ptr).phase = ChildPhase::Published;
        }
        VideoChildCallbackAction::Skip | VideoChildCallbackAction::Stop => {
            (*child_ptr).phase = ChildPhase::Deleting;
            let deletion = hosted_device_delete(child_device);
            if deletion != STATUS_SUCCESS {
                parent_update(parent_device, |parent| parent.phase = Phase::Blocked);
                return Err(deletion);
            }
            parent_update(parent_device, |parent| { parent.children.pop(); });
        }
    }
    Ok(action)
}

/// Roll back only children whose create and callback effects returned conclusively.
unsafe fn rollback(parent_device: u64) -> Result<(), i32> {
    loop {
        let Some(device) = parent_update(parent_device, |parent| {
            parent.children.last_mut().map(|child| {
                child.phase = ChildPhase::Deleting;
                child.device
            })
        }).flatten() else { break };
        if device != 0 {
            let deletion = hosted_device_delete(device);
            if deletion != STATUS_SUCCESS {
                parent_update(parent_device, |parent| parent.phase = Phase::Blocked);
                return Err(deletion);
            }
        }
        parent_update(parent_device, |parent| { parent.children.pop(); });
    }
    let _guard = ParentsGuard::acquire();
    let parents = &mut *core::ptr::addr_of_mut!(PARENTS);
    if let Some(index) = parents.iter().position(|parent| parent.device == parent_device) {
        parents.swap_remove(index);
    }
    Ok(())
}

unsafe fn enumerate(parent_device: u64, driver: u64, hw_extension: u64,
    child_extension_size: u32, callback: u64) -> Result<(), i32> {
    for index in 1..=MAX_CHILD_PROBES {
        match probe_child(parent_device, driver, hw_extension, index, child_extension_size, callback) {
            Ok(VideoChildCallbackAction::Publish | VideoChildCallbackAction::Skip) => {}
            Ok(VideoChildCallbackAction::Stop) => {
                parent_update(parent_device, |parent| parent.phase = Phase::Ready);
                return Ok(());
            }
            Err(status) => {
                if parent_update(parent_device, |parent| parent.phase) == Some(Phase::Enumerating) {
                    rollback(parent_device)?;
                }
                return Err(status);
            }
        }
    }
    rollback(parent_device)?;
    Err(STATUS_INSUFFICIENT_RESOURCES)
}

unsafe fn relation(parent_device: u64, irp: u64) -> i32 {
    let objects = parent_update(parent_device, |parent| {
        if parent.phase != Phase::Ready { return None; }
        let mut objects = Vec::new();
        if objects.try_reserve_exact(parent.children.len()).is_err() { return None; }
        for child in &parent.children {
            if child.phase != ChildPhase::Published || child.device == 0 { return None; }
            objects.push(child.device);
        }
        parent.phase = Phase::Publishing;
        Some(objects)
    }).flatten();
    let Some(objects) = objects else { return complete(irp, STATUS_INSUFFICIENT_RESOURCES, 0); };
    if objects.is_empty() {
        parent_update(parent_device, |parent| parent.phase = Phase::Ready);
        // ReactOS leaves the incoming status and Information untouched when there are no children.
        let status = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *const i32);
        let information = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *const u64);
        return complete(irp, status, information);
    }
    let bytes = 8u64 + (objects.len() as u64) * 8;
    let allocation = pool_alloc(bytes);
    if allocation == 0 {
        parent_update(parent_device, |parent| parent.phase = Phase::Ready);
        return complete(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    let generation = read_volatile((allocation - 8) as *const u64);
    if generation == 0 {
        parent_update(parent_device, |parent| parent.phase = Phase::Blocked);
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    parent_update(parent_device, |parent| {
        parent.relation = allocation;
        parent.relation_generation = generation;
    });
    for &device in &objects {
        // Record the possible effect before ObReferenceObject. A fault retains the owner.
        parent_update(parent_device, |parent| parent.referenced += 1);
        s_obf_reference_object(device);
    }
    let output = core::slice::from_raw_parts_mut(allocation as *mut u8, bytes as usize);
    if nt_pnp_manager::write_device_relations_x64(output, &objects).is_err() {
        parent_update(parent_device, |parent| {
            parent.phase = Phase::Releasing;
            parent.release_allocation = true;
        });
        if !release_recorded_references(parent_device, allocation, generation) {
            parent_update(parent_device, |parent| parent.phase = Phase::Blocked);
        }
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    // Publish the receipt before IoCompleteRequest can wake the root's copy/ACK path.
    // A fault during completion leaves this publication owned and blocks a new query.
    parent_update(parent_device, |parent| {
        parent.phase = Phase::Published;
    });
    // The root must copy/free the exact relation and acknowledge its generation; this component
    // then releases the counted child references.
    complete(irp, STATUS_SUCCESS, allocation)
}

unsafe fn complete_existing(irp: u64) -> i32 {
    let status = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *const i32);
    let information = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *const u64);
    complete(irp, status, information)
}

unsafe fn return_utf16(irp: u64, units: &[u16]) -> i32 {
    let bytes = (units.len() * 2) as u64;
    let allocation = pool_alloc(bytes);
    if allocation == 0 {
        return complete(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    for (index, &unit) in units.iter().enumerate() {
        write_unaligned((allocation + (index * 2) as u64) as *mut u16, unit);
    }
    complete(irp, STATUS_SUCCESS, allocation)
}

unsafe fn child_query_id(irp: u64, stack: u64, child: &ChildSnapshot) -> i32 {
    if child.child_type != VIDEO_CHILD_TYPE_MONITOR {
        return complete_existing(irp);
    }
    let id_type = read_unaligned((stack + 0x08) as *const u32);
    let mut units = [0u16; 32];
    let edid_valid = child.descriptor[..8] == EDID_HEADER;
    match write_monitor_child_id(
        id_type, child.child_id, edid_valid, &child.descriptor, &mut units,
    ) {
        Ok(MonitorChildIdResult::Written { units: count }) => return_utf16(irp, &units[..count]),
        Ok(MonitorChildIdResult::Unsupported) => complete_existing(irp),
        Err(_) => complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0),
    }
}

unsafe fn child_query_text(irp: u64, stack: u64, child: &ChildSnapshot) -> i32 {
    if read_unaligned((stack + 0x08) as *const u32) != nt_pnp_abi::DEVICE_TEXT_DESCRIPTION {
        return complete_existing(irp);
    }
    let default: &[u8] = match child.child_type {
        VIDEO_CHILD_TYPE_MONITOR => b"Monitor",
        VIDEO_CHILD_TYPE_VIDEO_CHIP => b"Video chip",
        _ => b"Other device",
    };
    let description = if child.child_type == VIDEO_CHILD_TYPE_MONITOR
        && child.descriptor[..8] == EDID_HEADER
    {
        [0x36usize, 0x48, 0x5a, 0x6c].iter().find_map(|&offset| {
            let block = &child.descriptor[offset..offset + 18];
            if block[..4] != [0, 0, 0, 0xfc] { return None; }
            let data = &block[5..18]; // ReactOS skips descriptor's reserved byte.
            let length = data.iter().position(|&byte| byte == b'\n').unwrap_or(data.len());
            (length != 0).then_some(&data[..length])
        }).unwrap_or(default)
    } else {
        default
    };
    let mut units = [0u16; 14];
    for (index, &byte) in description.iter().take(13).enumerate() {
        units[index] = u16::from(byte);
    }
    return_utf16(irp, &units[..description.len().min(13) + 1])
}

unsafe fn child_query_capabilities(irp: u64, stack: u64, child: &ChildSnapshot) -> i32 {
    let capabilities = read_unaligned((stack + 0x08) as *const u64);
    if component_pool_allocation_capacity(capabilities)
        .is_none_or(|capacity| capacity < nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE as u64)
        || read_unaligned(capabilities as *const u16)
            != nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE as u16
        || read_unaligned((capabilities + 2) as *const u16) != 1
    {
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    // ReactOS leaves Address and UINumber intact, and initializes every power state.
    let mut flags = read_unaligned((capabilities + 4) as *const u32);
    const REACTOS_FLAGS: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3)
        | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8)
        | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13)
        | (1 << 14) | (1 << 17);
    flags &= !REACTOS_FLAGS;
    if child.child_type == VIDEO_CHILD_TYPE_MONITOR {
        flags |= (1 << 4) | (1 << 7) | (1 << 9);
    }
    write_unaligned((capabilities + 4) as *mut u32, flags);
    for index in 1..7u64 {
        write_unaligned((capabilities + 16 + index * 4) as *mut u32, if index == 1 { 1 } else { 4 });
    }
    write_unaligned((capabilities + 44) as *mut u32, 0); // PowerSystemUnspecified
    write_unaligned((capabilities + 48) as *mut u32, 0); // PowerDeviceUnspecified
    for offset in [52u64, 56, 60] {
        write_unaligned((capabilities + offset) as *mut u32, 0);
    }
    let information = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *const u64);
    complete(irp, STATUS_SUCCESS, information)
}

unsafe fn child_remove(device: u64, irp: u64, child: &ChildSnapshot) -> i32 {
    let admitted = parent_update(child.parent_device, |parent| {
        if parent.phase != Phase::Ready { return false; }
        let Some(child) = parent.children.iter_mut().find(|child| child.device == device) else {
            return false;
        };
        if child.phase != ChildPhase::Published { return false; }
        child.phase = ChildPhase::Deleting;
        true
    }).unwrap_or(false);
    if !admitted { return complete(irp, STATUS_DEVICE_BUSY, 0); }
    // Match ReactOS's completion-before-delete order; retain Deleting on an uncertain effect.
    let status = complete(irp, STATUS_SUCCESS, 0);
    let deletion = hosted_device_delete(device);
    if deletion == STATUS_SUCCESS {
        parent_update(child.parent_device, |parent| {
            if let Some(index) = parent.children.iter().position(|child| {
                child.device == device && child.phase == ChildPhase::Deleting
            }) {
                parent.children.swap_remove(index);
            }
        });
    } else {
        parent_update(child.parent_device, |parent| parent.phase = Phase::Blocked);
    }
    status
}

unsafe fn child_dispatch(device: u64, irp: u64, stack: u64, minor: u8,
    child: &ChildSnapshot) -> i32 {
    match minor {
        nt_pnp_abi::IRP_MN_QUERY_ID => child_query_id(irp, stack, child),
        nt_pnp_abi::IRP_MN_QUERY_DEVICE_TEXT => child_query_text(irp, stack, child),
        nt_pnp_abi::IRP_MN_QUERY_CAPABILITIES => child_query_capabilities(irp, stack, child),
        nt_pnp_abi::IRP_MN_START_DEVICE | nt_pnp_abi::IRP_MN_STOP_DEVICE
        | nt_pnp_abi::IRP_MN_QUERY_REMOVE_DEVICE | nt_pnp_abi::IRP_MN_SURPRISE_REMOVAL => {
            complete(irp, STATUS_SUCCESS, 0)
        }
        nt_pnp_abi::IRP_MN_REMOVE_DEVICE => child_remove(device, irp, child),
        _ => complete_existing(irp),
    }
}

pub(super) unsafe extern "win64" fn dispatch(device: u64, irp: u64) -> i32 {
    let Some((stack_count, current_location, stack)) = validate_hosted_irp_packet(irp) else {
        return STATUS_INVALID_DEVICE_REQUEST;
    };
    if current_location > stack_count || !pending_irp_raw_identity_exists(irp)
        || read_unaligned(stack as *const u8) != major::IRP_MJ_PNP
        || read_unaligned((stack + WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET) as *const u64) != device
    {
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let minor = read_unaligned((stack + 1) as *const u8);
    if let Some(child) = child_snapshot(device) {
        return child_dispatch(device, irp, stack, minor, &child);
    }
    if minor != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
        || read_unaligned((stack + 0x08) as *const u32) != nt_pnp_abi::BUS_RELATIONS
    {
        return complete_existing(irp);
    }
    let (driver, hw_extension) = match opened_video_fdo(device) {
        Ok(opened) => opened,
        Err(status) => return complete(irp, status, 0),
    };
    let Some(initialization) = HOSTED_VIDEO_PORT_INITIALIZATION else {
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    };
    let callback = initialization.data.hw_get_video_child_descriptor;
    if callback == 0 {
        let status = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *const i32);
        return complete(irp, status, 0);
    }
    let admission = {
        let _guard = ParentsGuard::acquire();
        let parents = &mut *core::ptr::addr_of_mut!(PARENTS);
        if let Some(parent) = parents.iter().find(|parent| parent.device == device) {
            if parent.driver != driver || parent.phase != Phase::Ready {
                Err(STATUS_DEVICE_BUSY)
            } else {
                Ok(false)
            }
        } else {
            if parents.try_reserve(1).is_err() {
                Err(STATUS_INSUFFICIENT_RESOURCES)
            } else {
                parents.push(Parent {
                    device, driver, phase: Phase::Enumerating, children: Vec::new(),
                    relation: 0, relation_generation: 0, referenced: 0, released: 0,
                    release_in_flight: None, release_allocation: false,
                    release_allocation_in_flight: false,
                });
                Ok(true)
            }
        }
    };
    let fresh = match admission {
        Ok(fresh) => fresh,
        Err(status) => return complete(irp, status, 0),
    };
    if fresh {
        if let Err(status) = enumerate(
            device, driver, hw_extension,
            initialization.data.hw_child_device_extension_size, callback,
        ) {
            return complete(irp, status, 0);
        }
    }
    relation(device, irp)
}
