//! Referenced security descriptors for the provider's centralized USER object owner.

use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_object_manager::object_security::{
    ObjectSecurityCache, ObjectSecurityCacheIo, ObjectSecurityCacheStats,
};
use nt_user_host::win32k_object_security::AssignmentPacket;

static BUSY: AtomicBool = AtomicBool::new(false);
static mut CACHE: ObjectSecurityCache = ObjectSecurityCache::new();
static ASSIGNMENTS: AtomicU64 = AtomicU64::new(0);
static ASSIGNMENT_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static PRIVILEGE_CHECKS: AtomicU64 = AtomicU64::new(0);
static PRIVILEGE_DENIALS: AtomicU64 = AtomicU64::new(0);

fn record_assignment_audit(audit: nt_security::SecurityAssignmentAudit) {
    for decision in [audit.security, audit.restore].into_iter().flatten() {
        PRIVILEGE_CHECKS.fetch_add(1, Ordering::Relaxed);
        PRIVILEGE_DENIALS.fetch_add(
            u64::from(decision == nt_security::SecurityAssignmentPrivilegeOutcome::Denied),
            Ordering::Relaxed,
        );
    }
}

pub(crate) fn print_assignment_stats() {
    print_str(b"[user-object-security] assignments=");
    print_u64(ASSIGNMENTS.load(Ordering::Relaxed));
    print_str(b" successes=");
    print_u64(ASSIGNMENT_SUCCESSES.load(Ordering::Relaxed));
    print_str(b" privilege-checks=");
    print_u64(PRIVILEGE_CHECKS.load(Ordering::Relaxed));
    print_str(b" privilege-denials=");
    print_u64(PRIVILEGE_DENIALS.load(Ordering::Relaxed));
    print_str(b"\n");
}

struct AssignmentSubjectLease {
    id: u64,
    access_state: u64,
}

impl AssignmentSubjectLease {
    unsafe fn begin(access_state: u64) -> Result<Self, i32> {
        let (words, raw, id, spare, reserved) = crate::driver_launch::call_on4_raw(
            (W32_SUBJECT_LABEL << 12) | 4,
            3,
            access_state,
            0,
            0,
        );
        if words != 4 || spare != 0 || reserved != 0 || (raw != 0 && id != 0)
            || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64)
        {
            crate::provider_bugcheck::report(0xc4, [W32_SUBJECT_LABEL, 3, words, raw]);
        }
        if raw != 0 {
            return Err(raw as u32 as i32);
        }
        if id == 0 {
            crate::provider_bugcheck::report(0xc4, [W32_SUBJECT_LABEL, 3, words, id]);
        }
        Ok(Self { id, access_state })
    }
}

impl Drop for AssignmentSubjectLease {
    fn drop(&mut self) {
        let (words, raw, first, second, third) = unsafe {
            crate::driver_launch::call_on4_raw(
                (W32_SUBJECT_LABEL << 12) | 4,
                5,
                self.id,
                self.access_state,
                0,
            )
        };
        if words != 4 || raw != 0 || first != 0 || second != 0 || third != 0 {
            unsafe { crate::provider_bugcheck::report(0xc4, [W32_SUBJECT_LABEL, 5, words, raw]) };
        }
    }
}

unsafe fn assign_from_descriptors(
    access_state: u64,
    parent: Option<&[u8]>,
    creator: Option<&[u8]>,
    object: u64,
    object_type: u64,
) -> i32 {
    let packet = AssignmentPacket {
        object,
        object_type,
        access_state,
        parent,
        creator,
    };
    let len = match packet.encoded_len() {
        Ok(len) => len,
        Err(status) => return status as i32,
    };
    let lease = match AssignmentSubjectLease::begin(access_state) {
        Ok(lease) => lease,
        Err(status) => return status,
    };
    let buffer = provider_pool_alloc(len as u64, false);
    if buffer == 0 {
        return STATUS_INSUFFICIENT_RESOURCES_I32;
    }
    let output = core::slice::from_raw_parts_mut(buffer as *mut u8, len);
    packet.encode(output).expect("validated assignment packet length");
    let (words, raw, first, second, third) = crate::driver_launch::call_on4_raw(
        (W32_SUBJECT_LABEL << 12) | 4,
        4,
        lease.id,
        buffer,
        len as u64,
    );
    if words != 4 || first != 0 || second != 0 || third != 0
        || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64)
    {
        crate::provider_bugcheck::report(0xc4, [W32_SUBJECT_LABEL, 4, words, raw]);
    }
    assert!(provider_pool_free(buffer), "assignment packet allocation lost its owner");
    drop(lease);
    raw as u32 as i32
}

pub(super) extern "win64" fn assign_export(
    access_state: u64,
    parent_descriptor: u64,
    object: u64,
    object_type: u64,
) -> i32 {
    if access_state == 0 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    unsafe {
        let creator_pointer = read_unaligned(
            (access_state + core::mem::offset_of!(nt_kernel_abi::security_create_x64::AccessState, security_descriptor) as u64)
                as *const u64,
        );
        let parent = if parent_descriptor != 0 {
            match capture_user_object_security_descriptor(parent_descriptor) {
                Ok(descriptor) => Some(descriptor),
                Err(status) => return status,
            }
        } else {
            None
        };
        let creator = if creator_pointer != 0 {
            match capture_user_object_security_descriptor(creator_pointer) {
                Ok(descriptor) => Some(descriptor),
                Err(status) => return status,
            }
        } else {
            None
        };
        assign_from_descriptors(
            access_state,
            parent.as_ref().map(CapturedUserObjectSecurityDescriptor::as_slice),
            creator.as_ref().map(CapturedUserObjectSecurityDescriptor::as_slice),
            object,
            object_type,
        )
    }
}

pub(super) unsafe fn assign_opened_desktop(
    parent: Option<&[u8]>,
    creator: Option<&[u8]>,
    object: u64,
) -> i32 {
    assign_from_descriptors(
        0,
        parent,
        creator,
        object,
        nt_object_manager::object_type::desktop_object_type_addr(),
    )
}

pub(crate) unsafe fn assign(
    packet: AssignmentPacket<'_>,
    subject: &nt_security::CapturedSubjectTokens<'_>,
    mode: nt_types::AccessMode,
) -> Result<(), u32> {
    if packet.object_type != nt_object_manager::object_type::desktop_object_type_addr()
        || (*core::ptr::addr_of!(OBJ_TABLE)).kind_by_body(packet.object)
            != Some(ObKind::Desktop)
    {
        return Err(STATUS_INVALID_HANDLE_I32 as u32);
    }
    let object_type = packet.object_type as *const nt_object_manager::object_type::ObjectType;
    if read_volatile(core::ptr::addr_of!((*object_type).type_info.methods[5])) != 0 {
        return Err(STATUS_NOT_SUPPORTED_I32 as u32);
    }
    let native = &(*object_type).type_info.generic_mapping;
    let mapping = nt_security::GenericMapping {
        generic_read: read_volatile(core::ptr::addr_of!(native.generic_read)),
        generic_write: read_volatile(core::ptr::addr_of!(native.generic_write)),
        generic_execute: read_volatile(core::ptr::addr_of!(native.generic_execute)),
        generic_all: read_volatile(core::ptr::addr_of!(native.generic_all)),
    };
    ASSIGNMENTS.fetch_add(1, Ordering::Relaxed);
    let result = nt_user_host::win32k_object_security::assign_exact_desktop(
        &mut *core::ptr::addr_of_mut!(OBJ_TABLE),
        packet,
        subject,
        &mapping,
        match mode {
            nt_types::AccessMode::KernelMode => nt_security::ProcessorMode::KernelMode,
            nt_types::AccessMode::UserMode => nt_security::ProcessorMode::UserMode,
        },
        record_assignment_audit,
    );
    ASSIGNMENT_SUCCESSES.fetch_add(u64::from(result.is_ok()), Ordering::Relaxed);
    result
}

struct CacheGuard;

impl CacheGuard {
    fn acquire() -> Option<Self> {
        BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

struct PoolIo;

impl ObjectSecurityCacheIo for PoolIo {
    fn allocate_copy(&mut self, bytes: &[u8]) -> Result<u64, u32> {
        unsafe {
            let pointer = provider_pool_alloc(bytes.len() as u64, false);
            if pointer == 0 {
                return Err(STATUS_INSUFFICIENT_RESOURCES_I32 as u32);
            }
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer as *mut u8, bytes.len());
            Ok(pointer)
        }
    }

    fn free(&mut self, pointer: u64) -> Result<(), u32> {
        if unsafe { provider_pool_free(pointer) } {
            Ok(())
        } else {
            Err(STATUS_INVALID_PARAMETER_I32 as u32)
        }
    }
}

pub(crate) fn census() -> Option<ObjectSecurityCacheStats> {
    let _guard = CacheGuard::acquire()?;
    Some(unsafe { (&*core::ptr::addr_of!(CACHE)).stats() })
}

pub(super) unsafe fn retry_retirements() {
    let Some(_guard) = CacheGuard::acquire() else {
        return;
    };
    (&mut *core::ptr::addr_of_mut!(CACHE)).retry_retirements(&mut PoolIo);
}

pub(super) extern "win64" fn get(
    object: u64,
    descriptor_out: *mut u64,
    allocated_out: *mut u8,
) -> i32 {
    if descriptor_out.is_null() || allocated_out.is_null() {
        return 0xC000_0005u32 as i32;
    }
    unsafe {
        write_unaligned(descriptor_out, 0);
        write_volatile(allocated_out, 0);
        // The table borrow ends before any pool operation can yield or enter the broker.
        let mut captured = CapturedUserObjectSecurityDescriptor::empty();
        let kind = {
            let table = &*core::ptr::addr_of!(OBJ_TABLE);
            let Some((kind, descriptor)) = table.security_descriptor_by_body(object) else {
                return STATUS_INVALID_HANDLE_I32;
            };
            if let Some(bytes) = descriptor {
                captured.bytes[..bytes.len()].copy_from_slice(bytes);
                captured.len = bytes.len();
            }
            kind
        };
        let object_type = match kind {
            ObKind::Desktop => nt_object_manager::object_type::desktop_object_type_addr(),
            ObKind::WindowStation => {
                nt_object_manager::object_type::window_station_object_type_addr()
            }
            ObKind::Other => return STATUS_NOT_SUPPORTED_I32,
        } as *const nt_object_manager::object_type::ObjectType;
        // Only these two registered owners implement centralized security here. A custom
        // SecurityProcedure is a separate callout contract, never an implicit default method.
        if read_volatile(core::ptr::addr_of!((*object_type).type_info.methods[5])) != 0 {
            return STATUS_NOT_SUPPORTED_I32;
        }
        let Some(_guard) = CacheGuard::acquire() else {
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        };
        let descriptor = (captured.len != 0).then_some(captured.as_slice());
        match (&mut *core::ptr::addr_of_mut!(CACHE)).acquire(descriptor, &mut PoolIo) {
            Ok(pointer) => {
                write_unaligned(descriptor_out, pointer);
                0
            }
            Err(status) => status as i32,
        }
    }
}

pub(super) extern "win64" fn release(descriptor: u64, allocated: u8) {
    if descriptor == 0 {
        return;
    }
    let Some(_guard) = CacheGuard::acquire() else {
        print_str(b"[object-security] reentrant descriptor release\n");
        park();
    };
    unsafe {
        let cache = &mut *core::ptr::addr_of_mut!(CACHE);
        if allocated != 0 {
            // An allocated-query release must never bypass a live cache reference.
            if cache.contains(descriptor) || !provider_pool_free(descriptor) {
                print_str(b"[object-security] invalid allocated descriptor release\n");
                park();
            }
            return;
        }
        if let Err(status) = cache.release(descriptor, &mut PoolIo) {
            print_str(b"[object-security] descriptor release status=");
            print_hex(status);
            print_str(b"\n");
        }
    }
}
