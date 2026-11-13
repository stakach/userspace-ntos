//! In-process CSR connection transport for LiberNT's ALPC API port.
//!
//! The shared frame lives in `nt_ntdll::csr`; this module owns only the live
//! syscall, native server path, and publication of the accepted port view.

use core::sync::atomic::Ordering;

use nt_alpc_abi::{AlpcPortAttributes, SecurityQualityOfService};
use nt_ntdll::csr::{CsrAlpcConnectFrame, CsrApiConnectInfo};

use super::{
    current_image_subsystem, publish_native_csr_static_data, CSR_API_PORT, CSR_CONNECTED,
    CSR_INSIDE_PROCESS, CSR_PORT_HEAP, CSR_PORT_MEMORY_DELTA, CSR_PROCESS_ID,
};

const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
const STATUS_NAME_TOO_LONG: u64 = 0xC000_0106;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_INVALID_BUFFER_SIZE: u64 = 0xC000_0206;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    _pad: u32,
    buffer: u64,
}

/// Connect to `ObjectDirectory\ApiPort` with LiberNT's framed CSR ALPC request.
///
/// # Safety
/// `object_directory` is null or a NUL-terminated UTF-16 string. Output pointers
/// are null or writable. The call runs inside a hosted process with a PEB.
pub unsafe fn csr_client_connect_to_server(
    object_directory: *const u16,
    _server_id: u32,
    _connection_info: *mut core::ffi::c_void,
    connection_info_size: *mut u32,
    server_to_server: *mut u8,
) -> u64 {
    if super::CSR_INSIDE_PROCESS.load(Ordering::Relaxed)
        || unsafe { current_image_subsystem() } == Some(IMAGE_SUBSYSTEM_NATIVE)
    {
        CSR_INSIDE_PROCESS.store(true, Ordering::Relaxed);
        if !server_to_server.is_null() {
            unsafe { core::ptr::write(server_to_server, 1) };
        }
        return unsafe { publish_native_csr_static_data() };
    }
    if !server_to_server.is_null() {
        unsafe { core::ptr::write(server_to_server, 0) };
    }
    if CSR_CONNECTED.swap(true, Ordering::Relaxed) {
        if !connection_info_size.is_null() {
            unsafe { core::ptr::write(connection_info_size, core::mem::size_of::<CsrApiConnectInfo>() as u32) };
        }
        return 0;
    }
    let status = unsafe { connect_and_publish(object_directory, connection_info_size) };
    if status != 0 {
        CSR_CONNECTED.store(false, Ordering::Relaxed);
    }
    status
}

unsafe fn connect_and_publish(object_directory: *const u16, connection_info_size: *mut u32) -> u64 {
    let mut name_buf = [0u16; 260];
    let mut len = 0usize;
    if object_directory.is_null() {
        for unit in "\\Windows".encode_utf16() {
            name_buf[len] = unit;
            len += 1;
        }
    } else {
        // The caller supplied a NUL-terminated directory; bounded reading avoids
        // silently connecting to a truncated namespace identity.
        while len < name_buf.len() - 9 {
            let unit = unsafe { core::ptr::read(object_directory.add(len)) };
            if unit == 0 { break; }
            name_buf[len] = unit;
            len += 1;
        }
        if len == name_buf.len() - 9 && unsafe { core::ptr::read(object_directory.add(len)) } != 0 {
            return STATUS_NAME_TOO_LONG;
        }
    }
    if len == 0 { return STATUS_INVALID_PARAMETER; }
    for unit in "\\ApiPort".encode_utf16() {
        name_buf[len] = unit;
        len += 1;
    }
    let name = UnicodeString {
        length: (len * 2) as u16,
        maximum_length: ((len + 1) * 2) as u16,
        _pad: 0,
        buffer: name_buf.as_ptr() as u64,
    };
    let attributes = AlpcPortAttributes {
        security_qos: SecurityQualityOfService {
            length: core::mem::size_of::<SecurityQualityOfService>() as u32,
            impersonation_level: 2,
            context_tracking_mode: 1,
            effective_only: 1,
            ..Default::default()
        },
        max_message_length: 0x1000,
        ..Default::default()
    };
    // S-1-5-18, the explicit server SID passed by LiberNT's csrlib.
    let system_sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut frame = CsrAlpcConnectFrame::new();
    let mut buffer_length = core::mem::size_of::<CsrAlpcConnectFrame>();
    let mut port = 0u64;
    let status = unsafe {
        nt_ntdll::trap_stubs::nt_alpc_connect_port(
            &mut port as *mut u64 as u64,
            &name as *const UnicodeString as u64,
            0,
            &attributes as *const AlpcPortAttributes as u64,
            nt_alpc_abi::connect_flag::SYNC_CONNECTION as u64,
            system_sid.as_ptr() as u64,
            &mut frame.header as *mut _ as u64,
            &mut buffer_length as *mut usize as u64,
            0,
            0,
            0,
        )
    };
    if status != 0 { return status; }
    if buffer_length < core::mem::size_of::<CsrAlpcConnectFrame>() || port == 0 {
        let _ = unsafe { nt_ntdll::trap_stubs::nt_close(port) };
        return STATUS_INVALID_BUFFER_SIZE;
    }
    let Some(layout) = nt_ntdll::csr::CsrPortHeapLayout::from_accepted_view(&frame.info) else {
        let _ = unsafe { nt_ntdll::trap_stubs::nt_close(port) };
        return STATUS_INVALID_BUFFER_SIZE;
    };
    let heap = unsafe { crate::exports::rtl_create_heap(
        0, layout.base as *mut core::ffi::c_void, layout.reserve, layout.commit,
        core::ptr::null_mut(), core::ptr::null_mut(),
    ) };
    if heap.is_null() {
        let _ = unsafe { nt_ntdll::trap_stubs::nt_close(port) };
        return super::STATUS_NO_MEMORY;
    }
    unsafe { publish_accepted_connection(port, heap as u64, &frame.info) };
    if !connection_info_size.is_null() {
        unsafe { core::ptr::write(connection_info_size, core::mem::size_of::<CsrApiConnectInfo>() as u32) };
    }
    0
}

unsafe fn publish_accepted_connection(port: u64, heap: u64, info: &CsrApiConnectInfo) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CSR_API_PORT), port);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CSR_PORT_HEAP), heap);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(CSR_PORT_MEMORY_DELTA),
            (info.port_view_remote_base as isize).wrapping_sub(info.port_view_base as isize),
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CSR_PROCESS_ID), info.server_process_id);
        let peb: u64;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        if peb != 0 {
            core::ptr::write_volatile((peb + 0x88) as *mut u64, info.shared_section_base);
            core::ptr::write_volatile((peb + 0x90) as *mut u64, info.shared_section_heap);
            core::ptr::write_volatile((peb + 0x98) as *mut u64, info.shared_static_server_data);
        }
    }
}
