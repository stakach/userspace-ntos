//! `Csr*` — the CSR (Client/Server Runtime) client stubs (8 imported exports).
//!
//! The Win32 subsystem (csrss) is reached from a client process over an **LPC port** (`\Windows\
//! ApiPort`). The `Csr*` client exports build a **`CSR_API_MESSAGE`** — a `PORT_MESSAGE` header + a
//! CSR-specific body (API number + argument union) — optionally carrying a **capture buffer** for
//! the pointer arguments (CSR can't dereference client pointers directly, so variable-length args
//! are copied into a self-describing buffer whose internal pointers are relocated to server
//! address space on receipt), and then issue `NtRequestWaitReplyPort` on the CSR port.
//!
//! This module implements the **message construction + capture-buffer marshalling** (host-tested)
//! and models the connection handshake. The actual port send is the **LPC seam** over
//! [`nt_port_core`] (wired later — `project_alpc`): [`CsrPort::call_server`] builds the message and
//! routes it through the seam, which returns `STATUS_NOT_IMPLEMENTED` until the LPC transport is
//! connected — never a faked round-trip.

use alloc::vec::Vec;

use nt_port_core::PortApi;

use crate::NtStatus;
use crate::STATUS_INVALID_PARAMETER;
use crate::STATUS_NOT_IMPLEMENTED;

/// `STATUS_BUFFER_TOO_SMALL`.
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;

/// x64 `CSR_CAPTURE_BUFFER` header bytes before `PointerOffsetsArray`.
pub const CSR_CAPTURE_BUFFER_HEADER_LEN: usize = 0x20;
/// `CSR_CAPTURE_BUFFER.Size`.
pub const CSR_CAPTURE_BUFFER_SIZE_OFFSET: usize = 0x00;
/// `CSR_CAPTURE_BUFFER.PreviousCaptureBuffer`.
pub const CSR_CAPTURE_BUFFER_PREVIOUS_OFFSET: usize = 0x08;
/// `CSR_CAPTURE_BUFFER.PointerCount`.
pub const CSR_CAPTURE_BUFFER_POINTER_COUNT_OFFSET: usize = 0x10;
/// Private client-side copy of the original pointer-slot capacity. This lives in structure padding on
/// x64 and is ignored by ReactOS csrsrv; it prevents client-side overrun before the message is sent.
pub const CSR_CAPTURE_BUFFER_MAX_POINTERS_OFFSET: usize = 0x14;
/// `CSR_CAPTURE_BUFFER.BufferEnd`.
pub const CSR_CAPTURE_BUFFER_END_OFFSET: usize = 0x18;
/// `CSR_CAPTURE_BUFFER.PointerOffsetsArray`.
pub const CSR_CAPTURE_BUFFER_POINTERS_OFFSET: usize = 0x20;

/// x64 `CSR_API_MESSAGE` byte layout used by `CsrClientCallServer`.
pub const CSR_API_MESSAGE_HEADER_LEN: usize = PORT_MESSAGE_HEADER_LEN;
pub const CSR_API_MESSAGE_DATA_OFFSET: usize = 0x28;
pub const CSR_API_MESSAGE_CAPTURE_DATA_OFFSET: usize = 0x28;
pub const CSR_API_MESSAGE_API_NUMBER_OFFSET: usize = 0x30;
pub const CSR_API_MESSAGE_STATUS_OFFSET: usize = 0x34;
pub const CSR_API_MESSAGE_RESERVED_OFFSET: usize = 0x38;
pub const CSR_API_MESSAGE_API_MESSAGE_DATA_OFFSET: usize = 0x40;
pub const CSR_API_MESSAGE_SIZE: usize = 0x178;

const MAXLONG: usize = 0x7fff_ffff;
const MAXSHORT: usize = 0x7fff;

/// The x64 `PORT_MESSAGE` header size (bytes) — the frame every LPC/CSR message carries. Shared by
/// LPC and ALPC (`nt-port-core` docs).
pub const PORT_MESSAGE_HEADER_LEN: usize = 0x28;

#[inline]
fn align_up4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|v| v & !3)
}

#[inline]
fn add_signed_delta(value: u64, delta: isize) -> u64 {
    if delta >= 0 {
        value.wrapping_add(delta as u64)
    } else {
        value.wrapping_sub(delta.wrapping_neg() as u64)
    }
}

#[inline]
fn capture_offsets_span(pointer_count: usize) -> Option<usize> {
    pointer_count
        .checked_mul(core::mem::size_of::<u64>())?
        .checked_add(CSR_CAPTURE_BUFFER_POINTERS_OFFSET)
}

/// Calculate the heap allocation size for ReactOS' x64 `CSR_CAPTURE_BUFFER`.
pub fn raw_capture_buffer_size(argument_count: u32, buffer_size: u32) -> Option<usize> {
    let argument_count = argument_count as usize;
    let buffer_size = buffer_size as usize;
    if argument_count > MAXLONG / core::mem::size_of::<u64>() {
        return None;
    }
    let offsets_array_size = argument_count.checked_mul(core::mem::size_of::<u64>())?;
    let mut maximum_size = (MAXLONG & !3usize).checked_sub(CSR_CAPTURE_BUFFER_POINTERS_OFFSET)?;
    if offsets_array_size >= maximum_size {
        return None;
    }
    maximum_size -= offsets_array_size;
    if buffer_size >= maximum_size {
        return None;
    }
    maximum_size -= buffer_size;
    let padding = argument_count.checked_mul(3)?.checked_add(3)?;
    if padding >= maximum_size {
        return None;
    }

    let total = buffer_size
        .checked_add(CSR_CAPTURE_BUFFER_POINTERS_OFFSET)?
        .checked_add(offsets_array_size)?
        .checked_add(argument_count.checked_mul(3)?)?;
    align_up4(total)
}

/// Initialize an already-zeroed raw x64 `CSR_CAPTURE_BUFFER`.
///
/// # Safety
/// `buffer` must point to `total_size` writable bytes.
pub unsafe fn init_raw_capture_buffer(buffer: *mut u8, total_size: usize, argument_count: u32) {
    let pointer_array_bytes = argument_count as usize * core::mem::size_of::<u64>();
    let data_start = buffer as usize + CSR_CAPTURE_BUFFER_POINTERS_OFFSET + pointer_array_bytes;
    // SAFETY: caller supplied a writable allocation of `total_size` bytes.
    unsafe {
        core::ptr::write_unaligned(
            buffer.add(CSR_CAPTURE_BUFFER_SIZE_OFFSET) as *mut u32,
            total_size as u32,
        );
        core::ptr::write_unaligned(
            buffer.add(CSR_CAPTURE_BUFFER_PREVIOUS_OFFSET) as *mut u64,
            0,
        );
        core::ptr::write_unaligned(
            buffer.add(CSR_CAPTURE_BUFFER_POINTER_COUNT_OFFSET) as *mut u32,
            0,
        );
        core::ptr::write_unaligned(
            buffer.add(CSR_CAPTURE_BUFFER_MAX_POINTERS_OFFSET) as *mut u32,
            argument_count,
        );
        core::ptr::write_unaligned(
            buffer.add(CSR_CAPTURE_BUFFER_END_OFFSET) as *mut u64,
            data_start as u64,
        );
    }
}

/// Reserve `message_length` bytes in a raw `CSR_CAPTURE_BUFFER` and write the captured data pointer.
///
/// Returns the aligned byte count recorded in the captured string/buffer descriptor. A zero return is
/// both the Windows zero-length result and our failure result for invalid/exhausted buffers.
///
/// # Safety
/// `capture_buffer` must be a live buffer initialized by [`init_raw_capture_buffer`]; `captured_data`
/// is the caller's writable `PVOID*` slot.
pub unsafe fn raw_allocate_message_pointer(
    capture_buffer: *mut u8,
    message_length: u32,
    captured_data: *mut u64,
) -> u32 {
    if captured_data.is_null() {
        return 0;
    }
    if capture_buffer.is_null() {
        // SAFETY: captured_data was checked non-null.
        unsafe { core::ptr::write_unaligned(captured_data, 0) };
        return 0;
    }

    // SAFETY: raw capture buffer contract.
    unsafe {
        let size = core::ptr::read_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_SIZE_OFFSET) as *const u32
        ) as usize;
        let count = core::ptr::read_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_POINTER_COUNT_OFFSET) as *const u32,
        );
        let max_pointers = core::ptr::read_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_MAX_POINTERS_OFFSET) as *const u32,
        );
        if size < CSR_CAPTURE_BUFFER_POINTERS_OFFSET || count >= max_pointers {
            core::ptr::write_unaligned(captured_data, 0);
            return 0;
        }

        let base = capture_buffer as usize;
        let buffer_end = core::ptr::read_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_END_OFFSET) as *const u64,
        ) as usize;
        let buffer_limit = match base.checked_add(size) {
            Some(v) => v,
            None => {
                core::ptr::write_unaligned(captured_data, 0);
                return 0;
            }
        };
        if buffer_end < base + CSR_CAPTURE_BUFFER_POINTERS_OFFSET || buffer_end > buffer_limit {
            core::ptr::write_unaligned(captured_data, 0);
            return 0;
        }

        let (slot_value, aligned_len) = if message_length == 0 {
            core::ptr::write_unaligned(captured_data, 0);
            (0u64, 0usize)
        } else {
            let requested = message_length as usize;
            if requested >= MAXLONG {
                core::ptr::write_unaligned(captured_data, 0);
                return 0;
            }
            let aligned = match align_up4(requested) {
                Some(v) => v,
                None => {
                    core::ptr::write_unaligned(captured_data, 0);
                    return 0;
                }
            };
            let next_end = match buffer_end.checked_add(aligned) {
                Some(v) => v,
                None => {
                    core::ptr::write_unaligned(captured_data, 0);
                    return 0;
                }
            };
            if next_end > buffer_limit {
                core::ptr::write_unaligned(captured_data, 0);
                return 0;
            }
            core::ptr::write_unaligned(captured_data, buffer_end as u64);
            core::ptr::write_unaligned(
                capture_buffer.add(CSR_CAPTURE_BUFFER_END_OFFSET) as *mut u64,
                next_end as u64,
            );
            (captured_data as u64, aligned)
        };

        let slot = capture_buffer
            .add(CSR_CAPTURE_BUFFER_POINTERS_OFFSET)
            .add(count as usize * core::mem::size_of::<u64>()) as *mut u64;
        core::ptr::write_unaligned(slot, slot_value);
        core::ptr::write_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_POINTER_COUNT_OFFSET) as *mut u32,
            count + 1,
        );
        aligned_len as u32
    }
}

/// Capture a raw message buffer into a `CSR_CAPTURE_BUFFER`.
///
/// # Safety
/// Same requirements as [`raw_allocate_message_pointer`]; `message_buffer` must be readable for
/// `message_length` bytes when non-null.
pub unsafe fn raw_capture_message_buffer(
    capture_buffer: *mut u8,
    message_buffer: *const u8,
    message_length: u32,
    captured_data: *mut u64,
) {
    // SAFETY: forwarded raw capture-buffer contract.
    unsafe {
        let allocated = raw_allocate_message_pointer(capture_buffer, message_length, captured_data);
        if allocated == 0 || message_buffer.is_null() || message_length == 0 {
            return;
        }
        let dst = core::ptr::read_unaligned(captured_data) as *mut u8;
        if dst.is_null() {
            return;
        }
        core::ptr::copy_nonoverlapping(message_buffer, dst, message_length as usize);
    }
}

const STRING_LENGTH_OFFSET: usize = 0x00;
const STRING_MAXIMUM_LENGTH_OFFSET: usize = 0x02;
const STRING_BUFFER_OFFSET: usize = 0x08;

#[inline]
unsafe fn string_length(string: *const u8) -> u16 {
    unsafe { core::ptr::read_unaligned(string.add(STRING_LENGTH_OFFSET) as *const u16) }
}

#[inline]
unsafe fn string_maximum_length(string: *const u8) -> u16 {
    unsafe { core::ptr::read_unaligned(string.add(STRING_MAXIMUM_LENGTH_OFFSET) as *const u16) }
}

#[inline]
unsafe fn string_buffer(string: *const u8) -> u64 {
    unsafe { core::ptr::read_unaligned(string.add(STRING_BUFFER_OFFSET) as *const u64) }
}

#[inline]
unsafe fn set_string_length(string: *mut u8, value: u16) {
    unsafe { core::ptr::write_unaligned(string.add(STRING_LENGTH_OFFSET) as *mut u16, value) };
}

#[inline]
unsafe fn set_string_maximum_length(string: *mut u8, value: u16) {
    unsafe {
        core::ptr::write_unaligned(string.add(STRING_MAXIMUM_LENGTH_OFFSET) as *mut u16, value)
    };
}

#[inline]
unsafe fn set_string_buffer(string: *mut u8, value: u64) {
    unsafe { core::ptr::write_unaligned(string.add(STRING_BUFFER_OFFSET) as *mut u64, value) };
}

/// Capture an ANSI/byte string into a raw `CSR_CAPTURE_BUFFER`, filling a raw x64 `STRING`.
///
/// # Safety
/// `capture_buffer` is a live CSR capture buffer, `captured_string` is a writable x64 `STRING`,
/// and `string` is readable for `string_length` bytes when non-null.
pub unsafe fn raw_capture_message_string(
    capture_buffer: *mut u8,
    string: *const u8,
    string_len: u32,
    maximum_length: u32,
    captured_string: *mut u8,
) {
    if captured_string.is_null() {
        return;
    }

    let capped_maximum = maximum_length.min(u16::MAX as u32);
    unsafe {
        if string.is_null() {
            set_string_length(captured_string, 0);
            set_string_maximum_length(captured_string, capped_maximum as u16);
            let mut buffer = 0u64;
            raw_allocate_message_pointer(capture_buffer, capped_maximum, &mut buffer);
            set_string_buffer(captured_string, buffer);
        } else {
            let copy_len = string_len.min(capped_maximum);
            set_string_length(captured_string, copy_len as u16);
            let mut buffer = 0u64;
            let allocated =
                raw_allocate_message_pointer(capture_buffer, capped_maximum, &mut buffer);
            set_string_maximum_length(captured_string, allocated.min(u16::MAX as u32) as u16);
            set_string_buffer(captured_string, buffer);
            if copy_len != 0 && buffer != 0 {
                core::ptr::copy_nonoverlapping(string, buffer as *mut u8, copy_len as usize);
            }
        }

        let length = string_length(captured_string) as usize;
        let maximum = string_maximum_length(captured_string) as usize;
        let buffer = string_buffer(captured_string) as *mut u8;
        if !buffer.is_null() && length < maximum {
            core::ptr::write(buffer.add(length), 0);
        }
    }
}

/// Capture a raw x64 `UNICODE_STRING` in place into a CSR capture buffer.
///
/// # Safety
/// `capture_buffer` is a live CSR capture buffer and `unicode_string` is a writable x64
/// `UNICODE_STRING`.
pub unsafe fn raw_capture_message_unicode_string_in_place(
    capture_buffer: *mut u8,
    unicode_string: *mut u8,
) {
    if unicode_string.is_null() {
        return;
    }
    unsafe {
        let buffer = string_buffer(unicode_string) as *const u8;
        let length = string_length(unicode_string) as u32;
        let maximum = string_maximum_length(unicode_string) as u32;
        raw_capture_message_string(
            capture_buffer,
            buffer,
            length,
            maximum,
            unicode_string,
        );

        let captured_length = string_length(unicode_string) as usize;
        let captured_maximum = string_maximum_length(unicode_string) as usize;
        let captured_buffer = string_buffer(unicode_string) as *mut u16;
        if !captured_buffer.is_null() && captured_length + 2 <= captured_maximum {
            core::ptr::write(captured_buffer.add(captured_length / 2), 0);
        }
    }
}

/// Return the data byte count needed to capture non-null `UNICODE_STRING`s from an array.
///
/// # Safety
/// `strings` points to `count` raw x64 `UNICODE_STRING*` entries when `count != 0`.
pub unsafe fn raw_multi_unicode_capture_data_size(
    count: u32,
    strings: *const *mut u8,
) -> Option<u32> {
    if count != 0 && strings.is_null() {
        return None;
    }
    let mut total = 0u32;
    unsafe {
        for i in 0..count as usize {
            let string = core::ptr::read_unaligned(strings.add(i));
            if !string.is_null() {
                total = total.checked_add(string_maximum_length(string) as u32)?;
            }
        }
    }
    Some(total)
}

/// Capture each non-null raw x64 `UNICODE_STRING*` from an array in place.
///
/// # Safety
/// `capture_buffer` is a live CSR capture buffer and `strings` points to `count` raw
/// `UNICODE_STRING*` entries.
pub unsafe fn raw_capture_multi_unicode_strings_in_place(
    capture_buffer: *mut u8,
    count: u32,
    strings: *mut *mut u8,
) {
    if capture_buffer.is_null() || (count != 0 && strings.is_null()) {
        return;
    }
    unsafe {
        for i in 0..count as usize {
            let string = core::ptr::read_unaligned(strings.add(i));
            if !string.is_null() {
                raw_capture_message_unicode_string_in_place(capture_buffer, string);
            }
        }
    }
}

/// Convert a CSR millisecond timeout to NT relative 100ns ticks.
pub fn capture_timeout_ticks(milliseconds: u32) -> Option<i64> {
    if milliseconds == u32::MAX {
        None
    } else {
        Some((milliseconds as i64) * -10_000)
    }
}

/// Return `(PORT_MESSAGE.DataLength, PORT_MESSAGE.TotalLength)` for `CsrClientCallServer`.
pub fn csr_client_call_lengths(data_length: u32) -> Option<(u16, u16)> {
    let data_length = data_length as usize;
    if data_length > MAXSHORT.checked_sub(CSR_API_MESSAGE_SIZE)? {
        return None;
    }
    let total_length = data_length.checked_add(CSR_API_MESSAGE_HEADER_LEN)?;
    Some((data_length as u16, total_length as u16))
}

/// Fill the fixed CSR/PORT headers before sending a `CSR_API_MESSAGE`.
///
/// # Safety
/// `api_message` must be a writable x64 `CSR_API_MESSAGE`.
pub unsafe fn init_raw_api_message(
    api_message: *mut u8,
    api_number: u32,
    data_length: u32,
) -> Result<(), NtStatus> {
    let (port_data_len, port_total_len) =
        csr_client_call_lengths(data_length).ok_or(STATUS_INVALID_PARAMETER)?;
    // SAFETY: caller supplied a writable CSR_API_MESSAGE.
    unsafe {
        core::ptr::write_unaligned(api_message as *mut u16, port_data_len);
        core::ptr::write_unaligned(api_message.add(0x02) as *mut u16, port_total_len);
        core::ptr::write_unaligned(api_message.add(0x04) as *mut u32, 0);
        core::ptr::write_unaligned(
            api_message.add(CSR_API_MESSAGE_CAPTURE_DATA_OFFSET) as *mut u64,
            0,
        );
        core::ptr::write_unaligned(
            api_message.add(CSR_API_MESSAGE_API_NUMBER_OFFSET) as *mut u32,
            api_number,
        );
        core::ptr::write_unaligned(
            api_message.add(CSR_API_MESSAGE_STATUS_OFFSET) as *mut u32,
            0,
        );
        core::ptr::write_unaligned(
            api_message.add(CSR_API_MESSAGE_RESERVED_OFFSET) as *mut u32,
            0,
        );
    }
    Ok(())
}

/// Convert a client capture buffer into the server view before `NtRequestWaitReplyPort`.
///
/// # Safety
/// `api_message` and `capture_buffer` must point at writable raw CSR objects in the current process.
pub unsafe fn prepare_raw_capture_for_call(
    api_message: *mut u8,
    capture_buffer: *mut u8,
    port_memory_delta: isize,
) -> Result<(), NtStatus> {
    if api_message.is_null() || capture_buffer.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: raw CSR objects per the function contract.
    unsafe {
        let remote_capture = add_signed_delta(capture_buffer as u64, port_memory_delta);
        core::ptr::write_unaligned(
            api_message.add(CSR_API_MESSAGE_CAPTURE_DATA_OFFSET) as *mut u64,
            remote_capture,
        );
        core::ptr::write_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_END_OFFSET) as *mut u64,
            0,
        );

        let pointer_count = core::ptr::read_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_POINTER_COUNT_OFFSET) as *const u32,
        ) as usize;
        let size = core::ptr::read_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_SIZE_OFFSET) as *const u32
        ) as usize;
        if match capture_offsets_span(pointer_count) {
            Some(span) => span > size,
            None => true,
        } {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for i in 0..pointer_count {
            let slot = capture_buffer
                .add(CSR_CAPTURE_BUFFER_POINTERS_OFFSET + i * core::mem::size_of::<u64>())
                as *mut u64;
            let pointer_slot = core::ptr::read_unaligned(slot);
            if pointer_slot != 0 {
                let value_slot = pointer_slot as *mut u64;
                let value = core::ptr::read_unaligned(value_slot);
                core::ptr::write_unaligned(value_slot, add_signed_delta(value, port_memory_delta));
                core::ptr::write_unaligned(slot, pointer_slot.wrapping_sub(api_message as u64));
            }
        }
    }
    Ok(())
}

/// Undo [`prepare_raw_capture_for_call`] after the CSR reply returns.
///
/// # Safety
/// `api_message` and `capture_buffer` must be the same raw objects passed to preparation.
pub unsafe fn restore_raw_capture_after_call(
    api_message: *mut u8,
    capture_buffer: *mut u8,
    port_memory_delta: isize,
) -> Result<(), NtStatus> {
    if api_message.is_null() || capture_buffer.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: raw CSR objects per the function contract.
    unsafe {
        let remote_capture = core::ptr::read_unaligned(
            api_message.add(CSR_API_MESSAGE_CAPTURE_DATA_OFFSET) as *const u64,
        );
        core::ptr::write_unaligned(
            api_message.add(CSR_API_MESSAGE_CAPTURE_DATA_OFFSET) as *mut u64,
            add_signed_delta(remote_capture, port_memory_delta.wrapping_neg()),
        );

        let pointer_count = core::ptr::read_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_POINTER_COUNT_OFFSET) as *const u32,
        ) as usize;
        let size = core::ptr::read_unaligned(
            capture_buffer.add(CSR_CAPTURE_BUFFER_SIZE_OFFSET) as *const u32
        ) as usize;
        if match capture_offsets_span(pointer_count) {
            Some(span) => span > size,
            None => true,
        } {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for i in 0..pointer_count {
            let slot = capture_buffer
                .add(CSR_CAPTURE_BUFFER_POINTERS_OFFSET + i * core::mem::size_of::<u64>())
                as *mut u64;
            let offset = core::ptr::read_unaligned(slot);
            if offset != 0 {
                let pointer_slot = (api_message as u64).wrapping_add(offset);
                core::ptr::write_unaligned(slot, pointer_slot);
                let value_slot = pointer_slot as *mut u64;
                let value = core::ptr::read_unaligned(value_slot);
                core::ptr::write_unaligned(
                    value_slot,
                    add_signed_delta(value, port_memory_delta.wrapping_neg()),
                );
            }
        }
    }
    Ok(())
}

/// A CSR API number: `(ServerDllIndex << 16) | ApiIndex` (the `CSR_MAKE_API_NUMBER` encoding). The
/// server-dll index selects basesrv/winsrv/…; the api index selects the routine within it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CsrApiNumber(pub u32);

impl CsrApiNumber {
    /// Build an API number from a server-dll index + an API index (`CSR_MAKE_API_NUMBER`).
    pub const fn make(server_dll_index: u16, api_index: u16) -> Self {
        CsrApiNumber(((server_dll_index as u32) << 16) | api_index as u32)
    }
    /// The server-dll index (high 16 bits).
    pub const fn server_dll_index(self) -> u16 {
        (self.0 >> 16) as u16
    }
    /// The API index (low 16 bits).
    pub const fn api_index(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

/// A pointer argument captured into a [`CaptureBuffer`]: its offset within the buffer's data region
/// and its length. On receipt CSR relocates the message field that referenced it to
/// `server_base + offset`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapturedPointer {
    /// Byte offset of the captured data within the buffer's data region.
    pub offset: usize,
    /// Byte length of the captured data.
    pub length: usize,
}

/// A `CSR_CAPTURE_BUFFER`: a self-describing buffer that carries the client's pointer arguments so
/// CSR can access them without dereferencing client pointers. Layout mirrors the real structure
/// closely enough for the marshalling to be exercised: a header (size + pointer count) + a pointer-
/// offset array + the packed data region.
///
/// `CsrAllocateCaptureBuffer(count, size)` sizes it for `count` pointers and `size` data bytes;
/// `CsrCaptureMessageBuffer` packs one pointer arg; `CsrFreeCaptureBuffer` drops it (here = `Drop`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureBuffer {
    /// The maximum number of pointer arguments this buffer was sized for.
    pub max_pointers: usize,
    /// The captured pointers, in capture order.
    pub pointers: Vec<CapturedPointer>,
    /// The packed data region (all captured pointer payloads concatenated, 8-byte aligned).
    pub data: Vec<u8>,
    /// The data-region capacity this buffer was sized for.
    pub capacity: usize,
}

impl CaptureBuffer {
    /// `CsrAllocateCaptureBuffer(PointerCount, Size)` — allocate a capture buffer sized for
    /// `pointer_count` pointer args and `size` bytes of packed data.
    pub fn allocate(pointer_count: usize, size: usize) -> Self {
        CaptureBuffer {
            max_pointers: pointer_count,
            pointers: Vec::with_capacity(pointer_count),
            data: Vec::with_capacity(size),
            capacity: size,
        }
    }

    /// `CsrCaptureMessageBuffer(CaptureBuffer, Buffer, Length, CapturedBuffer*)` — pack `bytes` into
    /// the buffer (8-byte aligned) and record the pointer. Returns the [`CapturedPointer`] (the
    /// server-relocatable descriptor) or an error if the buffer is out of pointer slots / capacity.
    pub fn capture(&mut self, bytes: &[u8]) -> Result<CapturedPointer, NtStatus> {
        if self.pointers.len() >= self.max_pointers {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // Align the data region to 8 bytes before packing (CSR packs aligned).
        while !self.data.len().is_multiple_of(8) {
            self.data.push(0);
        }
        let offset = self.data.len();
        // Reject if a hard capacity was set and this capture would exceed it.
        if self.capacity != 0 && offset + bytes.len() > self.capacity {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        self.data.extend_from_slice(bytes);
        let p = CapturedPointer {
            offset,
            length: bytes.len(),
        };
        self.pointers.push(p);
        Ok(p)
    }

    /// The total wire size of this capture buffer (header + pointer array + aligned data).
    pub fn wire_size(&self) -> usize {
        // header: max_pointers (u32) + used data length (u32) — modelled as 16 bytes for x64
        // alignment; pointer array: 8 bytes each (offset); data region.
        16 + self.pointers.len() * 8 + self.data.len()
    }
}

/// A `CSR_API_MESSAGE`: the `PORT_MESSAGE` header + the CSR body (API number + a fixed argument
/// block) + an optional [`CaptureBuffer`]. This is exactly what `CsrClientCallServer` sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsrApiMessage {
    /// The API number (`CSR_MAKE_API_NUMBER`).
    pub api_number: CsrApiNumber,
    /// The fixed in-line argument block (the CSR API's argument union, register-width slots).
    pub args: Vec<u64>,
    /// The optional capture buffer for pointer args.
    pub capture: Option<CaptureBuffer>,
}

impl CsrApiMessage {
    /// Build a `CSR_API_MESSAGE` for `api` with the given fixed args + optional capture buffer.
    pub fn new(api: CsrApiNumber, args: Vec<u64>, capture: Option<CaptureBuffer>) -> Self {
        CsrApiMessage {
            api_number: api,
            args,
            capture,
        }
    }

    /// The total data length (`PORT_MESSAGE` `u1.s1.DataLength`) of this message: the CSR body plus
    /// any capture buffer. Used to fill the `PORT_MESSAGE` header before sending.
    pub fn data_length(&self) -> usize {
        // API number (u32, padded to 8) + args + capture wire size.
        8 + self.args.len() * 8 + self.capture.as_ref().map_or(0, |c| c.wire_size())
    }

    /// The total message length (header + data).
    pub fn total_length(&self) -> usize {
        PORT_MESSAGE_HEADER_LEN + self.data_length()
    }
}

/// A CSR client port: the client half of the connection to `\Windows\ApiPort`. Built by
/// `CsrClientConnectToServer` (the process-init CSR connect) and used by `CsrClientCallServer` for
/// every subsequent API call.
#[derive(Clone, Debug)]
pub struct CsrPort {
    /// The CSR port name (`\Windows\ApiPort`, folded UTF-16).
    pub name: Vec<u16>,
    /// The API dialect (CSR is classic LPC).
    pub api: PortApi,
    /// The connected comm-port handle (0 = not yet connected).
    pub handle: u64,
    /// The client's CSR process id (from `CsrClientConnectToServer` / `CsrGetProcessId`).
    pub process_id: u64,
}

impl CsrPort {
    /// `CsrClientConnectToServer(ObjectDirectory, ServerDllIndex, ConnectionInfo, …)` — model the
    /// client-side connect: name the CSR port + record the server-dll index. The actual
    /// `NtConnectPort`/`NtSecureConnectPort` is the LPC seam (returns the port unconnected here;
    /// `handle == 0` until wired).
    pub fn connect(port_name: &[u16]) -> Self {
        CsrPort {
            name: port_name.to_vec(),
            api: PortApi::Lpc,
            handle: 0,
            process_id: 0,
        }
    }

    /// Whether the port is connected (a comm-port handle has been assigned).
    pub fn is_connected(&self) -> bool {
        self.handle != 0
    }

    /// `CsrClientCallServer(Message, CaptureBuffer, ApiNumber, DataLength)` — build the
    /// `CSR_API_MESSAGE` and issue `NtRequestWaitReplyPort` on the CSR port. The message construction
    /// is done + returned; the send is the **LPC seam** (returns `STATUS_NOT_IMPLEMENTED` until the
    /// port transport is wired — never a faked reply).
    pub fn call_server(&self, msg: &CsrApiMessage) -> (CsrApiMessage, NtStatus) {
        // The message is fully built here (host-tested). The round-trip is the seam.
        let status = if self.is_connected() {
            // Real path: NtRequestWaitReplyPort(self.handle, &request, &reply) — Step 6 / LPC wire.
            STATUS_NOT_IMPLEMENTED
        } else {
            // Not connected → cannot send. Honest failure (not a fabricated success).
            STATUS_INVALID_PARAMETER
        };
        (msg.clone(), status)
    }

    /// `CsrGetProcessId()` — the client's CSR process id (assigned at connect).
    pub fn get_process_id(&self) -> u64 {
        self.process_id
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn api_number_encoding() {
        // BASESRV (index 0), CreateProcess (api 0) etc.
        let a = CsrApiNumber::make(0, 5);
        assert_eq!(a.server_dll_index(), 0);
        assert_eq!(a.api_index(), 5);
        let b = CsrApiNumber::make(2, 0x10);
        assert_eq!(b.server_dll_index(), 2);
        assert_eq!(b.api_index(), 0x10);
        assert_eq!(b.0, (2 << 16) | 0x10);
    }

    #[test]
    fn capture_buffer_packs_and_relocates() {
        let mut cb = CaptureBuffer::allocate(2, 64);
        let p1 = cb.capture(b"C:\\Windows").unwrap();
        assert_eq!(p1.offset, 0);
        assert_eq!(p1.length, 10);
        // Second capture is 8-byte aligned after the first.
        let p2 = cb.capture(b"cmd.exe").unwrap();
        assert_eq!(p2.offset, 16); // 10 -> aligned up to 16
        assert_eq!(p2.length, 7);
        assert_eq!(cb.pointers.len(), 2);
        // The packed data holds both payloads.
        assert_eq!(&cb.data[0..10], b"C:\\Windows");
        assert_eq!(&cb.data[16..23], b"cmd.exe");
    }

    #[test]
    fn capture_buffer_rejects_overflow() {
        let mut cb = CaptureBuffer::allocate(1, 8);
        // First pointer OK.
        assert!(cb.capture(b"ab").is_ok());
        // Second pointer exceeds the pointer count.
        assert_eq!(cb.capture(b"cd"), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn capture_buffer_rejects_capacity_overflow() {
        let mut cb = CaptureBuffer::allocate(4, 8);
        assert_eq!(
            cb.capture(b"0123456789ABCDEF"),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
    }

    #[test]
    fn api_message_lengths() {
        let mut cb = CaptureBuffer::allocate(1, 32);
        cb.capture(b"path").unwrap();
        let msg = CsrApiMessage::new(CsrApiNumber::make(0, 3), vec![0xdead, 0xbeef], Some(cb));
        // data = 8 (api) + 16 (2 args) + capture.wire_size()
        let expected_data = 8 + 16 + msg.capture.as_ref().unwrap().wire_size();
        assert_eq!(msg.data_length(), expected_data);
        assert_eq!(msg.total_length(), PORT_MESSAGE_HEADER_LEN + expected_data);
    }

    #[test]
    fn call_server_seam_is_honest() {
        let port = CsrPort::connect(&[b'A' as u16, b'p' as u16, b'i' as u16]);
        assert!(!port.is_connected());
        let msg = CsrApiMessage::new(CsrApiNumber::make(0, 1), vec![], None);
        // Not connected → honest failure, message still built.
        let (built, status) = port.call_server(&msg);
        assert_eq!(built, msg);
        assert_eq!(status, STATUS_INVALID_PARAMETER);

        // Connected → the send seam is unimplemented (NOT a fabricated success).
        let mut connected = port.clone();
        connected.handle = 0x1234;
        let (_built2, status2) = connected.call_server(&msg);
        assert_eq!(status2, STATUS_NOT_IMPLEMENTED);
    }

    #[test]
    fn raw_capture_buffer_size_matches_reactos_layout() {
        assert_eq!(
            raw_capture_buffer_size(0, 0),
            Some(CSR_CAPTURE_BUFFER_HEADER_LEN)
        );
        assert_eq!(raw_capture_buffer_size(1, 10), Some(0x38));
        assert_eq!(raw_capture_buffer_size(2, 17), Some(0x48));
        assert_eq!(raw_capture_buffer_size(u32::MAX, 0), None);
    }

    #[test]
    fn raw_capture_buffer_packs_message_pointers() {
        let size = raw_capture_buffer_size(2, 32).unwrap();
        let mut raw = vec![0u8; size];
        let mut pointer_a = 0u64;
        let mut pointer_b = 0u64;

        unsafe {
            init_raw_capture_buffer(raw.as_mut_ptr(), size, 2);
            let first = raw_allocate_message_pointer(raw.as_mut_ptr(), 5, &mut pointer_a);
            assert_eq!(first, 8);
            assert_eq!(
                pointer_a,
                raw.as_ptr() as u64 + CSR_CAPTURE_BUFFER_POINTERS_OFFSET as u64 + 16
            );
            let second = raw_allocate_message_pointer(raw.as_mut_ptr(), 7, &mut pointer_b);
            assert_eq!(second, 8);
            assert_eq!(pointer_b, pointer_a + 8);
            assert_eq!(
                core::ptr::read_unaligned(
                    raw.as_ptr().add(CSR_CAPTURE_BUFFER_POINTER_COUNT_OFFSET) as *const u32
                ),
                2
            );
            assert_eq!(
                core::ptr::read_unaligned(
                    raw.as_ptr().add(CSR_CAPTURE_BUFFER_POINTERS_OFFSET) as *const u64
                ),
                &mut pointer_a as *mut u64 as u64
            );
        }
    }

    #[test]
    fn raw_capture_message_buffer_copies_bytes() {
        let size = raw_capture_buffer_size(1, 16).unwrap();
        let mut raw = vec![0u8; size];
        let mut captured = 0u64;
        unsafe {
            init_raw_capture_buffer(raw.as_mut_ptr(), size, 1);
            raw_capture_message_buffer(raw.as_mut_ptr(), b"hello".as_ptr(), 5, &mut captured);
            assert_ne!(captured, 0);
            let copied = core::slice::from_raw_parts(captured as *const u8, 5);
            assert_eq!(copied, b"hello");
        }
    }

    unsafe fn write_raw_string(desc: &mut [u8; 16], length: u16, maximum: u16, buffer: *mut u8) {
        unsafe {
            core::ptr::write_unaligned(desc.as_mut_ptr() as *mut u16, length);
            core::ptr::write_unaligned(desc.as_mut_ptr().add(2) as *mut u16, maximum);
            core::ptr::write_unaligned(desc.as_mut_ptr().add(8) as *mut u64, buffer as u64);
        }
    }

    unsafe fn read_raw_string(desc: &[u8; 16]) -> (u16, u16, *mut u8) {
        unsafe {
            (
                core::ptr::read_unaligned(desc.as_ptr() as *const u16),
                core::ptr::read_unaligned(desc.as_ptr().add(2) as *const u16),
                core::ptr::read_unaligned(desc.as_ptr().add(8) as *const u64) as *mut u8,
            )
        }
    }

    #[test]
    fn raw_capture_message_string_truncates_and_terminates() {
        let size = raw_capture_buffer_size(1, 8).unwrap();
        let mut raw = vec![0u8; size];
        let mut captured = [0u8; 16];
        unsafe {
            init_raw_capture_buffer(raw.as_mut_ptr(), size, 1);
            raw_capture_message_string(
                raw.as_mut_ptr(),
                b"abcdef".as_ptr(),
                6,
                5,
                captured.as_mut_ptr(),
            );
            let (length, maximum, buffer) = read_raw_string(&captured);
            assert_eq!(length, 5);
            assert_eq!(maximum, 8);
            assert_eq!(core::slice::from_raw_parts(buffer, 6), b"abcde\0");
        }
    }

    #[test]
    fn raw_capture_unicode_string_in_place_copies_wide_bytes() {
        let size = raw_capture_buffer_size(1, 8).unwrap();
        let mut raw = vec![0u8; size];
        let mut wide = [b'A' as u16, b'B' as u16, 0];
        let mut desc = [0u8; 16];
        unsafe {
            write_raw_string(
                &mut desc,
                4,
                6,
                wide.as_mut_ptr() as *mut u8,
            );
            init_raw_capture_buffer(raw.as_mut_ptr(), size, 1);
            raw_capture_message_unicode_string_in_place(raw.as_mut_ptr(), desc.as_mut_ptr());
            let (length, maximum, buffer) = read_raw_string(&desc);
            assert_eq!(length, 4);
            assert_eq!(maximum, 8);
            assert_eq!(*(buffer as *const u16), b'A' as u16);
            assert_eq!(*((buffer as *const u16).add(1)), b'B' as u16);
            assert_eq!(*((buffer as *const u16).add(2)), 0);
        }
    }

    #[test]
    fn raw_multi_unicode_capture_sums_and_captures_non_null_strings() {
        let mut first_buf = [b'a' as u16, 0];
        let mut second_buf = [b'b' as u16, b'c' as u16, 0];
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        unsafe {
            write_raw_string(&mut first, 2, 4, first_buf.as_mut_ptr() as *mut u8);
            write_raw_string(&mut second, 4, 6, second_buf.as_mut_ptr() as *mut u8);
            let mut strings = [
                first.as_mut_ptr(),
                core::ptr::null_mut(),
                second.as_mut_ptr(),
            ];
            assert_eq!(
                raw_multi_unicode_capture_data_size(3, strings.as_ptr()),
                Some(10)
            );
            let size = raw_capture_buffer_size(3, 10).unwrap();
            let mut raw = vec![0u8; size];
            init_raw_capture_buffer(raw.as_mut_ptr(), size, 3);
            raw_capture_multi_unicode_strings_in_place(raw.as_mut_ptr(), 3, strings.as_mut_ptr());

            let (_, _, first_captured) = read_raw_string(&first);
            let (_, _, second_captured) = read_raw_string(&second);
            assert_eq!(*(first_captured as *const u16), b'a' as u16);
            assert_eq!(*(second_captured as *const u16), b'b' as u16);
            assert_eq!(*((second_captured as *const u16).add(1)), b'c' as u16);
        }
    }

    #[test]
    fn capture_timeout_ticks_matches_csr_contract() {
        assert_eq!(capture_timeout_ticks(0), Some(0));
        assert_eq!(capture_timeout_ticks(42), Some(-420_000));
        assert_eq!(capture_timeout_ticks(u32::MAX), None);
    }

    #[test]
    fn raw_capture_buffer_rejects_exhausted_pointer_slots() {
        let size = raw_capture_buffer_size(1, 8).unwrap();
        let mut raw = vec![0u8; size];
        let mut first = 0u64;
        let mut second = 0xccccu64;
        unsafe {
            init_raw_capture_buffer(raw.as_mut_ptr(), size, 1);
            assert_eq!(
                raw_allocate_message_pointer(raw.as_mut_ptr(), 4, &mut first),
                4
            );
            assert_eq!(
                raw_allocate_message_pointer(raw.as_mut_ptr(), 4, &mut second),
                0
            );
            assert_eq!(second, 0);
        }
    }

    #[test]
    fn csr_client_call_header_lengths_match_x64_layout() {
        assert_eq!(
            csr_client_call_lengths(0),
            Some((0, CSR_API_MESSAGE_HEADER_LEN as u16))
        );
        assert_eq!(csr_client_call_lengths(0x10), Some((0x10, 0x38)));
        assert_eq!(
            csr_client_call_lengths((MAXSHORT - CSR_API_MESSAGE_SIZE) as u32),
            Some((
                (MAXSHORT - CSR_API_MESSAGE_SIZE) as u16,
                (MAXSHORT - CSR_API_MESSAGE_SIZE + CSR_API_MESSAGE_HEADER_LEN) as u16
            ))
        );
        assert_eq!(
            csr_client_call_lengths((MAXSHORT - CSR_API_MESSAGE_SIZE + 1) as u32),
            None
        );
    }

    #[test]
    fn raw_capture_prepare_and_restore_relocate_message_fields() {
        let cap_size = raw_capture_buffer_size(1, 16).unwrap();
        let mut capture = vec![0u8; cap_size];
        let mut api = vec![0u8; CSR_API_MESSAGE_SIZE];
        let api_base = api.as_mut_ptr() as u64;
        let message_pointer_slot = unsafe {
            api.as_mut_ptr()
                .add(CSR_API_MESSAGE_API_MESSAGE_DATA_OFFSET) as *mut u64
        };
        let delta = 0x1000isize;

        unsafe {
            init_raw_capture_buffer(capture.as_mut_ptr(), cap_size, 1);
            raw_capture_message_buffer(
                capture.as_mut_ptr(),
                b"abc".as_ptr(),
                3,
                message_pointer_slot,
            );
            let local_data = core::ptr::read_unaligned(message_pointer_slot);

            prepare_raw_capture_for_call(api.as_mut_ptr(), capture.as_mut_ptr(), delta).unwrap();
            assert_eq!(
                core::ptr::read_unaligned(
                    api.as_ptr().add(CSR_API_MESSAGE_CAPTURE_DATA_OFFSET) as *const u64
                ),
                capture.as_ptr() as u64 + delta as u64
            );
            assert_eq!(
                core::ptr::read_unaligned(message_pointer_slot),
                local_data + delta as u64
            );
            assert_eq!(
                core::ptr::read_unaligned(
                    capture.as_ptr().add(CSR_CAPTURE_BUFFER_POINTERS_OFFSET) as *const u64
                ),
                CSR_API_MESSAGE_API_MESSAGE_DATA_OFFSET as u64
            );

            restore_raw_capture_after_call(api.as_mut_ptr(), capture.as_mut_ptr(), delta).unwrap();
            assert_eq!(
                core::ptr::read_unaligned(
                    api.as_ptr().add(CSR_API_MESSAGE_CAPTURE_DATA_OFFSET) as *const u64
                ),
                capture.as_ptr() as u64
            );
            assert_eq!(core::ptr::read_unaligned(message_pointer_slot), local_data);
            assert_eq!(
                core::ptr::read_unaligned(
                    capture.as_ptr().add(CSR_CAPTURE_BUFFER_POINTERS_OFFSET) as *const u64
                ),
                message_pointer_slot as u64
            );
            assert_eq!(
                api_base + CSR_API_MESSAGE_API_MESSAGE_DATA_OFFSET as u64,
                message_pointer_slot as u64
            );
        }
    }
}
