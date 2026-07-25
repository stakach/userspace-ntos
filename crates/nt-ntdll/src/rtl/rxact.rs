//! `RXACT` — the **registry transaction** log (`RtlInitializeRXact` … `RtlApplyRXact`), the pure
//! host-testable core.
//!
//! Faithful to `references/reactos/sdk/lib/rtl/rxact.c` (Timo Kreuzer, 2014). RXACT is the RTL's
//! crash-consistent registry transaction: the caller records a batch of `DeleteKey` /
//! `SetValueKey` actions into an in-memory log, and `RtlApplyRXact` first *persists* that log to
//! `RXACT\Log` (a `REG_BINARY` value) + flushes, then replays it against the registry, then deletes
//! the log value. If the machine dies mid-replay, the next `RtlInitializeRXact(Commit = TRUE)`
//! finds the surviving `Log` value and replays it — that is the whole point of the design.
//!
//! ## What lives here vs. in the DLL wrapper
//!
//! The registry syscalls (`NtCreateKey`/`NtSetValueKey`/`NtDeleteKey`/`NtDeleteValueKey`/
//! `NtFlushKey`) and the process-heap allocation are target concerns handled by the
//! `nt-ntdll-dll` exports. **Everything about the on-disk/in-memory log format is here**: the
//! `RXACT_DATA` header, the `RXACT_ACTION` record layout, the pointer→offset relocation
//! (`Action->KeyName.Buffer` is stored as an offset from the `RXACT_DATA` base so the log is
//! position-independent and can round-trip through the registry), the record-size arithmetic, and
//! the buffer-doubling growth policy. That is the part with real, testable logic.
//!
//! ## Layout (x64)
//!
//! ```text
//! RXACT_DATA   { ULONG ActionCount; ULONG BufferSize; ULONG CurrentSize; }          // 12 bytes
//! RXACT_ACTION { ULONG Size;                    // +0x00
//!                ULONG Type;                    // +0x04
//!                UNICODE_STRING KeyName;        // +0x08 (Length/MaximumLength/pad/Buffer)
//!                UNICODE_STRING ValueName;      // +0x18
//!                HANDLE KeyHandle;              // +0x28
//!                ULONG ValueType;               // +0x30
//!                ULONG ValueDataSize;           // +0x34
//!                PVOID ValueData; }             // +0x38 .. 0x40
//! ```
//!
//! Note that `sizeof(RXACT_DATA)` is 12, so the first `RXACT_ACTION` starts at offset 12 — *not*
//! 8-aligned. That is ReactOS's layout verbatim (x86 heritage); every field access here is
//! therefore an explicitly unaligned read/write, and the DLL wrapper does the same. Do not "fix"
//! the alignment: the log format is persisted into the registry and must stay byte-compatible.
//!
//! One deliberate, documented deviation: for a `DeleteKey` action ReactOS leaves `ValueData`
//! uninitialised (the buffer comes from `RtlAllocateHeap` without `HEAP_ZERO_MEMORY`), because the
//! commit path never reads it for a delete. We write `0` instead — deterministic, and unobservable
//! through the API.

/// `RXACT_DEFAULT_BUFFER_SIZE` — `4 * PAGE_SIZE` (rxact.c:16).
pub const RXACT_DEFAULT_BUFFER_SIZE: u32 = 4 * 4096;

/// `sizeof(RXACT_DATA)` — three `ULONG`s, no padding.
pub const RXACT_DATA_SIZE: u32 = 12;

/// `sizeof(RXACT_ACTION)` on x64 (see the module docs for the field map).
pub const RXACT_ACTION_SIZE: u32 = 0x40;

/// The revision stamped into the `RXACT` key's default value (`RXACT_INFO.Revision`, rxact.c:333).
pub const RXACT_REVISION: u32 = 1;

/// `RXactDeleteKey` (rxact.c:53).
pub const RXACT_DELETE_KEY: u32 = 1;

/// `RXactSetValueKey` (rxact.c:54).
pub const RXACT_SET_VALUE_KEY: u32 = 2;

/// `INVALID_HANDLE_VALUE` — the sentinel `RtlAddActionToRXact` stores in `Action->KeyHandle` to say
/// "no handle; open the key by name at commit time" (rxact.c:600).
pub const RXACT_INVALID_HANDLE: u64 = u64::MAX;

// --- RXACT_DATA field offsets ---------------------------------------------------------------

const D_ACTION_COUNT: usize = 0x00;
const D_BUFFER_SIZE: usize = 0x04;
const D_CURRENT_SIZE: usize = 0x08;

// --- RXACT_ACTION field offsets ---------------------------------------------------------------

const A_SIZE: usize = 0x00;
const A_TYPE: usize = 0x04;
const A_KEY_NAME: usize = 0x08;
const A_VALUE_NAME: usize = 0x18;
const A_KEY_HANDLE: usize = 0x28;
const A_VALUE_TYPE: usize = 0x30;
const A_VALUE_DATA_SIZE: usize = 0x34;
const A_VALUE_DATA: usize = 0x38;

// --- UNICODE_STRING field offsets (x64) -------------------------------------------------------

const US_LENGTH: usize = 0x00;
const US_MAXIMUM_LENGTH: usize = 0x02;
const US_BUFFER: usize = 0x08;

/// Why an RXACT log operation could not be performed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxactError {
    /// `STATUS_INVALID_PARAMETER` — an action type outside `{DeleteKey, SetValueKey}`, or a
    /// malformed/truncated log record.
    InvalidParameter,
    /// `STATUS_NO_MEMORY` — the record-size arithmetic overflowed `ULONG` (rxact.c:520), or the
    /// caller-supplied buffer cannot hold the grown log.
    NoMemory,
    /// `STATUS_RXACT_INVALID_STATE` — no transaction buffer is active.
    InvalidState,
}

/// `ALIGN_UP_BY(x, sizeof(ULONG))`.
const fn align_up4(value: u32) -> Option<u32> {
    match value.checked_add(3) {
        Some(sum) => Some(sum & !3),
        None => None,
    }
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let bytes = buf.get(off..off + 8)?;
    let mut octets = [0u8; 8];
    octets.copy_from_slice(bytes);
    Some(u64::from_le_bytes(octets))
}

fn write_u16(buf: &mut [u8], off: usize, value: u16) -> Option<()> {
    buf.get_mut(off..off + 2)?.copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn write_u32(buf: &mut [u8], off: usize, value: u32) -> Option<()> {
    buf.get_mut(off..off + 4)?.copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn write_u64(buf: &mut [u8], off: usize, value: u64) -> Option<()> {
    buf.get_mut(off..off + 8)?.copy_from_slice(&value.to_le_bytes());
    Some(())
}

/// `RtlStartRXact`'s buffer initialisation (rxact.c:255-262): a fresh log with no actions, whose
/// `CurrentSize` is exactly the header size (the first record lands right after it).
pub fn init_data(buf: &mut [u8], buffer_size: u32) -> Result<(), RxactError> {
    if (buf.len() as u64) < u64::from(buffer_size) || buffer_size < RXACT_DATA_SIZE {
        return Err(RxactError::NoMemory);
    }
    write_u32(buf, D_ACTION_COUNT, 0).ok_or(RxactError::NoMemory)?;
    write_u32(buf, D_BUFFER_SIZE, buffer_size).ok_or(RxactError::NoMemory)?;
    write_u32(buf, D_CURRENT_SIZE, RXACT_DATA_SIZE).ok_or(RxactError::NoMemory)?;
    Ok(())
}

/// `Data->ActionCount`.
pub fn action_count(buf: &[u8]) -> Option<u32> {
    read_u32(buf, D_ACTION_COUNT)
}

/// `Data->BufferSize`.
pub fn buffer_size(buf: &[u8]) -> Option<u32> {
    read_u32(buf, D_BUFFER_SIZE)
}

/// `Data->CurrentSize` — the number of bytes of `buf` the log currently occupies (header +
/// records). This is exactly what `RtlApplyRXact` persists as the `Log` value's data length.
pub fn current_size(buf: &[u8]) -> Option<u32> {
    read_u32(buf, D_CURRENT_SIZE)
}

/// Overwrite `Data->BufferSize` — used by the wrapper after it reallocates into a larger block
/// (rxact.c:545, `NewData->BufferSize = BufferSize`).
pub fn set_buffer_size(buf: &mut [u8], value: u32) -> Option<()> {
    write_u32(buf, D_BUFFER_SIZE, value)
}

/// `ActionSize` (rxact.c:508-511): the aligned record header plus the three aligned payloads
/// (key name, value name, value data). `None` on `ULONG` overflow.
pub fn action_record_size(
    key_name_length: u16,
    value_name_length: u16,
    value_data_size: u32,
) -> Option<u32> {
    let key = align_up4(u32::from(key_name_length))?;
    let value_name = align_up4(u32::from(value_name_length))?;
    let value_data = align_up4(value_data_size)?;
    let header = align_up4(RXACT_ACTION_SIZE)?;
    value_name
        .checked_add(value_data)?
        .checked_add(key)?
        .checked_add(header)
}

/// `RequiredSize = ActionSize + Context->Data->CurrentSize`, with ReactOS's overflow test
/// (rxact.c:514-520: `if (RequiredSize < ActionSize) return STATUS_NO_MEMORY`).
pub fn required_size(current_size: u32, action_size: u32) -> Result<u32, RxactError> {
    let required = current_size.wrapping_add(action_size);
    if required < action_size {
        return Err(RxactError::NoMemory);
    }
    Ok(required)
}

/// The growth policy (rxact.c:524-530): double `buffer_size` until it covers `required`. `None` if
/// doubling overflows `ULONG` before it can.
pub fn grown_buffer_size(buffer_size: u32, required: u32) -> Option<u32> {
    let mut size = buffer_size;
    while size < required {
        size = size.checked_mul(2)?;
    }
    Some(size)
}

/// A parsed `RXACT_ACTION`, with the `Buffer`/`ValueData` fields kept as **offsets from the
/// `RXACT_DATA` base** (the form they are stored + persisted in). `RXactpCommit` (rxact.c:141-144)
/// turns them into absolute pointers by adding the base; the DLL wrapper does the same.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// `Action->Size` — the byte stride to the next record.
    pub size: u32,
    /// `Action->Type` — [`RXACT_DELETE_KEY`] or [`RXACT_SET_VALUE_KEY`].
    pub action_type: u32,
    /// `Action->KeyName.Length` (bytes).
    pub key_name_length: u16,
    /// `Action->KeyName.MaximumLength` (bytes) — preserved from the caller's `UNICODE_STRING`.
    pub key_name_maximum_length: u16,
    /// `Action->KeyName.Buffer` as an offset from the log base.
    pub key_name_offset: u32,
    /// `Action->ValueName.Length` (bytes).
    pub value_name_length: u16,
    /// `Action->ValueName.MaximumLength` (bytes).
    pub value_name_maximum_length: u16,
    /// `Action->ValueName.Buffer` as an offset from the log base.
    pub value_name_offset: u32,
    /// `Action->KeyHandle` — [`RXACT_INVALID_HANDLE`] means "open the key by name at commit time".
    pub key_handle: u64,
    /// `Action->ValueType` — the `REG_*` type for a set action.
    pub value_type: u32,
    /// `Action->ValueDataSize`.
    pub value_data_size: u32,
    /// `Action->ValueData` as an offset from the log base.
    pub value_data_offset: u32,
}

/// `RtlAddAttributeActionToRXact`'s record writer (rxact.c:548-590), operating on a log buffer that
/// is *already large enough* (the caller grows it first — see [`required_size`] /
/// [`grown_buffer_size`]).
///
/// `key_name` / `value_name` are the UTF-16 code units of the respective `UNICODE_STRING`s;
/// `*_maximum_length` carry the callers' `MaximumLength` fields through verbatim, exactly as
/// ReactOS's `Action->KeyName = *KeyName` struct copy does.
#[allow(clippy::too_many_arguments)]
pub fn append_action(
    buf: &mut [u8],
    action_type: u32,
    key_name: &[u16],
    key_name_maximum_length: u16,
    key_handle: u64,
    value_name: &[u16],
    value_name_maximum_length: u16,
    value_type: u32,
    value_data: &[u8],
) -> Result<(), RxactError> {
    if action_type != RXACT_DELETE_KEY && action_type != RXACT_SET_VALUE_KEY {
        return Err(RxactError::InvalidParameter);
    }
    let key_name_length =
        u16::try_from(key_name.len() * 2).map_err(|_| RxactError::InvalidParameter)?;
    let value_name_length =
        u16::try_from(value_name.len() * 2).map_err(|_| RxactError::InvalidParameter)?;
    let value_data_size =
        u32::try_from(value_data.len()).map_err(|_| RxactError::InvalidParameter)?;

    let action_size = action_record_size(key_name_length, value_name_length, value_data_size)
        .ok_or(RxactError::NoMemory)?;
    let current = current_size(buf).ok_or(RxactError::InvalidState)?;
    let required = required_size(current, action_size)?;
    if (buf.len() as u64) < u64::from(required) {
        return Err(RxactError::NoMemory);
    }

    let record = current as usize;
    write_u32(buf, record + A_SIZE, action_size).ok_or(RxactError::NoMemory)?;
    write_u32(buf, record + A_TYPE, action_type).ok_or(RxactError::NoMemory)?;
    write_u16(buf, record + A_KEY_NAME + US_LENGTH, key_name_length).ok_or(RxactError::NoMemory)?;
    write_u16(
        buf,
        record + A_KEY_NAME + US_MAXIMUM_LENGTH,
        key_name_maximum_length,
    )
    .ok_or(RxactError::NoMemory)?;
    write_u16(buf, record + A_VALUE_NAME + US_LENGTH, value_name_length)
        .ok_or(RxactError::NoMemory)?;
    write_u16(
        buf,
        record + A_VALUE_NAME + US_MAXIMUM_LENGTH,
        value_name_maximum_length,
    )
    .ok_or(RxactError::NoMemory)?;
    write_u64(buf, record + A_KEY_HANDLE, key_handle).ok_or(RxactError::NoMemory)?;
    write_u32(buf, record + A_VALUE_TYPE, value_type).ok_or(RxactError::NoMemory)?;
    write_u32(buf, record + A_VALUE_DATA_SIZE, value_data_size).ok_or(RxactError::NoMemory)?;

    // Key name: stored right after the record header, its Buffer field holding the OFFSET.
    let mut offset = current
        .checked_add(RXACT_ACTION_SIZE)
        .ok_or(RxactError::NoMemory)?;
    write_u64(buf, record + A_KEY_NAME + US_BUFFER, u64::from(offset))
        .ok_or(RxactError::NoMemory)?;
    copy_units(buf, offset as usize, key_name)?;

    // Value name.
    offset = offset
        .checked_add(align_up4(u32::from(key_name_length)).ok_or(RxactError::NoMemory)?)
        .ok_or(RxactError::NoMemory)?;
    write_u64(buf, record + A_VALUE_NAME + US_BUFFER, u64::from(offset))
        .ok_or(RxactError::NoMemory)?;
    copy_units(buf, offset as usize, value_name)?;

    offset = offset
        .checked_add(align_up4(u32::from(value_name_length)).ok_or(RxactError::NoMemory)?)
        .ok_or(RxactError::NoMemory)?;

    // Value data — only for a set action (rxact.c:578-586).
    if action_type == RXACT_SET_VALUE_KEY {
        write_u64(buf, record + A_VALUE_DATA, u64::from(offset)).ok_or(RxactError::NoMemory)?;
        buf.get_mut(offset as usize..offset as usize + value_data.len())
            .ok_or(RxactError::NoMemory)?
            .copy_from_slice(value_data);
        offset = offset
            .checked_add(align_up4(value_data_size).ok_or(RxactError::NoMemory)?)
            .ok_or(RxactError::NoMemory)?;
    } else {
        // ReactOS leaves this uninitialised for a delete (never read); we zero it — see the module
        // docs.
        write_u64(buf, record + A_VALUE_DATA, 0).ok_or(RxactError::NoMemory)?;
    }

    write_u32(buf, D_CURRENT_SIZE, offset).ok_or(RxactError::NoMemory)?;
    let count = action_count(buf).ok_or(RxactError::InvalidState)?;
    write_u32(buf, D_ACTION_COUNT, count.wrapping_add(1)).ok_or(RxactError::NoMemory)?;
    Ok(())
}

fn copy_units(buf: &mut [u8], offset: usize, units: &[u16]) -> Result<(), RxactError> {
    let bytes = units.len() * 2;
    let dst = buf
        .get_mut(offset..offset + bytes)
        .ok_or(RxactError::NoMemory)?;
    for (index, unit) in units.iter().enumerate() {
        dst[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

/// Decode the `index`-th `RXACT_ACTION` of a log, walking the record chain by `Action->Size`
/// exactly as `RXactpCommit` does (rxact.c:137-236).
pub fn action_at(buf: &[u8], index: u32) -> Result<Action, RxactError> {
    let count = action_count(buf).ok_or(RxactError::InvalidParameter)?;
    if index >= count {
        return Err(RxactError::InvalidParameter);
    }
    let mut record = RXACT_DATA_SIZE as usize;
    for _ in 0..index {
        let size = read_u32(buf, record + A_SIZE).ok_or(RxactError::InvalidParameter)?;
        if size == 0 {
            return Err(RxactError::InvalidParameter);
        }
        record += size as usize;
    }
    decode_action(buf, record)
}

fn decode_action(buf: &[u8], record: usize) -> Result<Action, RxactError> {
    let e = RxactError::InvalidParameter;
    let action = Action {
        size: read_u32(buf, record + A_SIZE).ok_or(e)?,
        action_type: read_u32(buf, record + A_TYPE).ok_or(e)?,
        key_name_length: read_u16(buf, record + A_KEY_NAME + US_LENGTH).ok_or(e)?,
        key_name_maximum_length: read_u16(buf, record + A_KEY_NAME + US_MAXIMUM_LENGTH).ok_or(e)?,
        key_name_offset: read_u64(buf, record + A_KEY_NAME + US_BUFFER).ok_or(e)? as u32,
        value_name_length: read_u16(buf, record + A_VALUE_NAME + US_LENGTH).ok_or(e)?,
        value_name_maximum_length: read_u16(buf, record + A_VALUE_NAME + US_MAXIMUM_LENGTH)
            .ok_or(e)?,
        value_name_offset: read_u64(buf, record + A_VALUE_NAME + US_BUFFER).ok_or(e)? as u32,
        key_handle: read_u64(buf, record + A_KEY_HANDLE).ok_or(e)?,
        value_type: read_u32(buf, record + A_VALUE_TYPE).ok_or(e)?,
        value_data_size: read_u32(buf, record + A_VALUE_DATA_SIZE).ok_or(e)?,
        value_data_offset: read_u64(buf, record + A_VALUE_DATA).ok_or(e)? as u32,
    };
    if action.action_type != RXACT_DELETE_KEY && action.action_type != RXACT_SET_VALUE_KEY {
        return Err(RxactError::InvalidParameter);
    }
    Ok(action)
}

/// Read back the UTF-16 units a decoded [`Action`] points at (key name / value name), given the log
/// buffer. Returns `None` if the recorded offset/length falls outside the buffer.
pub fn units_at(buf: &[u8], offset: u32, length: u16) -> Option<&[u8]> {
    buf.get(offset as usize..offset as usize + usize::from(length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn utf16(s: &str) -> alloc::vec::Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn fresh_log_header_matches_reactos_start_rxact() {
        let mut buf = vec![0xAAu8; RXACT_DEFAULT_BUFFER_SIZE as usize];
        init_data(&mut buf, RXACT_DEFAULT_BUFFER_SIZE).unwrap();
        assert_eq!(action_count(&buf), Some(0));
        assert_eq!(buffer_size(&buf), Some(RXACT_DEFAULT_BUFFER_SIZE));
        assert_eq!(current_size(&buf), Some(RXACT_DATA_SIZE));
    }

    #[test]
    fn action_record_size_aligns_every_payload_to_four() {
        // 5 units of key name = 10 bytes -> 12; 1 unit of value name = 2 -> 4; 3 bytes data -> 4.
        assert_eq!(
            action_record_size(10, 2, 3),
            Some(12 + 4 + 4 + RXACT_ACTION_SIZE)
        );
        // Already-aligned payloads are untouched.
        assert_eq!(
            action_record_size(8, 4, 16),
            Some(8 + 4 + 16 + RXACT_ACTION_SIZE)
        );
        // Overflow is reported, never wrapped.
        assert_eq!(action_record_size(0, 0, u32::MAX), None);
    }

    #[test]
    fn required_size_detects_the_reactos_overflow_case() {
        assert_eq!(required_size(RXACT_DATA_SIZE, 0x40), Ok(RXACT_DATA_SIZE + 0x40));
        assert_eq!(required_size(u32::MAX, 0x40), Err(RxactError::NoMemory));
    }

    #[test]
    fn buffer_growth_doubles_until_it_fits() {
        assert_eq!(grown_buffer_size(0x1000, 0x900), Some(0x1000));
        assert_eq!(grown_buffer_size(0x1000, 0x1001), Some(0x2000));
        assert_eq!(grown_buffer_size(0x1000, 0x5000), Some(0x8000));
        assert_eq!(grown_buffer_size(0x8000_0000, 0xFFFF_FFFF), None);
    }

    #[test]
    fn set_value_action_round_trips_names_and_data() {
        let mut buf = vec![0u8; RXACT_DEFAULT_BUFFER_SIZE as usize];
        init_data(&mut buf, RXACT_DEFAULT_BUFFER_SIZE).unwrap();
        let key = utf16("Domains\\Account");
        let value = utf16("F");
        let data = [1u8, 2, 3, 4, 5];
        append_action(
            &mut buf,
            RXACT_SET_VALUE_KEY,
            &key,
            (key.len() * 2) as u16,
            0x1234,
            &value,
            (value.len() * 2) as u16,
            3, // REG_BINARY
            &data,
        )
        .unwrap();

        assert_eq!(action_count(&buf), Some(1));
        let action = action_at(&buf, 0).unwrap();
        assert_eq!(action.action_type, RXACT_SET_VALUE_KEY);
        assert_eq!(action.key_handle, 0x1234);
        assert_eq!(action.value_type, 3);
        assert_eq!(action.value_data_size, data.len() as u32);
        assert_eq!(action.key_name_length as usize, key.len() * 2);
        assert_eq!(action.value_name_length as usize, value.len() * 2);

        // The key name lands immediately after the record header.
        assert_eq!(action.key_name_offset, RXACT_DATA_SIZE + RXACT_ACTION_SIZE);
        let stored_key = units_at(&buf, action.key_name_offset, action.key_name_length).unwrap();
        let expected_key: alloc::vec::Vec<u8> =
            key.iter().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(stored_key, &expected_key[..]);

        let stored_value =
            units_at(&buf, action.value_name_offset, action.value_name_length).unwrap();
        let expected_value: alloc::vec::Vec<u8> =
            value.iter().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(stored_value, &expected_value[..]);

        let stored_data = units_at(
            &buf,
            action.value_data_offset,
            action.value_data_size as u16,
        )
        .unwrap();
        assert_eq!(stored_data, &data[..]);
    }

    #[test]
    fn delete_action_records_no_value_data() {
        let mut buf = vec![0xFFu8; RXACT_DEFAULT_BUFFER_SIZE as usize];
        init_data(&mut buf, RXACT_DEFAULT_BUFFER_SIZE).unwrap();
        let key = utf16("Stale");
        append_action(
            &mut buf,
            RXACT_DELETE_KEY,
            &key,
            (key.len() * 2) as u16,
            RXACT_INVALID_HANDLE,
            &[],
            0,
            0,
            &[],
        )
        .unwrap();
        let action = action_at(&buf, 0).unwrap();
        assert_eq!(action.action_type, RXACT_DELETE_KEY);
        assert_eq!(action.key_handle, RXACT_INVALID_HANDLE);
        assert_eq!(action.value_data_size, 0);
        assert_eq!(action.value_data_offset, 0);
        assert_eq!(action.value_name_length, 0);
    }

    #[test]
    fn multiple_actions_chain_by_size_and_grow_current_size() {
        let mut buf = vec![0u8; RXACT_DEFAULT_BUFFER_SIZE as usize];
        init_data(&mut buf, RXACT_DEFAULT_BUFFER_SIZE).unwrap();
        let names = ["Alpha", "Br", "GammaDelta"];
        for (index, name) in names.iter().enumerate() {
            let key = utf16(name);
            append_action(
                &mut buf,
                RXACT_SET_VALUE_KEY,
                &key,
                (key.len() * 2) as u16,
                index as u64,
                &utf16("V"),
                2,
                1, // REG_SZ
                &[index as u8; 3],
            )
            .unwrap();
        }
        assert_eq!(action_count(&buf), Some(3));

        let mut walked = RXACT_DATA_SIZE;
        for (index, name) in names.iter().enumerate() {
            let action = action_at(&buf, index as u32).unwrap();
            assert_eq!(action.key_handle, index as u64);
            assert_eq!(action.key_name_offset, walked + RXACT_ACTION_SIZE);
            let stored =
                units_at(&buf, action.key_name_offset, action.key_name_length).unwrap();
            let expected: alloc::vec::Vec<u8> =
                utf16(name).iter().flat_map(|u| u.to_le_bytes()).collect();
            assert_eq!(stored, &expected[..]);
            walked += action.size;
        }
        assert_eq!(current_size(&buf), Some(walked));
    }

    #[test]
    fn appending_past_the_buffer_reports_no_memory_and_never_writes() {
        // A buffer just big enough for the header + one record header, but not the payload.
        let size = RXACT_DATA_SIZE + RXACT_ACTION_SIZE;
        let mut buf = vec![0u8; size as usize];
        init_data(&mut buf, size).unwrap();
        let key = utf16("TooLong");
        assert_eq!(
            append_action(
                &mut buf,
                RXACT_SET_VALUE_KEY,
                &key,
                (key.len() * 2) as u16,
                0,
                &[],
                0,
                1,
                &[0u8; 8],
            ),
            Err(RxactError::NoMemory)
        );
        assert_eq!(action_count(&buf), Some(0));
        assert_eq!(current_size(&buf), Some(RXACT_DATA_SIZE));
    }

    #[test]
    fn an_unknown_action_type_is_rejected() {
        let mut buf = vec![0u8; RXACT_DEFAULT_BUFFER_SIZE as usize];
        init_data(&mut buf, RXACT_DEFAULT_BUFFER_SIZE).unwrap();
        assert_eq!(
            append_action(&mut buf, 7, &utf16("K"), 2, 0, &[], 0, 0, &[]),
            Err(RxactError::InvalidParameter)
        );
        assert_eq!(action_count(&buf), Some(0));
    }

    #[test]
    fn decoding_out_of_range_or_corrupt_records_fails_closed() {
        let mut buf = vec![0u8; RXACT_DEFAULT_BUFFER_SIZE as usize];
        init_data(&mut buf, RXACT_DEFAULT_BUFFER_SIZE).unwrap();
        assert_eq!(action_at(&buf, 0), Err(RxactError::InvalidParameter));

        append_action(
            &mut buf,
            RXACT_DELETE_KEY,
            &utf16("K"),
            2,
            RXACT_INVALID_HANDLE,
            &[],
            0,
            0,
            &[],
        )
        .unwrap();
        // Corrupt the recorded Type: the walker must refuse rather than commit a bogus action.
        write_u32(&mut buf, RXACT_DATA_SIZE as usize + A_TYPE, 99).unwrap();
        assert_eq!(action_at(&buf, 0), Err(RxactError::InvalidParameter));
    }

    #[test]
    fn a_zero_sized_record_cannot_loop_the_walker() {
        let mut buf = vec![0u8; RXACT_DEFAULT_BUFFER_SIZE as usize];
        init_data(&mut buf, RXACT_DEFAULT_BUFFER_SIZE).unwrap();
        for _ in 0..2 {
            append_action(
                &mut buf,
                RXACT_DELETE_KEY,
                &utf16("K"),
                2,
                RXACT_INVALID_HANDLE,
                &[],
                0,
                0,
                &[],
            )
            .unwrap();
        }
        write_u32(&mut buf, RXACT_DATA_SIZE as usize + A_SIZE, 0).unwrap();
        assert_eq!(action_at(&buf, 1), Err(RxactError::InvalidParameter));
    }

    #[test]
    fn set_buffer_size_matches_the_realloc_path() {
        let mut buf = vec![0u8; 0x2000];
        init_data(&mut buf, 0x1000).unwrap();
        set_buffer_size(&mut buf, 0x2000).unwrap();
        assert_eq!(buffer_size(&buf), Some(0x2000));
        assert_eq!(current_size(&buf), Some(RXACT_DATA_SIZE));
    }
}
