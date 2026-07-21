//! Private property-set `PROPVARIANT` conversion helpers.
//!
//! ReactOS ntdll forwards these legacy NT5 exports to ole32. The useful behavior lives in the
//! property serializer/deserializer, so the Rust ntdll keeps that core here and lets the DLL wrapper
//! handle raw allocation callbacks.

use alloc::vec::Vec;
use core::{char, ptr, slice, str};

pub const CP_WINUNICODE: u16 = 1200;
pub const CP_UTF8: u16 = 65001;

pub const VT_EMPTY: u16 = 0;
pub const VT_NULL: u16 = 1;
pub const VT_I2: u16 = 2;
pub const VT_I4: u16 = 3;
pub const VT_R4: u16 = 4;
pub const VT_R8: u16 = 5;
pub const VT_CY: u16 = 6;
pub const VT_DATE: u16 = 7;
pub const VT_BSTR: u16 = 8;
pub const VT_ERROR: u16 = 10;
pub const VT_BOOL: u16 = 11;
pub const VT_I1: u16 = 16;
pub const VT_UI1: u16 = 17;
pub const VT_UI2: u16 = 18;
pub const VT_UI4: u16 = 19;
pub const VT_I8: u16 = 20;
pub const VT_UI8: u16 = 21;
pub const VT_INT: u16 = 22;
pub const VT_UINT: u16 = 23;
pub const VT_LPSTR: u16 = 30;
pub const VT_LPWSTR: u16 = 31;
pub const VT_FILETIME: u16 = 64;
pub const VT_BLOB: u16 = 65;
pub const VT_BLOB_OBJECT: u16 = 70;
pub const VT_CLSID: u16 = 72;
pub const VT_VECTOR: u16 = 0x1000;
pub const VT_ARRAY: u16 = 0x2000;
pub const VT_BYREF: u16 = 0x4000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropVariantError {
    InvalidParameter,
    InvalidData,
    UnsupportedType,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PropVariant {
    pub vt: u16,
    pub reserved1: u16,
    pub reserved2: u16,
    pub reserved3: u16,
    pub data: [u8; 16],
}

impl PropVariant {
    pub const fn zeroed() -> Self {
        Self {
            vt: VT_EMPTY,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            data: [0; 16],
        }
    }

    pub fn with_vt(vt: u16) -> Self {
        let mut value = Self::zeroed();
        value.vt = vt;
        value
    }

    pub fn set_data_bytes(&mut self, bytes: &[u8]) {
        self.data = [0; 16];
        self.data[..bytes.len()].copy_from_slice(bytes);
    }

    pub fn data_u64(&self) -> u64 {
        u64::from_ne_bytes(self.data[..8].try_into().unwrap())
    }

    pub fn set_data_u64(&mut self, value: u64) {
        self.set_data_bytes(&value.to_ne_bytes());
    }
}

impl Default for PropVariant {
    fn default() -> Self {
        Self::zeroed()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParsedVariant {
    Empty,
    Null,
    I1(i8),
    Ui1(u8),
    I2(i16),
    Ui2(u16),
    Bool(i16),
    I4(i32),
    Ui4(u32),
    R4(u32),
    Error(i32),
    I8(i64),
    Ui8(u64),
    R8(u64),
    Cy(i64),
    Date(u64),
    FileTime(u64),
    Bstr(Option<Vec<u16>>),
    LpStr(Option<Vec<u8>>),
    LpWstr(Option<Vec<u16>>),
    Blob(Vec<u8>),
    Clsid([u8; 16]),
}

impl ParsedVariant {
    pub fn vt(&self) -> u16 {
        match self {
            Self::Empty => VT_EMPTY,
            Self::Null => VT_NULL,
            Self::I1(_) => VT_I1,
            Self::Ui1(_) => VT_UI1,
            Self::I2(_) => VT_I2,
            Self::Ui2(_) => VT_UI2,
            Self::Bool(_) => VT_BOOL,
            Self::I4(_) => VT_I4,
            Self::Ui4(_) => VT_UI4,
            Self::R4(_) => VT_R4,
            Self::Error(_) => VT_ERROR,
            Self::I8(_) => VT_I8,
            Self::Ui8(_) => VT_UI8,
            Self::R8(_) => VT_R8,
            Self::Cy(_) => VT_CY,
            Self::Date(_) => VT_DATE,
            Self::FileTime(_) => VT_FILETIME,
            Self::Bstr(_) => VT_BSTR,
            Self::LpStr(_) => VT_LPSTR,
            Self::LpWstr(_) => VT_LPWSTR,
            Self::Blob(_) => VT_BLOB,
            Self::Clsid(_) => VT_CLSID,
        }
    }
}

pub fn dword_align(value: usize) -> usize {
    (value + 3) & !3
}

pub fn quad_align(value: usize) -> usize {
    (value + 7) & !7
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PropVariantError> {
    let end = offset
        .checked_add(4)
        .ok_or(PropVariantError::InvalidParameter)?;
    let chunk = bytes
        .get(offset..end)
        .ok_or(PropVariantError::InvalidParameter)?;
    Ok(u32::from_le_bytes(chunk.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PropVariantError> {
    let end = offset
        .checked_add(8)
        .ok_or(PropVariantError::InvalidParameter)?;
    let chunk = bytes
        .get(offset..end)
        .ok_or(PropVariantError::InvalidParameter)?;
    Ok(u64::from_le_bytes(chunk.try_into().unwrap()))
}

fn payload<'a>(bytes: &'a [u8], offset: usize, len: usize) -> Result<&'a [u8], PropVariantError> {
    let end = offset
        .checked_add(len)
        .ok_or(PropVariantError::InvalidParameter)?;
    bytes
        .get(offset..end)
        .ok_or(PropVariantError::InvalidParameter)
}

fn vt_from_serialized(bytes: &[u8]) -> Result<u16, PropVariantError> {
    Ok(read_u32(bytes, 0)? as u16)
}

fn reject_compound_vt(vt: u16) -> Result<(), PropVariantError> {
    if vt & (VT_VECTOR | VT_ARRAY | VT_BYREF) != 0 {
        return Err(PropVariantError::UnsupportedType);
    }
    Ok(())
}

pub fn serialized_len(bytes: &[u8]) -> Result<usize, PropVariantError> {
    let vt = vt_from_serialized(bytes)?;
    reject_compound_vt(vt)?;
    serialized_len_for_vt(vt, |offset| read_u32(bytes, offset))
}

/// Calculate a serialized property's byte length from a raw pointer.
///
/// # Safety
/// `property` must point at a valid `SERIALIZEDPROPERTYVALUE` whose inline count fields describe
/// mapped memory. This mirrors the legacy ntdll API, which has no explicit byte-count parameter for
/// `RtlConvertPropertyToVariant`.
pub unsafe fn serialized_len_from_ptr(property: *const u8) -> Result<usize, PropVariantError> {
    if property.is_null() {
        return Err(PropVariantError::InvalidParameter);
    }
    // SAFETY: caller supplies a mapped serialized property.
    let vt = unsafe { ptr::read_unaligned(property as *const u32) as u16 };
    reject_compound_vt(vt)?;
    serialized_len_for_vt(vt, |offset| {
        // SAFETY: caller supplies a mapped serialized property with enough bytes for its count fields.
        Ok(unsafe { ptr::read_unaligned(property.add(offset) as *const u32) })
    })
}

fn serialized_len_for_vt<F>(vt: u16, mut read_count: F) -> Result<usize, PropVariantError>
where
    F: FnMut(usize) -> Result<u32, PropVariantError>,
{
    let fixed = match vt {
        VT_EMPTY | VT_NULL => return Ok(4),
        VT_I1 | VT_UI1 => 1,
        VT_I2 | VT_UI2 | VT_BOOL => 2,
        VT_I4 | VT_UI4 | VT_INT | VT_UINT | VT_R4 | VT_ERROR => 4,
        VT_I8 | VT_UI8 | VT_R8 | VT_CY | VT_DATE | VT_FILETIME => 8,
        VT_CLSID => 16,
        VT_BSTR | VT_LPSTR | VT_BLOB | VT_BLOB_OBJECT => {
            let count = read_count(4)? as usize;
            return Ok(8 + dword_align(count));
        }
        VT_LPWSTR => {
            let count = read_count(4)? as usize;
            let bytes = count
                .checked_mul(2)
                .ok_or(PropVariantError::InvalidParameter)?;
            return Ok(8 + dword_align(bytes));
        }
        _ => return Err(PropVariantError::UnsupportedType),
    };
    Ok(4 + dword_align(fixed))
}

pub fn parse_property(bytes: &[u8], code_page: u16) -> Result<ParsedVariant, PropVariantError> {
    let vt = vt_from_serialized(bytes)?;
    reject_compound_vt(vt)?;
    match vt {
        VT_EMPTY => Ok(ParsedVariant::Empty),
        VT_NULL => Ok(ParsedVariant::Null),
        VT_I1 => Ok(ParsedVariant::I1(payload(bytes, 4, 1)?[0] as i8)),
        VT_UI1 => Ok(ParsedVariant::Ui1(payload(bytes, 4, 1)?[0])),
        VT_I2 => Ok(ParsedVariant::I2(i16::from_le_bytes(
            payload(bytes, 4, 2)?.try_into().unwrap(),
        ))),
        VT_UI2 => Ok(ParsedVariant::Ui2(u16::from_le_bytes(
            payload(bytes, 4, 2)?.try_into().unwrap(),
        ))),
        VT_BOOL => Ok(ParsedVariant::Bool(i16::from_le_bytes(
            payload(bytes, 4, 2)?.try_into().unwrap(),
        ))),
        VT_I4 | VT_INT => Ok(ParsedVariant::I4(read_u32(bytes, 4)? as i32)),
        VT_UI4 | VT_UINT => Ok(ParsedVariant::Ui4(read_u32(bytes, 4)?)),
        VT_R4 => Ok(ParsedVariant::R4(read_u32(bytes, 4)?)),
        VT_ERROR => Ok(ParsedVariant::Error(read_u32(bytes, 4)? as i32)),
        VT_I8 => Ok(ParsedVariant::I8(read_u64(bytes, 4)? as i64)),
        VT_UI8 => Ok(ParsedVariant::Ui8(read_u64(bytes, 4)?)),
        VT_R8 => Ok(ParsedVariant::R8(read_u64(bytes, 4)?)),
        VT_CY => Ok(ParsedVariant::Cy(read_u64(bytes, 4)? as i64)),
        VT_DATE => Ok(ParsedVariant::Date(read_u64(bytes, 4)?)),
        VT_FILETIME => Ok(ParsedVariant::FileTime(read_u64(bytes, 4)?)),
        VT_CLSID => {
            let mut guid = [0u8; 16];
            guid.copy_from_slice(payload(bytes, 4, 16)?);
            Ok(ParsedVariant::Clsid(guid))
        }
        VT_BLOB | VT_BLOB_OBJECT => {
            let count = read_u32(bytes, 4)? as usize;
            Ok(ParsedVariant::Blob(payload(bytes, 8, count)?.to_vec()))
        }
        VT_BSTR => parse_bstr(bytes, code_page),
        VT_LPSTR => parse_lpstr(bytes, code_page),
        VT_LPWSTR => parse_lpwstr(bytes),
        _ => Err(PropVariantError::UnsupportedType),
    }
}

fn parse_bstr(bytes: &[u8], code_page: u16) -> Result<ParsedVariant, PropVariantError> {
    let count = read_u32(bytes, 4)? as usize;
    if count == 0 {
        return Ok(ParsedVariant::Bstr(None));
    }
    let raw = payload(bytes, 8, count)?;
    let mut wide = if code_page == CP_WINUNICODE {
        if count % 2 != 0 {
            return Err(PropVariantError::InvalidData);
        }
        let mut out = Vec::with_capacity(count / 2);
        for chunk in raw.chunks_exact(2) {
            out.push(u16::from_le_bytes(chunk.try_into().unwrap()));
        }
        out
    } else {
        bytes_to_utf16(raw, code_page)?
    };
    match wide.last() {
        Some(0) => {
            wide.pop();
            Ok(ParsedVariant::Bstr(Some(wide)))
        }
        _ => Err(PropVariantError::InvalidData),
    }
}

fn parse_lpstr(bytes: &[u8], code_page: u16) -> Result<ParsedVariant, PropVariantError> {
    let count = read_u32(bytes, 4)? as usize;
    if count == 0 {
        return Ok(ParsedVariant::LpStr(None));
    }
    let raw = payload(bytes, 8, count)?;
    let mut ansi = if code_page == CP_WINUNICODE {
        let wide = utf16_from_le_bytes(raw)?;
        utf16_to_ansi_bytes(&wide)
    } else {
        raw.to_vec()
    };
    if ansi.last().copied() != Some(0) {
        return Err(PropVariantError::InvalidData);
    }
    if ansi.is_empty() {
        ansi.push(0);
    }
    Ok(ParsedVariant::LpStr(Some(ansi)))
}

fn parse_lpwstr(bytes: &[u8]) -> Result<ParsedVariant, PropVariantError> {
    let count = read_u32(bytes, 4)? as usize;
    if count == 0 {
        return Ok(ParsedVariant::LpWstr(None));
    }
    let raw_len = count
        .checked_mul(2)
        .ok_or(PropVariantError::InvalidParameter)?;
    let mut wide = utf16_from_le_bytes(payload(bytes, 8, raw_len)?)?;
    match wide.last() {
        Some(0) => {
            wide.pop();
            Ok(ParsedVariant::LpWstr(Some(wide)))
        }
        _ => Err(PropVariantError::InvalidData),
    }
}

pub fn property_length_as_variant(
    serialized: &[u8],
    code_page: u16,
) -> Result<u32, PropVariantError> {
    let vt = vt_from_serialized(serialized)?;
    reject_compound_vt(vt)?;
    let cbprop = serialized_len(serialized)?;
    let cbvar = match vt {
        VT_CLSID => cbprop.saturating_sub(4),
        VT_BLOB | VT_BLOB_OBJECT => cbprop.saturating_sub(8),
        VT_BSTR => cbprop.saturating_sub(4).saturating_mul(2),
        VT_LPSTR | VT_LPWSTR => cbprop.saturating_sub(8),
        _ => {
            let _ = code_page;
            0
        }
    };
    Ok(quad_align(cbvar) as u32)
}

/// Serialize a raw x64 `PROPVARIANT` into the private `SERIALIZEDPROPERTYVALUE` wire format.
///
/// # Safety
/// Pointer-bearing variants must contain valid process pointers for the represented type.
pub unsafe fn serialize_variant_to_vec(
    value: &PropVariant,
    code_page: u16,
) -> Result<Vec<u8>, PropVariantError> {
    reject_compound_vt(value.vt)?;
    let mut out = Vec::new();
    out.extend_from_slice(&(value.vt as u32).to_le_bytes());
    match value.vt {
        VT_EMPTY | VT_NULL => {}
        VT_I1 | VT_UI1 => append_padded(&mut out, &value.data[..1]),
        VT_I2 | VT_UI2 | VT_BOOL => append_padded(&mut out, &value.data[..2]),
        VT_I4 | VT_UI4 | VT_INT | VT_UINT | VT_R4 | VT_ERROR => {
            append_padded(&mut out, &value.data[..4])
        }
        VT_I8 | VT_UI8 | VT_R8 | VT_CY | VT_DATE | VT_FILETIME => {
            append_padded(&mut out, &value.data[..8])
        }
        VT_CLSID => {
            let ptr = value.data_u64() as *const u8;
            if ptr.is_null() {
                return Err(PropVariantError::InvalidParameter);
            }
            // SAFETY: caller supplies a valid CLSID pointer.
            append_padded(&mut out, unsafe { slice::from_raw_parts(ptr, 16) });
        }
        VT_BLOB | VT_BLOB_OBJECT => {
            let count = u32::from_ne_bytes(value.data[..4].try_into().unwrap()) as usize;
            let ptr = value.data_u64_at(8) as *const u8;
            if count != 0 && ptr.is_null() {
                return Err(PropVariantError::InvalidParameter);
            }
            out.extend_from_slice(&(count as u32).to_le_bytes());
            if count != 0 {
                // SAFETY: caller supplies a valid BLOB pointer for `count` bytes.
                append_padded(&mut out, unsafe { slice::from_raw_parts(ptr, count) });
            }
        }
        VT_BSTR => {
            let ptr = value.data_u64() as *const u16;
            let payload = if ptr.is_null() {
                Vec::new()
            } else {
                // SAFETY: BSTR byte length is stored immediately before the data pointer.
                let byte_len =
                    unsafe { ptr::read_unaligned((ptr as *const u8).sub(4) as *const u32) }
                        as usize;
                if byte_len % 2 != 0 {
                    return Err(PropVariantError::InvalidData);
                }
                // SAFETY: caller supplies a valid BSTR buffer.
                let wide = unsafe { slice::from_raw_parts(ptr, byte_len / 2) };
                encode_bstr_payload(wide, code_page)
            };
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            append_padded(&mut out, &payload);
        }
        VT_LPSTR => {
            let ptr = value.data_u64() as *const u8;
            let bytes = if ptr.is_null() {
                Vec::new()
            } else {
                // SAFETY: caller supplies a NUL-terminated string.
                unsafe { read_nul_bytes(ptr) }
            };
            let payload = if code_page == CP_WINUNICODE {
                let wide = bytes_to_utf16(&bytes, 0)?;
                utf16_to_le_bytes(&wide)
            } else {
                bytes
            };
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            append_padded(&mut out, &payload);
        }
        VT_LPWSTR => {
            let ptr = value.data_u64() as *const u16;
            let wide = if ptr.is_null() {
                Vec::new()
            } else {
                // SAFETY: caller supplies a NUL-terminated UTF-16 string.
                unsafe { read_nul_wide(ptr) }
            };
            out.extend_from_slice(&(wide.len() as u32).to_le_bytes());
            append_padded(&mut out, &utf16_to_le_bytes(&wide));
        }
        _ => return Err(PropVariantError::UnsupportedType),
    }
    Ok(out)
}

trait PropVariantDataExt {
    fn data_u64_at(&self, offset: usize) -> u64;
}

impl PropVariantDataExt for PropVariant {
    fn data_u64_at(&self, offset: usize) -> u64 {
        u64::from_ne_bytes(self.data[offset..offset + 8].try_into().unwrap())
    }
}

fn append_padded(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
    let pad = dword_align(bytes.len()) - bytes.len();
    out.extend(core::iter::repeat(0).take(pad));
}

fn encode_bstr_payload(wide_without_nul: &[u16], code_page: u16) -> Vec<u8> {
    if code_page == CP_WINUNICODE {
        let mut payload = utf16_to_le_bytes(wide_without_nul);
        payload.extend_from_slice(&0u16.to_le_bytes());
        return payload;
    }

    let mut payload = if code_page == CP_UTF8 {
        utf16_to_utf8_bytes(wide_without_nul)
    } else {
        utf16_to_ansi_bytes(wide_without_nul)
    };
    payload.push(0);
    payload
}

fn utf16_from_le_bytes(bytes: &[u8]) -> Result<Vec<u16>, PropVariantError> {
    if bytes.len() % 2 != 0 {
        return Err(PropVariantError::InvalidData);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        out.push(u16::from_le_bytes(chunk.try_into().unwrap()));
    }
    Ok(out)
}

fn utf16_to_le_bytes(wide: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wide.len() * 2);
    for unit in wide {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn bytes_to_utf16(bytes_with_nul: &[u8], code_page: u16) -> Result<Vec<u16>, PropVariantError> {
    if code_page == CP_UTF8 {
        let s = str::from_utf8(bytes_with_nul).map_err(|_| PropVariantError::InvalidData)?;
        Ok(s.encode_utf16().collect())
    } else {
        Ok(bytes_with_nul.iter().map(|b| *b as u16).collect())
    }
}

fn utf16_to_utf8_bytes(wide: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    for decoded in char::decode_utf16(wide.iter().copied()) {
        let ch = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
    out
}

fn utf16_to_ansi_bytes(wide: &[u16]) -> Vec<u8> {
    wide.iter()
        .map(|unit| if *unit <= 0xFF { *unit as u8 } else { b'?' })
        .collect()
}

/// # Safety
/// `ptr` must point to a NUL-terminated byte string.
unsafe fn read_nul_bytes(ptr: *const u8) -> Vec<u8> {
    let mut len = 0usize;
    // SAFETY: caller supplies a NUL-terminated string.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // Include the terminator in serialized strings.
    // SAFETY: caller supplies a buffer valid through the terminator.
    unsafe { slice::from_raw_parts(ptr, len + 1) }.to_vec()
}

/// # Safety
/// `ptr` must point to a NUL-terminated UTF-16 string.
unsafe fn read_nul_wide(ptr: *const u16) -> Vec<u16> {
    let mut len = 0usize;
    // SAFETY: caller supplies a NUL-terminated string.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // Include the terminator in serialized strings.
    // SAFETY: caller supplies a buffer valid through the terminator.
    unsafe { slice::from_raw_parts(ptr, len + 1) }.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::mem::{offset_of, size_of};

    const SERIALIZED_EMPTY: &[u8] = &[0, 0, 0, 0];
    const SERIALIZED_NULL: &[u8] = &[1, 0, 0, 0];
    const SERIALIZED_I4: &[u8] = &[3, 0, 0, 0, 0xef, 0xcd, 0xab, 0xfe];
    const SERIALIZED_BSTR_WC: &[u8] = &[
        8, 0, 0, 0, 10, 0, 0, 0, b't', 0, b'e', 0, b's', 0, b't', 0, 0, 0, 0, 0,
    ];
    const SERIALIZED_BSTR_UTF8: &[u8] =
        &[8, 0, 0, 0, 5, 0, 0, 0, b't', b'e', b's', b't', 0, 0, 0, 0];

    #[test]
    fn propvariant_layout_matches_x64_union_shape() {
        assert_eq!(size_of::<PropVariant>(), 24);
        assert_eq!(offset_of!(PropVariant, data), 8);
    }

    #[test]
    fn parses_scalar_and_bstr_properties() {
        assert_eq!(
            parse_property(SERIALIZED_I4, CP_WINUNICODE).unwrap(),
            ParsedVariant::I4(0xfeab_cdefu32 as i32)
        );
        assert_eq!(
            parse_property(SERIALIZED_BSTR_WC, CP_WINUNICODE).unwrap(),
            ParsedVariant::Bstr(Some(vec![
                b't' as u16,
                b'e' as u16,
                b's' as u16,
                b't' as u16
            ]))
        );
        assert_eq!(
            parse_property(SERIALIZED_BSTR_UTF8, CP_UTF8).unwrap(),
            ParsedVariant::Bstr(Some(vec![
                b't' as u16,
                b'e' as u16,
                b's' as u16,
                b't' as u16
            ]))
        );
    }

    #[test]
    fn serialized_length_follows_inline_counts() {
        assert_eq!(serialized_len(SERIALIZED_EMPTY), Ok(4));
        assert_eq!(serialized_len(SERIALIZED_NULL), Ok(4));
        assert_eq!(serialized_len(SERIALIZED_I4), Ok(8));
        assert_eq!(serialized_len(SERIALIZED_BSTR_WC), Ok(20));
        assert_eq!(serialized_len(SERIALIZED_BSTR_UTF8), Ok(16));
    }

    #[test]
    fn property_length_as_variant_uses_nt5_overestimate_rules() {
        assert_eq!(
            property_length_as_variant(SERIALIZED_I4, CP_WINUNICODE),
            Ok(0)
        );
        assert_eq!(
            property_length_as_variant(SERIALIZED_BSTR_WC, CP_WINUNICODE),
            Ok(32)
        );
        assert_eq!(
            property_length_as_variant(SERIALIZED_BSTR_UTF8, CP_UTF8),
            Ok(24)
        );
    }

    #[test]
    fn serializes_winetest_scalar_fixtures() {
        let empty = PropVariant::with_vt(VT_EMPTY);
        let null = PropVariant::with_vt(VT_NULL);
        let mut i4 = PropVariant::with_vt(VT_I4);
        i4.set_data_bytes(&0xfeab_cdefu32.to_ne_bytes());

        assert_eq!(
            unsafe { serialize_variant_to_vec(&empty, CP_WINUNICODE).unwrap() },
            SERIALIZED_EMPTY
        );
        assert_eq!(
            unsafe { serialize_variant_to_vec(&null, CP_WINUNICODE).unwrap() },
            SERIALIZED_NULL
        );
        assert_eq!(
            unsafe { serialize_variant_to_vec(&i4, CP_WINUNICODE).unwrap() },
            SERIALIZED_I4
        );
    }

    #[test]
    fn serializes_bstr_as_unicode_and_utf8_properties() {
        let mut storage = Vec::new();
        storage.extend_from_slice(&8u32.to_ne_bytes());
        for unit in [b't' as u16, b'e' as u16, b's' as u16, b't' as u16, 0] {
            storage.extend_from_slice(&unit.to_ne_bytes());
        }
        let bstr = unsafe { storage.as_ptr().add(4) } as u64;
        let mut variant = PropVariant::with_vt(VT_BSTR);
        variant.set_data_u64(bstr);

        assert_eq!(
            unsafe { serialize_variant_to_vec(&variant, CP_WINUNICODE).unwrap() },
            SERIALIZED_BSTR_WC
        );
        assert_eq!(
            unsafe { serialize_variant_to_vec(&variant, CP_UTF8).unwrap() },
            SERIALIZED_BSTR_UTF8
        );
    }
}
