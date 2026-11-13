//! UTF-16 normalization and IDN entries used by the released kernelbase.

type NtStatus = u32;
const STATUS_SUCCESS: NtStatus = 0;
const STATUS_INVALID_PARAMETER: NtStatus = 0xc000_000d;
const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xc000_0023;
const STATUS_NOT_SUPPORTED: NtStatus = 0xc000_00bb;
const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xc000_0034;
const STATUS_INVALID_IDN_NORMALIZATION: NtStatus = 0xc000_0716;
const STATUS_NO_UNICODE_TRANSLATION: NtStatus = 0xc000_0717;

const IDN_ALLOW_UNASSIGNED: u32 = 1;
const IDN_USE_STD3_ASCII_RULES: u32 = 2;
const MAX_NUL_TERMINATED_UNITS: usize = 1 << 20;
const MAX_IDN_UNITS: usize = 256;

fn check_form(form: u32) -> Result<(), NtStatus> {
    match form {
        1 | 2 | 5 | 6 | 13 => Ok(()),
        0 => Err(STATUS_INVALID_PARAMETER),
        _ => Err(STATUS_OBJECT_NAME_NOT_FOUND),
    }
}

/// Convert the NT signed UTF-16 length to a bounded slice. A `-1` length includes the terminal
/// NUL for copying APIs, while the normalized predicate ignores it (a final NUL is invariant).
///
/// # Safety
/// `src` must be readable through the stated count or a terminal NUL. The pointer contract is
/// inherited from the native caller; a user-mode DLL cannot validate arbitrary mapped memory.
unsafe fn source<'a>(src: *const u16, len: i32, include_nul: bool) -> Result<&'a [u16], NtStatus> {
    if src.is_null() || len < -1 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let count = if len == -1 {
        let mut i = 0;
        while i < MAX_NUL_TERMINATED_UNITS {
            // SAFETY: the caller promises a NUL-terminated UTF-16 string.
            if unsafe { *src.add(i) } == 0 {
                return Ok(unsafe {
                    core::slice::from_raw_parts(src, i + usize::from(include_nul))
                });
            }
            i += 1;
        }
        return Err(STATUS_INVALID_PARAMETER);
    } else {
        len as usize
    };
    if count > MAX_NUL_TERMINATED_UNITS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: the caller provides `count` readable UTF-16 units.
    Ok(unsafe { core::slice::from_raw_parts(src, count) })
}

/// Exact copy after validating all status conditions. A zero capacity is the NT size query.
///
/// # Safety
/// `dst_len` must be writable; a nonzero capacity requires `dst` to be writable for that count.
unsafe fn copy_result(src: &[u16], dst: *mut u16, dst_len: *mut i32) -> NtStatus {
    if dst_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: `dst_len` is writable by the caller's contract.
    let capacity = unsafe { *dst_len };
    if capacity < 0 || (capacity != 0 && dst.is_null()) || src.len() > i32::MAX as usize {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: `dst_len` is writable. NT returns required UTF-16 units, not bytes.
    unsafe { *dst_len = src.len() as i32 };
    if capacity == 0 {
        return STATUS_SUCCESS;
    }
    if (capacity as usize) < src.len() {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: caller owns the writable `capacity` units. `ptr::copy` permits overlapping ranges.
    unsafe { core::ptr::copy(src.as_ptr(), dst, src.len()) };
    STATUS_SUCCESS
}

fn ascii_only(src: &[u16]) -> Result<(), NtStatus> {
    // Full Unicode normalization needs the NT normalization table for each form. ASCII is
    // invariant under all supported forms and can be handled without a partial Unicode table.
    if src.iter().any(|&ch| ch >= 0x80) {
        return Err(STATUS_NOT_SUPPORTED);
    }
    if src
        .iter()
        .enumerate()
        .any(|(i, &ch)| ch == 0 && i + 1 != src.len())
    {
        return Err(STATUS_NO_UNICODE_TRANSLATION);
    }
    if src.iter().any(|&ch| ch < 0x20 && ch != 0) {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(())
}

/// `RtlNormalizeString(NORM_FORM, PCWSTR, INT, PWSTR, PINT)`.
///
/// # Safety
/// Pointers follow the NT caller contract; `dst_len` is writable and `dst` has its stated count.
#[export_name = "RtlNormalizeString"]
pub unsafe extern "system" fn rtl_normalize_string(
    form: u32,
    src: *const u16,
    src_len: i32,
    dst: *mut u16,
    dst_len: *mut i32,
) -> NtStatus {
    if let Err(status) = check_form(form) {
        return status;
    }
    // Form 13 is Nameprep: even ASCII may undergo case mapping. The separate IDN entry has
    // Wine's literal ASCII fast path, but this general entry needs the normalization table.
    if form == 13 {
        return STATUS_NOT_SUPPORTED;
    }
    if dst_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let src = match unsafe { source(src, src_len, true) } {
        Ok(src) => src,
        Err(status) => return status,
    };
    if let Err(status) = ascii_only(src) {
        return status;
    }
    unsafe { copy_result(src, dst, dst_len) }
}

/// `RtlIsNormalizedString(NORM_FORM, PCWSTR, INT, PBOOLEAN)`.
///
/// # Safety
/// `src` is readable for the indicated length, and `result` is writable.
#[export_name = "RtlIsNormalizedString"]
pub unsafe extern "system" fn rtl_is_normalized_string(
    form: u32,
    src: *const u16,
    src_len: i32,
    result: *mut u8,
) -> NtStatus {
    if let Err(status) = check_form(form) {
        return status;
    }
    if form == 13 {
        return STATUS_NOT_SUPPORTED;
    }
    if result.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let src = match unsafe { source(src, src_len, false) } {
        Ok(src) => src,
        Err(status) => return status,
    };
    if let Err(status) = ascii_only(src) {
        return status;
    }
    unsafe { *result = 1 };
    STATUS_SUCCESS
}

fn check_ascii_domain(src: &[u16], flags: u32, reject_ace: bool) -> Result<(), NtStatus> {
    if flags & !(IDN_ALLOW_UNASSIGNED | IDN_USE_STD3_ASCII_RULES) != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if src.is_empty() || src.len() > MAX_IDN_UNITS {
        return Err(STATUS_INVALID_IDN_NORMALIZATION);
    }
    if src.iter().any(|&ch| ch >= 0x80) {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let logical_len = if src.last() == Some(&0) {
        src.len() - 1
    } else {
        src.len()
    };
    if logical_len == 0 || src[..logical_len].contains(&0) {
        return Err(STATUS_INVALID_IDN_NORMALIZATION);
    }
    let mut start = 0;
    for end in 0..=logical_len {
        if end != logical_len && src[end] != b'.' as u16 {
            continue;
        }
        let label = &src[start..end];
        if label.is_empty() && end != logical_len {
            return Err(STATUS_INVALID_IDN_NORMALIZATION);
        }
        if label.len() > 63 {
            return Err(STATUS_INVALID_IDN_NORMALIZATION);
        }
        if !label.is_empty() {
            if flags & IDN_USE_STD3_ASCII_RULES != 0 {
                if label[0] == b'-' as u16
                    || label[label.len() - 1] == b'-' as u16
                    || label
                        .iter()
                        .any(|&ch| !ch.is_ascii_alphanumeric_u16() && ch != b'-' as u16)
                {
                    return Err(STATUS_INVALID_IDN_NORMALIZATION);
                }
            }
            if reject_ace
                && label.len() >= 4
                && label[0].eq_ignore_ascii_case_u16(b'x')
                && label[1].eq_ignore_ascii_case_u16(b'n')
                && label[2] == b'-' as u16
                && label[3] == b'-' as u16
            {
                return Err(STATUS_NOT_SUPPORTED);
            }
        }
        start = end + 1;
    }
    Ok(())
}

trait AsciiUnit {
    fn is_ascii_alphanumeric_u16(self) -> bool;
    fn eq_ignore_ascii_case_u16(self, other: u8) -> bool;
}

impl AsciiUnit for u16 {
    fn is_ascii_alphanumeric_u16(self) -> bool {
        (b'a' as u16..=b'z' as u16).contains(&self)
            || (b'A' as u16..=b'Z' as u16).contains(&self)
            || (b'0' as u16..=b'9' as u16).contains(&self)
    }
    fn eq_ignore_ascii_case_u16(self, other: u8) -> bool {
        self == other as u16 || self == (other as char).to_ascii_uppercase() as u16
    }
}

/// The common ASCII-only IDN path. Non-ASCII labels require Nameprep normalization data and
/// Punycode; returning an error protects callers from incorrectly encoded DNS names.
unsafe fn idn_ascii(
    flags: u32,
    src: *const u16,
    src_len: i32,
    dst: *mut u16,
    dst_len: *mut i32,
    reject_ace: bool,
) -> NtStatus {
    if dst_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let src = match unsafe { source(src, src_len, true) } {
        Ok(src) => src,
        Err(status) => return status,
    };
    if let Err(status) = check_ascii_domain(src, flags, reject_ace) {
        return status;
    }
    unsafe { copy_result(src, dst, dst_len) }
}

/// `RtlIdnToNameprepUnicode(DWORD, PCWSTR, INT, PWSTR, PINT)`.
///
/// # Safety
/// Pointers follow the NT caller contract.
#[export_name = "RtlIdnToNameprepUnicode"]
pub unsafe extern "system" fn rtl_idn_to_nameprep_unicode(
    flags: u32,
    src: *const u16,
    src_len: i32,
    dst: *mut u16,
    dst_len: *mut i32,
) -> NtStatus {
    unsafe { idn_ascii(flags, src, src_len, dst, dst_len, false) }
}

/// `RtlIdnToAscii(DWORD, PCWSTR, INT, PWSTR, PINT)`.
///
/// # Safety
/// Pointers follow the NT caller contract.
#[export_name = "RtlIdnToAscii"]
pub unsafe extern "system" fn rtl_idn_to_ascii(
    flags: u32,
    src: *const u16,
    src_len: i32,
    dst: *mut u16,
    dst_len: *mut i32,
) -> NtStatus {
    unsafe { idn_ascii(flags, src, src_len, dst, dst_len, false) }
}

/// `RtlIdnToUnicode(DWORD, PCWSTR, INT, PWSTR, PINT)`.
///
/// # Safety
/// Pointers follow the NT caller contract.
#[export_name = "RtlIdnToUnicode"]
pub unsafe extern "system" fn rtl_idn_to_unicode(
    flags: u32,
    src: *const u16,
    src_len: i32,
    dst: *mut u16,
    dst_len: *mut i32,
) -> NtStatus {
    unsafe { idn_ascii(flags, src, src_len, dst, dst_len, true) }
}

#[used]
pub static UNICODE_NORMALIZATION_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// This routine is only stored in a `#[used]` static.
pub unsafe extern "C" fn export_anchor() {
    core::hint::black_box([
        rtl_normalize_string as *const () as usize,
        rtl_is_normalized_string as *const () as usize,
        rtl_idn_to_nameprep_unicode as *const () as usize,
        rtl_idn_to_ascii as *const () as usize,
        rtl_idn_to_unicode as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_normalization_respects_explicit_and_terminated_lengths() {
        let src = [b'A' as u16, b'.' as u16, 0, b'Z' as u16];
        let mut dst = [0u16; 4];
        let mut len = 2;
        assert_eq!(
            unsafe { rtl_normalize_string(1, src.as_ptr(), -1, dst.as_mut_ptr(), &mut len) },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(len, 3);
        len = 3;
        assert_eq!(
            unsafe { rtl_normalize_string(1, src.as_ptr(), -1, dst.as_mut_ptr(), &mut len) },
            STATUS_SUCCESS
        );
        assert_eq!((&dst[..3], len), (&src[..3], 3));
        let mut normalized = 0u8;
        assert_eq!(
            unsafe { rtl_is_normalized_string(1, src.as_ptr(), -1, &mut normalized) },
            STATUS_SUCCESS
        );
        assert_eq!(normalized, 1);
        len = 2;
        assert_eq!(
            unsafe { rtl_normalize_string(2, src.as_ptr(), 2, dst.as_mut_ptr(), &mut len) },
            STATUS_SUCCESS
        );
        assert_eq!(&dst[..2], &src[..2]);
    }

    #[test]
    fn normalization_rejects_unsupported_unicode_without_touching_output() {
        let composed = [0x00e9u16];
        let mut dst = [0xaaaau16];
        let mut len = 1;
        assert_eq!(
            unsafe { rtl_normalize_string(1, composed.as_ptr(), 1, dst.as_mut_ptr(), &mut len) },
            STATUS_NOT_SUPPORTED
        );
        assert_eq!((dst[0], len), (0xaaaa, 1));
        let mut normalized = 0x55u8;
        assert_eq!(
            unsafe { rtl_is_normalized_string(1, composed.as_ptr(), 1, &mut normalized) },
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(normalized, 0x55);
        assert_eq!(
            unsafe { rtl_normalize_string(0, composed.as_ptr(), 1, dst.as_mut_ptr(), &mut len) },
            STATUS_INVALID_PARAMETER
        );
        let ascii = [b'A' as u16];
        assert_eq!(
            unsafe { rtl_normalize_string(13, ascii.as_ptr(), 1, dst.as_mut_ptr(), &mut len) },
            STATUS_NOT_SUPPORTED
        );
    }

    #[test]
    fn ascii_idn_validates_labels_and_buffer_contract() {
        let domain: Vec<u16> = "example.com".encode_utf16().collect();
        let mut dst = [0u16; 16];
        let mut len = 0;
        assert_eq!(
            unsafe {
                rtl_idn_to_nameprep_unicode(
                    2,
                    domain.as_ptr(),
                    domain.len() as i32,
                    core::ptr::null_mut(),
                    &mut len,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(len, domain.len() as i32);
        len = 5;
        assert_eq!(
            unsafe {
                rtl_idn_to_ascii(
                    2,
                    domain.as_ptr(),
                    domain.len() as i32,
                    dst.as_mut_ptr(),
                    &mut len,
                )
            },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(len, domain.len() as i32);
        len = dst.len() as i32;
        assert_eq!(
            unsafe {
                rtl_idn_to_unicode(
                    2,
                    domain.as_ptr(),
                    domain.len() as i32,
                    dst.as_mut_ptr(),
                    &mut len,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(&dst[..len as usize], &domain);

        let bad = [b'-' as u16, b'a' as u16];
        assert_eq!(
            unsafe { rtl_idn_to_ascii(2, bad.as_ptr(), 2, dst.as_mut_ptr(), &mut len) },
            STATUS_INVALID_IDN_NORMALIZATION
        );
        let unicode = [0x00e9u16];
        assert_eq!(
            unsafe { rtl_idn_to_ascii(0, unicode.as_ptr(), 1, dst.as_mut_ptr(), &mut len) },
            STATUS_NOT_SUPPORTED
        );
    }
}
