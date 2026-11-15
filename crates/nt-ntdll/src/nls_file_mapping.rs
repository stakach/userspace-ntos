//! NLS file mapping ownership sequences over installed files.
//!
//! Wine's ntdll maps `locale.nls` as a read-only data Section and leaves each returned view
//! owned by the process. The File and Section handles are closed after the view is established.

pub const LOCALE_NLS_PATH: &str = "\\SystemRoot\\System32\\locale.nls";
pub const SORTDEFAULT_NLS_PATH: &str = "\\SystemRoot\\System32\\sortdefault.nls";
const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xc000_007b;
const STATUS_INVALID_PARAMETER_1: u32 = 0xc000_00ef;
const MAX_LOCALE_MAPPING_SIZE: u64 = 64 * 1024 * 1024;
const NLS_LOCALE_MAGIC: u32 = 0x5344_534e;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NlsFileMapping {
    pub address: u64,
    pub lcid: u32,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NlsSectionMapping {
    pub address: u64,
    pub size: u64,
}

pub trait NlsFileMappingOps {
    fn system_lcid(&mut self) -> Result<u32, u32>;
    fn open_file(&mut self, path: &str) -> Result<u64, u32>;
    fn create_readonly_section(&mut self, file: u64) -> Result<u64, u32>;
    fn map_readonly_section(&mut self, section: u64) -> Result<(u64, u64), u32>;
    fn mapped_bytes(&self, address: u64, size: u64) -> Option<&[u8]>;
    fn unmap_view(&mut self, address: u64);
    fn close(&mut self, handle: u64);
}

fn valid_locale_mapping(bytes: &[u8]) -> bool {
    let Some(offset) = bytes.get(16..20) else {
        return false;
    };
    let offset = u32::from_le_bytes(offset.try_into().unwrap()) as usize;
    let Some(locale_header) = bytes.get(offset..offset.saturating_add(16)) else {
        return false;
    };
    u32::from_le_bytes(locale_header[0..4].try_into().unwrap()) == 8
        && u32::from_le_bytes(locale_header[12..16].try_into().unwrap()) == NLS_LOCALE_MAGIC
}

fn valid_sortdefault_mapping(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..16) else { return false };
    let mut previous = 15usize;
    for field in header.chunks_exact(4) {
        let offset = u32::from_le_bytes(field.try_into().unwrap()) as usize;
        if offset <= previous || offset > bytes.len().saturating_sub(8) {
            return false;
        }
        previous = offset;
    }
    true
}

fn map_checked_file(
    ops: &mut impl NlsFileMappingOps,
    path: &str,
    minimum_size: u64,
    valid_bytes: impl Fn(&[u8]) -> bool,
) -> Result<NlsSectionMapping, u32> {
    let file = ops.open_file(path)?;
    let section = match ops.create_readonly_section(file) {
        Ok(section) => section,
        Err(status) => {
            ops.close(file);
            return Err(status);
        }
    };
    ops.close(file);
    let view = ops.map_readonly_section(section);
    ops.close(section);
    let (address, size) = view?;
    let valid = address != 0
        && size >= minimum_size
        && size <= MAX_LOCALE_MAPPING_SIZE
        && ops.mapped_bytes(address, size).is_some_and(valid_bytes);
    if !valid {
        if address != 0 {
            ops.unmap_view(address);
        }
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    Ok(NlsSectionMapping { address, size })
}

/// Return a process-owned, verified mapping of the exact installed locale file.
/// Failed publication withdraws its view; returned views survive File/Section handle closure.
pub fn initialize_nls_files(ops: &mut impl NlsFileMappingOps) -> Result<NlsFileMapping, u32> {
    let lcid = ops.system_lcid()?;
    let view = map_checked_file(ops, LOCALE_NLS_PATH, 48, valid_locale_mapping)?;
    Ok(NlsFileMapping { address: view.address, lcid, size: view.size })
}

/// `NLS_SECTION_*` section types (`winternl.h`).
const NLS_SECTION_SORTKEYS: u32 = 9;
const NLS_SECTION_CASEMAP: u32 = 10;
const NLS_SECTION_CODEPAGE: u32 = 11;
const NLS_SECTION_NORMALIZE: u32 = 12;
const STATUS_UNSUCCESSFUL: u32 = 0xc000_0001;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;

/// A single- or double-byte code page file starts with a 13-word header whose second word is
/// the code page it describes (`NLS_FILE_HEADER`, read by `RtlInitCodePageTable`).
fn valid_code_page_mapping(bytes: &[u8], code_page: u16) -> bool {
    bytes.len() >= 26
        && u16::from_le_bytes([bytes[0], bytes[1]]) == 13
        && u16::from_le_bytes([bytes[2], bytes[3]]) == code_page
}

/// Map the installed NLS data file behind one `NtGetNlsSectionPtr` request, as Wine's ntdll
/// does (`dlls/ntdll/unix/env.c`): the sort keys, the case map, a code page (`c_<id>.nls`) or
/// a normalization form. An unsupported request fails before any file or section effect.
pub fn get_nls_section_ptr(
    ops: &mut impl NlsFileMappingOps,
    section_type: u32,
    id: u32,
) -> Result<NlsSectionMapping, u32> {
    use core::fmt::Write;
    let mut path = nt_printf::record::RecordBuffer::<64>::new();
    path.push_bytes(b"\\SystemRoot\\System32\\");
    let mut code_page = None;
    match section_type {
        NLS_SECTION_SORTKEYS if id == 0 => {
            return map_checked_file(ops, SORTDEFAULT_NLS_PATH, 16, valid_sortdefault_mapping);
        }
        NLS_SECTION_SORTKEYS => return Err(STATUS_INVALID_PARAMETER_1),
        NLS_SECTION_CASEMAP if id == 0 => {
            path.push_bytes(b"l_intl.nls");
        }
        NLS_SECTION_CASEMAP => return Err(STATUS_UNSUCCESSFUL),
        NLS_SECTION_CODEPAGE => {
            // The file header holds the code page in 16 bits; a wider identifier names no file.
            code_page = Some(u16::try_from(id).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?);
            let _ = core::write!(&mut path, "c_{id:03}.nls");
        }
        NLS_SECTION_NORMALIZE => {
            path.push_bytes(match id {
                1 => b"normnfc.nls",   // NormalizationC
                2 => b"normnfd.nls",   // NormalizationD
                5 => b"normnfkc.nls",  // NormalizationKC
                6 => b"normnfkd.nls",  // NormalizationKD
                13 => b"normidna.nls", // IDNA
                _ => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
            });
        }
        _ => return Err(STATUS_INVALID_PARAMETER_1),
    }
    let path = core::str::from_utf8(path.bytes()).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    map_checked_file(ops, path, 16, |bytes| {
        code_page.is_none_or(|code_page| valid_code_page_mapping(bytes, code_page))
    })
}

#[cfg(target_arch = "x86_64")]
struct NativeNlsOps;

#[cfg(target_arch = "x86_64")]
impl NlsFileMappingOps for NativeNlsOps {
    fn system_lcid(&mut self) -> Result<u32, u32> {
        let mut lcid = 0u32;
        let status = unsafe {
            crate::trap_stubs::nt_query_default_locale(0, (&mut lcid as *mut u32) as u64) as u32
        };
        if (status as i32) < 0 { Err(status) } else { Ok(lcid) }
    }

    fn open_file(&mut self, path: &str) -> Result<u64, u32> {
        use nt_ntdll_layout::{ObjectAttributes, UnicodeString};
        let mut name = [0u16; 64];
        if path.len() >= name.len() || !path.is_ascii() {
            return Err(0xc000_0033);
        }
        for (dst, byte) in name.iter_mut().zip(path.bytes()) {
            *dst = u16::from(byte);
        }
        let mut unicode = UnicodeString::default();
        unicode.length = (path.len() * 2) as u16;
        unicode.maximum_length = ((path.len() + 1) * 2) as u16;
        unicode.buffer = name.as_ptr() as u64;
        let mut attributes = ObjectAttributes::default();
        attributes.length = core::mem::size_of::<ObjectAttributes>() as u32;
        attributes.object_name = (&unicode as *const UnicodeString) as u64;
        attributes.attributes = 0x40; // OBJ_CASE_INSENSITIVE
        let mut handle = 0u64;
        let mut iosb = [0u64; 2];
        let status = unsafe {
            crate::trap_stubs::nt_open_file(
                (&mut handle as *mut u64) as u64,
                0x0012_0089, // FILE_GENERIC_READ
                (&attributes as *const ObjectAttributes) as u64,
                iosb.as_mut_ptr() as u64,
                0x7, // share read/write/delete
                0x20, // FILE_SYNCHRONOUS_IO_NONALERT
            ) as u32
        };
        if (status as i32) < 0 {
            Err(status)
        } else if handle == 0 {
            Err(0xc000_0008)
        } else {
            Ok(handle)
        }
    }

    fn create_readonly_section(&mut self, file: u64) -> Result<u64, u32> {
        let mut section = 0u64;
        let status = unsafe {
            crate::trap_stubs::nt_create_section(
                (&mut section as *mut u64) as u64,
                0x4, // SECTION_MAP_READ
                0,
                0,
                0x2, // PAGE_READONLY
                0x0800_0000, // SEC_COMMIT
                file,
            ) as u32
        };
        if (status as i32) < 0 {
            Err(status)
        } else if section == 0 {
            Err(0xc000_0008)
        } else {
            Ok(section)
        }
    }

    fn map_readonly_section(&mut self, section: u64) -> Result<(u64, u64), u32> {
        let mut address = 0u64;
        let mut size = 0u64;
        let status = unsafe {
            crate::trap_stubs::nt_map_view_of_section(
                section,
                u64::MAX, // current process
                (&mut address as *mut u64) as u64,
                0,
                0,
                0,
                (&mut size as *mut u64) as u64,
                1, // ViewShare
                0,
                0x2, // PAGE_READONLY
            ) as u32
        };
        if (status as i32) < 0 { Err(status) } else { Ok((address, size)) }
    }

    fn mapped_bytes(&self, address: u64, size: u64) -> Option<&[u8]> {
        let size = usize::try_from(size).ok()?;
        if address == 0 || size < 16 || size > MAX_LOCALE_MAPPING_SIZE as usize {
            return None;
        }
        Some(unsafe { core::slice::from_raw_parts(address as *const u8, size) })
    }

    fn unmap_view(&mut self, address: u64) {
        let _ = unsafe { crate::trap_stubs::nt_unmap_view_of_section(u64::MAX, address) };
    }

    fn close(&mut self, handle: u64) {
        let _ = unsafe { crate::trap_stubs::nt_close(handle) };
    }
}

/// The exported `NtInitializeNlsFiles` user-mode wrapper. Wine keeps this operation in ntdll:
/// ordinary file/Section services own every effect and the returned view has process lifetime.
#[cfg(target_arch = "x86_64")]
pub unsafe fn initialize_native(address: u64, lcid: u64, size: u64) -> u64 {
    if address == 0 || lcid == 0 || size == 0 {
        return 0xc000_000d;
    }
    let mapping = match initialize_nls_files(&mut NativeNlsOps) {
        Ok(mapping) => mapping,
        Err(status) => return u64::from(status),
    };
    unsafe {
        (address as *mut u64).write(mapping.address);
        (lcid as *mut u32).write(mapping.lcid);
        (size as *mut i64).write(mapping.size as i64);
    }
    0
}

/// The exported `NtGetNlsSectionPtr` user-mode wrapper over the installed NLS data files.
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_section_native(
    section_type: u64,
    id: u64,
    _unknown: u64,
    address: u64,
    size: u64,
) -> u64 {
    if address == 0 || size == 0 {
        return 0xc000_000d;
    }
    let section_type = match u32::try_from(section_type) {
        Ok(value) => value,
        Err(_) => return u64::from(STATUS_INVALID_PARAMETER_1),
    };
    let id = match u32::try_from(id) {
        Ok(value) => value,
        Err(_) => return u64::from(STATUS_INVALID_PARAMETER_1),
    };
    let mapping = match get_nls_section_ptr(&mut NativeNlsOps, section_type, id) {
        Ok(mapping) => mapping,
        Err(status) => return u64::from(status),
    };
    unsafe {
        (address as *mut u64).write(mapping.address);
        (size as *mut u64).write(mapping.size);
    }
    0
}
