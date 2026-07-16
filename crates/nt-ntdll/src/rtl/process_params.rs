//! `RtlCreateProcessParameters` — build an `RTL_USER_PROCESS_PARAMETERS` block (the process-launch
//! parameter block smss's `SmpExecuteImage` hands to `RtlCreateUserProcess`).
//!
//! Ported from ReactOS `references/reactos/sdk/lib/rtl/ppb.c` (`RtlCreateProcessParameters`,
//! `RtlpCopyParameterString`, `RtlDeNormalizeProcessParams`, `RtlNormalizeProcessParams`). The real
//! ntdll allocates ONE heap block that holds the fixed `RTL_USER_PROCESS_PARAMETERS` header followed
//! by the packed string bodies (each `UNICODE_STRING.Buffer` points inside the same block); the block
//! is returned **de-normalized** (every `Buffer` is an OFFSET from the block base, `NORMALIZED` flag
//! clear) so it can be relocated into the child's address space.
//!
//! This module is the PURE, host-tested builder: it lays out the exact same block into a `Vec<u8>`
//! (the string bodies at the same offsets, the same `MAX_PATH` current-directory reserve, the same
//! 8-byte alignment, the same trailing environment copy) and records where each `UNICODE_STRING`
//! landed. The cdylib export ([`crate::rtl::process_params`]) copies this into a heap block. Because
//! the layout math is identical, a consumer walking the block by the x64 offsets (below) recovers
//! every string. `normalize`/`denormalize` implement the pointer↔offset rebase over a live base VA.
//!
//! Category A (pure). Host-tested with I/O vectors derived from the ppb.c semantics (no ReactOS
//! apitest exists for `RtlCreateProcessParameters`).

use alloc::vec;
use alloc::vec::Vec;

use nt_ntdll_layout::RTL_USER_PROC_PARAMS_NORMALIZED;

/// `MAX_PATH` (the current-directory reserve, per ppb.c `Length += (MAX_PATH * sizeof(WCHAR))`).
pub const MAX_PATH: usize = 260;

/// `sizeof(RTL_USER_PROCESS_PARAMETERS)` on x64 (the fixed header before the packed strings).
/// Derived from the byte-exact `nt_ntdll_layout::RtlUserProcessParameters` (0xE0 = last
/// `UNICODE_STRING` `RuntimeData` + 0x10 = 0xF0).
pub const PARAMS_HEADER_SIZE: usize = 0xF0;

// --- The x64 field offsets used by the block builder + a consumer (matching the layout crate) -----

/// `Flags` (bit 0 = `RTL_USER_PROC_PARAMS_NORMALIZED`).
pub const OFF_FLAGS: usize = 0x08;
/// `CurrentDirectory.DosPath` (`UNICODE_STRING`).
pub const OFF_CURRENT_DIRECTORY: usize = 0x38;
/// `DllPath` (`UNICODE_STRING`).
pub const OFF_DLL_PATH: usize = 0x50;
/// `ImagePathName` (`UNICODE_STRING`).
pub const OFF_IMAGE_PATH_NAME: usize = 0x60;
/// `CommandLine` (`UNICODE_STRING`).
pub const OFF_COMMAND_LINE: usize = 0x70;
/// `Environment` (`PVOID`).
pub const OFF_ENVIRONMENT: usize = 0x80;
/// `WindowTitle` (`UNICODE_STRING`).
pub const OFF_WINDOW_TITLE: usize = 0xB0;
/// `DesktopInfo` (`UNICODE_STRING`).
pub const OFF_DESKTOP_INFO: usize = 0xC0;
/// `ShellInfo` (`UNICODE_STRING`).
pub const OFF_SHELL_INFO: usize = 0xD0;
/// `RuntimeData` (`UNICODE_STRING`).
pub const OFF_RUNTIME_DATA: usize = 0xE0;

/// The offset of each `UNICODE_STRING`'s `Buffer` field within its 16-byte record (Length@0,
/// MaximumLength@2, pad@4, Buffer@8).
const US_BUFFER: usize = 8;

/// The `UNICODE_STRING` field offsets that carry a `Buffer` needing normalize/denormalize, in the
/// order ppb.c walks them.
const BUFFER_STRINGS: [usize; 8] = [
    OFF_CURRENT_DIRECTORY,
    OFF_DLL_PATH,
    OFF_IMAGE_PATH_NAME,
    OFF_COMMAND_LINE,
    OFF_WINDOW_TITLE,
    OFF_DESKTOP_INFO,
    OFF_SHELL_INFO,
    OFF_RUNTIME_DATA,
];

/// An input `UNICODE_STRING` for the builder: the UTF-16 body plus an explicit `MaximumLength` (in
/// bytes) — the real API takes a `PUNICODE_STRING` whose `MaximumLength` drives the reserve for the
/// title/desktop/shell/runtime strings. `None` means "use the source length + a NUL".
#[derive(Clone, Debug, Default)]
pub struct ParamString {
    /// The UTF-16 body (no NUL). Empty for the `EmptyString` default.
    pub body: Vec<u16>,
    /// The caller's `MaximumLength` in bytes. `0` with `!is_null` → the copy uses `body.len()*2 + 2`.
    pub maximum_length: u16,
    /// `true` for the `NullString` (`{Length=0, MaximumLength=0, Buffer=NULL}`) — ppb.c substitutes it
    /// for a NULL `RuntimeData`. Distinguishes "genuine null string, no buffer" from "empty body,
    /// allocate a NUL" (both have an empty `body`).
    pub is_null: bool,
}

impl ParamString {
    /// A string from a UTF-16 body (MaximumLength = body + NUL).
    pub fn new(body: &[u16]) -> Self {
        ParamString { body: body.to_vec(), maximum_length: 0, is_null: false }
    }
    /// The `EmptyString` default (`Length=0, MaximumLength=sizeof(WCHAR)`), which ppb.c substitutes
    /// for NULL DllPath/CurrentDirectory/CommandLine/WindowTitle/DesktopInfo/ShellInfo.
    pub fn empty() -> Self {
        ParamString { body: Vec::new(), maximum_length: 2, is_null: false }
    }
    /// The `NullString` (`{0, 0, NULL}`), ppb.c's default for a NULL `RuntimeData` — no buffer.
    pub fn null_string() -> Self {
        ParamString { body: Vec::new(), maximum_length: 0, is_null: true }
    }
}

/// Round `x` up to the next multiple of `align` (the ppb.c `ALIGN(x, sizeof(PVOID))` macro).
#[inline]
fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

/// The record of where a string body landed in the built block (offset from block base + lengths),
/// for host tests + the normalize step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StringPlacement {
    /// The `UNICODE_STRING` field offset (one of the `OFF_*` above).
    pub field_offset: usize,
    /// `Length` (bytes, excludes the NUL) written into the record.
    pub length: u16,
    /// `MaximumLength` (bytes) written into the record.
    pub maximum_length: u16,
    /// The `Buffer` value as stored in the DE-normalized block (an OFFSET from the block base), or 0
    /// when `MaximumLength == 0` (real ppb.c leaves `Buffer` NULL for a zero-max string).
    pub buffer_offset: u64,
}

/// The result of building the block: the flat bytes (de-normalized, `NORMALIZED` flag clear) plus the
/// per-string placements and the environment location.
#[derive(Clone, Debug)]
pub struct BuiltParams {
    /// The flat de-normalized block (`RTL_USER_PROCESS_PARAMETERS` header + packed strings + env).
    pub block: Vec<u8>,
    /// `Length`/`MaximumLength` (equal), the header size covering the strings (NOT the env tail) —
    /// ppb.c sets both to `Length` (the pre-environment size).
    pub length: u32,
    /// The per-string placements (for tests + normalize).
    pub placements: Vec<StringPlacement>,
    /// The environment block's offset from the block base (0 if no environment was copied).
    pub environment_offset: u64,
    /// The environment block byte length (0 if none).
    pub environment_size: u64,
}

/// The inputs to [`create_process_parameters`], each already resolved (NULL substitution done by the
/// export layer, which reads the live PEB for the UserMode NULL cases).
#[derive(Clone, Debug, Default)]
pub struct ParamsInput {
    /// `ImagePathName` (required, non-empty in practice).
    pub image_path_name: ParamString,
    /// `DllPath`.
    pub dll_path: ParamString,
    /// `CurrentDirectory.DosPath`.
    pub current_directory: ParamString,
    /// `CommandLine` (ppb.c defaults it to `ImagePathName` when NULL — the export does that).
    pub command_line: ParamString,
    /// `WindowTitle`.
    pub window_title: ParamString,
    /// `DesktopInfo`.
    pub desktop_info: ParamString,
    /// `ShellInfo`.
    pub shell_info: ParamString,
    /// `RuntimeData` (defaults to the `NullString` = `{0,0,NULL}` when NULL).
    pub runtime_data: ParamString,
    /// The environment double-NUL UTF-16 block (empty → no environment copied).
    pub environment: Vec<u16>,
}

/// The per-string copy size ppb.c uses (the `Size` arg to `RtlpCopyParameterString`):
/// - CurrentDirectory: `MAX_PATH * sizeof(WCHAR)` (a fixed reserve).
/// - ImagePathName / CommandLine: `src.Length + sizeof(WCHAR)`.
/// - DllPath / WindowTitle / DesktopInfo / ShellInfo / RuntimeData: `0` → uses `src.MaximumLength`.
fn copy_size(field: usize, body_len_bytes: usize, src_max: u16) -> usize {
    match field {
        OFF_CURRENT_DIRECTORY => MAX_PATH * 2,
        OFF_IMAGE_PATH_NAME | OFF_COMMAND_LINE => body_len_bytes + 2,
        // Size == 0 → RtlpCopyParameterString uses Source->MaximumLength.
        _ => src_max as usize,
    }
}

/// `RtlCreateProcessParameters` (the pure block builder). Lays out the header + packed strings + env
/// EXACTLY as ppb.c does, returning a DE-normalized block (`Buffer` = offset-from-base, `NORMALIZED`
/// clear). The export copies `block` onto the process heap; `normalize(base_va)` rebases the offsets
/// to absolute VAs if a consumer needs them.
pub fn create_process_parameters(input: &ParamsInput) -> BuiltParams {
    // --- 1. Compute the total length exactly as ppb.c (Length += ALIGN(...) per string). -----------
    // Order + Size semantics mirror ppb.c precisely.
    let strings: [(usize, &ParamString); 8] = [
        (OFF_CURRENT_DIRECTORY, &input.current_directory),
        (OFF_DLL_PATH, &input.dll_path),
        (OFF_IMAGE_PATH_NAME, &input.image_path_name),
        (OFF_COMMAND_LINE, &input.command_line),
        (OFF_WINDOW_TITLE, &input.window_title),
        (OFF_DESKTOP_INFO, &input.desktop_info),
        (OFF_SHELL_INFO, &input.shell_info),
        (OFF_RUNTIME_DATA, &input.runtime_data),
    ];

    // Length starts at sizeof(header) + MAX_PATH*WCHAR (the current-dir reserve counted BEFORE the
    // per-string loop in ppb.c, which then also aligns each string). NOTE ppb.c adds the MAX_PATH
    // reserve to Length up front AND then adds ALIGN(CurrentDirectory->MaximumLength?) — no: it adds
    // MAX_PATH once, and the current-directory copy uses MAX_PATH as its Size. It does NOT add a
    // separate aligned current-dir string. It DOES add the aligned sizes for the OTHER 7 strings.
    let mut length = PARAMS_HEADER_SIZE + MAX_PATH * 2;
    // ppb.c adds: DllPath.MaximumLength, ImagePathName.Length+WCHAR, CommandLine.Length+WCHAR,
    // WindowTitle.MaximumLength, DesktopInfo.MaximumLength, ShellInfo.MaximumLength,
    // RuntimeData.MaximumLength — each ALIGN'd to sizeof(PVOID). (CurrentDirectory is the MAX_PATH
    // reserve already added.)
    for &(field, s) in strings.iter() {
        if field == OFF_CURRENT_DIRECTORY {
            continue;
        }
        let body_bytes = s.body.len() * 2;
        let add = match field {
            OFF_IMAGE_PATH_NAME | OFF_COMMAND_LINE => body_bytes + 2,
            _ => effective_max(s) as usize,
        };
        length += align_up(add, 8);
    }
    let length = length as u32;

    // --- 2. Environment size (ppb.c walks the double-NUL block). ----------------------------------
    let env_size_bytes = if input.environment.is_empty() {
        0usize
    } else {
        // The block already includes its terminating double-NUL; its byte length is len*2.
        input.environment.len() * 2
    };

    let allocation = length as usize + env_size_bytes;
    let mut block = vec![0u8; allocation];

    // --- 3. Header fixed fields. -------------------------------------------------------------------
    write_u32(&mut block, 0x00, length); // MaximumLength
    write_u32(&mut block, 0x04, length); // Length
    // ppb.c sets Flags = NORMALIZED here, then DeNormalizes at the end → NORMALIZED clear. We build
    // de-normalized directly, so Flags is left clear (0). (The export/caller sets debug/reserve bits.)
    write_u32(&mut block, OFF_FLAGS, 0);

    // --- 4. Pack the strings (RtlpCopyParameterString), Dest starts after the header. --------------
    let mut dest = PARAMS_HEADER_SIZE; // byte offset of the next string body
    let mut placements = Vec::with_capacity(8);
    for &(field, s) in strings.iter() {
        let body_bytes = s.body.len() * 2;
        let src_max = effective_max(s);
        let size = copy_size(field, body_bytes, src_max);
        // Destination->Length = Source->Length; MaximumLength = Size ? Size : Source->MaximumLength.
        let dst_len = body_bytes as u16;
        let dst_max = if size != 0 { size as u16 } else { src_max };
        let buffer_offset = if dst_max != 0 {
            // Copy the body + NUL-terminate at Length/2.
            let start = dest;
            for (i, &u) in s.body.iter().enumerate() {
                write_u16(&mut block, start + i * 2, u);
            }
            // Destination->Buffer[Length/sizeof(WCHAR)] = 0; (already zero-filled, explicit for clarity)
            write_u16(&mut block, start + body_bytes, 0);
            start as u64
        } else {
            0
        };
        write_string_record(&mut block, field, dst_len, dst_max, buffer_offset);
        placements.push(StringPlacement {
            field_offset: field,
            length: dst_len,
            maximum_length: dst_max,
            buffer_offset,
        });
        // *Ptr += MaximumLength/sizeof(WCHAR); *Ptr = ALIGN_UP(*Ptr, sizeof(PVOID));
        dest += dst_max as usize;
        dest = align_up(dest, 8);

        // The current-directory trailing-backslash fix-up (ppb.c lines 164-174).
        if field == OFF_CURRENT_DIRECTORY && dst_len > 0 {
            let n = (dst_len / 2) as usize;
            let last = read_u16(&block, buffer_offset as usize + (n - 1) * 2);
            if last != b'\\' as u16 {
                write_u16(&mut block, buffer_offset as usize + n * 2, b'\\' as u16);
                write_u16(&mut block, buffer_offset as usize + (n + 1) * 2, 0);
                let new_len = dst_len + 2;
                // Update the record's Length.
                write_u16(&mut block, field, new_len);
                if let Some(p) = placements.last_mut() {
                    p.length = new_len;
                }
            }
        }
    }

    // --- 5. Environment copy (Dest is now aligned past the last string). --------------------------
    let (environment_offset, environment_size) = if env_size_bytes != 0 {
        let start = dest;
        for (i, &u) in input.environment.iter().enumerate() {
            write_u16(&mut block, start + i * 2, u);
        }
        write_u64(&mut block, OFF_ENVIRONMENT, start as u64);
        (start as u64, env_size_bytes as u64)
    } else {
        (0, 0)
    };

    BuiltParams { block, length, placements, environment_offset, environment_size }
}

/// The effective source `MaximumLength` (bytes): 0 for a NullString, the caller's if set, else
/// body + NUL.
fn effective_max(s: &ParamString) -> u16 {
    if s.is_null {
        0
    } else if s.maximum_length != 0 {
        s.maximum_length
    } else {
        (s.body.len() * 2 + 2) as u16
    }
}

/// Write a `UNICODE_STRING` record (Length, MaximumLength, pad, Buffer) at `field`.
fn write_string_record(block: &mut [u8], field: usize, length: u16, max: u16, buffer: u64) {
    write_u16(block, field, length);
    write_u16(block, field + 2, max);
    // pad @ +4 stays zero.
    write_u64(block, field + US_BUFFER, buffer);
}

/// `RtlNormalizeProcessParams` — rebase each non-null string `Buffer` offset to `base + offset`,
/// setting the `NORMALIZED` flag. Idempotent (no-op if already normalized). Operates on the flat
/// block in place.
///
/// ★ The `Environment` field (`OFF_ENVIRONMENT`) is DELIBERATELY NOT rebased here — matching ReactOS
/// `RtlNormalizeProcessParams`/`RtlDeNormalizeProcessParams` (sdk/lib/rtl/ppb.c), whose
/// `NORMALIZE`/`DENORMALIZE` macros cover ONLY the 8 `UNICODE_STRING` Buffers. In real ntdll
/// `Environment` is ALWAYS a live VA (`RtlCreateProcessParameters` sets `Param->Environment = Dest`,
/// a VA, and denormalize leaves it untouched). Rebasing it here corrupted the field: a subsequently-
/// denormalized block carried `Environment = offset` (e.g. `0x668`), which `RtlpInitEnvironment`
/// then dereferenced as a VA → `#PF cr2=0x668`.
pub fn normalize(block: &mut [u8], base: u64) {
    let flags = read_u32(block, OFF_FLAGS);
    if flags & RTL_USER_PROC_PARAMS_NORMALIZED != 0 {
        return;
    }
    for &field in BUFFER_STRINGS.iter() {
        let b = read_u64(block, field + US_BUFFER);
        if b != 0 {
            write_u64(block, field + US_BUFFER, b + base);
        }
    }
    write_u32(block, OFF_FLAGS, flags | RTL_USER_PROC_PARAMS_NORMALIZED);
}

/// `RtlDeNormalizeProcessParams` — the inverse of [`normalize`]: subtract `base` from each non-null
/// string `Buffer` and clear the `NORMALIZED` flag. No-op if already de-normalized. Like
/// [`normalize`], the `Environment` field is NOT rebased (ReactOS ppb.c parity — see [`normalize`]).
pub fn denormalize(block: &mut [u8], base: u64) {
    let flags = read_u32(block, OFF_FLAGS);
    if flags & RTL_USER_PROC_PARAMS_NORMALIZED == 0 {
        return;
    }
    for &field in BUFFER_STRINGS.iter() {
        let b = read_u64(block, field + US_BUFFER);
        if b != 0 {
            write_u64(block, field + US_BUFFER, b - base);
        }
    }
    write_u32(block, OFF_FLAGS, flags & !RTL_USER_PROC_PARAMS_NORMALIZED);
}

// --- Little-endian block accessors ----------------------------------------------------------------

fn write_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn read_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn u(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }
    fn env_block(vars: &[&str]) -> Vec<u16> {
        let mut b = Vec::new();
        for v in vars {
            b.extend(v.encode_utf16());
            b.push(0);
        }
        b.push(0);
        b
    }

    /// Read a UNICODE_STRING record (Length, MaximumLength, Buffer-offset) at `field` from a
    /// de-normalized block, returning the decoded string body.
    fn read_string(block: &[u8], field: usize) -> (u16, u16, u64, std::string::String) {
        let len = read_u16(block, field);
        let max = read_u16(block, field + 2);
        let buf = read_u64(block, field + US_BUFFER);
        let mut units = Vec::new();
        if buf != 0 {
            for i in 0..(len / 2) as usize {
                units.push(read_u16(block, buf as usize + i * 2));
            }
        }
        (len, max, buf, std::string::String::from_utf16(&units).unwrap())
    }

    #[test]
    fn image_and_command_line_placed() {
        let mut input = ParamsInput::default();
        input.image_path_name = ParamString::new(&u("\\??\\C:\\Windows\\system32\\csrss.exe"));
        // ppb.c: CommandLine NULL → defaults to ImagePathName (done by the export; simulate here).
        input.command_line = input.image_path_name.clone();
        input.dll_path = ParamString::empty();
        input.current_directory = ParamString::empty();
        input.window_title = ParamString::empty();
        input.desktop_info = ParamString::empty();
        input.shell_info = ParamString::empty();
        input.runtime_data = ParamString::null_string();

        let built = create_process_parameters(&input);

        // Header MaximumLength == Length == the header+strings length.
        assert_eq!(read_u32(&built.block, 0x00), built.length);
        assert_eq!(read_u32(&built.block, 0x04), built.length);
        // NORMALIZED flag is clear (de-normalized block).
        assert_eq!(read_u32(&built.block, OFF_FLAGS) & RTL_USER_PROC_PARAMS_NORMALIZED, 0);

        let (ilen, imax, ibuf, ipath) = read_string(&built.block, OFF_IMAGE_PATH_NAME);
        assert_eq!(ipath, "\\??\\C:\\Windows\\system32\\csrss.exe");
        assert_eq!(ilen as usize, "\\??\\C:\\Windows\\system32\\csrss.exe".len() * 2);
        // ImagePathName MaximumLength = Length + WCHAR.
        assert_eq!(imax, ilen + 2);
        // Buffer offset lands inside the block, past the header.
        assert!(ibuf >= PARAMS_HEADER_SIZE as u64);
        assert!((ibuf as usize) < built.block.len());
        // A NUL terminator follows the body.
        assert_eq!(read_u16(&built.block, ibuf as usize + ilen as usize), 0);

        let (_, _, _, cline) = read_string(&built.block, OFF_COMMAND_LINE);
        assert_eq!(cline, "\\??\\C:\\Windows\\system32\\csrss.exe");
    }

    #[test]
    fn current_directory_gets_trailing_backslash() {
        let mut input = ParamsInput::default();
        input.image_path_name = ParamString::new(&u("x"));
        input.command_line = ParamString::empty();
        input.dll_path = ParamString::empty();
        input.current_directory = ParamString::new(&u("C:\\Windows\\system32")); // no trailing \
        input.window_title = ParamString::empty();
        input.desktop_info = ParamString::empty();
        input.shell_info = ParamString::empty();
        input.runtime_data = ParamString::null_string();

        let built = create_process_parameters(&input);
        let (len, max, _buf, path) = read_string(&built.block, OFF_CURRENT_DIRECTORY);
        assert_eq!(path, "C:\\Windows\\system32\\"); // trailing backslash appended
        assert_eq!(len as usize, path.len() * 2);
        // MaximumLength is the MAX_PATH reserve.
        assert_eq!(max as usize, MAX_PATH * 2);
    }

    #[test]
    fn empty_strings_get_a_buffer_and_nul() {
        // ppb.c EmptyString has MaximumLength = sizeof(WCHAR), so a Buffer IS allocated (Length 0).
        let mut input = ParamsInput::default();
        input.image_path_name = ParamString::new(&u("a"));
        input.command_line = ParamString::empty();
        input.dll_path = ParamString::empty();
        input.current_directory = ParamString::empty();
        input.window_title = ParamString::empty();
        input.desktop_info = ParamString::empty();
        input.shell_info = ParamString::empty();
        input.runtime_data = ParamString::null_string();

        let built = create_process_parameters(&input);
        let (wlen, wmax, wbuf, _) = read_string(&built.block, OFF_WINDOW_TITLE);
        assert_eq!(wlen, 0);
        assert_eq!(wmax, 2); // sizeof(WCHAR)
        assert_ne!(wbuf, 0); // a buffer was allocated
        // RuntimeData NullString → MaximumLength 0 → Buffer NULL.
        let (rlen, rmax, rbuf, _) = read_string(&built.block, OFF_RUNTIME_DATA);
        assert_eq!(rlen, 0);
        assert_eq!(rmax, 0);
        assert_eq!(rbuf, 0);
    }

    #[test]
    fn environment_copied_after_strings() {
        let mut input = ParamsInput::default();
        input.image_path_name = ParamString::new(&u("a"));
        input.command_line = ParamString::empty();
        input.dll_path = ParamString::empty();
        input.current_directory = ParamString::empty();
        input.window_title = ParamString::empty();
        input.desktop_info = ParamString::empty();
        input.shell_info = ParamString::empty();
        input.runtime_data = ParamString::null_string();
        input.environment = env_block(&["Path=C:\\Windows", "TEMP=C:\\Temp"]);

        let built = create_process_parameters(&input);
        assert_ne!(built.environment_offset, 0);
        assert_eq!(built.environment_size as usize, input.environment.len() * 2);
        // The environment lives at/after Length (past the header+strings).
        assert!(built.environment_offset >= built.length as u64);
        // The Environment pointer field holds the offset.
        assert_eq!(read_u64(&built.block, OFF_ENVIRONMENT), built.environment_offset);
        // Round-trip the first env var from the block.
        let start = built.environment_offset as usize;
        let mut units = Vec::new();
        let mut i = start;
        while read_u16(&built.block, i) != 0 {
            units.push(read_u16(&built.block, i));
            i += 2;
        }
        assert_eq!(std::string::String::from_utf16(&units).unwrap(), "Path=C:\\Windows");
    }

    #[test]
    fn normalize_denormalize_roundtrip() {
        let mut input = ParamsInput::default();
        input.image_path_name = ParamString::new(&u("\\??\\C:\\csrss.exe"));
        input.command_line = input.image_path_name.clone();
        input.dll_path = ParamString::empty();
        input.current_directory = ParamString::empty();
        input.window_title = ParamString::empty();
        input.desktop_info = ParamString::empty();
        input.shell_info = ParamString::empty();
        input.runtime_data = ParamString::null_string();
        input.environment = env_block(&["A=1"]);

        let mut built = create_process_parameters(&input);
        let img_off = read_u64(&built.block, OFF_IMAGE_PATH_NAME + US_BUFFER);
        let env_off = read_u64(&built.block, OFF_ENVIRONMENT);
        assert!(img_off != 0);

        const BASE: u64 = 0x0000_0002_0010_0000;
        normalize(&mut built.block, BASE);
        assert_eq!(read_u32(&built.block, OFF_FLAGS) & RTL_USER_PROC_PARAMS_NORMALIZED,
                   RTL_USER_PROC_PARAMS_NORMALIZED);
        assert_eq!(read_u64(&built.block, OFF_IMAGE_PATH_NAME + US_BUFFER), img_off + BASE);
        // ★ ReactOS ppb.c parity: normalize/denormalize NEVER touch `Environment` — it stays exactly
        // as the pure builder left it (an offset here; a live VA once the export fixes it up). This is
        // the root fix for the `#PF cr2=0x668` (a denormalized `Environment` offset deref'd as a VA).
        assert_eq!(read_u64(&built.block, OFF_ENVIRONMENT), env_off);
        // Idempotent.
        normalize(&mut built.block, BASE);
        assert_eq!(read_u64(&built.block, OFF_IMAGE_PATH_NAME + US_BUFFER), img_off + BASE);

        denormalize(&mut built.block, BASE);
        assert_eq!(read_u32(&built.block, OFF_FLAGS) & RTL_USER_PROC_PARAMS_NORMALIZED, 0);
        assert_eq!(read_u64(&built.block, OFF_IMAGE_PATH_NAME + US_BUFFER), img_off);
        // Environment untouched across the whole round-trip.
        assert_eq!(read_u64(&built.block, OFF_ENVIRONMENT), env_off);
        // A NULL buffer (RuntimeData) stays NULL through both.
        assert_eq!(read_u64(&built.block, OFF_RUNTIME_DATA + US_BUFFER), 0);
    }

    #[test]
    fn offsets_match_the_layout_crate() {
        // The builder's OFF_* constants MUST equal the byte-exact `nt_ntdll_layout` struct offsets,
        // or a consumer reading the block via the layout type recovers garbage. Pin them together.
        use core::mem::offset_of;
        use nt_ntdll_layout::RtlUserProcessParameters as P;
        assert_eq!(OFF_FLAGS, offset_of!(P, flags));
        assert_eq!(OFF_CURRENT_DIRECTORY, offset_of!(P, current_directory_dospath));
        assert_eq!(OFF_DLL_PATH, offset_of!(P, dll_path));
        assert_eq!(OFF_IMAGE_PATH_NAME, offset_of!(P, image_path_name));
        assert_eq!(OFF_COMMAND_LINE, offset_of!(P, command_line));
        assert_eq!(OFF_ENVIRONMENT, offset_of!(P, environment));
        assert_eq!(OFF_WINDOW_TITLE, offset_of!(P, window_title));
        assert_eq!(OFF_DESKTOP_INFO, offset_of!(P, desktop_info));
        assert_eq!(OFF_SHELL_INFO, offset_of!(P, shell_info));
        assert_eq!(OFF_RUNTIME_DATA, offset_of!(P, runtime_data));
        // The header size covers the whole fixed struct.
        assert_eq!(PARAMS_HEADER_SIZE, core::mem::size_of::<P>());
    }

    #[test]
    fn all_buffer_offsets_within_block() {
        // Every non-null Buffer offset (+ its Length body) must fit inside the allocation — the ppb.c
        // ASSERT that Dest never runs past MaximumLength.
        let mut input = ParamsInput::default();
        input.image_path_name = ParamString::new(&u("\\??\\C:\\Windows\\explorer.exe"));
        input.command_line = ParamString::new(&u("\\??\\C:\\Windows\\explorer.exe -flag"));
        input.dll_path = ParamString::new(&u("C:\\Windows\\system32"));
        input.current_directory = ParamString::new(&u("C:\\Windows"));
        input.window_title = ParamString::new(&u("Title"));
        input.desktop_info = ParamString::new(&u("WinSta0\\Default"));
        input.shell_info = ParamString::empty();
        input.runtime_data = ParamString::null_string();
        input.environment = env_block(&["Path=C:\\Windows;C:\\Windows\\system32"]);

        let built = create_process_parameters(&input);
        for p in &built.placements {
            if p.buffer_offset != 0 {
                let end = p.buffer_offset as usize + p.maximum_length as usize;
                assert!(end <= built.block.len(), "buffer for field {:#x} overruns", p.field_offset);
            }
        }
        // The header+string length must be <= the total (env is the tail).
        assert!(built.length as usize <= built.block.len());
    }
}
