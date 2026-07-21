//! `RTL_ATOM_TABLE` primitives as raw-memory operations (the `Rtl*AtomTable` ntoskrnl exports).
//!
//! win32k's window-class subsystem stores class-name atoms in a global atom table (`gAtomTable`,
//! created by `InitSessionImpl` → `RtlCreateAtomTable(37, &gAtomTable)`, ReactOS
//! win32ss/user/ntuser/session.c:20) and per-window-station atom tables (winsta.c:514). Class
//! registration (`IntCreateClass` → `IntRegisterClassAtom` → `RtlAddAtomToAtomTable`) and lookup
//! (`IntGetAndReferenceClass` → `IntGetClassAtom` → `IntGetAtomFromStringOrAtom` →
//! `RtlLookupAtomInAtomTable`) both go through these functions. Stubbing them to no-ops left
//! `gAtomTable == NULL`, so the string system classes (e.g. "ScrollBar") in
//! `UserRegisterSystemClasses` null-deref inside `RtlpLockAtomTable(NULL)` — the whole system-class
//! registration never completes, so `IntGetAndReferenceClass(WC_DESKTOP)` finds no class and
//! `IntCreateDesktop` cannot build the desktop window.
//!
//! win32k treats `PRTL_ATOM_TABLE` as an OPAQUE handle (it never inspects the internals — only the
//! `RTL_ATOM` values these functions hand back), so this is a self-contained raw-pointer table over
//! a caller-provided arena (mirroring [`rtl_bitmap`](crate::rtl_bitmap) /
//! [`session_section`](crate::session_section)): the host trampoline pool-allocates the arena and
//! passes it to [`create`]; every other function takes the opaque table pointer [`create`] returns.
//! Reused by every hosted binary that needs an atom table.
//!
//! ## Semantics (match ReactOS sdk/lib/rtl/atom.c)
//! - **Integer atoms** (`RtlpCheckIntegerAtom`): a name pointer whose high 16 bits are zero is a
//!   `MAKEINTATOM` value — the atom IS the low 16 bits (0 → 0xC000), returned WITHOUT touching the
//!   table. A `"#<decimal>"` string names integer atom `<decimal> & 0xFFFF`. Integer atoms are
//!   never stored.
//! - **String atoms** are stored case-insensitively; dynamic atoms are minted from 0xC000 upward.
//!   Re-adding an existing name bumps its reference count; deleting decrements and frees at zero.
//!   Pinned atoms are never ref-counted or deleted.

use alloc::vec;
use alloc::vec::Vec;

/// NTSTATUS values these functions return (subset used by the atom table).
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    /// `STATUS_WAS_LOCKED` — NOT a failure code (returned when deleting a pinned atom).
    pub const WAS_LOCKED: u32 = 0x0000_0001;
    pub const INVALID_HANDLE: u32 = 0xC000_0008;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const NO_MEMORY: u32 = 0xC000_0017;
    pub const INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    pub const OBJECT_NAME_INVALID: u32 = 0xC000_0033;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub const BUFFER_TOO_SMALL: u32 = 0xC000_0023;
}

/// `RTL_ATOM_IS_PINNED`.
const FLAG_PINNED: u16 = 0x0001;
/// First dynamically-assigned atom value (Windows: string atoms start at 0xC000).
const FIRST_DYNAMIC_ATOM: u16 = 0xC000;
/// Maximum characters stored per atom name (Windows `RTL_MAXIMUM_ATOM_LENGTH` is 255; the atom
/// table entry stores an inline copy — names longer than this are rejected `OBJECT_NAME_INVALID`).
pub const NAME_CAP: usize = 255;

/// Table header field offsets.
mod hdr {
    /// Magic marking an initialized table (`'motA'`, matching ReactOS `Table->Signature`).
    pub const SIGNATURE: usize = 0x00;
    /// Number of entry slots the arena backs.
    pub const CAPACITY: usize = 0x04;
    /// Number of occupied slots.
    pub const COUNT: usize = 0x08;
    /// Next dynamic atom value to hand out.
    pub const NEXT_ATOM: usize = 0x0C;
    /// Total header size; entry array starts here.
    pub const SIZE: usize = 0x10;
}
const SIGNATURE_MAGIC: u32 = 0x416F_746D; // 'motA' little-endian bytes m,t,o,A

/// Per-atom entry field offsets. Entry size is [`ENTRY_SIZE`].
mod ent {
    /// Atom value (0 = free slot).
    pub const ATOM: usize = 0x00;
    /// Reference count.
    pub const REF: usize = 0x02;
    /// Flags ([`super::FLAG_PINNED`]).
    pub const FLAGS: usize = 0x04;
    /// Name length in characters.
    pub const NAME_LEN: usize = 0x06;
    /// Inline UTF-16 name buffer.
    pub const NAME: usize = 0x08;
}
/// Size of one atom entry: header (8 bytes) + inline name buffer + terminating null.
pub const ENTRY_SIZE: usize = ent::NAME + (NAME_CAP + 1) * 2;

/// An allocation-backed atom table whose address remains stable for its lifetime. This is the
/// owning form used for the executive's global atom table; the raw functions below remain the ABI
/// used by hosted ntoskrnl/win32k exports.
pub struct OwnedAtomTable {
    arena: Vec<u8>,
}

impl OwnedAtomTable {
    /// Create a table with exactly `capacity` string-atom slots.
    pub fn with_capacity(capacity: usize) -> Option<Self> {
        if capacity == 0 || capacity > u32::MAX as usize {
            return None;
        }
        let arena_len = hdr::SIZE.checked_add(capacity.checked_mul(ENTRY_SIZE)?)?;
        let mut arena = vec![0u8; arena_len];
        // SAFETY: `arena` is writable for `arena_len` bytes and its allocation remains stable: no
        // method changes its length or capacity after construction.
        if unsafe { create(arena.as_mut_ptr(), arena.len()) }.is_null() {
            return None;
        }
        Some(Self { arena })
    }

    #[inline]
    fn as_ptr(&self) -> *const u8 {
        self.arena.as_ptr()
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.arena.as_mut_ptr()
    }

    /// Add an explicit-length UTF-16 name. The slice need not contain a trailing null.
    pub fn add_name(&mut self, name: &[u16]) -> Result<u16, u32> {
        let mut terminated = [0u16; NAME_CAP + 1];
        if name.len() > NAME_CAP {
            return Err(status::INVALID_PARAMETER);
        }
        terminated[..name.len()].copy_from_slice(name);
        let mut atom = 0u16;
        // SAFETY: `terminated` is null-terminated and the owned table allocation is valid.
        let status = unsafe { add(self.as_mut_ptr(), terminated.as_ptr(), &mut atom) };
        if status == status::SUCCESS {
            Ok(atom)
        } else {
            Err(status)
        }
    }

    /// Find an explicit-length UTF-16 name without changing its reference count.
    pub fn find_name(&self, name: &[u16]) -> Result<u16, u32> {
        let mut terminated = [0u16; NAME_CAP + 1];
        if name.len() > NAME_CAP {
            return Err(status::INVALID_PARAMETER);
        }
        terminated[..name.len()].copy_from_slice(name);
        let mut atom = 0u16;
        // SAFETY: `terminated` is null-terminated and the owned table allocation is valid.
        let status = unsafe { lookup(self.as_ptr(), terminated.as_ptr(), &mut atom) };
        if status == status::SUCCESS {
            Ok(atom)
        } else {
            Err(status)
        }
    }

    /// Add an integer atom. Integer atoms are synthesized and never consume a table slot.
    pub fn add_integer(&mut self, atom: u16) -> Result<u16, u32> {
        let mut out = 0u16;
        // SAFETY: small pointer values are the documented MAKEINTATOM representation and are not
        // dereferenced by `add`.
        let status = unsafe { add(self.as_mut_ptr(), atom as usize as *const u16, &mut out) };
        if status == status::SUCCESS {
            Ok(out)
        } else {
            Err(status)
        }
    }

    /// Find an integer atom. Like add, this is a synthesized pass-through operation.
    pub fn find_integer(&self, atom: u16) -> Result<u16, u32> {
        let mut out = 0u16;
        // SAFETY: see `add_integer`.
        let status = unsafe { lookup(self.as_ptr(), atom as usize as *const u16, &mut out) };
        if status == status::SUCCESS {
            Ok(out)
        } else {
            Err(status)
        }
    }

    pub fn delete(&mut self, atom: u16) -> u32 {
        // SAFETY: the pointer is the live allocation initialized by `with_capacity`.
        unsafe { delete(self.as_mut_ptr(), atom) }
    }

    pub fn pin(&mut self, atom: u16) -> u32 {
        // SAFETY: the pointer is the live allocation initialized by `with_capacity`.
        unsafe { pin(self.as_mut_ptr(), atom) }
    }

    pub fn empty(&mut self, delete_pinned: bool) -> u32 {
        // SAFETY: the pointer is the live allocation initialized by `with_capacity`.
        unsafe { empty(self.as_mut_ptr(), delete_pinned) }
    }

    /// Raw `RtlQueryAtomInAtomTable` form for ABI wrappers that need null out-params.
    ///
    /// # Safety
    /// Any non-null out-param must be writable. If `name` is non-null, `name_len` must point to the
    /// caller-provided byte capacity.
    pub unsafe fn query_raw(
        &self,
        atom: u16,
        ref_count: *mut u32,
        pin_count: *mut u32,
        name: *mut u16,
        name_len: *mut u32,
    ) -> u32 {
        unsafe { query(self.as_ptr(), atom, ref_count, pin_count, name, name_len) }
    }

    /// Query an atom into `name`. `name_capacity_bytes` preserves the native byte-sized contract,
    /// including odd/truncated capacities; callers must provide a 256-unit scratch buffer.
    pub fn query(
        &self,
        atom: u16,
        name: &mut [u16; NAME_CAP + 1],
        name_capacity_bytes: u32,
    ) -> AtomQueryResult {
        let mut reference_count = 0u32;
        let mut pin_count = 0u32;
        let mut name_length = name_capacity_bytes.min((name.len() * 2) as u32);
        // SAFETY: all outputs point to initialized writable locals and `name_length` is capped to
        // the actual scratch buffer size.
        let status = unsafe {
            query(
                self.as_ptr(),
                atom,
                &mut reference_count,
                &mut pin_count,
                name.as_mut_ptr(),
                &mut name_length,
            )
        };
        AtomQueryResult {
            status,
            reference_count,
            pin_count,
            name_length,
        }
    }

    /// Enumerate all stored string atoms. Integer atoms are never table entries.
    pub fn list(&self, atoms: &mut [u16]) -> AtomListResult {
        let mut count = 0u32;
        // SAFETY: the table is live and `atoms` describes its writable output capacity.
        let status = unsafe { query_list(self.as_ptr(), atoms, &mut count) };
        AtomListResult {
            status,
            count: count as usize,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AtomQueryResult {
    pub status: u32,
    pub reference_count: u32,
    pub pin_count: u32,
    /// Bytes copied, excluding the terminating null; on `BUFFER_TOO_SMALL`, required name bytes.
    pub name_length: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AtomListResult {
    pub status: u32,
    /// Total atoms in the table, even when the output slice was too small.
    pub count: usize,
}

#[inline]
unsafe fn rd_u32(p: *const u8, off: usize) -> u32 {
    core::ptr::read_unaligned(p.add(off) as *const u32)
}
#[inline]
unsafe fn wr_u32(p: *mut u8, off: usize, v: u32) {
    core::ptr::write_unaligned(p.add(off) as *mut u32, v);
}
#[inline]
unsafe fn rd_u16(p: *const u8, off: usize) -> u16 {
    core::ptr::read_unaligned(p.add(off) as *const u16)
}
#[inline]
unsafe fn wr_u16(p: *mut u8, off: usize, v: u16) {
    core::ptr::write_unaligned(p.add(off) as *mut u16, v);
}

#[inline]
fn up(c: u16) -> u16 {
    // ASCII upcase — enough for class / module atom names.
    if (0x61..=0x7A).contains(&c) {
        c - 0x20
    } else {
        c
    }
}

/// Length (in chars) of a null-terminated UTF-16 string, capped at `cap`.
unsafe fn wstr_len(name: *const u16, cap: usize) -> usize {
    let mut n = 0usize;
    while n < cap && core::ptr::read_unaligned(name.add(n)) != 0 {
        n += 1;
    }
    n
}

/// Classify an atom name per `RtlpCheckIntegerAtom`. Returns `Some(atom)` for an integer atom
/// (MAKEINTATOM pointer, or `"#<decimal>"`), else `None` (a real string name).
///
/// # Safety
/// `name` is either a small integer (MAKEINTATOM) reinterpreted as a pointer — NOT dereferenced —
/// or a valid null-terminated UTF-16 string pointer.
pub unsafe fn check_integer_atom(name: *const u16) -> Option<u16> {
    let raw = name as u64;
    if raw & 0xFFFF_0000 == 0 {
        // MAKEINTATOM: the atom is the low 16 bits (0 maps to 0xC000). Do NOT dereference.
        let lo = (raw & 0xFFFF) as u16;
        return Some(if lo == 0 { FIRST_DYNAMIC_ATOM } else { lo });
    }
    // "#<decimal>" → integer atom.
    if core::ptr::read_unaligned(name) != b'#' as u16 {
        return None;
    }
    let mut i = 1usize;
    let mut val: u32 = 0;
    let mut any = false;
    loop {
        let c = core::ptr::read_unaligned(name.add(i));
        if c == 0 {
            break;
        }
        if !(b'0' as u16..=b'9' as u16).contains(&c) {
            return None;
        }
        val = val.wrapping_mul(10).wrapping_add((c - b'0' as u16) as u32);
        any = true;
        i += 1;
    }
    if !any {
        return None;
    }
    Some((val & 0xFFFF) as u16)
}

/// `RtlCreateAtomTable` — lay a fresh (empty) atom table over `arena`/`arena_len` and return the
/// opaque table pointer (== `arena`). Idempotent: if `arena` already holds an initialized table,
/// its contents are left intact (matches Windows returning `STATUS_SUCCESS` when `*AtomTable`
/// already exists). Returns null if the arena cannot hold the header plus at least one entry.
///
/// # Safety
/// `arena` must be writable for `arena_len` bytes and remain valid for the table's lifetime.
pub unsafe fn create(arena: *mut u8, arena_len: usize) -> *mut u8 {
    if arena.is_null() || arena_len < hdr::SIZE + ENTRY_SIZE {
        return core::ptr::null_mut();
    }
    if rd_u32(arena, hdr::SIGNATURE) == SIGNATURE_MAGIC {
        return arena; // already initialized
    }
    let capacity = ((arena_len - hdr::SIZE) / ENTRY_SIZE) as u32;
    // Zero the header + entry array so every slot's atom == 0 (free).
    core::ptr::write_bytes(arena, 0, hdr::SIZE + capacity as usize * ENTRY_SIZE);
    wr_u32(arena, hdr::SIGNATURE, SIGNATURE_MAGIC);
    wr_u32(arena, hdr::CAPACITY, capacity);
    wr_u32(arena, hdr::COUNT, 0);
    wr_u32(arena, hdr::NEXT_ATOM, FIRST_DYNAMIC_ATOM as u32);
    arena
}

#[inline]
unsafe fn entry(table: *const u8, i: u32) -> *const u8 {
    table.add(hdr::SIZE + i as usize * ENTRY_SIZE)
}
#[inline]
unsafe fn entry_mut(table: *mut u8, i: u32) -> *mut u8 {
    table.add(hdr::SIZE + i as usize * ENTRY_SIZE)
}

/// Case-insensitively compare an entry's inline name to `name`/`len`.
unsafe fn name_eq(e: *const u8, name: *const u16, len: usize) -> bool {
    if rd_u16(e, ent::NAME_LEN) as usize != len {
        return false;
    }
    for k in 0..len {
        let a = rd_u16(e, ent::NAME + k * 2);
        let b = core::ptr::read_unaligned(name.add(k));
        if up(a) != up(b) {
            return false;
        }
    }
    true
}

/// Find the slot index of the string atom `name`/`len`, or `None`.
unsafe fn find_by_name(table: *const u8, name: *const u16, len: usize) -> Option<u32> {
    let cap = rd_u32(table, hdr::CAPACITY);
    for i in 0..cap {
        let e = entry(table, i);
        if rd_u16(e, ent::ATOM) != 0 && name_eq(e, name, len) {
            return Some(i);
        }
    }
    None
}

/// Find the slot index holding atom value `atom`, or `None`.
unsafe fn find_by_atom(table: *const u8, atom: u16) -> Option<u32> {
    let cap = rd_u32(table, hdr::CAPACITY);
    for i in 0..cap {
        let e = entry(table, i);
        if rd_u16(e, ent::ATOM) == atom {
            return Some(i);
        }
    }
    None
}

/// `RtlAddAtomToAtomTable(table, name, out_atom)`. Integer atoms return their value directly. A new
/// string atom is minted from 0xC000 up; re-adding bumps the reference count. Returns an NTSTATUS.
///
/// # Safety
/// `table` must be a table from [`create`] (or null → `INVALID_HANDLE`); `name` an integer atom or
/// null-terminated UTF-16 string; `out_atom` writable if non-null.
pub unsafe fn add(table: *mut u8, name: *const u16, out_atom: *mut u16) -> u32 {
    if let Some(a) = check_integer_atom(name) {
        // Integer atom: never stored, never touches the table.
        if a >= FIRST_DYNAMIC_ATOM {
            return status::INVALID_PARAMETER;
        }
        if !out_atom.is_null() {
            core::ptr::write_unaligned(out_atom, a);
        }
        return status::SUCCESS;
    }
    if table.is_null() {
        return status::INVALID_HANDLE;
    }
    let len = wstr_len(name, NAME_CAP + 1);
    if len == 0 {
        return status::OBJECT_NAME_INVALID;
    }
    if len > NAME_CAP {
        return status::INVALID_PARAMETER;
    }
    if let Some(i) = find_by_name(table, name, len) {
        let e = entry_mut(table, i);
        if rd_u16(e, ent::FLAGS) & FLAG_PINNED == 0 {
            let rc = rd_u16(e, ent::REF).wrapping_add(1);
            if rc == 0 {
                wr_u16(e, ent::FLAGS, rd_u16(e, ent::FLAGS) | FLAG_PINNED);
            } else {
                wr_u16(e, ent::REF, rc);
            }
        }
        if !out_atom.is_null() {
            core::ptr::write_unaligned(out_atom, rd_u16(e, ent::ATOM));
        }
        return status::SUCCESS;
    }
    // New atom: find a free slot.
    let cap = rd_u32(table, hdr::CAPACITY);
    let mut free = None;
    for i in 0..cap {
        if rd_u16(entry(table, i), ent::ATOM) == 0 {
            free = Some(i);
            break;
        }
    }
    let i = match free {
        Some(i) => i,
        None => return status::NO_MEMORY,
    };
    let atom = rd_u32(table, hdr::NEXT_ATOM) as u16;
    if atom < FIRST_DYNAMIC_ATOM {
        return status::NO_MEMORY; // wrapped past the dynamic range
    }
    wr_u32(table, hdr::NEXT_ATOM, atom as u32 + 1);
    wr_u32(table, hdr::COUNT, rd_u32(table, hdr::COUNT) + 1);
    let e = entry_mut(table, i);
    wr_u16(e, ent::ATOM, atom);
    wr_u16(e, ent::REF, 1);
    wr_u16(e, ent::FLAGS, 0);
    wr_u16(e, ent::NAME_LEN, len as u16);
    for k in 0..len {
        wr_u16(e, ent::NAME + k * 2, core::ptr::read_unaligned(name.add(k)));
    }
    wr_u16(e, ent::NAME + len * 2, 0);
    if !out_atom.is_null() {
        core::ptr::write_unaligned(out_atom, atom);
    }
    status::SUCCESS
}

/// `RtlLookupAtomInAtomTable(table, name, out_atom)`. Integer atoms return their value directly;
/// string atoms return the stored value or `OBJECT_NAME_NOT_FOUND`.
///
/// # Safety
/// See [`add`].
pub unsafe fn lookup(table: *const u8, name: *const u16, out_atom: *mut u16) -> u32 {
    if let Some(a) = check_integer_atom(name) {
        if a >= FIRST_DYNAMIC_ATOM {
            return status::INVALID_PARAMETER;
        }
        if !out_atom.is_null() {
            core::ptr::write_unaligned(out_atom, a);
        }
        return status::SUCCESS;
    }
    if table.is_null() {
        return status::INVALID_HANDLE;
    }
    let len = wstr_len(name, NAME_CAP + 1);
    if len == 0 || len > NAME_CAP {
        return status::OBJECT_NAME_NOT_FOUND;
    }
    match find_by_name(table, name, len) {
        Some(i) => {
            if !out_atom.is_null() {
                core::ptr::write_unaligned(out_atom, rd_u16(entry(table, i), ent::ATOM));
            }
            status::SUCCESS
        }
        None => status::OBJECT_NAME_NOT_FOUND,
    }
}

/// `RtlDeleteAtomFromAtomTable(table, atom)`. Integer atoms (< 0xC000) are a no-op success.
/// String atoms decrement the ref count and free the slot at zero; pinned atoms return
/// `WAS_LOCKED` (a success code) without deleting.
///
/// # Safety
/// `table` must be a table from [`create`] (or null → `INVALID_HANDLE`).
pub unsafe fn delete(table: *mut u8, atom: u16) -> u32 {
    if atom < FIRST_DYNAMIC_ATOM {
        return status::SUCCESS;
    }
    if table.is_null() {
        return status::INVALID_HANDLE;
    }
    let i = match find_by_atom(table, atom) {
        Some(i) => i,
        None => return status::INVALID_HANDLE,
    };
    let e = entry_mut(table, i);
    if rd_u16(e, ent::FLAGS) & FLAG_PINNED != 0 {
        return status::WAS_LOCKED;
    }
    let rc = rd_u16(e, ent::REF).wrapping_sub(1);
    if rc == 0 {
        wr_u16(e, ent::ATOM, 0); // free the slot
        wr_u16(e, ent::NAME_LEN, 0);
        let cnt = rd_u32(table, hdr::COUNT);
        wr_u32(table, hdr::COUNT, cnt.saturating_sub(1));
    } else {
        wr_u16(e, ent::REF, rc);
    }
    status::SUCCESS
}

/// `RtlPinAtomInAtomTable(table, atom)`. Integer atoms are a no-op success.
///
/// # Safety
/// See [`delete`].
pub unsafe fn pin(table: *mut u8, atom: u16) -> u32 {
    if atom < FIRST_DYNAMIC_ATOM {
        return status::SUCCESS;
    }
    if table.is_null() {
        return status::INVALID_HANDLE;
    }
    match find_by_atom(table, atom) {
        Some(i) => {
            let e = entry_mut(table, i);
            wr_u16(e, ent::FLAGS, rd_u16(e, ent::FLAGS) | FLAG_PINNED);
            status::SUCCESS
        }
        None => status::INVALID_HANDLE,
    }
}

/// `RtlEmptyAtomTable(table, delete_pinned)`. Clears string atoms in-place, preserving pinned atoms
/// when requested. Integer atoms are synthesized and therefore never table entries.
///
/// # Safety
/// `table` must be a table from [`create`] (or null -> `INVALID_HANDLE`).
pub unsafe fn empty(table: *mut u8, delete_pinned: bool) -> u32 {
    if table.is_null() {
        return status::INVALID_HANDLE;
    }
    let cap = rd_u32(table, hdr::CAPACITY);
    let mut kept = 0u32;
    for i in 0..cap {
        let e = entry_mut(table, i);
        if rd_u16(e, ent::ATOM) == 0 {
            continue;
        }
        if !delete_pinned && (rd_u16(e, ent::FLAGS) & FLAG_PINNED) != 0 {
            kept += 1;
            continue;
        }
        wr_u16(e, ent::ATOM, 0);
        wr_u16(e, ent::REF, 0);
        wr_u16(e, ent::FLAGS, 0);
        wr_u16(e, ent::NAME_LEN, 0);
        wr_u16(e, ent::NAME, 0);
    }
    wr_u32(table, hdr::COUNT, kept);
    status::SUCCESS
}

/// `RtlQueryAtomInAtomTable(table, atom, ref_count, pin_count, name, name_len)`. Fills whichever of
/// the out-params are non-null. `name_len` is IN/OUT in BYTES (the odd Windows contract): on entry
/// the `name` buffer capacity, on exit the copied length excluding the null terminator. Returns
/// `INVALID_HANDLE` if the atom is unknown.
///
/// # Safety
/// `table` from [`create`]; the out-params writable if non-null; `name` backs `*name_len` bytes.
pub unsafe fn query(
    table: *const u8,
    atom: u16,
    ref_count: *mut u32,
    pin_count: *mut u32,
    name: *mut u16,
    name_len: *mut u32,
) -> u32 {
    // Integer atoms synthesize a "#<n>" entry with ref 1, pinned.
    if atom < FIRST_DYNAMIC_ATOM {
        if !ref_count.is_null() {
            core::ptr::write_unaligned(ref_count, 1);
        }
        if !pin_count.is_null() {
            core::ptr::write_unaligned(pin_count, 1);
        }
        return query_write_name_int(atom, name, name_len);
    }
    if table.is_null() {
        return status::INVALID_HANDLE;
    }
    let i = match find_by_atom(table, atom) {
        Some(i) => i,
        None => return status::INVALID_HANDLE,
    };
    let e = entry(table, i);
    if !ref_count.is_null() {
        core::ptr::write_unaligned(ref_count, rd_u16(e, ent::REF) as u32);
    }
    if !pin_count.is_null() {
        core::ptr::write_unaligned(pin_count, (rd_u16(e, ent::FLAGS) & FLAG_PINNED) as u32);
    }
    if name_len.is_null() {
        return if name.is_null() {
            status::SUCCESS
        } else {
            status::INVALID_PARAMETER
        };
    }
    let stored = rd_u16(e, ent::NAME_LEN) as usize;
    let byte_len = stored * 2;
    if name.is_null() {
        core::ptr::write_unaligned(name_len, byte_len as u32);
        return status::SUCCESS;
    }
    let cap = core::ptr::read_unaligned(name_len) as usize;
    let mut copy = byte_len;
    if cap < byte_len + 2 {
        if cap < 4 {
            core::ptr::write_unaligned(name_len, byte_len as u32);
            return status::BUFFER_TOO_SMALL;
        }
        copy = cap - 2;
    }
    let chars = copy / 2;
    for k in 0..chars {
        core::ptr::write_unaligned(name.add(k), rd_u16(e, ent::NAME + k * 2));
    }
    core::ptr::write_unaligned(name.add(chars), 0);
    core::ptr::write_unaligned(name_len, (chars * 2) as u32);
    status::SUCCESS
}

/// `RtlQueryAtomListInAtomTable` — copy as many stored string atoms as fit and always return the
/// total count. Integer atoms are synthesized and therefore never appear in this list.
///
/// # Safety
/// `table` must be a table from [`create`]; `count` must be writable.
pub unsafe fn query_list(table: *const u8, atoms: &mut [u16], count: *mut u32) -> u32 {
    if table.is_null() {
        return status::INVALID_HANDLE;
    }
    let cap = rd_u32(table, hdr::CAPACITY);
    let mut total = 0usize;
    for i in 0..cap {
        let atom = rd_u16(entry(table, i), ent::ATOM);
        if atom == 0 {
            continue;
        }
        if total < atoms.len() {
            atoms[total] = atom;
        }
        total += 1;
    }
    if !count.is_null() {
        core::ptr::write_unaligned(count, total as u32);
    }
    if total > atoms.len() {
        status::INFO_LENGTH_MISMATCH
    } else {
        status::SUCCESS
    }
}

/// Format a `#<decimal>` name for an integer atom into `name`/`*name_len` (bytes).
unsafe fn query_write_name_int(atom: u16, name: *mut u16, name_len: *mut u32) -> u32 {
    if name_len.is_null() {
        return if name.is_null() {
            status::SUCCESS
        } else {
            status::INVALID_PARAMETER
        };
    }
    let mut buf = [0u16; 8];
    buf[0] = b'#' as u16;
    let mut digits = [0u8; 5];
    let mut n = atom as u32;
    let mut d = 0usize;
    if n == 0 {
        digits[0] = b'0';
        d = 1;
    } else {
        while n > 0 {
            digits[d] = b'0' + (n % 10) as u8;
            n /= 10;
            d += 1;
        }
    }
    for k in 0..d {
        buf[1 + k] = digits[d - 1 - k] as u16;
    }
    let total = 1 + d; // chars
    let byte_len = total * 2;
    if name.is_null() {
        core::ptr::write_unaligned(name_len, byte_len as u32);
        return status::SUCCESS;
    }
    let cap = core::ptr::read_unaligned(name_len) as usize;
    let mut copy = byte_len;
    if cap < byte_len + 2 {
        if cap < 4 {
            core::ptr::write_unaligned(name_len, byte_len as u32);
            return status::BUFFER_TOO_SMALL;
        }
        copy = cap - 2;
    }
    let chars = copy / 2;
    for k in 0..chars {
        core::ptr::write_unaligned(name.add(k), buf[k]);
    }
    core::ptr::write_unaligned(name.add(chars), 0);
    core::ptr::write_unaligned(name_len, (chars * 2) as u32);
    status::SUCCESS
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    fn arena(len: usize) -> std::vec::Vec<u8> {
        vec![0xABu8; len]
    }
    fn w(s: &str) -> std::vec::Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    #[test]
    fn create_lays_out_header() {
        let mut a = arena(4096);
        unsafe {
            let t = create(a.as_mut_ptr(), a.len());
            assert!(!t.is_null());
            assert_eq!(rd_u32(t, hdr::SIGNATURE), SIGNATURE_MAGIC);
            assert_eq!(rd_u32(t, hdr::NEXT_ATOM), FIRST_DYNAMIC_ATOM as u32);
            assert!(rd_u32(t, hdr::CAPACITY) > 0);
            // Idempotent.
            let t2 = create(a.as_mut_ptr(), a.len());
            assert_eq!(t2, t);
        }
    }

    #[test]
    fn add_mints_distinct_dynamic_atoms_and_dedups() {
        let mut a = arena(65536);
        let sb = w("ScrollBar");
        let ed = w("Edit");
        unsafe {
            let t = create(a.as_mut_ptr(), a.len());
            let mut a1 = 0u16;
            let mut a2 = 0u16;
            assert_eq!(add(t, sb.as_ptr(), &mut a1), status::SUCCESS);
            assert_eq!(add(t, ed.as_ptr(), &mut a2), status::SUCCESS);
            assert_eq!(a1, 0xC000);
            assert_eq!(a2, 0xC001);
            // Re-add "ScrollBar" → same atom, ref bumped.
            let mut a3 = 0u16;
            assert_eq!(add(t, sb.as_ptr(), &mut a3), status::SUCCESS);
            assert_eq!(a3, a1);
            assert_eq!(rd_u32(t, hdr::COUNT), 2);
        }
    }

    #[test]
    fn lookup_is_case_insensitive_and_reports_missing() {
        let mut a = arena(65536);
        let name = w("ScrollBar");
        let up = w("SCROLLBAR");
        let miss = w("NoSuchClass");
        unsafe {
            let t = create(a.as_mut_ptr(), a.len());
            let mut atom = 0u16;
            add(t, name.as_ptr(), &mut atom);
            let mut got = 0u16;
            assert_eq!(lookup(t, up.as_ptr(), &mut got), status::SUCCESS);
            assert_eq!(got, atom);
            assert_eq!(
                lookup(t, miss.as_ptr(), core::ptr::null_mut()),
                status::OBJECT_NAME_NOT_FOUND
            );
        }
    }

    #[test]
    fn integer_atoms_pass_through_without_table() {
        // WC_DESKTOP = MAKEINTATOM(0x8001): the name pointer IS 0x8001; add/lookup return it
        // WITHOUT dereferencing or touching the table.
        unsafe {
            let name = 0x8001usize as *const u16;
            let mut atom = 0u16;
            assert_eq!(add(core::ptr::null_mut(), name, &mut atom), status::SUCCESS);
            assert_eq!(atom, 0x8001);
            let mut got = 0u16;
            assert_eq!(lookup(core::ptr::null(), name, &mut got), status::SUCCESS);
            assert_eq!(got, 0x8001);
            // MAKEINTATOM(0) maps to 0xC000, which is out of the integer range → INVALID_PARAMETER.
            assert_eq!(
                add(core::ptr::null_mut(), 0usize as *const u16, &mut atom),
                status::INVALID_PARAMETER
            );
        }
    }

    #[test]
    fn hash_string_integer_atom() {
        // "#256" → integer atom 256, not stored.
        let name = w("#256");
        unsafe {
            let mut atom = 0u16;
            assert_eq!(
                add(core::ptr::null_mut(), name.as_ptr(), &mut atom),
                status::SUCCESS
            );
            assert_eq!(atom, 256);
        }
    }

    #[test]
    fn delete_refcounts_and_pin_protects() {
        let mut a = arena(65536);
        let name = w("Button");
        unsafe {
            let t = create(a.as_mut_ptr(), a.len());
            let mut atom = 0u16;
            add(t, name.as_ptr(), &mut atom);
            add(t, name.as_ptr(), core::ptr::null_mut()); // ref = 2
                                                          // First delete just decrements.
            assert_eq!(delete(t, atom), status::SUCCESS);
            let mut got = 0u16;
            assert_eq!(lookup(t, name.as_ptr(), &mut got), status::SUCCESS);
            // Second delete frees.
            assert_eq!(delete(t, atom), status::SUCCESS);
            assert_eq!(
                lookup(t, name.as_ptr(), core::ptr::null_mut()),
                status::OBJECT_NAME_NOT_FOUND
            );
            // Re-add reuses the freed slot; pin protects from deletion.
            let mut a2 = 0u16;
            add(t, name.as_ptr(), &mut a2);
            assert_eq!(pin(t, a2), status::SUCCESS);
            assert_eq!(delete(t, a2), status::WAS_LOCKED);
            assert_eq!(
                lookup(t, name.as_ptr(), core::ptr::null_mut()),
                status::SUCCESS
            );
        }
    }

    #[test]
    fn empty_preserves_pinned_unless_requested() {
        let mut a = arena(65536);
        let pinned_name = w("Pinned");
        let transient_name = w("Transient");
        unsafe {
            let t = create(a.as_mut_ptr(), a.len());
            let mut pinned = 0u16;
            let mut transient = 0u16;
            assert_eq!(add(t, pinned_name.as_ptr(), &mut pinned), status::SUCCESS);
            assert_eq!(
                add(t, transient_name.as_ptr(), &mut transient),
                status::SUCCESS
            );
            assert_eq!(pin(t, pinned), status::SUCCESS);

            assert_eq!(empty(t, false), status::SUCCESS);
            assert_eq!(
                lookup(t, pinned_name.as_ptr(), core::ptr::null_mut()),
                status::SUCCESS
            );
            assert_eq!(
                lookup(t, transient_name.as_ptr(), core::ptr::null_mut()),
                status::OBJECT_NAME_NOT_FOUND
            );
            assert_eq!(rd_u32(t, hdr::COUNT), 1);

            assert_eq!(empty(t, true), status::SUCCESS);
            assert_eq!(
                lookup(t, pinned_name.as_ptr(), core::ptr::null_mut()),
                status::OBJECT_NAME_NOT_FOUND
            );
            assert_eq!(rd_u32(t, hdr::COUNT), 0);
        }
    }

    #[test]
    fn query_returns_name_and_refs() {
        let mut a = arena(65536);
        let name = w("ScrollBar");
        unsafe {
            let t = create(a.as_mut_ptr(), a.len());
            let mut atom = 0u16;
            add(t, name.as_ptr(), &mut atom);
            let mut rc = 0u32;
            let mut pc = 0u32;
            let mut buf = [0u16; 32];
            let mut len = (buf.len() * 2) as u32;
            assert_eq!(
                query(t, atom, &mut rc, &mut pc, buf.as_mut_ptr(), &mut len),
                status::SUCCESS
            );
            assert_eq!(rc, 1);
            assert_eq!(pc, 0);
            assert_eq!(len, ("ScrollBar".len() * 2) as u32);
            let got: std::string::String = std::string::String::from_utf16_lossy(&buf[..9]);
            assert_eq!(got, "ScrollBar");
        }
    }

    #[test]
    fn add_rejects_overlong_name() {
        let mut a = arena(65536);
        let long: std::vec::Vec<u16> = core::iter::repeat(b'x' as u16)
            .take(NAME_CAP + 1)
            .chain(core::iter::once(0))
            .collect();
        unsafe {
            let t = create(a.as_mut_ptr(), a.len());
            assert_eq!(
                add(t, long.as_ptr(), core::ptr::null_mut()),
                status::INVALID_PARAMETER
            );
        }
    }

    #[test]
    fn owned_table_uses_explicit_lengths_and_global_refcounts() {
        let mut table = OwnedAtomTable::with_capacity(4).unwrap();
        let mixed: std::vec::Vec<u16> = "WinSta0".encode_utf16().collect();
        let upper: std::vec::Vec<u16> = "WINSTA0".encode_utf16().collect();

        let atom = table.add_name(&mixed).unwrap();
        assert_eq!(table.add_name(&upper), Ok(atom));
        assert_eq!(table.find_name(&upper), Ok(atom));

        let mut name = [0u16; NAME_CAP + 1];
        let name_capacity = (name.len() * 2) as u32;
        let queried = table.query(atom, &mut name, name_capacity);
        assert_eq!(queried.status, status::SUCCESS);
        assert_eq!(queried.reference_count, 2);
        assert_eq!(queried.name_length, 14);
        assert_eq!(&name[..7], mixed.as_slice());

        assert_eq!(table.delete(atom), status::SUCCESS);
        assert_eq!(table.find_name(&mixed), Ok(atom));
        assert_eq!(table.delete(atom), status::SUCCESS);
        assert_eq!(table.find_name(&mixed), Err(status::OBJECT_NAME_NOT_FOUND));
    }

    #[test]
    fn owned_table_synthesizes_integer_atoms() {
        let mut table = OwnedAtomTable::with_capacity(1).unwrap();
        assert_eq!(table.add_integer(123), Ok(123));
        assert_eq!(table.find_integer(0xBFFF), Ok(0xBFFF));
        assert_eq!(table.add_integer(0), Err(status::INVALID_PARAMETER));
        assert_eq!(table.add_integer(0xC000), Err(status::INVALID_PARAMETER));

        let mut name = [0u16; NAME_CAP + 1];
        let queried = table.query(123, &mut name, 64);
        assert_eq!(queried.status, status::SUCCESS);
        assert_eq!(queried.reference_count, 1);
        assert_eq!(queried.pin_count, 1);
        assert_eq!(queried.name_length, 8);
        assert_eq!(
            &name[..4],
            &[b'#' as u16, b'1' as u16, b'2' as u16, b'3' as u16]
        );
    }

    #[test]
    fn owned_table_lists_all_atoms_and_reports_short_output() {
        let mut table = OwnedAtomTable::with_capacity(3).unwrap();
        let one: std::vec::Vec<u16> = "One".encode_utf16().collect();
        let two: std::vec::Vec<u16> = "Two".encode_utf16().collect();
        let a1 = table.add_name(&one).unwrap();
        let a2 = table.add_name(&two).unwrap();

        let mut short = [0u16; 1];
        assert_eq!(
            table.list(&mut short),
            AtomListResult {
                status: status::INFO_LENGTH_MISMATCH,
                count: 2,
            }
        );
        assert_eq!(short[0], a1);

        let mut all = [0u16; 3];
        assert_eq!(
            table.list(&mut all),
            AtomListResult {
                status: status::SUCCESS,
                count: 2,
            }
        );
        assert_eq!(&all[..2], &[a1, a2]);
    }

    #[test]
    fn accepts_the_full_255_character_contract() {
        let mut table = OwnedAtomTable::with_capacity(1).unwrap();
        let maximum = std::vec![b'x' as u16; NAME_CAP];
        assert!(table.add_name(&maximum).is_ok());
        let overlong = std::vec![b'x' as u16; NAME_CAP + 1];
        assert_eq!(table.add_name(&overlong), Err(status::INVALID_PARAMETER));
    }

    #[test]
    fn owned_query_preserves_native_truncation_contract() {
        let mut table = OwnedAtomTable::with_capacity(1).unwrap();
        let value: std::vec::Vec<u16> = "LongName".encode_utf16().collect();
        let atom = table.add_name(&value).unwrap();
        let mut name = [0xCCCCu16; NAME_CAP + 1];

        let too_small = table.query(atom, &mut name, 2);
        assert_eq!(too_small.status, status::BUFFER_TOO_SMALL);
        assert_eq!(too_small.name_length, 16);

        let truncated = table.query(atom, &mut name, 4);
        assert_eq!(truncated.status, status::SUCCESS);
        assert_eq!(truncated.name_length, 2);
        assert_eq!(name[0], b'L' as u16);
        assert_eq!(name[1], 0);
        assert_eq!(name[2], 0xCCCC);
    }

    #[test]
    fn owned_pin_empty_and_raw_query_support_export_contracts() {
        let mut table = OwnedAtomTable::with_capacity(2).unwrap();
        let pinned_name: std::vec::Vec<u16> = "Pinned".encode_utf16().collect();
        let transient_name: std::vec::Vec<u16> = "Transient".encode_utf16().collect();
        let pinned = table.add_name(&pinned_name).unwrap();
        let transient = table.add_name(&transient_name).unwrap();

        assert_eq!(table.pin(pinned), status::SUCCESS);
        let mut refs = 0u32;
        let mut pins = 0u32;
        unsafe {
            assert_eq!(
                table.query_raw(
                    pinned,
                    &mut refs,
                    &mut pins,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                ),
                status::SUCCESS
            );
        }
        assert_eq!(refs, 1);
        assert_eq!(pins, 1);

        assert_eq!(table.empty(false), status::SUCCESS);
        assert_eq!(table.find_name(&pinned_name), Ok(pinned));
        assert_eq!(
            table.find_name(&transient_name),
            Err(status::OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(table.delete(pinned), status::WAS_LOCKED);
        assert_eq!(table.delete(transient), status::INVALID_HANDLE);

        assert_eq!(table.empty(true), status::SUCCESS);
        assert_eq!(
            table.find_name(&pinned_name),
            Err(status::OBJECT_NAME_NOT_FOUND)
        );
    }
}
