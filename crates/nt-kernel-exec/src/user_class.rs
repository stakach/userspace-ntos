//! Exact identities for USER32 builtin classes already registered in the hosted win32k process.

use crate::user_cursor::CursorResource;

pub const WNDCLASSEXW_SIZE: usize = 0x50;
pub const CS_GLOBALCLASS: u32 = 0x4000;
pub const CS_DBLCLKS: u32 = 0x0008;
pub const CS_HREDRAW: u32 = 0x0002;
pub const CS_PARENTDC: u32 = 0x0080;
pub const CS_VREDRAW: u32 = 0x0001;
pub const FNID_FIRST: u32 = 0x029a;
pub const FNID_SCROLLBAR: u32 = 0x029a;
pub const FNID_BUILTIN_FIRST: u32 = 0x02a1;
pub const FNID_BUILTIN_LAST: u32 = 0x02aa;
pub const CLASS_ATOM_NAME_CAP: usize = 255;
pub const PFNCLIENT_ENTRY_COUNT: usize = 23;
pub const PFNCLIENT_SIZE: usize = PFNCLIENT_ENTRY_COUNT * 8;
pub const SCROLLBAR_CLASS_STYLE: u32 = CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC;
pub const SCROLLBAR_CB_WND_EXTRA: u32 = 0x48;
pub const SCROLLBAR_CLASS_NAME: [u16; 9] = [
    b'S' as u16,
    b'c' as u16,
    b'r' as u16,
    b'o' as u16,
    b'l' as u16,
    b'l' as u16,
    b'B' as u16,
    b'a' as u16,
    b'r' as u16,
];

#[derive(Clone, Copy, Debug)]
pub enum ClassNameIdentity {
    None,
    Resource(CursorResource),
}

impl ClassNameIdentity {
    pub const fn none() -> Self {
        Self::None
    }

    pub const fn atom(atom: u16) -> Self {
        Self::Resource(CursorResource::atom(atom))
    }

    pub fn name(units: &[u16]) -> Option<Self> {
        CursorResource::name(units).map(Self::Resource)
    }

    fn same_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (Self::Resource(left), Self::Resource(right)) => left.same_identity(right),
            _ => false,
        }
    }

    fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BuiltinClassKey {
    class_name: ClassNameIdentity,
    class_version: ClassNameIdentity,
    menu_name: ClassNameIdentity,
    fn_id: u32,
    flags: u32,
}

impl BuiltinClassKey {
    /// Decode the x64 WNDCLASSEXW scalar fields consumed by win32k. The two raw name pointers in the
    /// structure are deliberately ignored because the syscall consumes the separately captured
    /// class/version/menu arguments instead.
    pub fn decode(
        wnd_class: &[u8; WNDCLASSEXW_SIZE],
        class_name: ClassNameIdentity,
        class_version: ClassNameIdentity,
        menu_name: ClassNameIdentity,
        fn_id: u32,
        flags: u32,
    ) -> Option<Self> {
        let u32_at =
            |offset: usize| u32::from_le_bytes(wnd_class[offset..offset + 4].try_into().unwrap());
        let i32_at =
            |offset: usize| i32::from_le_bytes(wnd_class[offset..offset + 4].try_into().unwrap());
        let u64_at =
            |offset: usize| u64::from_le_bytes(wnd_class[offset..offset + 8].try_into().unwrap());
        let style = u32_at(0x04);
        let class_extra = i32_at(0x10);
        let window_extra = i32_at(0x14);
        let instance = u64_at(0x18);
        if u32_at(0) as usize != WNDCLASSEXW_SIZE
            || class_name.is_none()
            || class_version.is_none()
            || class_extra < 0
            || window_extra < 0
            || instance == 0
            || style & CS_GLOBALCLASS == 0
            || !(FNID_BUILTIN_FIRST..=FNID_BUILTIN_LAST).contains(&fn_id)
            || flags != 0
        {
            return None;
        }
        Some(Self {
            class_name,
            class_version,
            menu_name,
            fn_id,
            flags,
        })
    }

    pub const fn fn_id(&self) -> u32 {
        self.fn_id
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.class_name.same_identity(&other.class_name)
            && self.class_version.same_identity(&other.class_version)
            && self.menu_name.same_identity(&other.menu_name)
            && self.fn_id == other.fn_id
            && self.flags == other.flags
    }
}

#[derive(Clone, Copy)]
struct Entry {
    key: Option<BuiltinClassKey>,
    atom: u16,
}

impl Entry {
    const EMPTY: Self = Self { key: None, atom: 0 };
}

pub struct BuiltinClassMirror<const N: usize> {
    entries: [Entry; N],
    next: usize,
}

impl<const N: usize> BuiltinClassMirror<N> {
    pub const fn new() -> Self {
        Self {
            entries: [Entry::EMPTY; N],
            next: 0,
        }
    }

    pub fn observe(&mut self, key: &BuiltinClassKey, atom: u16) {
        if N == 0 || atom == 0 {
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry
                .key
                .is_some_and(|existing| existing.same_identity(key))
        }) {
            entry.atom = atom;
            return;
        }
        self.entries[self.next] = Entry {
            key: Some(*key),
            atom,
        };
        self.next = (self.next + 1) % N;
    }

    pub fn lookup(&self, key: &BuiltinClassKey) -> Option<u16> {
        self.entries
            .iter()
            .find(|entry| {
                entry
                    .key
                    .is_some_and(|existing| existing.same_identity(key))
            })
            .map(|entry| entry.atom)
    }
}

impl<const N: usize> Default for BuiltinClassMirror<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct ClassAtomNameEntry {
    atom: u16,
    len: u16,
    units: [u16; CLASS_ATOM_NAME_CAP],
}

impl ClassAtomNameEntry {
    const EMPTY: Self = Self {
        atom: 0,
        len: 0,
        units: [0; CLASS_ATOM_NAME_CAP],
    };
}

/// Bounded mirror of the dynamic class atom names learned from real successful registrations.
///
/// ReactOS stores USER class names in win32k's session-global atom table. In userspace-ntos the
/// executive sometimes needs that atom name at the cross-VSpace boundary, after the real win32k
/// query had no copyable result. This mirror never invents an atom: callers can only observe a
/// nonzero atom returned by `NtUserRegisterClassExWOW` and later resolve that same atom.
pub struct ClassAtomNameMirror<const N: usize> {
    entries: [ClassAtomNameEntry; N],
    next: usize,
}

impl<const N: usize> ClassAtomNameMirror<N> {
    pub const fn new() -> Self {
        Self {
            entries: [ClassAtomNameEntry::EMPTY; N],
            next: 0,
        }
    }

    pub fn observe(&mut self, atom: u16, units: &[u16]) -> bool {
        if N == 0 || atom == 0 || units.is_empty() || units.len() > CLASS_ATOM_NAME_CAP {
            return false;
        }
        let entry = if let Some(existing) = self.entries.iter_mut().find(|entry| entry.atom == atom)
        {
            existing
        } else {
            let entry = &mut self.entries[self.next];
            self.next = (self.next + 1) % N;
            entry
        };
        entry.atom = atom;
        entry.len = units.len() as u16;
        entry.units.fill(0);
        entry.units[..units.len()].copy_from_slice(units);
        true
    }

    pub fn copy_name(&self, atom: u16, out: &mut [u16]) -> Option<usize> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.atom == atom && entry.len != 0)?;
        let len = entry.len as usize;
        if out.len() < len {
            return None;
        }
        out[..len].copy_from_slice(&entry.units[..len]);
        Some(len)
    }
}

impl<const N: usize> Default for ClassAtomNameMirror<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassInfoPayload {
    atom: u16,
    wnd_class: [u8; WNDCLASSEXW_SIZE],
    menu_name: u64,
}

impl ClassInfoPayload {
    pub const fn atom(&self) -> u16 {
        self.atom
    }

    pub const fn wnd_class(&self) -> &[u8; WNDCLASSEXW_SIZE] {
        &self.wnd_class
    }

    pub const fn menu_name(&self) -> u64 {
        self.menu_name
    }
}

pub fn pfn_client_proc(raw: &[u8], fn_id: u32) -> Option<u64> {
    let index = fn_id.checked_sub(FNID_FIRST)? as usize;
    if index >= PFNCLIENT_ENTRY_COUNT {
        return None;
    }
    let offset = index * 8;
    let bytes: [u8; 8] = raw.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

pub fn is_scrollbar_class_name(units: &[u16]) -> bool {
    units == SCROLLBAR_CLASS_NAME
}

pub fn scrollbar_class_info(
    initial_wnd_class: &[u8; WNDCLASSEXW_SIZE],
    atom: u16,
    wnd_proc: u64,
    hcursor: u64,
) -> Option<ClassInfoPayload> {
    if atom == 0 || wnd_proc == 0 {
        return None;
    }

    let mut wnd = *initial_wnd_class;
    wnd[0x04..0x08].copy_from_slice(&SCROLLBAR_CLASS_STYLE.to_le_bytes());
    wnd[0x08..0x10].copy_from_slice(&wnd_proc.to_le_bytes());
    wnd[0x10..0x14].copy_from_slice(&0u32.to_le_bytes());
    wnd[0x14..0x18].copy_from_slice(&SCROLLBAR_CB_WND_EXTRA.to_le_bytes());
    wnd[0x18..0x20].copy_from_slice(&0u64.to_le_bytes());
    wnd[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
    wnd[0x28..0x30].copy_from_slice(&hcursor.to_le_bytes());
    wnd[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());
    wnd[0x38..0x40].copy_from_slice(&0u64.to_le_bytes());
    wnd[0x48..0x50].copy_from_slice(&0u64.to_le_bytes());

    Some(ClassInfoPayload {
        atom,
        wnd_class: wnd,
        menu_name: 0,
    })
}

pub fn integer_atom_name(atom: u16, out: &mut [u16]) -> Option<usize> {
    if atom >= 0xC000 {
        return None;
    }
    let mut digits = [0u16; 5];
    let mut n = atom as u32;
    let mut digit_count = 0usize;
    if n == 0 {
        digits[0] = b'0' as u16;
        digit_count = 1;
    } else {
        while n > 0 {
            digits[digit_count] = (b'0' + (n % 10) as u8) as u16;
            n /= 10;
            digit_count += 1;
        }
    }
    let len = 1 + digit_count;
    if out.len() < len {
        return None;
    }
    out[0] = b'#' as u16;
    for index in 0..digit_count {
        out[1 + index] = digits[digit_count - 1 - index];
    }
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wnd_class() -> [u8; WNDCLASSEXW_SIZE] {
        let mut raw = [0u8; WNDCLASSEXW_SIZE];
        raw[0..4].copy_from_slice(&(WNDCLASSEXW_SIZE as u32).to_le_bytes());
        raw[4..8].copy_from_slice(&(CS_GLOBALCLASS | 0x0008).to_le_bytes());
        raw[8..16].copy_from_slice(&0x8012_3456u64.to_le_bytes());
        raw[0x14..0x18].copy_from_slice(&0x30i32.to_le_bytes());
        raw[0x18..0x20].copy_from_slice(&0x0040_0000u64.to_le_bytes());
        raw[0x28..0x30].copy_from_slice(&0x0002_0044u64.to_le_bytes());
        raw
    }

    fn dialog(raw: &[u8; WNDCLASSEXW_SIZE]) -> Option<BuiltinClassKey> {
        BuiltinClassKey::decode(
            raw,
            ClassNameIdentity::atom(0x8002),
            ClassNameIdentity::atom(0x8002),
            ClassNameIdentity::none(),
            0x02a4,
            0,
        )
    }

    #[test]
    fn reuses_only_an_observed_real_atom() {
        let key = dialog(&wnd_class()).unwrap();
        let mut mirror = BuiltinClassMirror::<4>::new();
        assert_eq!(mirror.lookup(&key), None);
        mirror.observe(&key, 0x8002);
        assert_eq!(mirror.lookup(&key), Some(0x8002));
    }

    #[test]
    fn rejects_bad_layout_private_or_nonbuiltin_classes() {
        let mut raw = wnd_class();
        raw[0..4].copy_from_slice(&0x48u32.to_le_bytes());
        assert!(dialog(&raw).is_none());
        raw = wnd_class();
        raw[4..8].copy_from_slice(&0x0008u32.to_le_bytes());
        assert!(dialog(&raw).is_none());
        assert!(BuiltinClassKey::decode(
            &wnd_class(),
            ClassNameIdentity::atom(0x8002),
            ClassNameIdentity::atom(0x8002),
            ClassNameIdentity::none(),
            0,
            0,
        )
        .is_none());
    }

    #[test]
    fn class_name_version_menu_and_fnid_participate_in_identity() {
        let raw = wnd_class();
        let key = dialog(&raw).unwrap();
        let mut mirror = BuiltinClassMirror::<4>::new();
        mirror.observe(&key, 0x8002);

        let changed_name = BuiltinClassKey::decode(
            &raw,
            ClassNameIdentity::atom(0x8003),
            ClassNameIdentity::atom(0x8003),
            ClassNameIdentity::none(),
            0x02a4,
            0,
        )
        .unwrap();
        assert_eq!(mirror.lookup(&changed_name), None);
        let changed_fnid = BuiltinClassKey::decode(
            &raw,
            ClassNameIdentity::atom(0x8002),
            ClassNameIdentity::atom(0x8002),
            ClassNameIdentity::none(),
            0x02a5,
            0,
        )
        .unwrap();
        assert_eq!(mirror.lookup(&changed_fnid), None);
    }

    #[test]
    fn caller_specific_wndclass_payload_does_not_break_builtin_reuse() {
        let raw = wnd_class();
        let key = dialog(&raw).unwrap();
        let mut mirror = BuiltinClassMirror::<4>::new();
        mirror.observe(&key, 0x8002);

        let mut changed = raw;
        changed[0x08..0x10].copy_from_slice(&0x9000_0000u64.to_le_bytes());
        changed[0x18..0x20].copy_from_slice(&0x0050_0000u64.to_le_bytes());
        changed[0x28..0x30].copy_from_slice(&0x0002_0046u64.to_le_bytes());
        assert_eq!(mirror.lookup(&dialog(&changed).unwrap()), Some(0x8002));
    }

    #[test]
    fn named_menu_matches_case_insensitively_but_not_atom_or_null() {
        let raw = wnd_class();
        let lower: alloc::vec::Vec<u16> = "menu".encode_utf16().collect();
        let upper: alloc::vec::Vec<u16> = "MENU".encode_utf16().collect();
        let with_menu = |menu| {
            BuiltinClassKey::decode(
                &raw,
                ClassNameIdentity::atom(0x8002),
                ClassNameIdentity::atom(0x8002),
                menu,
                0x02a4,
                0,
            )
            .unwrap()
        };
        let key = with_menu(ClassNameIdentity::name(&lower).unwrap());
        let mut mirror = BuiltinClassMirror::<4>::new();
        mirror.observe(&key, 0x8002);
        assert_eq!(
            mirror.lookup(&with_menu(ClassNameIdentity::name(&upper).unwrap())),
            Some(0x8002)
        );
        assert_eq!(mirror.lookup(&with_menu(ClassNameIdentity::atom(1))), None);
        assert_eq!(mirror.lookup(&with_menu(ClassNameIdentity::none())), None);
    }

    #[test]
    fn class_atom_name_mirror_resolves_only_observed_atoms() {
        let name: alloc::vec::Vec<u16> = "ATL:ExplorerBand".encode_utf16().collect();
        let mut mirror = ClassAtomNameMirror::<2>::new();
        assert_eq!(
            mirror.copy_name(0xc052, &mut [0u16; CLASS_ATOM_NAME_CAP]),
            None
        );
        assert!(mirror.observe(0xc052, &name));

        let mut out = [0u16; CLASS_ATOM_NAME_CAP];
        let len = mirror.copy_name(0xc052, &mut out).unwrap();
        assert_eq!(&out[..len], &name[..]);
        assert_eq!(mirror.copy_name(0xc053, &mut out), None);
    }

    #[test]
    fn class_atom_name_mirror_replaces_entries_boundedly() {
        let first: alloc::vec::Vec<u16> = "First".encode_utf16().collect();
        let second: alloc::vec::Vec<u16> = "Second".encode_utf16().collect();
        let third: alloc::vec::Vec<u16> = "Third".encode_utf16().collect();
        let mut mirror = ClassAtomNameMirror::<2>::new();
        assert!(mirror.observe(0xc001, &first));
        assert!(mirror.observe(0xc002, &second));
        assert!(mirror.observe(0xc003, &third));

        let mut out = [0u16; CLASS_ATOM_NAME_CAP];
        assert_eq!(mirror.copy_name(0xc001, &mut out), None);
        let len = mirror.copy_name(0xc002, &mut out).unwrap();
        assert_eq!(&out[..len], &second[..]);
        let len = mirror.copy_name(0xc003, &mut out).unwrap();
        assert_eq!(&out[..len], &third[..]);
    }

    #[test]
    fn class_atom_name_mirror_rejects_empty_or_oversized_names() {
        let mut mirror = ClassAtomNameMirror::<2>::new();
        assert!(!mirror.observe(0xc001, &[]));
        assert!(!mirror.observe(0, &[b'A' as u16]));
        let oversized = [b'X' as u16; CLASS_ATOM_NAME_CAP + 1];
        assert!(!mirror.observe(0xc002, &oversized));
    }

    #[test]
    fn integer_atom_name_uses_makeintatom_decimal_form() {
        let mut out = [0u16; 8];
        let len = integer_atom_name(0x8002, &mut out).unwrap();
        let expected: alloc::vec::Vec<u16> = "#32770".encode_utf16().collect();
        assert_eq!(&out[..len], &expected[..]);
        assert_eq!(integer_atom_name(0xc000, &mut out), None);
        assert_eq!(integer_atom_name(42, &mut [0u16; 2]), None);
    }

    #[test]
    fn pfn_client_proc_decodes_fnid_indexed_entries() {
        let mut raw = [0u8; PFNCLIENT_SIZE];
        raw[0..8].copy_from_slice(&0x8012_3456u64.to_le_bytes());
        raw[6 * 8..7 * 8].copy_from_slice(&0x8077_1122u64.to_le_bytes());

        assert_eq!(
            pfn_client_proc(&raw, FNID_SCROLLBAR),
            Some(0x8012_3456)
        );
        assert_eq!(pfn_client_proc(&raw, FNID_FIRST + 6), Some(0x8077_1122));
        assert_eq!(pfn_client_proc(&raw[..7], FNID_SCROLLBAR), None);
        assert_eq!(pfn_client_proc(&raw, FNID_FIRST - 1), None);
        assert_eq!(
            pfn_client_proc(&raw, FNID_FIRST + PFNCLIENT_ENTRY_COUNT as u32),
            None
        );
    }

    #[test]
    fn scrollbar_class_name_matches_reactos_system_class() {
        assert!(is_scrollbar_class_name(&SCROLLBAR_CLASS_NAME));
        assert!(!is_scrollbar_class_name(&[
            b's' as u16,
            b'c' as u16,
            b'r' as u16,
            b'o' as u16,
            b'l' as u16,
            b'l' as u16,
            b'B' as u16,
            b'a' as u16,
            b'r' as u16,
        ]));
        assert!(!is_scrollbar_class_name(&SCROLLBAR_CLASS_NAME[..8]));
    }

    #[test]
    fn scrollbar_class_info_uses_real_client_proc_and_system_shape() {
        let mut initial = [0xccu8; WNDCLASSEXW_SIZE];
        initial[0..4].copy_from_slice(&(WNDCLASSEXW_SIZE as u32).to_le_bytes());
        initial[0x40..0x48].copy_from_slice(&0x1234_5678u64.to_le_bytes());

        let payload =
            scrollbar_class_info(&initial, 0xc004, 0x8020_1000, 0x0001_0005).unwrap();
        let wnd = payload.wnd_class();

        assert_eq!(payload.atom(), 0xc004);
        assert_eq!(payload.menu_name(), 0);
        assert_eq!(
            u32::from_le_bytes(wnd[0x04..0x08].try_into().unwrap()),
            SCROLLBAR_CLASS_STYLE
        );
        assert_eq!(
            u64::from_le_bytes(wnd[0x08..0x10].try_into().unwrap()),
            0x8020_1000
        );
        assert_eq!(
            u32::from_le_bytes(wnd[0x14..0x18].try_into().unwrap()),
            SCROLLBAR_CB_WND_EXTRA
        );
        assert_eq!(
            u64::from_le_bytes(wnd[0x28..0x30].try_into().unwrap()),
            0x0001_0005
        );
        assert_eq!(
            u64::from_le_bytes(wnd[0x38..0x40].try_into().unwrap()),
            0
        );
        assert_eq!(
            u64::from_le_bytes(wnd[0x40..0x48].try_into().unwrap()),
            0x1234_5678
        );
        assert_eq!(scrollbar_class_info(&initial, 0, 0x8020_1000, 0), None);
        assert_eq!(scrollbar_class_info(&initial, 0xc004, 0, 0), None);
    }
}
