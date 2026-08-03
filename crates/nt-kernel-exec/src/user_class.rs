//! Exact identities and layout helpers for USER32 builtin classes.

use crate::user_cursor::CursorResource;

pub const WNDCLASSEXW_SIZE: usize = 0x50;
pub const CS_GLOBALCLASS: u32 = 0x4000;
pub const FNID_BUILTIN_FIRST: u32 = 0x02a1;
pub const FNID_BUILTIN_LAST: u32 = 0x02aa;
pub const CLASS_ATOM_NAME_CAP: usize = 255;
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

    pub fn same_identity(&self, other: &Self) -> bool {
        self.class_name.same_identity(&other.class_name)
            && self.class_version.same_identity(&other.class_version)
            && self.menu_name.same_identity(&other.menu_name)
            && self.fn_id == other.fn_id
            && self.flags == other.flags
    }
}

pub fn is_scrollbar_class_name(units: &[u16]) -> bool {
    units == SCROLLBAR_CLASS_NAME
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

        let changed_name = BuiltinClassKey::decode(
            &raw,
            ClassNameIdentity::atom(0x8003),
            ClassNameIdentity::atom(0x8003),
            ClassNameIdentity::none(),
            0x02a4,
            0,
        )
        .unwrap();
        assert!(!key.same_identity(&changed_name));
        let changed_fnid = BuiltinClassKey::decode(
            &raw,
            ClassNameIdentity::atom(0x8002),
            ClassNameIdentity::atom(0x8002),
            ClassNameIdentity::none(),
            0x02a5,
            0,
        )
        .unwrap();
        assert!(!key.same_identity(&changed_fnid));
    }

    #[test]
    fn caller_specific_wndclass_payload_does_not_break_builtin_reuse() {
        let raw = wnd_class();
        let key = dialog(&raw).unwrap();

        let mut changed = raw;
        changed[0x08..0x10].copy_from_slice(&0x9000_0000u64.to_le_bytes());
        changed[0x18..0x20].copy_from_slice(&0x0050_0000u64.to_le_bytes());
        changed[0x28..0x30].copy_from_slice(&0x0002_0046u64.to_le_bytes());
        assert!(key.same_identity(&dialog(&changed).unwrap()));
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
        assert!(key.same_identity(&with_menu(ClassNameIdentity::name(&upper).unwrap())));
        assert!(!key.same_identity(&with_menu(ClassNameIdentity::atom(1))));
        assert!(!key.same_identity(&with_menu(ClassNameIdentity::none())));
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
}
