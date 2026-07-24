//! Stateful DOS 8.3 short-name generation.

use alloc::vec::Vec;

const SHORT_ILLEGALS: [u32; 4] = [0xffff_ffff, 0xfc00_9c04, 0x3800_0000, 0x1000_0000];

/// Native `GENERATE_NAME_CONTEXT` layout.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GenerateNameContext {
    /// Checksum of the long name used after the fourth collision.
    pub checksum: u16,
    /// Whether checksum digits have been inserted into `name_buffer`.
    pub checksum_inserted: u8,
    /// Used UTF-16 units in `name_buffer`.
    pub name_length: u8,
    /// Short-name stem basis.
    pub name_buffer: [u16; 8],
    /// Used UTF-16 units in `extension_buffer`.
    pub extension_length: u32,
    /// Dot plus up to three extension units.
    pub extension_buffer: [u16; 4],
    /// Collision suffix counter.
    pub last_index_value: u32,
}

/// Result of mapping an extended Unicode character through the active OEM code page.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OemMappedChar {
    /// Round-tripped and uppercased Unicode unit.
    pub unit: u16,
    /// OEM byte width, one for SBCS and one or two for DBCS.
    pub width: u8,
}

fn is_short_illegal(unit: u16) -> bool {
    unit < 128 && SHORT_ILLEGALS[unit as usize / 32] & (1u32 << (unit as usize % 32)) != 0
}

/// Validate an already-upcased counted OEM name using `RtlIsNameLegalDOS8Dot3` rules.
///
/// `Some(spaces)` is a legal name and reports whether it contains an interior space. `None` is
/// illegal; native callers must leave their `NameContainsSpaces` output untouched in that case.
pub fn legal_dos_8dot3_oem(name: &[u8]) -> Option<bool> {
    const ILLEGAL: &[u8] = b"*?<>|\"+=,;[]:/\\\xe5\0";

    if name.is_empty() || name.len() > 12 {
        return None;
    }
    if name[0] == b'.' {
        return matches!(name, b"." | b"..").then_some(false);
    }

    let mut dot = None;
    let mut spaces = false;
    for (index, &byte) in name.iter().enumerate() {
        match byte {
            b' ' => {
                if index == 0 || index + 1 == name.len() || name[index + 1] == b'.' {
                    return None;
                }
                spaces = true;
            }
            b'.' => {
                if dot.replace(index).is_some() {
                    return None;
                }
            }
            _ if ILLEGAL.contains(&byte) => return None,
            _ => {}
        }
    }

    match dot {
        None if name.len() > 8 => None,
        Some(position)
            if position > 8 || name.len() - position > 4 || position + 1 == name.len() =>
        {
            None
        }
        _ => Some(spaces),
    }
}

fn checksum(name: &[u16]) -> u16 {
    match name {
        [] => 0,
        [unit] => *unit,
        _ => {
            let mut hash = name[0].wrapping_shl(8).wrapping_add(name[1]);
            if name.len() == 2 {
                return hash;
            }
            let mut saved = hash;
            let mut length = 2usize;
            loop {
                hash = hash.wrapping_shl(7).wrapping_add(name[length]);
                hash = (saved >> 1).wrapping_add(hash.wrapping_shl(8));
                if length + 1 < name.len() {
                    hash = hash.wrapping_add(name[length + 1]);
                }
                saved = hash;
                length += 2;
                if length >= name.len() {
                    return hash;
                }
            }
        }
    }
}

fn checksum_digit(value: u16) -> u16 {
    if value > 9 {
        b'A' as u16 + value - 10
    } else {
        b'0' as u16 + value
    }
}

fn write_checksum_digits(destination: &mut [u16], mut value: u16) {
    for unit in destination.iter_mut().take(4) {
        *unit = checksum_digit(value & 0xf);
        value >>= 4;
    }
}

/// Generate the next 8.3 candidate using ReactOS's stateful collision algorithm.
pub fn generate_8dot3_name(
    name: &[u16],
    allow_extended_characters: bool,
    context: &mut GenerateNameContext,
    mut map_extended: impl FnMut(u16) -> Option<OemMappedChar>,
) -> Vec<u16> {
    if context.name_length == 0 {
        let dot_position = name
            .iter()
            .rposition(|&unit| unit == b'.' as u16)
            .unwrap_or(name.len());

        let mut oem_size_left = 6u8;
        for &original in &name[..dot_position] {
            if oem_size_left == 0 {
                break;
            }
            if original <= b' ' as u16 || original == b'.' as u16 {
                continue;
            }

            let mapped = if original < 127 {
                let unit = if is_short_illegal(original) {
                    b'_' as u16
                } else if (b'a' as u16..=b'z' as u16).contains(&original) {
                    original - (b'a' - b'A') as u16
                } else {
                    original
                };
                Some(OemMappedChar { unit, width: 1 })
            } else if allow_extended_characters {
                map_extended(original)
            } else {
                None
            };
            let Some(mapped) = mapped else {
                continue;
            };
            let width = mapped.width.clamp(1, 2);
            if width > oem_size_left {
                break;
            }
            context.name_buffer[context.name_length as usize] = mapped.unit;
            context.name_length += 1;
            oem_size_left -= width;
        }

        context.extension_length = 0;
        if dot_position < name.len() {
            context.extension_buffer[0] = b'.' as u16;
            context.extension_length = 1;
            for &original in &name[dot_position..] {
                if context.extension_length >= 4 {
                    break;
                }
                if original <= b' ' as u16 || original == b'.' as u16 {
                    continue;
                }
                let mapped = if original < 127 {
                    let unit = if is_short_illegal(original) {
                        b'_' as u16
                    } else if (b'a' as u16..=b'z' as u16).contains(&original) {
                        original - (b'a' - b'A') as u16
                    } else {
                        original
                    };
                    Some(unit)
                } else if allow_extended_characters {
                    map_extended(original).map(|mapped| mapped.unit)
                } else {
                    None
                };
                if let Some(unit) = mapped {
                    context.extension_buffer[context.extension_length as usize] = unit;
                    context.extension_length += 1;
                }
            }
        }

        if context.name_length <= 2 {
            context.checksum = checksum(name);
            let start = context.name_length as usize;
            write_checksum_digits(&mut context.name_buffer[start..start + 4], context.checksum);
            context.checksum_inserted = 1;
            context.name_length += 4;
        }
    }

    context.last_index_value = context.last_index_value.wrapping_add(1);
    if context.last_index_value > 4 && context.checksum_inserted == 0 {
        context.checksum = checksum(name);
        write_checksum_digits(&mut context.name_buffer[2..6], context.checksum);
        context.checksum_inserted = 1;
        context.name_length = 6;
        context.last_index_value = 1;
    }

    let mut index = context.last_index_value;
    let mut reverse_digits = [0u16; 7];
    let mut digit_count = 0usize;
    while digit_count < reverse_digits.len() && index > 0 {
        reverse_digits[digit_count] = b'0' as u16 + (index % 10) as u16;
        digit_count += 1;
        index /= 10;
    }

    let mut output = Vec::with_capacity(context.name_length as usize + digit_count + 5);
    output.extend_from_slice(&context.name_buffer[..context.name_length as usize]);
    output.push(b'~' as u16);
    output.extend(reverse_digits[..digit_count].iter().rev().copied());
    output.extend_from_slice(&context.extension_buffer[..context.extension_length as usize]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    fn u(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn s(value: &[u16]) -> alloc::string::String {
        alloc::string::String::from_utf16(value).unwrap()
    }

    fn ascii(name: &str, context: &mut GenerateNameContext) -> alloc::string::String {
        s(&generate_8dot3_name(&u(name), false, context, |_| None))
    }

    #[test]
    fn context_layout_matches_nt() {
        assert_eq!(size_of::<GenerateNameContext>(), 36);
        assert_eq!(align_of::<GenerateNameContext>(), 4);
        assert_eq!(offset_of!(GenerateNameContext, checksum), 0);
        assert_eq!(offset_of!(GenerateNameContext, checksum_inserted), 2);
        assert_eq!(offset_of!(GenerateNameContext, name_length), 3);
        assert_eq!(offset_of!(GenerateNameContext, name_buffer), 4);
        assert_eq!(offset_of!(GenerateNameContext, extension_length), 20);
        assert_eq!(offset_of!(GenerateNameContext, extension_buffer), 24);
        assert_eq!(offset_of!(GenerateNameContext, last_index_value), 32);
    }

    #[test]
    fn ascii_names_and_collisions() {
        let mut context = GenerateNameContext::default();
        assert_eq!(ascii("Long file name.txt", &mut context), "LONGFI~1.TXT");
        assert_eq!(ascii("Long file name.txt", &mut context), "LONGFI~2.TXT");
        assert_eq!(
            ascii("a+b.txt", &mut GenerateNameContext::default()),
            "A_B~1.TXT"
        );
        assert_eq!(
            ascii("foo.bar.baz", &mut GenerateNameContext::default()),
            "FOOBAR~1.BAZ"
        );
    }

    #[test]
    fn fifth_collision_inserts_reversed_checksum_digits() {
        let mut context = GenerateNameContext::default();
        let expected = [
            "LONGFI~1.TXT",
            "LONGFI~2.TXT",
            "LONGFI~3.TXT",
            "LONGFI~4.TXT",
            "LO1796~1.TXT",
            "LO1796~2.TXT",
        ];
        for (index, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                ascii(
                    &alloc::format!("Long File Name {}.txt", index + 1),
                    &mut context
                ),
                expected
            );
        }
    }

    #[test]
    fn short_and_non_ascii_stems_use_checksum() {
        assert_eq!(
            ascii("ab.txt", &mut GenerateNameContext::default()),
            "AB6082~1.TXT"
        );
        assert_eq!(
            ascii(
                "\u{30c7}\u{30b9}\u{30af}\u{30c8}\u{30c3}\u{30d7}",
                &mut GenerateNameContext::default()
            ),
            "9A16~1"
        );
        assert_eq!(
            ascii("Menu D\u{e9}marrer", &mut GenerateNameContext::default()),
            "MENUDM~1"
        );
    }

    #[test]
    fn injected_extended_oem_mapping_is_used() {
        let mut context = GenerateNameContext::default();
        let output = generate_8dot3_name(&u("Menu D\u{e9}marrer"), true, &mut context, |unit| {
            Some(OemMappedChar {
                unit: crate::rtl::strings::upcase_char(unit),
                width: 1,
            })
        });
        assert_eq!(s(&output), "MENUD\u{c9}~1");
    }

    #[test]
    fn legal_oem_names_match_reactos_vectors() {
        let cases: &[(&[u8], Option<bool>)] = &[
            (b"12345678", Some(false)),
            (b"123 5678", Some(true)),
            (b"12345678.", None),
            (b"1234 678.", None),
            (b"12345678.A", Some(false)),
            (b"12345678.A ", None),
            (b"12345678.A C", Some(true)),
            (b" 2345678.A ", None),
            (b"1 345678.ABC", Some(true)),
            (b"1      8.A C", Some(true)),
            (b"1 3 5 7 .ABC", None),
            (b"12345678.  C", Some(true)),
            (b"123456789.A", None),
            (b"12345.ABCD", None),
            (b"12345.AB D", None),
            (b".ABC", None),
            (b"12.ABC.D", None),
            (b".", Some(false)),
            (b"..", Some(false)),
            (b"...", None),
            (b"", None),
        ];
        for &(name, expected) in cases {
            assert_eq!(legal_dos_8dot3_oem(name), expected, "{name:?}");
        }
    }

    #[test]
    fn legal_oem_names_reject_native_illegal_bytes() {
        for byte in b"*?<>|\"+=,;[]:/\\".iter().copied().chain([0xe5, 0]) {
            assert_eq!(legal_dos_8dot3_oem(&[b'A', byte]), None, "{byte:#x}");
        }
    }
}
