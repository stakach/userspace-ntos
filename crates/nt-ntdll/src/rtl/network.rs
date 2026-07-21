//! `RtlIpv4*` network address formatting helpers.
//!
//! Category A. These are pure string-formatting routines; the DLL export layer handles raw pointers
//! and ABI return values.

use alloc::vec::Vec;

pub const IPV4_ADDR_STRING_MAX_LEN: usize = 16; // "255.255.255.255" + NUL
pub const IPV4_PORT_STRING_MAX_LEN: usize = 6; // ":65535"

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4AddressParse {
    pub address: [u8; 4],
    pub terminator: usize,
}

/// Format an IPv4 address as ASCII octets (`a.b.c.d`).
pub fn ipv4_address_to_string(address: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(IPV4_ADDR_STRING_MAX_LEN - 1);
    push_ipv4(&mut out, address);
    out
}

/// Format an IPv4 address plus optional network-byte-order port.
pub fn ipv4_address_to_string_ex(address: [u8; 4], port_network_order: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(IPV4_ADDR_STRING_MAX_LEN + IPV4_PORT_STRING_MAX_LEN - 1);
    push_ipv4(&mut out, address);
    if port_network_order != 0 {
        out.push(b':');
        push_decimal(&mut out, u16::from_be(port_network_order));
    }
    out
}

/// UTF-16 form of [`ipv4_address_to_string`].
pub fn ipv4_address_to_string_w(address: [u8; 4]) -> Vec<u16> {
    ipv4_address_to_string(address)
        .into_iter()
        .map(u16::from)
        .collect()
}

/// UTF-16 form of [`ipv4_address_to_string_ex`].
pub fn ipv4_address_to_string_ex_w(address: [u8; 4], port_network_order: u16) -> Vec<u16> {
    ipv4_address_to_string_ex(address, port_network_order)
        .into_iter()
        .map(u16::from)
        .collect()
}

/// Parse an ANSI IPv4 string. Non-strict mode accepts the classic ntdll shortened/octal/hex forms.
pub fn ipv4_string_to_address_a(
    string: &[u8],
    strict: bool,
) -> Result<Ipv4AddressParse, usize> {
    let wide: Vec<u16> = string.iter().copied().map(u16::from).collect();
    ipv4_string_to_address_w(&wide, strict)
}

/// Parse a UTF-16 IPv4 string. The returned terminator is a UTF-16 code-unit offset.
pub fn ipv4_string_to_address_w(
    string: &[u16],
    strict: bool,
) -> Result<Ipv4AddressParse, usize> {
    let parsed = parse_ipv4_parts(string, strict);
    if !parsed.ok || (strict && parsed.parts < 4) {
        return Err(parsed.terminator);
    }
    let address = combine_ipv4_parts(&parsed.values, parsed.parts)
        .ok_or(parsed.terminator)?
        .to_be_bytes();
    Ok(Ipv4AddressParse {
        address,
        terminator: parsed.terminator,
    })
}

/// Parse an ANSI port after an IPv4 `:` suffix. Returns the port in network byte order.
pub fn ipv4_parse_port_a(string: &[u8]) -> Result<u16, usize> {
    let wide: Vec<u16> = string.iter().copied().map(u16::from).collect();
    ipv4_parse_port_w(&wide)
}

/// Parse a UTF-16 port after an IPv4 `:` suffix. Returns the port in network byte order.
pub fn ipv4_parse_port_w(string: &[u16]) -> Result<u16, usize> {
    let parsed = parse_ulong(string, 0, false);
    if !parsed.ok || parsed.terminator != string.len() || parsed.value == 0 || parsed.value > 0xFFFF
    {
        return Err(parsed.terminator);
    }
    Ok((parsed.value as u16).to_be())
}

fn push_ipv4(out: &mut Vec<u8>, address: [u8; 4]) {
    for (i, octet) in address.into_iter().enumerate() {
        if i != 0 {
            out.push(b'.');
        }
        push_decimal(out, octet as u16);
    }
}

fn push_decimal(out: &mut Vec<u8>, mut value: u16) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 5];
    let mut len = 0usize;
    while value != 0 {
        buf[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    while len != 0 {
        len -= 1;
        out.push(buf[len]);
    }
}

#[derive(Clone, Copy)]
struct PartsParse {
    ok: bool,
    terminator: usize,
    values: [u32; 4],
    parts: usize,
}

#[derive(Clone, Copy)]
struct UlongParse {
    ok: bool,
    terminator: usize,
    value: u32,
}

fn parse_ipv4_parts(string: &[u16], strict: bool) -> PartsParse {
    let mut values = [0u32; 4];
    let mut parts = 0usize;
    let mut index = 0usize;
    let mut ok;
    loop {
        let parsed = parse_ulong(string, index, strict);
        ok = parsed.ok;
        values[parts] = parsed.value;
        parts += 1;
        index = parsed.terminator;

        if char_at(string, index) != b'.' as u16 {
            break;
        }
        if parts == 4 {
            ok = false;
            break;
        }
        index += 1;
        if !ok {
            break;
        }
    }
    PartsParse {
        ok,
        terminator: index,
        values,
        parts,
    }
}

fn parse_ulong(string: &[u16], start: usize, strict: bool) -> UlongParse {
    let mut index = start;
    let mut base = 10u32;
    if char_at(string, index) == b'0' as u16 {
        let next = char_at(string, index + 1);
        if next == b'x' as u16 || next == b'X' as u16 {
            index += 2;
            base = 16;
        } else if is_ascii_digit(next) {
            index += 1;
            base = 8;
        }
    }
    if strict && base != 10 {
        return UlongParse {
            ok: false,
            terminator: index,
            value: 0,
        };
    }
    parse_ulong_base(string, index, base)
}

fn parse_ulong_base(string: &[u16], mut index: usize, base: u32) -> UlongParse {
    let mut ok = false;
    let mut result = 0u32;
    loop {
        let Some(digit) = digit_value(char_at(string, index), base) else {
            break;
        };
        let Some(multiplied) = result.checked_mul(base) else {
            return UlongParse {
                ok: false,
                terminator: index,
                value: result,
            };
        };
        let Some(next) = multiplied.checked_add(digit) else {
            return UlongParse {
                ok: false,
                terminator: index,
                value: result,
            };
        };
        result = next;
        ok = true;
        index += 1;
    }
    UlongParse {
        ok,
        terminator: index,
        value: result,
    }
}

fn combine_ipv4_parts(values: &[u32; 4], parts: usize) -> Option<u32> {
    if parts == 0 || parts > 4 {
        return None;
    }
    let mut result = values[parts - 1];
    for (i, value) in values.iter().copied().enumerate().take(parts - 1) {
        let shift = 8 * (3 - i);
        if value > 0xFF || (result & (0xFFu32 << shift)) != 0 {
            return None;
        }
        result |= value << shift;
    }
    Some(result)
}

fn char_at(string: &[u16], index: usize) -> u16 {
    string.get(index).copied().unwrap_or(0)
}

fn is_ascii_digit(c: u16) -> bool {
    (b'0' as u16..=b'9' as u16).contains(&c)
}

fn digit_value(c: u16, base: u32) -> Option<u32> {
    let digit = if is_ascii_digit(c) {
        (c - b'0' as u16) as u32
    } else {
        let lower = if (b'A' as u16..=b'Z' as u16).contains(&c) {
            c + 0x20
        } else {
            c
        };
        if (b'a' as u16..=b'f' as u16).contains(&lower) {
            (lower - b'a' as u16 + 10) as u32
        } else {
            return None;
        }
    };
    if digit < base { Some(digit) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn formats_ipv4_address() {
        assert_eq!(ipv4_address_to_string([1, 2, 3, 4]), b"1.2.3.4");
        assert_eq!(
            ipv4_address_to_string([255, 255, 255, 255]),
            b"255.255.255.255"
        );
        assert_eq!(
            ipv4_address_to_string_w([127, 0, 0, 1]),
            wide("127.0.0.1")
        );
    }

    #[test]
    fn formats_ipv4_address_with_network_order_port() {
        assert_eq!(
            ipv4_address_to_string_ex([1, 2, 3, 4], 80u16.to_be()),
            b"1.2.3.4:80"
        );
        assert_eq!(
            ipv4_address_to_string_ex([1, 2, 3, 4], 0),
            b"1.2.3.4"
        );
        assert_eq!(
            ipv4_address_to_string_ex_w([1, 2, 3, 4], 65535u16.to_be()),
            wide("1.2.3.4:65535")
        );
    }

    #[test]
    fn max_lengths_match_windows_constants() {
        assert_eq!(
            ipv4_address_to_string([255, 255, 255, 255]).len() + 1,
            IPV4_ADDR_STRING_MAX_LEN
        );
        assert_eq!(
            ipv4_address_to_string_ex([255, 255, 255, 255], 65535u16.to_be()).len() + 1,
            IPV4_ADDR_STRING_MAX_LEN + IPV4_PORT_STRING_MAX_LEN
        );
    }

    #[test]
    fn parses_dotted_ipv4_addresses() {
        let parsed = ipv4_string_to_address_a(b"1.2.3.4", false).unwrap();
        assert_eq!(parsed.address, [1, 2, 3, 4]);
        assert_eq!(parsed.terminator, 7);

        let parsed = ipv4_string_to_address_w(&wide("255.255.255.255:123"), false).unwrap();
        assert_eq!(parsed.address, [255, 255, 255, 255]);
        assert_eq!(parsed.terminator, 15);

        assert_eq!(ipv4_string_to_address_a(b"255.255.255.256", false), Err(15));
        assert_eq!(ipv4_string_to_address_a(b"1.2.3", true), Err(5));
    }

    #[test]
    fn parses_non_strict_radix_and_short_forms() {
        assert_eq!(
            ipv4_string_to_address_a(b"1.1.1.0xff", false)
                .unwrap()
                .address,
            [1, 1, 1, 255]
        );
        assert_eq!(
            ipv4_string_to_address_a(b"1.1.1.010", false)
                .unwrap()
                .address,
            [1, 1, 1, 8]
        );
        assert_eq!(
            ipv4_string_to_address_a(b"203569230", false)
                .unwrap()
                .address,
            [12, 34, 56, 78]
        );
        assert_eq!(
            ipv4_string_to_address_a(b"1.223756", false)
                .unwrap()
                .address,
            [1, 3, 106, 12]
        );
        assert_eq!(
            ipv4_string_to_address_a(b"017700000001", false)
                .unwrap()
                .address,
            [127, 0, 0, 1]
        );
    }

    #[test]
    fn reports_reactos_terminators_for_malformed_parts() {
        assert_eq!(ipv4_string_to_address_a(b".", false), Err(1));
        assert_eq!(ipv4_string_to_address_a(b"1..2", false), Err(3));
        assert_eq!(ipv4_string_to_address_a(b"1.2.", false), Err(4));
        assert_eq!(ipv4_string_to_address_a(b"3.4.5.6.7", false), Err(7));
        assert_eq!(ipv4_string_to_address_a(b"1.1.1.08", false), Err(7));
        assert_eq!(ipv4_string_to_address_a(b"1.1.1.008", false).unwrap().terminator, 8);
    }

    #[test]
    fn parses_ipv4_ports() {
        assert_eq!(ipv4_parse_port_a(b"1").unwrap(), 1u16.to_be());
        assert_eq!(ipv4_parse_port_a(b"65535").unwrap(), 65535u16.to_be());
        assert_eq!(ipv4_parse_port_a(b"0xffff").unwrap(), 65535u16.to_be());
        assert_eq!(ipv4_parse_port_a(b"011064").unwrap(), 0x1234u16.to_be());
        assert!(ipv4_parse_port_a(b"").is_err());
        assert!(ipv4_parse_port_a(b"0").is_err());
        assert!(ipv4_parse_port_a(b"65536").is_err());
        assert!(ipv4_parse_port_a(b"1234a").is_err());
    }
}
