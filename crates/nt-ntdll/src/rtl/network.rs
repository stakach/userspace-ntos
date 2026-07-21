//! `RtlIpv4*` / `RtlIpv6*` network address formatting helpers.
//!
//! Category A. These are pure string-formatting routines; the DLL export layer handles raw pointers
//! and ABI return values.

use alloc::vec::Vec;

pub const IPV4_ADDR_STRING_MAX_LEN: usize = 16; // "255.255.255.255" + NUL
pub const IPV4_PORT_STRING_MAX_LEN: usize = 6; // ":65535"
pub const IPV6_ADDR_STRING_MAX_LEN: usize = 46;
pub const IPV6_ADDR_EX_STRING_MAX_LEN: usize = 65;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4AddressParse {
    pub address: [u8; 4],
    pub terminator: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6AddressParse {
    pub address: [u8; 16],
    pub terminator: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6AddressExParse {
    pub address: [u8; 16],
    pub scope_id: u32,
    pub port: u16,
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

/// Format an IPv6 address using the same canonicalization as ReactOS/Wine `RtlIpv6AddressToString`.
pub fn ipv6_address_to_string(address: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(IPV6_ADDR_STRING_MAX_LEN - 1);
    let raw_words = ipv6_raw_words(address);

    if raw_words[..4] == [0, 0, 0, 0] && raw_words[6] != 0 {
        let prefix = if raw_words[4] == 0xffff && raw_words[5] == 0 {
            Some(&b"ffff:0:"[..])
        } else if raw_words[4] == 0 && raw_words[5] == 0xffff {
            Some(&b"ffff:"[..])
        } else if raw_words[4] == 0 && raw_words[5] == 0 {
            Some(&b""[..])
        } else {
            None
        };
        if let Some(prefix) = prefix {
            out.extend_from_slice(b"::");
            out.extend_from_slice(prefix);
            push_ipv4(
                &mut out,
                [address[12], address[13], address[14], address[15]],
            );
            return out;
        }
    }

    let parts = if (raw_words[4] & 0xfffd) == 0 && raw_words[5] == 0xfe5e {
        6
    } else {
        8
    };
    push_ipv6_words(&mut out, &raw_words, parts);
    if parts < 8 {
        out.push(b':');
        push_ipv4(
            &mut out,
            [address[12], address[13], address[14], address[15]],
        );
    }
    out
}

/// Format an IPv6 address plus optional scope id and network-byte-order port.
pub fn ipv6_address_to_string_ex(
    address: [u8; 16],
    scope_id: u32,
    port_network_order: u16,
) -> Vec<u8> {
    let address = ipv6_address_to_string(address);
    let mut out = Vec::with_capacity(IPV6_ADDR_EX_STRING_MAX_LEN - 1);
    if port_network_order != 0 {
        out.push(b'[');
    }
    out.extend_from_slice(&address);
    if scope_id != 0 {
        out.push(b'%');
        push_decimal_u32(&mut out, scope_id);
    }
    if port_network_order != 0 {
        out.extend_from_slice(b"]:");
        push_decimal_u32(&mut out, u16::from_be(port_network_order) as u32);
    }
    out
}

/// UTF-16 form of [`ipv6_address_to_string`].
pub fn ipv6_address_to_string_w(address: [u8; 16]) -> Vec<u16> {
    ipv6_address_to_string(address)
        .into_iter()
        .map(u16::from)
        .collect()
}

/// UTF-16 form of [`ipv6_address_to_string_ex`].
pub fn ipv6_address_to_string_ex_w(
    address: [u8; 16],
    scope_id: u32,
    port_network_order: u16,
) -> Vec<u16> {
    ipv6_address_to_string_ex(address, scope_id, port_network_order)
        .into_iter()
        .map(u16::from)
        .collect()
}

/// Parse an ANSI IPv6 string. The returned terminator is a byte offset.
pub fn ipv6_string_to_address_a(string: &[u8]) -> Result<Ipv6AddressParse, usize> {
    let wide: Vec<u16> = string.iter().copied().map(u16::from).collect();
    ipv6_string_to_address_w(&wide)
}

/// Parse a UTF-16 IPv6 string. The returned terminator is a UTF-16 code-unit offset.
pub fn ipv6_string_to_address_w(string: &[u16]) -> Result<Ipv6AddressParse, usize> {
    match ipv6_string_to_address_inner(string, false) {
        Ok(parsed) => Ok(Ipv6AddressParse {
            address: parsed.address,
            terminator: parsed.terminator,
        }),
        Err(term) => Err(term),
    }
}

/// Parse an ANSI IPv6 string with optional scope and port. The whole string must be consumed.
pub fn ipv6_string_to_address_ex_a(string: &[u8]) -> Result<Ipv6AddressExParse, usize> {
    let wide: Vec<u16> = string.iter().copied().map(u16::from).collect();
    ipv6_string_to_address_ex_w(&wide)
}

/// Parse a UTF-16 IPv6 string with optional scope and port. The whole string must be consumed.
pub fn ipv6_string_to_address_ex_w(string: &[u16]) -> Result<Ipv6AddressExParse, usize> {
    match ipv6_string_to_address_inner(string, true) {
        Ok(parsed) => Ok(Ipv6AddressExParse {
            address: parsed.address,
            scope_id: parsed.scope_id,
            port: parsed.port,
        }),
        Err(term) => Err(term),
    }
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

fn push_decimal_u32(out: &mut Vec<u8>, mut value: u32) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 10];
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

fn ipv6_raw_words(address: [u8; 16]) -> [u16; 8] {
    let mut words = [0u16; 8];
    for i in 0..8 {
        words[i] = u16::from_le_bytes([address[i * 2], address[i * 2 + 1]]);
    }
    words
}

fn push_ipv6_words(out: &mut Vec<u8>, raw_words: &[u16; 8], parts: usize) {
    let mut skip_once = true;
    let mut n = 0usize;
    while n < parts {
        if skip_once && n + 1 < parts && raw_words[n] == 0 && raw_words[n + 1] == 0 {
            skip_once = false;
            while n + 1 < parts && raw_words[n + 1] == 0 {
                n += 1;
            }
            out.push(b':');
            if n + 1 >= parts {
                out.push(b':');
            }
        } else {
            if n != 0 {
                out.push(b':');
            }
            push_hex_u16(out, u16::from_be(raw_words[n]));
        }
        n += 1;
    }
}

fn push_hex_u16(out: &mut Vec<u8>, mut value: u16) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 4];
    let mut len = 0usize;
    while value != 0 {
        let digit = (value & 0xf) as u8;
        buf[len] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        value >>= 4;
        len += 1;
    }
    while len != 0 {
        len -= 1;
        out.push(buf[len]);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ipv6InnerParse {
    address: [u8; 16],
    terminator: usize,
    scope_id: u32,
    port: u16,
}

fn ipv6_string_to_address_inner(string: &[u16], ex: bool) -> Result<Ipv6InnerParse, usize> {
    let mut address = [0u8; 16];
    let mut expecting_port = false;
    let mut has_0x = false;
    let mut has_0x_terminator = None;
    let mut too_big = false;
    let mut n_bytes = 0usize;
    let mut n_ipv4_bytes = 0usize;
    let mut gap: Option<usize> = None;
    let mut scope_id = 0u32;
    let mut port = 0u16;
    let mut index = 0usize;

    if char_at(string, 0) == b'[' as u16 {
        if !ex {
            return Err(0);
        }
        expecting_port = true;
        index += 1;
    }

    if char_at(string, index) == b':' as u16 {
        if char_at(string, index + 1) != b':' as u16 {
            return Err(index);
        }
        index += 1;
    }

    loop {
        let prev_index;
        if n_ipv4_bytes == 0 && char_at(string, index) == b':' as u16 {
            if gap.is_some() {
                return Err(index);
            }
            index += 1;
            prev_index = index;
            gap = Some(n_bytes);
            let mut probe = index;
            if n_bytes == 14 || parse_ipv6_component(string, &mut probe, 16).is_none() {
                break;
            }
            index = prev_index;
        } else {
            prev_index = index;
        }

        let ipv4_probe_limit = if gap.is_some() { 10 } else { 12 };
        if n_ipv4_bytes == 0 && n_bytes <= ipv4_probe_limit {
            let mut probe = prev_index;
            if parse_ipv6_component(string, &mut probe, 10).is_some()
                && char_at(string, probe) == b'.' as u16
            {
                n_ipv4_bytes = 1;
            }
            index = prev_index;
        }

        if n_ipv4_bytes != 0 {
            let mut next = index;
            let Some(component) = parse_ipv6_component(string, &mut next, 10) else {
                return Err(index);
            };
            index = next;
            if index - prev_index > 3 || component > 255 {
                too_big = true;
            } else {
                if char_at(string, index) != b'.' as u16
                    && (n_ipv4_bytes < 4 || (n_bytes < 15 && gap.is_none()))
                {
                    return Err(index);
                }
                address[n_bytes] = component as u8;
                n_bytes += 1;
            }
            if n_ipv4_bytes == 4 || char_at(string, index) != b'.' as u16 {
                break;
            }
            n_ipv4_bytes += 1;
        } else {
            let mut next = index;
            let Some(component) = parse_ipv6_component(string, &mut next, 16) else {
                return Err(index);
            };
            index = next;
            if char_at(string, prev_index) == b'0' as u16
                && matches!(char_at(string, prev_index + 1), c if c == b'x' as u16 || c == b'X' as u16)
            {
                if n_bytes < 14 && gap.is_none() {
                    return Err(prev_index);
                }
                write_ipv6_word(&mut address, n_bytes, component as u16);
                n_bytes += 2;
                has_0x = true;
                has_0x_terminator = Some(prev_index + 1);
                break;
            }
            if char_at(string, index) != b':' as u16 && n_bytes < 14 && gap.is_none() {
                return Err(index);
            }
            if index - prev_index > 4 {
                too_big = true;
            } else {
                write_ipv6_word(&mut address, n_bytes, component as u16);
            }
            n_bytes += 2;
            if char_at(string, index) != b':' as u16
                || (gap.is_some() && char_at(string, index + 1) == b':' as u16)
            {
                break;
            }
        }

        let byte_limit = if gap.is_some() { 14 } else { 16 };
        if n_bytes == byte_limit {
            break;
        }
        if too_big {
            return Err(index);
        }
        index += 1;
    }

    let terminator = has_0x_terminator.unwrap_or(index);
    if too_big {
        return Err(index);
    }

    if let Some(gap_start) = gap {
        let trailing_len = n_bytes.saturating_sub(gap_start);
        let trailing_dst = 16 - trailing_len;
        address.copy_within(gap_start..n_bytes, trailing_dst);
        for b in &mut address[gap_start..trailing_dst] {
            *b = 0;
        }
    } else if n_bytes < 16 {
        return Err(index);
    }

    if ex {
        if has_0x {
            return Err(index);
        }
        if char_at(string, index) == b'%' as u16 {
            index += 1;
            let Some(scope) = parse_ipv4_component(string, &mut index, true) else {
                return Err(index);
            };
            scope_id = scope;
        }
        if expecting_port {
            if char_at(string, index) != b']' as u16 {
                return Err(index);
            }
            index += 1;
            if char_at(string, index) == b':' as u16 {
                index += 1;
                let Some(parsed_port) = parse_ipv4_component(string, &mut index, false) else {
                    return Err(index);
                };
                if parsed_port == 0 || parsed_port > 0xFFFF || char_at(string, index) != 0 {
                    return Err(index);
                }
                port = (parsed_port as u16).to_be();
            }
        }
        if char_at(string, index) != 0 {
            return Err(index);
        }
    }

    Ok(Ipv6InnerParse {
        address,
        terminator,
        scope_id,
        port,
    })
}

fn parse_ipv6_component(string: &[u16], index: &mut usize, base: u32) -> Option<u32> {
    let start = *index;
    let mut i = start;
    hex_value(char_at(string, i))?;

    let has_prefix = base == 16
        && char_at(string, i) == b'0' as u16
        && matches!(char_at(string, i + 1), c if c == b'x' as u16 || c == b'X' as u16);
    if has_prefix {
        i += 2;
    }

    let mut value = 0u64;
    let mut success = false;
    while let Some(digit) = digit_value(char_at(string, i), base) {
        value = value.saturating_mul(base as u64).saturating_add(digit as u64);
        success = true;
        i += 1;
    }

    if !success {
        if has_prefix {
            *index = start + 1;
            return Some(0);
        }
        return None;
    }

    *index = i;
    Some(value.min(0x7FFF_FFFF) as u32)
}

fn parse_ipv4_component(string: &[u16], index: &mut usize, strict: bool) -> Option<u32> {
    if char_at(string, *index) == b'.' as u16 {
        *index += 1;
        return None;
    }
    let parsed = parse_ulong(string, *index, strict);
    if !parsed.ok {
        return None;
    }
    *index = parsed.terminator;
    Some(parsed.value)
}

fn write_ipv6_word(address: &mut [u8; 16], offset: usize, value: u16) {
    let bytes = value.to_be_bytes();
    address[offset] = bytes[0];
    address[offset + 1] = bytes[1];
}

fn hex_value(c: u16) -> Option<u32> {
    digit_value(c, 16)
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

    fn ipv6_from_s6_words(words: [u16; 8]) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for (i, word) in words.into_iter().enumerate() {
            let word_bytes = word.to_le_bytes();
            bytes[i * 2] = word_bytes[0];
            bytes[i * 2 + 1] = word_bytes[1];
        }
        bytes
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
    fn formats_ipv6_zero_and_normal_addresses() {
        let cases = [
            ("::", [0, 0, 0, 0, 0, 0, 0, 0]),
            ("::1", [0, 0, 0, 0, 0, 0, 0, 0x100]),
            (
                "0:1:2:3:4:5:6:7",
                [0, 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700],
            ),
            (
                "1080::8:800:200c:417a",
                [0x8010, 0, 0, 0, 0x800, 0x8, 0x0c20, 0x7a41],
            ),
            (
                "1111:2222:3333:4444:5555:6666:0:8888",
                [
                    0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0, 0x8888,
                ],
            ),
            (
                "1111::4444:5555:6666:7777:8888",
                [0x1111, 0, 0, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888],
            ),
            ("1111::", [0x1111, 0, 0, 0, 0, 0, 0, 0]),
            ("2001::ffd3", [0x120, 0, 0, 0, 0, 0, 0, 0xd3ff]),
        ];
        for (expected, words) in cases {
            assert_eq!(ipv6_address_to_string(ipv6_from_s6_words(words)), expected.as_bytes());
        }
    }

    #[test]
    fn formats_ipv6_ipv4_compatible_and_isatap_addresses() {
        let cases = [
            ("::13.1.68.3", [0, 0, 0, 0, 0, 0, 0x010d, 0x0344]),
            (
                "::ffff:13.1.68.3",
                [0, 0, 0, 0, 0, 0xffff, 0x010d, 0x0344],
            ),
            (
                "::ffff:0:13.1.68.3",
                [0, 0, 0, 0, 0xffff, 0, 0x010d, 0x0344],
            ),
            ("::ffff", [0, 0, 0, 0, 0, 0, 0, 0xffff]),
            (
                "::1:d01:4403",
                [0, 0, 0, 0, 0, 0x100, 0x010d, 0x0344],
            ),
            (
                "1111:2222:3333:4444:0:5efe:129.144.52.38",
                [
                    0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634,
                ],
            ),
            (
                "1111::5efe:129.144.52.38",
                [0x1111, 0, 0, 0, 0, 0xfe5e, 0x9081, 0x2634],
            ),
            (
                "::100:5efe:8190:3426",
                [0, 0, 0, 0, 1, 0xfe5e, 0x9081, 0x2634],
            ),
            (
                "::200:5efe:129.144.52.38",
                [0, 0, 0, 0, 2, 0xfe5e, 0x9081, 0x2634],
            ),
        ];
        for (expected, words) in cases {
            assert_eq!(ipv6_address_to_string(ipv6_from_s6_words(words)), expected.as_bytes());
        }
    }

    #[test]
    fn formats_ipv6_address_with_scope_and_network_order_port() {
        let address = ipv6_from_s6_words([0, 0, 0, 0, 0, 0, 0x010d, 0x0344]);
        assert_eq!(
            ipv6_address_to_string_ex(address, 0, 0),
            b"::13.1.68.3"
        );
        assert_eq!(
            ipv6_address_to_string_ex(address, 1, 0),
            b"::13.1.68.3%1"
        );
        assert_eq!(
            ipv6_address_to_string_ex(address, 0xffffbbbb, 0xeeff),
            b"[::13.1.68.3%4294949819]:65518"
        );
        assert_eq!(
            ipv6_address_to_string_ex(address, 0, 1),
            b"[::13.1.68.3]:256"
        );
        assert_eq!(
            ipv6_address_to_string_ex_w(address, 1, 0),
            wide("::13.1.68.3%1")
        );
    }

    #[test]
    fn parses_ipv6_addresses_with_terminators() {
        let cases = [
            ("::", [0, 0, 0, 0, 0, 0, 0, 0], 2),
            ("::1", [0, 0, 0, 0, 0, 0, 0, 0x100], 3),
            (
                "::13.1.68.3",
                [0, 0, 0, 0, 0, 0, 0x010d, 0x0344],
                11,
            ),
            (
                "1111:2222:3333:4444:0:5efe:129.144.52.38",
                [
                    0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634,
                ],
                40,
            ),
            (
                "2001:db8::1428:57ab",
                [0x120, 0xb80d, 0, 0, 0, 0, 0x2814, 0xab57],
                19,
            ),
        ];
        for (input, words, terminator) in cases {
            let parsed = ipv6_string_to_address_a(input.as_bytes()).unwrap();
            assert_eq!(parsed.address, ipv6_from_s6_words(words));
            assert_eq!(parsed.terminator, terminator);
        }

        let parsed = ipv6_string_to_address_a(b"::1 trailing").unwrap();
        assert_eq!(parsed.address, ipv6_from_s6_words([0, 0, 0, 0, 0, 0, 0, 0x100]));
        assert_eq!(parsed.terminator, 3);

        let parsed = ipv6_string_to_address_a(b"::0x12345tail").unwrap();
        assert_eq!(parsed.address, ipv6_from_s6_words([0, 0, 0, 0, 0, 0, 0, 0x4523]));
        assert_eq!(parsed.terminator, 3);
    }

    #[test]
    fn parses_ipv6_ex_scope_and_network_order_port() {
        let parsed =
            ipv6_string_to_address_ex_a(b"[::13.1.68.3%4294949819]:65518").unwrap();
        assert_eq!(
            parsed.address,
            ipv6_from_s6_words([0, 0, 0, 0, 0, 0, 0x010d, 0x0344])
        );
        assert_eq!(parsed.scope_id, 0xffffbbbb);
        assert_eq!(parsed.port, 65518u16.to_be());

        let parsed = ipv6_string_to_address_ex_w(&wide("::1%1")).unwrap();
        assert_eq!(parsed.address, ipv6_from_s6_words([0, 0, 0, 0, 0, 0, 0, 0x100]));
        assert_eq!(parsed.scope_id, 1);
        assert_eq!(parsed.port, 0);
    }

    #[test]
    fn rejects_invalid_ipv6_inputs() {
        assert!(ipv6_string_to_address_ex_a(b"::1 trailing").is_err());
        assert!(ipv6_string_to_address_ex_a(b"[::1").is_err());
        assert!(ipv6_string_to_address_ex_a(b"[::1]:0").is_err());
        assert!(ipv6_string_to_address_a(b"1:2").is_err());
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
