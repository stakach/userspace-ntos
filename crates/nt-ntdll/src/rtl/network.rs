//! `RtlIpv4*` network address formatting helpers.
//!
//! Category A. These are pure string-formatting routines; the DLL export layer handles raw pointers
//! and ABI return values.

use alloc::vec::Vec;

pub const IPV4_ADDR_STRING_MAX_LEN: usize = 16; // "255.255.255.255" + NUL
pub const IPV4_PORT_STRING_MAX_LEN: usize = 6; // ":65535"

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
}
