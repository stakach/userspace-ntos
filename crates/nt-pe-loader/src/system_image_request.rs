//! Immutable captured-pool request for system-image load-reference admission.

use alloc::string::String;

pub const PACKET_BYTES: usize = 288;
const MAGIC: u32 = 0x4744494c;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request { Load(String), Unload(u64) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_load_and_unload_round_trip() {
        for request in [Request::Load("framebuf.dll".into()), Request::Unload(0x12345000)] {
            assert_eq!(decode(&encode(&request).unwrap()), Some(request));
        }
    }
    #[test]
    fn malformed_packet_and_noncanonical_identity_rejected() {
        assert!(encode(&Request::Load("../evil.dll".into())).is_none());
        assert!(encode(&Request::Unload(0)).is_none());
        let mut bytes = encode(&Request::Load("framebuf.dll".into())).unwrap();
        bytes[24] = 1;
        assert_eq!(decode(&bytes), None);
        bytes[24] = 0;
        bytes[287] = 1;
        assert_eq!(decode(&bytes), None);
        assert_eq!(decode(&bytes[..287]), None);
    }
}

pub fn encode(request: &Request) -> Option<[u8; PACKET_BYTES]> {
    let mut bytes = [0; PACKET_BYTES];
    bytes[..4].copy_from_slice(&MAGIC.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    match request {
        Request::Load(name) => {
            let name = crate::module_namespace::module_leaf(name).ok()?;
            bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
            bytes[12..16].copy_from_slice(&(name.len() as u32).to_le_bytes());
            bytes[32..32 + name.len()].copy_from_slice(name.as_bytes());
        }
        Request::Unload(handle) if *handle != 0 => {
            bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
            bytes[16..24].copy_from_slice(&handle.to_le_bytes());
        }
        _ => return None,
    }
    Some(bytes)
}

pub fn decode(bytes: &[u8]) -> Option<Request> {
    if bytes.len() != PACKET_BYTES || bytes[..4] != MAGIC.to_le_bytes()
        || bytes[4..8] != 1u32.to_le_bytes() || bytes[24..32].iter().any(|b| *b != 0)
    { return None; }
    let op = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let length = u32::from_le_bytes(bytes[12..16].try_into().ok()?) as usize;
    let handle = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
    match op {
        1 if handle == 0 && length != 0 && length <= 255 && bytes[32 + length..].iter().all(|b| *b == 0) => {
            let name = core::str::from_utf8(&bytes[32..32 + length]).ok()?;
            let canonical = crate::module_namespace::module_leaf(name).ok()?;
            if name != canonical { return None; }
            Some(Request::Load(canonical))
        }
        2 if length == 0 && handle != 0 && bytes[32..].iter().all(|b| *b == 0) => Some(Request::Unload(handle)),
        _ => None,
    }
}
