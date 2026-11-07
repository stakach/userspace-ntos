//! Owned, bounded create input for a win32k named Event.
use alloc::vec::Vec;

pub const MAX_NAME_UNITS: usize = 128;
pub const MAX_DESCRIPTOR_BYTES: usize = 1024;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

pub struct NamedEventCreate<O> {
    owner: O,
    pub root_directory: u64,
    pub attributes: u32,
    pub desired_access: u32,
    pub event_type: u32,
    pub initial_state: bool,
    pub name: Vec<u16>,
    pub security_descriptor: Vec<u8>,
}

impl<O: Copy + Eq> NamedEventCreate<O> {
    pub fn capture(
        owner: O,
        root_directory: u64,
        attributes: u32,
        desired_access: u32,
        event_type: u32,
        initial_state: bool,
        name: &[u16],
        security_descriptor: &[u8],
    ) -> Result<Self, u32> {
        if event_type > 1 || attributes & !(0x40 | 0x80 | 0x200 | 0x400) != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if name.is_empty() || name.len() > MAX_NAME_UNITS
            || name.iter().any(|&unit| unit == 0 || unit > 0x7f)
        {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if security_descriptor.len() > MAX_DESCRIPTOR_BYTES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut owned_name = Vec::new();
        owned_name.try_reserve_exact(name.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        owned_name.extend_from_slice(name);
        let mut owned_descriptor = Vec::new();
        owned_descriptor.try_reserve_exact(security_descriptor.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        owned_descriptor.extend_from_slice(security_descriptor);
        Ok(Self { owner, root_directory, attributes, desired_access, event_type,
            initial_state, name: owned_name, security_descriptor: owned_descriptor })
    }

    pub fn owner(&self) -> O { self.owner }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_event_capture_owns_name_sd_and_physical_owner() {
        let mut name = [b'X' as u16];
        let mut sd = [1u8, 2, 3];
        let captured = NamedEventCreate::capture((7u64, 13u64, 17u64), 0x40,
            0x80, 0x1f0003, 0, false, &name, &sd).unwrap();
        name[0] = b'Y' as u16;
        sd[0] = 9;
        assert_eq!(captured.owner(), (7, 13, 17));
        assert_eq!(captured.root_directory, 0x40);
        assert_eq!(captured.name, [b'X' as u16]);
        assert_eq!(captured.security_descriptor, [1, 2, 3]);
        assert_eq!(NamedEventCreate::capture(0u64, 0, 0, 0, 0, false,
            &[b'X' as u16; MAX_NAME_UNITS + 1], &[]).err(), Some(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(NamedEventCreate::capture(0u64, 0, 0, 0, 0, false,
            &[0x0100], &[]).err(), Some(STATUS_OBJECT_NAME_INVALID));
    }
}
