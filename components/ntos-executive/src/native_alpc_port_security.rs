//! Executive-owned security bound to exact native ALPC listen objects.
//! The port service checks the same handle again before a granted connect can queue.

use alloc::vec::Vec;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const MAX_SECURED_PORTS: usize = 64;

pub(crate) struct SecuredPort {
    pub(crate) listen_handle: u64,
    pub(crate) descriptor: Vec<u8>,
    name: Vec<u16>,
}

pub(crate) struct SecuredPortRegistry {
    ports: Vec<SecuredPort>,
}

fn fold(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 0x20 } else { unit }
}

fn same_name(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| fold(*left) == fold(*right))
}

impl SecuredPortRegistry {
    pub(crate) fn new() -> Self { Self { ports: Vec::new() } }

    pub(crate) fn register(&mut self, name: Vec<u16>, descriptor: Vec<u8>,
        listen_handle: u64) -> Result<(), u32> {
        if listen_handle == 0 || descriptor.is_empty() {
            return Err(0xC000_000D);
        }
        if let Some(old) = self.ports.iter_mut().find(|port| same_name(&port.name, &name)) {
            *old = SecuredPort { name, descriptor, listen_handle };
            return Ok(());
        }
        if self.ports.len() == MAX_SECURED_PORTS {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        self.ports.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.ports.push(SecuredPort { name, descriptor, listen_handle });
        Ok(())
    }

    pub(crate) fn find(&self, name: &[u16]) -> Option<&SecuredPort> {
        self.ports.iter().find(|port| same_name(&port.name, name))
    }

    pub(crate) fn retire(&mut self, listen_handle: u64) {
        self.ports.retain(|port| port.listen_handle != listen_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_replacement_rebinds_exact_handle_and_retire_is_identity_checked() {
        let mut ports = SecuredPortRegistry::new();
        ports.register("\\SmApiPort".encode_utf16().collect(), alloc::vec![1], 10).unwrap();
        ports.register("\\SMAPIPORT".encode_utf16().collect(), alloc::vec![2], 11).unwrap();
        ports.retire(10);
        let bound = ports.find(&"\\smapiport".encode_utf16().collect::<Vec<_>>()).unwrap();
        assert_eq!(bound.listen_handle, 11);
        assert_eq!(bound.descriptor, alloc::vec![2]);
    }
}
