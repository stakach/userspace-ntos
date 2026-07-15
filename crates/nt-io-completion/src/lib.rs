//! Allocation-free NT I/O completion-port objects and packet queues.

#![no_std]

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
pub const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_0044;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompletionPacket {
    pub key_context: u64,
    pub apc_context: u64,
    pub status: u32,
    pub information: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportCompletion {
    pub request_id: u64,
    pub user_data: u64,
    pub status: i32,
    pub information: u64,
}

impl From<TransportCompletion> for CompletionPacket {
    fn from(completion: TransportCompletion) -> Self {
        Self {
            // SURT preserves `user_data` as the caller's opaque cookie. The NT adapter uses it as
            // the completion key and uses the stable request id as the APC/overlapped context.
            key_context: completion.user_data,
            apc_context: completion.request_id,
            status: completion.status as u32,
            information: completion.information,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveMode {
    Poll,
    Wait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveResult {
    Packet(CompletionPacket),
    Empty(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateResult {
    pub id: u32,
    pub created: bool,
}

#[derive(Clone, Copy)]
struct CompletionPort<const PACKETS: usize, const NAME_UNITS: usize> {
    occupied: bool,
    references: u16,
    concurrency: u32,
    name_len: u16,
    name: [u16; NAME_UNITS],
    packets: [CompletionPacket; PACKETS],
    head: usize,
    len: usize,
}

impl<const PACKETS: usize, const NAME_UNITS: usize> CompletionPort<PACKETS, NAME_UNITS> {
    const fn empty() -> Self {
        Self {
            occupied: false,
            references: 0,
            concurrency: 0,
            name_len: 0,
            name: [0; NAME_UNITS],
            packets: [CompletionPacket {
                key_context: 0,
                apc_context: 0,
                status: 0,
                information: 0,
            }; PACKETS],
            head: 0,
            len: 0,
        }
    }

    fn name(&self) -> &[u16] {
        &self.name[..self.name_len as usize]
    }

    fn reset(&mut self) {
        *self = Self::empty();
    }
}

pub struct CompletionPortTable<const PORTS: usize, const PACKETS: usize, const NAME_UNITS: usize> {
    ports: [CompletionPort<PACKETS, NAME_UNITS>; PORTS],
}

impl<const PORTS: usize, const PACKETS: usize, const NAME_UNITS: usize>
    CompletionPortTable<PORTS, PACKETS, NAME_UNITS>
{
    pub const fn new() -> Self {
        assert!(PORTS > 0);
        assert!(PACKETS > 0);
        Self {
            ports: [CompletionPort::empty(); PORTS],
        }
    }

    pub fn create(
        &mut self,
        name: &[u16],
        concurrency: u32,
        case_insensitive: bool,
    ) -> Result<CreateResult, u32> {
        if name.len() > NAME_UNITS {
            return Err(STATUS_NAME_TOO_LONG);
        }
        if !name.is_empty() {
            if let Some(index) = self.find_name(name, case_insensitive) {
                self.ports[index].references = self.ports[index].references.saturating_add(1);
                return Ok(CreateResult {
                    id: index as u32,
                    created: false,
                });
            }
        }
        let index = self
            .ports
            .iter()
            .position(|port| !port.occupied)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let port = &mut self.ports[index];
        port.occupied = true;
        port.references = 1;
        port.concurrency = concurrency;
        port.name_len = name.len() as u16;
        port.name[..name.len()].copy_from_slice(name);
        Ok(CreateResult {
            id: index as u32,
            created: true,
        })
    }

    pub fn open(&mut self, name: &[u16], case_insensitive: bool) -> Result<u32, u32> {
        if name.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let index = self
            .find_name(name, case_insensitive)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        self.ports[index].references = self.ports[index].references.saturating_add(1);
        Ok(index as u32)
    }

    pub fn release(&mut self, id: u32) -> Result<(), u32> {
        let port = self.port_mut(id)?;
        if port.references > 1 {
            port.references -= 1;
        } else {
            port.reset();
        }
        Ok(())
    }

    pub fn enqueue(&mut self, id: u32, packet: CompletionPacket) -> Result<(), u32> {
        let port = self.port_mut(id)?;
        if port.len == PACKETS {
            return Err(STATUS_QUOTA_EXCEEDED);
        }
        let tail = (port.head + port.len) % PACKETS;
        port.packets[tail] = packet;
        port.len += 1;
        Ok(())
    }

    pub fn enqueue_transport(
        &mut self,
        id: u32,
        completion: TransportCompletion,
    ) -> Result<(), u32> {
        self.enqueue(id, completion.into())
    }

    pub fn remove(&mut self, id: u32, mode: RemoveMode) -> Result<RemoveResult, u32> {
        let port = self.port_mut(id)?;
        if port.len == 0 {
            return Ok(RemoveResult::Empty(match mode {
                RemoveMode::Poll => STATUS_TIMEOUT,
                RemoveMode::Wait => STATUS_PENDING,
            }));
        }
        let packet = port.packets[port.head];
        port.head = (port.head + 1) % PACKETS;
        port.len -= 1;
        Ok(RemoveResult::Packet(packet))
    }

    pub fn depth(&self, id: u32) -> Result<u32, u32> {
        Ok(self.port(id)?.len as u32)
    }

    pub fn concurrency(&self, id: u32) -> Result<u32, u32> {
        Ok(self.port(id)?.concurrency)
    }

    fn port(&self, id: u32) -> Result<&CompletionPort<PACKETS, NAME_UNITS>, u32> {
        self.ports
            .get(id as usize)
            .filter(|port| port.occupied)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn port_mut(&mut self, id: u32) -> Result<&mut CompletionPort<PACKETS, NAME_UNITS>, u32> {
        self.ports
            .get_mut(id as usize)
            .filter(|port| port.occupied)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn find_name(&self, name: &[u16], case_insensitive: bool) -> Option<usize> {
        self.ports.iter().position(|port| {
            port.occupied
                && port.name().len() == name.len()
                && port.name().iter().zip(name).all(|(&left, &right)| {
                    if case_insensitive {
                        fold_ascii(left) == fold_ascii(right)
                    } else {
                        left == right
                    }
                })
        })
    }
}

impl<const PORTS: usize, const PACKETS: usize, const NAME_UNITS: usize> Default
    for CompletionPortTable<PORTS, PACKETS, NAME_UNITS>
{
    fn default() -> Self {
        Self::new()
    }
}

fn fold_ascii(unit: u16) -> u16 {
    if unit >= b'A' as u16 && unit <= b'Z' as u16 {
        unit + (b'a' - b'A') as u16
    } else {
        unit
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    type Ports = CompletionPortTable<2, 2, 16>;

    fn packet(value: u64) -> CompletionPacket {
        CompletionPacket {
            key_context: value,
            apc_context: value + 1,
            status: value as u32,
            information: value + 2,
        }
    }

    #[test]
    fn create_tracks_concurrency_and_distinct_anonymous_objects() {
        let mut ports = Ports::new();
        let first = ports.create(&[], 4, false).unwrap();
        let second = ports.create(&[], 0, false).unwrap();
        assert!(first.created);
        assert!(second.created);
        assert_ne!(first.id, second.id);
        assert_eq!(ports.concurrency(first.id), Ok(4));
    }

    #[test]
    fn named_create_and_open_share_an_object() {
        let mut ports = Ports::new();
        let created = ports
            .create(
                &[b'P' as u16, b'o' as u16, b'r' as u16, b't' as u16],
                2,
                true,
            )
            .unwrap();
        let duplicate = ports
            .create(
                &[b'p' as u16, b'O' as u16, b'R' as u16, b'T' as u16],
                9,
                true,
            )
            .unwrap();
        assert!(!duplicate.created);
        assert_eq!(duplicate.id, created.id);
        assert_eq!(ports.concurrency(created.id), Ok(2));
        assert_eq!(
            ports.open(&[b'p' as u16, b'o' as u16, b'r' as u16, b't' as u16], true),
            Ok(created.id)
        );
    }

    #[test]
    fn case_sensitive_names_and_missing_opens_are_distinct() {
        let mut ports = Ports::new();
        let upper = [b'P' as u16];
        let lower = [b'p' as u16];
        let first = ports.create(&upper, 1, false).unwrap();
        let second = ports.create(&lower, 1, false).unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(
            ports.open(&[b'x' as u16], false),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn object_and_name_capacity_fail_truthfully() {
        let mut ports = Ports::new();
        assert_eq!(
            ports.create(&[b'x' as u16; 17], 1, false),
            Err(STATUS_NAME_TOO_LONG)
        );
        ports.create(&[], 1, false).unwrap();
        ports.create(&[], 1, false).unwrap();
        assert_eq!(
            ports.create(&[], 1, false),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
    }

    #[test]
    fn packets_are_fifo_and_depth_is_exact() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        ports.enqueue(id, packet(10)).unwrap();
        ports.enqueue(id, packet(20)).unwrap();
        assert_eq!(ports.depth(id), Ok(2));
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(packet(10)))
        );
        assert_eq!(
            ports.remove(id, RemoveMode::Wait),
            Ok(RemoveResult::Packet(packet(20)))
        );
        assert_eq!(ports.depth(id), Ok(0));
    }

    #[test]
    fn full_queue_is_reported_without_overwrite() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        ports.enqueue(id, packet(1)).unwrap();
        ports.enqueue(id, packet(2)).unwrap();
        assert_eq!(ports.enqueue(id, packet(3)), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(packet(1)))
        );
    }

    #[test]
    fn empty_remove_distinguishes_poll_from_blocking_wait() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Empty(STATUS_TIMEOUT))
        );
        assert_eq!(
            ports.remove(id, RemoveMode::Wait),
            Ok(RemoveResult::Empty(STATUS_PENDING))
        );
    }

    #[test]
    fn invalid_and_released_ids_are_rejected() {
        let mut ports = Ports::new();
        assert_eq!(ports.depth(99), Err(STATUS_INVALID_HANDLE));
        let id = ports.create(&[], 1, false).unwrap().id;
        ports.release(id).unwrap();
        assert_eq!(ports.enqueue(id, packet(1)), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn final_release_recycles_but_shared_reference_does_not() {
        let mut ports = Ports::new();
        let name = [b'x' as u16];
        let id = ports.create(&name, 1, false).unwrap().id;
        assert_eq!(ports.open(&name, false), Ok(id));
        ports.release(id).unwrap();
        assert_eq!(ports.depth(id), Ok(0));
        ports.release(id).unwrap();
        assert_eq!(ports.depth(id), Err(STATUS_INVALID_HANDLE));
        assert_eq!(ports.create(&[], 3, false).unwrap().id, id);
    }

    #[test]
    fn transport_adapter_maps_surt_fields_without_transport_dependency() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        ports
            .enqueue_transport(
                id,
                TransportCompletion {
                    request_id: 0x1111,
                    user_data: 0x2222,
                    status: -7,
                    information: 0x3333,
                },
            )
            .unwrap();
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(CompletionPacket {
                key_context: 0x2222,
                apc_context: 0x1111,
                status: (-7i32) as u32,
                information: 0x3333,
            }))
        );
    }
}
