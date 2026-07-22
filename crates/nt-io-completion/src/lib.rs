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

pub const INFINITE_DEADLINE: u64 = u64::MAX;

/// Executive-owned state for one blocking `NtRemoveIoCompletion` call. Addresses are kept opaque;
/// the executive validates them before parking and writes them in the waiter's process on wake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompletionWaiter {
    pub port_id: u32,
    pub process_index: u8,
    pub _reserved: [u8; 3],
    pub reply_cap: u64,
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
    pub thread_id: u64,
    pub badge: u64,
    pub key_context_out: u64,
    pub apc_context_out: u64,
    pub io_status_block_out: u64,
    pub deadline_100ns: u64,
    sequence: u64,
}

/// Allocation-free FIFO wait table shared by completion ports.
pub struct CompletionWaiterTable<const WAITERS: usize> {
    slots: [Option<CompletionWaiter>; WAITERS],
    next_sequence: u64,
}

impl<const WAITERS: usize> CompletionWaiterTable<WAITERS> {
    pub const fn new() -> Self {
        assert!(WAITERS > 0);
        Self {
            slots: [None; WAITERS],
            next_sequence: 0,
        }
    }

    pub fn insert(&mut self, mut waiter: CompletionWaiter) -> Result<(), u32> {
        if waiter.reply_cap == 0
            || self
                .slots
                .iter()
                .flatten()
                .any(|existing| existing.reply_cap == waiter.reply_cap)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        waiter.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        *slot = Some(waiter);
        Ok(())
    }

    /// Release the newest waiter for `port_id`, matching NT KQUEUE/IOCP LIFO thread scheduling.
    /// Packet order remains FIFO in [`CompletionPortTable`].
    pub fn pop_port(&mut self, port_id: u32) -> Option<CompletionWaiter> {
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, waiter)| waiter.map(|waiter| (index, waiter)))
            .filter(|(_, waiter)| waiter.port_id == port_id)
            .max_by_key(|(_, waiter)| waiter.sequence)
            .map(|(index, _)| index)?;
        self.slots[index].take()
    }

    /// Remove the oldest waiter owned by a terminating thread.
    pub fn pop_thread(&mut self, thread_id: u64) -> Option<CompletionWaiter> {
        self.pop_oldest_matching(|waiter| waiter.thread_id == thread_id)
    }

    /// Remove the earliest expired waiter. Equal deadlines retain park order.
    pub fn pop_due(&mut self, now_100ns: u64) -> Option<CompletionWaiter> {
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, waiter)| waiter.map(|waiter| (index, waiter)))
            .filter(|(_, waiter)| {
                waiter.deadline_100ns != INFINITE_DEADLINE && waiter.deadline_100ns <= now_100ns
            })
            .min_by_key(|(_, waiter)| (waiter.deadline_100ns, waiter.sequence))
            .map(|(index, _)| index)?;
        self.slots[index].take()
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .map(|waiter| waiter.deadline_100ns)
            .filter(|deadline| *deadline != INFINITE_DEADLINE)
            .min()
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn pop_oldest_matching(
        &mut self,
        predicate: impl Fn(&CompletionWaiter) -> bool,
    ) -> Option<CompletionWaiter> {
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, waiter)| waiter.map(|waiter| (index, waiter)))
            .filter(|(_, waiter)| predicate(waiter))
            .min_by_key(|(_, waiter)| waiter.sequence)
            .map(|(index, _)| index)?;
        self.slots[index].take()
    }
}

impl<const WAITERS: usize> Default for CompletionWaiterTable<WAITERS> {
    fn default() -> Self {
        Self::new()
    }
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

    fn retain(&mut self) -> Result<(), u32> {
        self.references = self
            .references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        Ok(())
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
                self.ports[index].retain()?;
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
        self.ports[index].retain()?;
        Ok(index as u32)
    }

    /// Hold an executive-internal reference while a blocking remove is parked.
    pub fn retain(&mut self, id: u32) -> Result<(), u32> {
        self.port_mut(id)?.retain()
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

    fn waiter(port_id: u32, value: u64, deadline_100ns: u64) -> CompletionWaiter {
        CompletionWaiter {
            port_id,
            process_index: value as u8,
            reply_cap: value,
            thread_id: value + 100,
            key_context_out: value + 200,
            deadline_100ns,
            ..CompletionWaiter::default()
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
    fn parked_waiter_reference_survives_last_handle_close() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        ports.retain(id).unwrap();
        ports.release(id).unwrap();
        assert_eq!(ports.depth(id), Ok(0));
        ports.enqueue(id, packet(1)).unwrap();
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(packet(1)))
        );
        ports.release(id).unwrap();
        assert_eq!(ports.depth(id), Err(STATUS_INVALID_HANDLE));
        assert_eq!(ports.create(&[], 2, false).unwrap().id, id);
    }

    #[test]
    fn every_reference_path_reports_overflow_without_saturating() {
        let mut ports = Ports::new();
        let name = [b'x' as u16];
        let id = ports.create(&name, 1, false).unwrap().id;
        ports.ports[id as usize].references = u16::MAX;
        assert_eq!(ports.retain(id), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(ports.open(&name, false), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(ports.create(&name, 9, false), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(ports.ports[id as usize].references, u16::MAX);
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

    #[test]
    fn completion_packets_are_fifo_but_waiters_are_lifo_per_port() {
        let mut waiters = CompletionWaiterTable::<4>::new();
        waiters.insert(waiter(1, 10, INFINITE_DEADLINE)).unwrap();
        waiters.insert(waiter(2, 20, INFINITE_DEADLINE)).unwrap();
        waiters.insert(waiter(1, 30, INFINITE_DEADLINE)).unwrap();
        assert_eq!(waiters.pop_port(1).unwrap().reply_cap, 30);
        assert_eq!(waiters.pop_port(1).unwrap().reply_cap, 10);
        assert_eq!(waiters.pop_port(1), None);
        assert_eq!(waiters.pop_port(2).unwrap().reply_cap, 20);
        assert!(waiters.is_empty());
    }

    #[test]
    fn completion_waiter_capacity_and_reply_identity_are_enforced() {
        let mut waiters = CompletionWaiterTable::<2>::new();
        assert_eq!(
            waiters.insert(waiter(1, 0, INFINITE_DEADLINE)),
            Err(STATUS_INVALID_PARAMETER)
        );
        waiters.insert(waiter(1, 1, INFINITE_DEADLINE)).unwrap();
        assert_eq!(
            waiters.insert(waiter(2, 1, INFINITE_DEADLINE)),
            Err(STATUS_INVALID_PARAMETER)
        );
        waiters.insert(waiter(2, 2, INFINITE_DEADLINE)).unwrap();
        assert_eq!(
            waiters.insert(waiter(3, 3, INFINITE_DEADLINE)),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
    }

    #[test]
    fn completion_waiter_deadlines_are_ordered_and_infinite_is_ignored() {
        let mut waiters = CompletionWaiterTable::<5>::new();
        waiters.insert(waiter(1, 1, INFINITE_DEADLINE)).unwrap();
        waiters.insert(waiter(1, 2, 200)).unwrap();
        waiters.insert(waiter(2, 3, 100)).unwrap();
        waiters.insert(waiter(3, 4, 100)).unwrap();
        assert_eq!(waiters.next_deadline(), Some(100));
        assert_eq!(waiters.pop_due(99), None);
        assert_eq!(waiters.pop_due(100).unwrap().reply_cap, 3);
        assert_eq!(waiters.pop_due(100).unwrap().reply_cap, 4);
        assert_eq!(waiters.next_deadline(), Some(200));
        assert_eq!(waiters.pop_due(200).unwrap().reply_cap, 2);
        assert_eq!(waiters.next_deadline(), None);
        assert_eq!(waiters.len(), 1);
    }

    #[test]
    fn completion_waiters_cancel_by_thread_without_disturbing_others() {
        let mut waiters = CompletionWaiterTable::<4>::new();
        waiters.insert(waiter(1, 1, INFINITE_DEADLINE)).unwrap();
        let mut second = waiter(1, 2, INFINITE_DEADLINE);
        second.thread_id = 101;
        waiters.insert(second).unwrap();
        waiters.insert(waiter(2, 3, INFINITE_DEADLINE)).unwrap();
        assert_eq!(waiters.pop_thread(101).unwrap().reply_cap, 1);
        assert_eq!(waiters.pop_thread(101).unwrap().reply_cap, 2);
        assert_eq!(waiters.pop_thread(101), None);
        assert_eq!(waiters.pop_port(2).unwrap().reply_cap, 3);
    }
}
