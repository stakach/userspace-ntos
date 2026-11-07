//! Exact binding between a hosted worker and its Process Manager thread object.
//! Process Manager owns public handles and pointer references; this record only
//! gates the wait signal on acknowledged worker termination.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDriverThreadObjectKey {
    instance: usize,
    domain_id: u64,
    domain_cookie: u64,
    handle: u64,
    tcb: u64,
    body: u64,
}

impl HostedDriverThreadObjectKey {
    pub const fn new(instance: usize, domain_id: u64, domain_cookie: u64,
        handle: u64, tcb: u64, body: u64) -> Option<Self>
    {
        if domain_id == 0 || domain_cookie == 0 || handle == 0 || tcb == 0 || body == 0 {
            return None;
        }
        Some(Self { instance, domain_id, domain_cookie, handle, tcb, body })
    }

    pub const fn instance(self) -> usize { self.instance }
    pub const fn domain_id(self) -> u64 { self.domain_id }
    pub const fn domain_cookie(self) -> u64 { self.domain_cookie }
    pub const fn handle(self) -> u64 { self.handle }
    pub const fn tcb(self) -> u64 { self.tcb }
    pub const fn body(self) -> u64 { self.body }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDriverThreadObjectRecord {
    key: HostedDriverThreadObjectKey,
    canonical: Option<(u64, u64, u64, u32)>,
    terminated: bool,
}

impl HostedDriverThreadObjectRecord {
    pub const fn new(key: HostedDriverThreadObjectKey) -> Self {
        Self { key, canonical: None, terminated: false }
    }

    pub const fn key(self) -> HostedDriverThreadObjectKey { self.key }

    pub fn publish_canonical(&mut self, key: HostedDriverThreadObjectKey,
        process_id: u64, thread_id: u64, public_handle: u64, access: u32) -> bool
    {
        if key != self.key || self.canonical.is_some() || process_id == 0
            || thread_id == 0 || public_handle == 0 || access == 0
        { return false; }
        self.canonical = Some((process_id, thread_id, public_handle, access));
        true
    }

    pub const fn canonical(self) -> Option<(u64, u64, u64, u32)> { self.canonical }

    pub fn matches_public(self, key: HostedDriverThreadObjectKey,
        process_id: u64, thread_id: u64, public_handle: u64) -> bool
    {
        key == self.key && self.canonical.is_some_and(|canonical| {
            canonical.0 == process_id && canonical.1 == thread_id
                && canonical.2 == public_handle
        })
    }

    pub fn terminate(&mut self, key: HostedDriverThreadObjectKey) -> bool {
        if key != self.key || self.canonical.is_none() { return false; }
        self.terminated = true;
        true
    }

    pub fn wait_ready(self, key: HostedDriverThreadObjectKey) -> bool {
        key == self.key && self.terminated
    }

}
