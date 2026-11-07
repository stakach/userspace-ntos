//! Immutable owner identity in the ordered Win32k shared request snapshot.

pub const WORDS: usize = 38;

#[derive(Clone, Copy)]
pub struct RequestOwner {
    pub ssn: u64,
    pub pid: u64,
    pub pi: u64,
    pub tid: u64,
    pub generation: u64,
    pub token_auth: u64,
    pub token_sid_len: u64,
    pub token_sid_ptr: u64,
}

/// The callback header and retained dispatch/client authenticate these fields. The component
/// may clear or overwrite the physical page while a callback is parked. Its remaining words
/// are component-owned mutable state and stay exactly as observed.
pub fn canonicalize(words: &mut [u64; WORDS], owner: RequestOwner) {
    words[0] = owner.ssn;
    words[20] = owner.pid;
    words[22] = owner.pi;
    words[25] = owner.tid;
    words[29] = owner.token_auth;
    words[30] = owner.token_sid_len;
    words[31] = owner.token_sid_ptr;
    words[37] = owner.generation;
}
