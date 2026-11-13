//! Bounded, root-owned observation of a completed PlugPlay client exchange.
//! These labels are diagnostic only; File and IRP managers retain authority.

pub const RPC_SAMPLE_CAP: usize = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcClientKey {
    pub pid: u32,
    pub generation: u64,
    pub file_id: u64,
    pub npfs_fid: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcCaptureDirection { Request, Response }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcCaptureEvent {
    pub key: RpcClientKey,
    pub direction: RpcCaptureDirection,
    pub call_id: u32,
    pub length: usize,
    pub status: u32,
    pub sample: [u8; RPC_SAMPLE_CAP],
    pub sample_len: usize,
}

#[derive(Clone, Copy)]
struct Fragment {
    bytes: [u8; RPC_SAMPLE_CAP],
    sample_len: usize,
    length: usize,
}

impl Fragment {
    const fn new() -> Self { Self { bytes: [0; RPC_SAMPLE_CAP], sample_len: 0, length: 0 } }

    fn append(&mut self, bytes: &[u8], total: usize) -> bool {
        if total < bytes.len() || self.length.checked_add(total).is_none() { return false; }
        let copy = bytes.len().min(RPC_SAMPLE_CAP - self.sample_len);
        self.bytes[self.sample_len..self.sample_len + copy].copy_from_slice(&bytes[..copy]);
        self.sample_len += copy;
        self.length += total;
        true
    }

    fn declared_length(&self) -> Option<usize> {
        (self.sample_len >= 16 && self.bytes[0] == 5)
            .then(|| u16::from_le_bytes([self.bytes[8], self.bytes[9]]) as usize)
            .filter(|length| *length >= 24)
    }

    fn complete(&self) -> bool { self.declared_length() == Some(self.length) }
    fn exceeded(&self) -> bool { self.declared_length().is_some_and(|length| self.length > length) }
    fn call_id(&self) -> u32 { u32::from_le_bytes(self.bytes[12..16].try_into().unwrap()) }
}

#[derive(Clone, Copy)]
struct Staged { irp_id: u64, fragment: Fragment, transceive: bool }

#[derive(Clone, Copy)]
struct Slot {
    key: RpcClientKey,
    request: Fragment,
    response: Fragment,
    staged: Option<Staged>,
    awaiting_op6: bool,
    ambiguous: bool,
}

pub struct RpcOp6ClientCapture<const N: usize> {
    slots: [Option<Slot>; N],
    rejected: u64,
    overflow: u64,
    ambiguities: u64,
}

impl<const N: usize> RpcOp6ClientCapture<N> {
    pub const fn new() -> Self { Self { slots: [None; N], rejected: 0, overflow: 0, ambiguities: 0 } }
    pub fn rejected(&self) -> u64 { self.rejected }
    pub fn overflow(&self) -> u64 { self.overflow }
    pub fn ambiguities(&self) -> u64 { self.ambiguities }

    /// Called only when the canonical File has reached cleanup.
    pub fn retire_file(&mut self, file_id: u64) {
        for slot in &mut self.slots {
            if slot.is_some_and(|entry| entry.key.file_id == file_id) { *slot = None; }
        }
    }

    fn existing_slot(&mut self, key: RpcClientKey) -> Option<&mut Slot> {
        self.slots.iter_mut().flatten().find(|slot| slot.key == key)
    }

    fn slot(&mut self, key: RpcClientKey) -> Option<&mut Slot> {
        if key.file_id == 0 || key.npfs_fid == 0 || key.generation == 0 { return None; }
        if let Some(index) = self.slots.iter().position(|slot| slot.is_some_and(|slot| slot.key == key)) {
            return self.slots[index].as_mut();
        }
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            self.overflow = self.overflow.saturating_add(1);
            return None;
        };
        self.slots[index] = Some(Slot {
            key, request: Fragment::new(), response: Fragment::new(), staged: None,
            awaiting_op6: false, ambiguous: false,
        });
        self.slots[index].as_mut()
    }

    pub fn stage_write(&mut self, key: RpcClientKey, irp_id: u64, bytes: &[u8]) -> bool {
        self.stage(key, irp_id, bytes, false)
    }

    pub fn stage_transceive(&mut self, key: RpcClientKey, irp_id: u64, bytes: &[u8]) -> bool {
        self.stage(key, irp_id, bytes, true)
    }

    fn stage(&mut self, key: RpcClientKey, irp_id: u64, bytes: &[u8], transceive: bool) -> bool {
        if irp_id == 0 { self.rejected += 1; return false; }
        let Some(slot) = self.slot(key) else { self.rejected += 1; return false; };
        if slot.staged.is_some() { self.rejected += 1; return false; }
        let mut fragment = Fragment::new();
        if !fragment.append(bytes, bytes.len()) { self.rejected += 1; return false; }
        slot.staged = Some(Staged { irp_id, fragment, transceive });
        true
    }

    pub fn complete_write(&mut self, key: RpcClientKey, irp_id: u64, status: u32, information: u64)
        -> Option<RpcCaptureEvent>
    {
        let Some(slot) = self.existing_slot(key) else { self.rejected += 1; return None; };
        let Some(staged) = slot.staged else { self.rejected += 1; return None; };
        if staged.irp_id != irp_id { self.rejected += 1; return None; }
        slot.staged = None;
        if status != 0 || (!staged.transceive && information != staged.fragment.length as u64) {
            self.rejected += 1;
            return None;
        }
        let was_ambiguous = slot.ambiguous;
        let event = Self::append_request(slot, &staged.fragment.bytes[..staged.fragment.sample_len], staged.fragment.length, status);
        if !was_ambiguous && slot.ambiguous { self.ambiguities = self.ambiguities.saturating_add(1); }
        event
    }

    pub fn write(&mut self, key: RpcClientKey, bytes: &[u8], status: u32, information: u64)
        -> Option<RpcCaptureEvent>
    {
        if status != 0 || information != bytes.len() as u64 { self.rejected += 1; return None; }
        let Some(slot) = self.slot(key) else { self.rejected += 1; return None; };
        let was_ambiguous = slot.ambiguous;
        let event = Self::append_request(slot, bytes, bytes.len(), status);
        if !was_ambiguous && slot.ambiguous { self.ambiguities = self.ambiguities.saturating_add(1); }
        event
    }

    pub fn transceive(&mut self, key: RpcClientKey, bytes: &[u8], status: u32)
        -> Option<RpcCaptureEvent>
    {
        if status != 0 { self.rejected += 1; return None; }
        let Some(slot) = self.slot(key) else { self.rejected += 1; return None; };
        let was_ambiguous = slot.ambiguous;
        let event = Self::append_request(slot, bytes, bytes.len(), status);
        if !was_ambiguous && slot.ambiguous { self.ambiguities = self.ambiguities.saturating_add(1); }
        event
    }

    fn append_request(slot: &mut Slot, bytes: &[u8], total: usize, status: u32)
        -> Option<RpcCaptureEvent>
    {
        if !slot.request.append(bytes, total) || slot.request.exceeded() {
            slot.request = Fragment::new();
            slot.awaiting_op6 = false;
            return None;
        }
        if !slot.request.complete() { return None; }
        let fragment = core::mem::replace(&mut slot.request, Fragment::new());
        let op6 = fragment.bytes[2] == 0
            && fragment.sample_len >= 24
            && u16::from_le_bytes([fragment.bytes[22], fragment.bytes[23]]) == 6;
        if slot.awaiting_op6 { slot.ambiguous = true; }
        if !slot.ambiguous { slot.awaiting_op6 = op6; }
        op6.then(|| RpcCaptureEvent {
            key: slot.key, direction: RpcCaptureDirection::Request,
            call_id: fragment.call_id(), length: fragment.length, status,
            sample: fragment.bytes, sample_len: fragment.sample_len,
        })
    }

    /// Called only for bytes actually copied from a completed client read.
    pub fn read_chunk(&mut self, key: RpcClientKey, bytes: &[u8], status: u32)
        -> Option<RpcCaptureEvent>
    {
        let Some(slot) = self.existing_slot(key) else { return None; };
        if !slot.response.append(bytes, bytes.len()) || slot.response.exceeded() {
            slot.response = Fragment::new();
            slot.awaiting_op6 = false;
            self.rejected += 1;
            return None;
        }
        if !slot.response.complete() { return None; }
        let fragment = core::mem::replace(&mut slot.response, Fragment::new());
        if fragment.bytes[2] != 2 || !slot.awaiting_op6 || slot.ambiguous { return None; }
        slot.awaiting_op6 = false;
        Some(RpcCaptureEvent {
            key, direction: RpcCaptureDirection::Response,
            call_id: fragment.call_id(), length: fragment.length, status,
            sample: fragment.bytes, sample_len: fragment.sample_len,
        })
    }
}

impl<const N: usize> Default for RpcOp6ClientCapture<N> {
    fn default() -> Self { Self::new() }
}
