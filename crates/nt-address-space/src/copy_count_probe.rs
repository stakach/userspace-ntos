//! Retained, byte-exact SIZE_T output probe for VM copy syscalls.

use crate::PAGE_SIZE;

const COUNT_BYTES: usize = 8;

#[derive(Clone, Copy)]
struct Pending<Source, Irp> {
    address: u64,
    source: Source,
    irp: Irp,
    acknowledged: bool,
}

/// Captures all original output bytes before any self-write. Each page-contained effect is
/// entered once, including when the output straddles pages or a routed read goes Pending.
pub struct VmCopyCountProbe<Caller, Source, Irp> {
    caller: Caller,
    address: u64,
    original: [u8; COUNT_BYTES],
    captured: usize,
    written: usize,
    write_entered: bool,
    pending: Option<Pending<Source, Irp>>,
    failure: Option<u32>,
}

impl<Caller: Copy + Eq, Source: Copy + Eq, Irp: Copy + Eq>
    VmCopyCountProbe<Caller, Source, Irp>
{
    pub fn new(caller: Caller, address: u64) -> Self {
        Self {
            caller,
            address,
            original: [0; COUNT_BYTES],
            captured: 0,
            written: 0,
            write_entered: false,
            pending: None,
            failure: None,
        }
    }

    fn exact(&self, caller: Caller) -> bool {
        self.caller == caller
    }

    fn chunk(&self, offset: usize) -> Option<(u64, usize)> {
        if offset >= COUNT_BYTES {
            return None;
        }
        let address = self.address.checked_add(offset as u64)?;
        let length = (COUNT_BYTES - offset).min((PAGE_SIZE - address % PAGE_SIZE) as usize);
        address.checked_add(length as u64)?;
        Some((address, length))
    }

    pub fn next_capture(&self, caller: Caller) -> Option<(u64, usize)> {
        (self.exact(caller) && self.pending.is_none() && self.failure.is_none())
            .then(|| self.chunk(self.captured))?
    }

    pub fn capture_bytes(&mut self, caller: Caller, address: u64, bytes: &[u8]) -> bool {
        let Some((expected, length)) = self.next_capture(caller) else {
            return false;
        };
        if address != expected || bytes.len() != length {
            return false;
        }
        self.original[self.captured..self.captured + length].copy_from_slice(bytes);
        self.captured += length;
        true
    }

    pub fn begin_pending(
        &mut self, caller: Caller, address: u64, source: Source, irp: Irp,
    ) -> bool {
        if self.next_capture(caller).map(|(next, _)| next) != Some(address) {
            return false;
        }
        self.pending = Some(Pending { address, source, irp, acknowledged: false });
        true
    }

    pub fn acknowledge_pending(
        &mut self, caller: Caller, address: u64, source: Source, irp: Irp,
    ) -> bool {
        if !self.exact(caller) {
            return false;
        }
        let Some(pending) = self.pending.as_mut() else {
            return false;
        };
        if pending.address != address || pending.source != source || pending.irp != irp
            || pending.acknowledged
        {
            return false;
        }
        pending.acknowledged = true;
        true
    }

    pub fn resume_pending(
        &mut self, caller: Caller, address: u64, source: Source, irp: Irp,
    ) -> bool {
        if !self.exact(caller)
            || !self.pending.is_some_and(|pending|
                pending.address == address && pending.source == source
                    && pending.irp == irp && pending.acknowledged)
        {
            return false;
        }
        self.pending = None;
        true
    }

    pub fn fail_pending(
        &mut self, caller: Caller, address: u64, source: Source, irp: Irp, status: u32,
    ) -> bool {
        if status == 0 || status == 0x103 || !self.exact(caller)
            || !self.pending.is_some_and(|pending|
                pending.address == address && pending.source == source
                    && pending.irp == irp && pending.acknowledged)
        {
            return false;
        }
        self.pending = None;
        self.failure = Some(status);
        true
    }

    pub fn failure(&self, caller: Caller) -> Option<u32> {
        self.exact(caller).then_some(self.failure)?
    }

    /// A definitive inline capture failure may terminate the probe before any self-write.
    pub fn fail(&mut self, caller: Caller, status: u32) -> bool {
        if status == 0 || status == 0x103 || !self.exact(caller)
            || self.failure.is_some() || self.pending.is_some() || self.write_entered
            || self.written != 0
        {
            return false;
        }
        self.failure = Some(status);
        true
    }

    /// Returns the exact page-contained self-write, entering it before native effects.
    pub fn enter_write(&mut self, caller: Caller) -> Option<(u64, &[u8])> {
        if !self.exact(caller) || self.captured != COUNT_BYTES || self.pending.is_some()
            || self.write_entered || self.failure.is_some()
        {
            return None;
        }
        let (address, length) = self.chunk(self.written)?;
        self.write_entered = true;
        Some((address, &self.original[self.written..self.written + length]))
    }

    pub fn write_completed(&mut self, caller: Caller, address: u64) -> bool {
        if !self.exact(caller) || !self.write_entered
            || self.chunk(self.written).map(|(next, _)| next) != Some(address)
        {
            return false;
        }
        let (_, length) = self.chunk(self.written).unwrap();
        self.written += length;
        self.write_entered = false;
        true
    }

    pub fn published(&self, caller: Caller) -> bool {
        self.exact(caller) && self.captured == COUNT_BYTES
            && self.written == COUNT_BYTES && !self.write_entered && self.pending.is_none()
            && self.failure.is_none()
    }
}
